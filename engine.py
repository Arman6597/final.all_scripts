"""Планирование baseline и проверок; ограниченное число параллельных задач."""
import asyncio
from collections import Counter
from datetime import datetime, timezone
import signal

from .checks import CHECKS
from .core import (Context, HttpClient, RequestBudgetReached, add_parameters,
                   check_result, choose_agent, operational_error, origin, parameters)
from .discovery import discover
from .reporting import Reporter
from .probes import baseline_ready
from .runtime import bounded


async def run_scan(args, roots: list[str], cookie_origin: str | None) -> dict:
    started = datetime.now(timezone.utc).isoformat()
    reporter = Reporter(args.output, color=not args.no_color)
    targets, baselines, agents = {}, {}, {}
    skipped, status, unexpected = Counter(), 'completed', None
    loop, current = asyncio.get_running_loop(), asyncio.current_task()
    signal_installed = False
    try:
        loop.add_signal_handler(signal.SIGTERM, current.cancel)
        signal_installed = True
    except (NotImplementedError, RuntimeError):
        pass
    async with HttpClient(args, {origin(url) for url in roots}, cookie_origin) as client:
        try:
            # --params — явные гипотезы пользователя, без словаря несуществующих параметров.
            for url in roots:
                target = add_parameters(url, args.params)
                targets[target] = {'source': url, 'discovered': False}
            async def baseline(url):
                if client.request_count >= args.max_requests:
                    skipped['baseline_request_budget'] += 1
                    return
                agent = agents.setdefault(url, choose_agent(args))
                try:
                    baselines[url] = await client.fetch(url, agent, 'baseline')
                except RequestBudgetReached:
                    skipped['baseline_request_budget'] += 1
            await bounded(list(targets), baseline, args.workers)
            if not args.no_discovery:
                for url in list(targets):
                    response = baselines.get(url)
                    if parameters(url) or not response or not response.usable or response.truncated:
                        continue
                    mime = response.headers.get('content-type', '').split(';', 1)[0].strip().lower()
                    if mime not in ('text/html', 'application/xhtml+xml'):
                        continue
                    for found in discover(url, response.text, args.max_targets):
                        if len(targets) >= args.max_targets:
                            skipped['max_targets'] += 1
                            break
                        targets.setdefault(found, {'source': url, 'discovered': True})
                await bounded([url for url in targets if url not in baselines], baseline, args.workers)
            jobs = []
            for url in targets:
                available = parameters(url)
                if args.params:
                    available = [(i, name) for i, name in available if name in args.params]
                if not available:
                    skipped['no_query_parameters'] += 1
                    continue
                if len(available) > args.max_parameters:
                    skipped['max_parameters'] += len(available) - args.max_parameters
                response = baselines.get(url)
                if response is None:
                    skipped['missing_baseline'] += 1
                    continue
                for index, name in available[:args.max_parameters]:
                    context = Context(url, index, name, response, agents[url])
                    for module in args.modules:
                        if not baseline_ready(module, response):
                            reporter.record(check_result(module, context, 'inconclusive',
                                'baseline_' + (response.error or 'truncated_or_unusable')))
                        else:
                            jobs.append((module, context))
            reporter.message(f'URL: {len(targets)}; проверок параметров: {len(jobs)}; лимит запросов: {args.max_requests}')
            async def execute(job):
                module, context = job
                if client.request_count >= args.max_requests:
                    reporter.record(check_result(module, context, 'skipped', 'request_budget'))
                    return
                try:
                    result = await CHECKS[module](client, context)
                except RequestBudgetReached:
                    result = check_result(module, context, 'inconclusive', 'request_budget')
                except Exception as exc:
                    # Ошибка одной проверки не отменяет остальные URL.
                    result = check_result(module, context, 'inconclusive', 'module_error:' + type(exc).__name__)
                reporter.record(result)
            await bounded(jobs, execute, args.workers)
            if client.budget_rejections or skipped.get('baseline_request_budget') or any(x['reason'] == 'request_budget' for x in reporter.checks):
                status = 'budget_exhausted'
            elif not reporter.checks:
                status = 'no_testable_parameters' if any(x.usable for x in baselines.values()) else 'failed'
            elif all(x['state'] in ('inconclusive', 'skipped') for x in reporter.checks):
                status = 'inconclusive'
            elif any(operational_error(x) for x in client.events) or any(x['state'] == 'inconclusive' for x in reporter.checks):
                status = 'completed_with_errors'
        except asyncio.CancelledError:
            status = 'interrupted'
            reporter.message('Прервано: сохраняю уже завершённые проверки.')
        except Exception as exc:
            status, unexpected = 'failed', type(exc).__name__
        finally:
            if signal_installed:
                loop.remove_signal_handler(signal.SIGTERM)
            summary = {'status': status, 'started_at': started,
                'finished_at': datetime.now(timezone.utc).isoformat(),
                'requests': client.request_count, 'target_count': len(targets),
                'check_states': dict(Counter(x['state'] for x in reporter.checks)),
                'findings': len(reporter.findings),
                'confirmed_signals': sum(x['status'] == 'confirmed_signal' for x in reporter.findings),
                'candidates': sum(x['status'] == 'candidate' for x in reporter.findings),
                'oast_probes_pending': len(client.oast.latest) if client.oast else 0,
                'http_errors': sum(operational_error(x) for x in client.events),
                'limits_and_skips': dict(skipped), 'unexpected_error': unexpected,
                'settings': {'workers': args.workers, 'rate': args.rate, 'timeout': args.timeout,
                             'modules': args.modules, 'max_requests': args.max_requests,
                             'cookie_origin': cookie_origin, 'authenticated': bool(args.cookies)}}
            reporter.finish(summary, client.events, targets)
            reporter.message(f"Статус: {status}; подтверждённых признаков: {summary['confirmed_signals']}; кандидатов: {summary['candidates']}")
            reporter.message(f'Отчёт: {args.output / "vulns_report.txt"}')
    return summary
