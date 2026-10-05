"""Дополнительные последовательные этапы общего конвейера; без сетевых импортов."""
from __future__ import annotations

import asyncio
import contextlib
from dataclasses import asdict
import hashlib
import json
import math
import re
from pathlib import Path
from urllib.parse import urlsplit

from bbscanner.probes import strict_json


def add_arguments(parser, base: Path) -> None:
    parser.add_argument('--with-js', action='store_true', help='JS secrets → scope-фильтр → GET')
    parser.add_argument('--with-monitor', action='store_true', help='один цикл DNS/Takeover перед Recon')
    parser.add_argument('--with-smuggling', action='store_true', help='отдельный time-based этап после GET/POST и IDOR')
    parser.add_argument('--idor-config', type=Path, help='UTF-8 JSONL: URL, cookie-файлы двух аккаунтов, attacker_ids')
    parser.add_argument('--monitor-output', type=Path, default=base / 'monitor_results', help='постоянная база поддоменов')
    parser.add_argument('--monitor-tool', choices=('subfinder', 'assetfinder'), default='subfinder')
    parser.add_argument('--monitor-recon-rate', type=int, default=2, help='отдельный rate внешнего subfinder')
    parser.add_argument('--extra-max-requests', type=int, default=200, help='бюджет отдельно для JS, IDOR, Smuggling на корень')
    parser.add_argument('--smuggling-timeout', type=float, default=6, help='таймаут финального HTTP-ответа (6)')


def validate_arguments(args) -> None:
    from pipeline_manager import normalize_url
    if not 1 <= args.extra_max_requests <= 10000:
        raise ValueError('--extra-max-requests: 1…10000')
    if not 1 <= args.monitor_recon_rate <= 1000:
        raise ValueError('--monitor-recon-rate: 1…1000')
    if not math.isfinite(args.smuggling_timeout) or not 1 <= args.smuggling_timeout <= 30:
        raise ValueError('--smuggling-timeout: 1…30 секунд')
    if args.with_smuggling and args.rate < .05:
        raise ValueError('Smuggling требует --rate >= 0.05')
    if args.with_monitor and not {80, 443}.issubset(args.ports):
        raise ValueError('Монитор проверяет HTTP/HTTPS: --ports должен включать 80 и 443')
    args.monitor_output = args.monitor_output.expanduser().resolve()
    args.idor_jobs = []
    if args.idor_config is None:
        return
    args.idor_config = args.idor_config.expanduser().resolve()
    if args.idor_config.stat().st_size > args.max_input_mib * 1024 * 1024:
        raise ValueError('IDOR JSONL превышает --max-input-mib')
    allowed = {'url', 'cookie_victim_file', 'cookie_attacker_file', 'attacker_ids',
               'data', 'json', 'id_params', 'mode', 'steps', 'victim_marker'}
    seen = set()
    with args.idor_config.open(encoding='utf-8-sig') as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            try:
                row = strict_json(line)
                if not isinstance(row, dict) or set(row) - allowed:
                    raise ValueError('неизвестные поля/не JSON-объект')
                row['url'] = normalize_url(row['url'])
                for key in ('cookie_victim_file', 'cookie_attacker_file'):
                    path = Path(row[key]).expanduser()
                    if not path.is_absolute():
                        path = args.idor_config.parent / path
                    path = path.resolve()
                    if not path.is_file() or not 0 < path.stat().st_size <= 16384:
                        raise ValueError('Cookie-файл отсутствует, пуст или больше 16 KiB')
                    row[key] = str(path)
                if not isinstance(row['attacker_ids'], dict) or not row['attacker_ids']:
                    raise ValueError('attacker_ids должен быть непустым объектом')
                if type(row.get('json', False)) is not bool:
                    raise ValueError('json должен быть boolean')
                if 'data' in row:
                    if row.get('json', False):
                        value = strict_json(row['data']) if isinstance(row['data'], str) else row['data']
                        if not isinstance(value, (dict, list)):
                            raise ValueError('JSON data должен быть объектом/массивом')
                        row['data'] = json.dumps(value, ensure_ascii=False, allow_nan=False)
                    elif not isinstance(row['data'], str):
                        raise ValueError('form data должен быть строкой')
                elif row.get('json'):
                    raise ValueError('json требует data')
                params = row.get('id_params', [])
                if not isinstance(params, list) or any(not isinstance(p, str) or not p or ',' in p for p in params):
                    raise ValueError('id_params должен быть списком имён/селекторов')
                if row.get('mode', 'direct') not in {'direct', 'increment', 'both'}:
                    raise ValueError('mode: direct, increment или both')
                if type(row.get('steps', 20)) is not int or not 1 <= row.get('steps', 20) <= 20:
                    raise ValueError('steps: целое 1…20')
                if 'victim_marker' in row and not isinstance(row['victim_marker'], str):
                    raise ValueError('victim_marker должен быть строкой')
                identity = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
                if identity in seen:
                    continue
                seen.add(identity)
                row['_identity'] = identity
                args.idor_jobs.append(row)
                if len(args.idor_jobs) > args.max_records:
                    raise ValueError('число IDOR-шаблонов превышает --max-records')
            except (ValueError, TypeError, KeyError, OSError) as exc:
                raise ValueError(f'IDOR JSONL, строка {number}: {exc}') from None


class ExtraStages:
    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.args = pipeline.args
        self.root = Path(__file__).resolve().parent.parent
        self.claimed_idor = set()

    def skipped(self, reason):
        return {'state': 'skipped', 'reason': reason}

    async def guarded(self, stage, domain, operation):
        try:
            return await operation
        except Exception as exc:
            self.pipeline.error(domain, stage, 'stage_exception', exception=type(exc).__name__)
            return {'state': 'exception', 'error': type(exc).__name__}

    def command(self, name):
        return [self.args.python, '-u', str(self.root / name)]

    async def execute(self, domain, command, stage, logs, output):
        result = await self.pipeline.execute(domain, command, stage, logs,
                                             self.args.scanner_timeout, output)
        if not self.pipeline.stop.is_set():
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self.pipeline.stop.wait(), 1 / self.args.rate)
        return asdict(result)

    async def monitor(self, domains):
        if not self.args.with_monitor:
            return self.skipped('not_enabled')
        if self.args.dry_run or not domains or self.pipeline.stop.is_set():
            return self.skipped('dry_run_or_no_targets_or_interrupted')
        targets = self.pipeline.run_dir / 'monitor_targets.txt'
        targets.write_text(''.join(d + '\n' for d in domains), encoding='utf-8')
        # Раздельная история для разных scope; предыдущие запуски остаются доступны.
        identity = json.dumps([sorted(domains), self.args.include_subdomains,
                               sorted(self.args.exclude_host)], sort_keys=True)
        scope_id = hashlib.sha256(identity.encode()).hexdigest()[:16]
        output = self.args.monitor_output / scope_id
        cmd = self.command('subdomain_monitor.py') + [
            '--targets', str(targets), '--output', str(output), '--interval', '0',
            '--tool', self.args.monitor_tool, '--recon-rate', str(self.args.monitor_recon_rate),
            '--rate', str(self.args.rate), '--concurrency', str(self.args.workers),
            '--timeout', str(self.args.http_timeout), '--recon-timeout', str(self.args.recon_timeout),
            '--max-hosts', str(self.args.max_records), '--no-color']
        if not self.args.include_subdomains:
            cmd.append('--roots-only')
        for host in self.args.exclude_host:
            cmd += ['--exclude-host', host]
        result = await self.execute('-', cmd, 'monitor', self.pipeline.run_dir / 'logs/monitor', output)
        result['output'] = str(output)
        return result

    async def js(self, domain, folder, data, scope):
        from pipeline_manager import filter_records
        if not self.args.with_js:
            return self.skipped('not_enabled')
        urls = [u for u in data.resource_urls if urlsplit(u).path.lower().endswith('.js')]
        urls = urls[:self.args.extra_max_requests]
        path = folder / 'js_urls.txt'
        path.write_text(''.join(u + '\n' for u in urls), encoding='utf-8')
        if not urls or self.args.dry_run or self.pipeline.stop.is_set():
            return self.skipped('no_js_urls_or_dry_run_or_interrupted')
        output = folder / 'js_results'
        cmd = self.command('js_secrets_finder.py') + ['-l', str(path), '-o', str(output),
            '--rate', str(self.args.rate), '--concurrency', str(self.args.workers),
            '--timeout', str(self.args.http_timeout), '--max-urls', str(len(urls)), '--no-color']
        result = await self.execute(domain, cmd, 'js', folder / 'logs/js', output)
        endpoints = output / 'extracted_endpoints.txt'
        if result['state'] in {'ok', 'nonzero'} and endpoints.is_file():
            extra = filter_records([endpoints], scope, self.args.max_records,
                                   self.args.max_input_mib * 1024 * 1024)
            scoped = folder / 'js_endpoints_in_scope.txt'
            scoped.write_text(''.join(u + '\n' for u in extra.resource_urls), encoding='utf-8')
            result['endpoint_filter'] = extra.counts
            for name in ('get_urls', 'resource_urls'):
                original = getattr(data, name)
                merged = list(dict.fromkeys(original + getattr(extra, name)))
                result['added_' + name] = max(0, min(len(merged), self.args.max_records) - len(original))
                result['omitted_' + name] = max(0, len(merged) - self.args.max_records)
                setattr(data, name, merged[:self.args.max_records])
        return result

    async def idor(self, domain, folder, scope):
        if not self.args.idor_jobs:
            return self.skipped('no_idor_config')
        if self.args.dry_run or self.pipeline.stop.is_set():
            return self.skipped('dry_run_or_interrupted')
        jobs = [r for r in self.args.idor_jobs if scope.contains(r['url'])
                and r['_identity'] not in self.claimed_idor]
        if not jobs:
            return self.skipped('no_matching_idor_templates')
        results = []
        budget = self.args.extra_max_requests
        for index, row in enumerate(jobs, 1):
            if self.pipeline.stop.is_set():
                break
            self.claimed_idor.add(row['_identity'])
            allocation = budget // (len(jobs) - index + 1)
            if allocation < 1:
                results.append(self.skipped('budget_exhausted'))
                continue
            budget -= allocation
            job = folder / 'idor_jobs' / f'{index:04d}'
            job.mkdir(parents=True, mode=0o700)
            output = job / 'results'
            cmd = self.command('idor_scanner.py') + ['-u', row['url'],
                '--cookie-victim', '@' + row['cookie_victim_file'],
                '--cookie-attacker', '@' + row['cookie_attacker_file'],
                '--attacker-ids', json.dumps(row['attacker_ids']),
                '--mode', row.get('mode', 'direct'), '--steps', str(row.get('steps', 20)),
                '--rate', str(self.args.rate), '--concurrency', str(self.args.workers),
                '--timeout', str(self.args.http_timeout), '--max-requests', str(allocation),
                '--output', str(output), '--no-color']
            if 'data' in row:
                body = job / 'body.txt'
                body.write_text(row['data'], encoding='utf-8')
                cmd += ['--data-file', str(body)]
            if row.get('json'):
                cmd.append('--json')
            if row.get('id_params'):
                cmd += ['--id-params', ','.join(row['id_params'])]
            if row.get('victim_marker'):
                cmd += ['--victim-marker', row['victim_marker']]
            results.append(await self.execute(domain, cmd, f'idor_{index:04d}', job / 'logs', output))
        return {'state': 'finished', 'jobs': results}

    async def smuggling(self, domain, folder, data):
        if not self.args.with_smuggling:
            return self.skipped('not_enabled')
        if self.args.dry_run or self.pipeline.stop.is_set():
            return self.skipped('dry_run_or_interrupted')
        # Не более 14 соединений на URL в данной версии scanner: baseline + probes + repeat/control.
        urls, rejected = [], 0
        for url in data.resource_urls:
            if urlsplit(url).path.lower().endswith(('.js', '.css', '.png', '.jpg', '.svg', '.woff', '.woff2')):
                continue
            if len(url) > 8192 or re.search(r'%(?:0[0-9a-f]|1[0-9a-f]|7f)', url, re.I):
                rejected += 1
            else:
                urls.append(url)
        cap = self.args.extra_max_requests // 14
        selected = list(dict.fromkeys(urls))[:cap]
        if not selected:
            return self.skipped('no_urls_or_budget_below_14')
        path = folder / 'smuggling_urls.txt'
        path.write_text(''.join(u + '\n' for u in selected), encoding='utf-8')
        output = folder / 'smuggling_results'
        cmd = self.command('smuggling_scanner.py') + ['-l', str(path), '-o', str(output),
            '--rate', str(min(self.args.rate, 2)), '--timeout', str(self.args.smuggling_timeout),
            '--connect-timeout', str(min(30, max(1, self.args.http_timeout))), '--method', 'OPTIONS']
        result = await self.execute(domain, cmd, 'smuggling', folder / 'logs/smuggling', output)
        result.update(urls=len(selected), rejected=rejected, omitted=max(0, len(urls) - len(selected)))
        return result
