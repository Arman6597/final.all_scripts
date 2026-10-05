#!/usr/bin/env python3
"""Монитор поддоменов: пассивный Recon, DNS и HTTP-признаки takeover-кандидатов."""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
import contextlib
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import sys
import tempfile
import uuid

import aiodns
import aiohttp
from aiohttp.abc import AbstractResolver
import pycares
from colorama import Fore, Style, just_fix_windows_console


LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
S3 = re.compile(r'(?:^|\.)s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com(?:\.cn)?\Z')
MAX_STATE_BYTES = 20 * 1024 * 1024


def now():
    return datetime.now(timezone.utc).isoformat()


def domain(value):
    value = value.strip().rstrip('.').lower()
    if not value or any(c in value for c in '/\\:@*?#') or any(c.isspace() for c in value):
        raise ValueError('ожидается hostname без схемы, пути, порта и wildcard')
    value = value.encode('idna').decode('ascii')
    if len(value) > 253 or '.' not in value or not all(LABEL.fullmatch(x) for x in value.split('.')):
        raise ValueError('некорректное доменное имя')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('ожидается домен, а не IP')


def beneath(host, root):
    return host == root or host.endswith('.' + root)


@dataclass(frozen=True)
class Scope:
    roots: tuple[str, ...]
    excluded: tuple[str, ...] = ()
    include_subdomains: bool = True

    def contains(self, host):
        return any(host == root or (self.include_subdomains and beneath(host, root)) for root in self.roots) and not any(beneath(host, root) for root in self.excluded)


def load_domains(path):
    if path.stat().st_size > MAX_STATE_BYTES:
        raise ValueError(f'слишком большой файл: {path}')
    result = set()
    with path.open(encoding='utf-8-sig') as stream:
        for number, line in enumerate(stream, 1):
            value = line.strip()
            if not value or value.startswith('#'):
                continue
            try:
                result.add(domain(value))
            except (ValueError, UnicodeError) as exc:
                raise ValueError(f'{path}: некорректный домен в строке {number}') from exc
    return result


def atomic_write(path, text):
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def private_open(path, append=True):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_APPEND if append else os.O_TRUNC), 0o600)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, 'a' if append else 'w', encoding='utf-8')


def write_line(stream, data):
    stream.write(json.dumps(data, ensure_ascii=True) + '\n')
    stream.flush()


def update_history(folder, discovered):
    path = folder / 'known_subdomains.txt'
    known = load_domains(path) if path.exists() else set()
    fresh = discovered - known
    atomic_write(folder / 'new_discovered.txt', ''.join(x + '\n' for x in sorted(fresh)))
    atomic_write(path, ''.join(x + '\n' for x in sorted(known | discovered)))
    return fresh, known | discovered


class NetworkGate:
    def __init__(self, rate, concurrency):
        self.interval = 1 / rate
        self.semaphore = asyncio.Semaphore(concurrency)
        self.lock = asyncio.Lock()
        self.next_start = 0.0
        self.counts = Counter()

    @contextlib.asynccontextmanager
    async def slot(self, kind):
        async with self.semaphore:
            async with self.lock:
                loop = asyncio.get_running_loop()
                await asyncio.sleep(max(0, self.next_start - loop.time()))
                self.next_start = loop.time() + self.interval
                self.counts[kind] += 1
            yield


class DNS:
    def __init__(self, gate, timeout, resolver=None):
        self.gate, self.timeout = gate, timeout
        self.resolver = resolver or aiodns.DNSResolver(timeout=timeout, tries=1)

    async def query(self, name, kind):
        async with self.gate.slot('dns'):
            try:
                result = await asyncio.wait_for(self.resolver.query_dns(name + '.', kind), timeout=self.timeout)
                code = getattr(pycares, 'QUERY_TYPE_' + kind)
                records = [r for r in result.answer if r.type == code]
                if kind == 'CNAME':
                    # Только CNAME запрошенного owner, а не произвольный alias в answer.
                    records = [r for r in records if r.name.rstrip('.').lower() == name]
                    values = [domain(r.data.cname) for r in records]
                else:
                    values = [str(ipaddress.ip_address(r.data.addr)) for r in records]
                return {'name': name, 'type': kind, 'state': 'ok' if values else 'nodata', 'values': values}
            except aiodns.error.DNSError as exc:
                states = {pycares.errno.ARES_ENOTFOUND: 'nxdomain', pycares.errno.ARES_ENODATA: 'nodata'}
                code = exc.args[0] if exc.args else None
                return {'name': name, 'type': kind, 'state': states.get(code, 'error'), 'code': code, 'values': []}
            except (asyncio.TimeoutError, OSError, ValueError, UnicodeError) as exc:
                return {'name': name, 'type': kind, 'state': 'error', 'error': type(exc).__name__, 'values': []}

    async def inspect(self, host, scope):
        if not scope.contains(host):
            raise ValueError('out_of_scope')
        current, seen, chain, trace = host, {host}, [], []
        for _ in range(8):
            answer = await self.query(current, 'CNAME')
            trace.append(answer)
            if answer['state'] != 'ok':
                break
            target = answer['values'][0]
            chain.append({'owner': current, 'target': target})
            if target in seen:
                return {'state': 'cname_loop', 'chain': chain, 'trace': trace, 'addresses': [], 'dangling': False}
            seen.add(target)
            current = target
        else:
            return {'state': 'chain_limit', 'chain': chain, 'trace': trace, 'addresses': [], 'dangling': False}
        answers = [await self.query(current, kind) for kind in ('A', 'AAAA')]
        trace.extend(answers)
        addresses = sorted({ip for a in answers for ip in a['values']})
        nxdomain = all(a['state'] == 'nxdomain' for a in answers)
        dangling = False
        if chain and nxdomain:
            confirmation = await self.query(current, 'A')
            trace.append(confirmation)
            dangling = confirmation['state'] == 'nxdomain'
        state = 'resolved' if addresses else ('nxdomain' if nxdomain else 'unresolved')
        if any(a['state'] == 'error' for a in trace):
            state = 'partial_dns_error' if addresses else 'dns_error'
        return {'state': state, 'chain': chain, 'trace': trace, 'addresses': addresses, 'dangling': dangling}

    async def close(self):
        await self.resolver.close()


def public_addresses(addresses):
    return bool(addresses) and all(ipaddress.ip_address(ip).is_global for ip in addresses)


class PinnedResolver(AbstractResolver):
    def __init__(self, scope):
        self.scope, self.pins = scope, {}

    async def resolve(self, host, port=0, family=socket.AF_INET):
        if not self.scope.contains(host) or host not in self.pins:
            raise OSError('hostname не разрешён для HTTP')
        addresses = self.pins[host]
        if not public_addresses(addresses):
            raise OSError('непубличный IP заблокирован')
        return [{'hostname': host, 'host': ip, 'port': port,
                 'family': socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET,
                 'proto': socket.IPPROTO_TCP, 'flags': socket.AI_NUMERICHOST}
                for ip in addresses
                if family in (socket.AF_UNSPEC, socket.AF_INET6 if ':' in ip else socket.AF_INET)]

    async def close(self):
        self.pins.clear()


async def http_get(session, gate, scope, host, scheme, max_bytes):
    if not scope.contains(host):
        raise ValueError('out_of_scope')
    url = f'{scheme}://{host}/'
    row = {'url': url, 'status': None, 'headers': {}, 'error': None}
    async with gate.slot('http'):
        try:
            async with session.get(url, allow_redirects=False) as response:
                row['status'] = response.status
                row['headers'] = {k: v for k, v in response.headers.items()
                                  if k.lower() in {'server', 'content-type', 'location', 'x-amz-request-id'}}
                body = bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    if len(body) + len(chunk) > max_bytes:
                        row['error'] = 'response_too_large'
                        return row
                    body.extend(chunk)
                row['size'] = len(body)
                row['sha256'] = hashlib.sha256(body).hexdigest()
                try:
                    row['text'] = body.decode(response.charset or 'utf-8', errors='replace')
                except LookupError:
                    row['text'] = body.decode('utf-8', errors='replace')
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, OSError) as exc:
            row['error'] = type(exc).__name__
    return row


def provider(target):
    if beneath(target, 'github.io'):
        return 'github_pages'
    if any(beneath(target, root) for root in ('herokuapp.com', 'herokudns.com')):
        return 'heroku'
    if S3.search(target):
        return 'aws_s3'
    return None


FINGERPRINTS = {
    'github_pages': re.compile(r"There isn['’]t a GitHub Pages site here|GitHub Pages\s*[-–—]\s*404 Not Found", re.I),
    'heroku': re.compile(r'There is no app here for this domain|There is no app configured at that hostname|No such app|herokucdn\.com/error-pages/no-such-app\.html', re.I),
    'aws_s3': re.compile(r'\bNoSuchBucket\b'),
}


def detect(dns, responses):
    results = []
    if dns['dangling']:
        results.append({'kind': 'dangling_cname', 'provider': provider(dns['chain'][-1]['target']),
                        'confidence': 'low', 'evidence': 'CNAME target: repeated NXDOMAIN; availability not verified'})
    providers = {provider(link['target']) for link in dns['chain']} - {None}
    for row in responses:
        if row.get('error') or row['status'] != 404:
            continue
        for name in providers:
            match = FINGERPRINTS[name].search(row.get('text', ''))
            if match:
                results.append({'kind': 'service_fingerprint', 'provider': name, 'confidence': 'medium',
                                'url': row['url'], 'status': row['status'], 'evidence': match.group(0),
                                'sha256': row['sha256'],
                                'excerpt': row['text'][max(0, match.start()-100):match.end()+200]})
    return results


async def terminate(process):
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        await asyncio.wait_for(process.wait(), timeout=2)
    except asyncio.TimeoutError:
        pass
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    await process.wait()


async def run_recon(argv, folder, timeout, max_bytes):
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    process, job = None, None
    try:
        with private_open(folder / 'stdout.log', False) as stdout, private_open(folder / 'stderr.log', False) as stderr:
            process = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.DEVNULL, start_new_session=True)
            async def pump(source, destination):
                size = 0
                while chunk := await source.read(65536):
                    size += len(chunk)
                    if size > max_bytes:
                        raise ValueError('recon_output_limit')
                    destination.buffer.write(chunk)
                    destination.flush()
            job = asyncio.gather(process.wait(), pump(process.stdout, stdout), pump(process.stderr, stderr))
            try:
                await asyncio.wait_for(asyncio.shield(job), timeout=timeout)
            finally:
                await terminate(process)
                if not job.done():
                    job.cancel()
                await asyncio.gather(job, return_exceptions=True)
            return {'state': 'ok' if process.returncode == 0 else 'nonzero', 'returncode': process.returncode}
    except asyncio.TimeoutError:
        return {'state': 'timeout'}
    except (OSError, ValueError) as exc:
        return {'state': 'error', 'reason': str(exc)}


class Monitor:
    def __init__(self, args, stop):
        self.args, self.stop = args, stop
        self.gate = NetworkGate(args.rate, args.concurrency)
        self.color = sys.stdout.isatty() and not args.no_color

    def message(self, label, value, shade=''):
        print((shade if self.color else '') + label + ' ' + json.dumps(value, ensure_ascii=True)
              + (Style.RESET_ALL if self.color else ''), flush=True)

    async def cycle(self):
        args = self.args
        roots = tuple(sorted(load_domains(args.targets)))
        if not roots or len(roots) > 100:
            raise ValueError('targets должен содержать от 1 до 100 корневых доменов')
        scope = Scope(roots, tuple(args.exclude_host), not args.roots_only)
        cycle_id = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:8]
        run_dir = args.output / 'runs' / cycle_id
        run_dir.mkdir(parents=True, mode=0o700)
        counts, discovered = Counter(), set()
        before = self.gate.counts.copy()
        summary = {'cycle': cycle_id, 'started': now(), 'status': 'failed', 'roots': roots}
        known_path = args.output / 'known_subdomains.txt'
        known_before = load_domains(known_path) if known_path.exists() else set()
        observed_path = args.output / 'last_observations.json'
        previous = {}
        if observed_path.exists():
            if observed_path.stat().st_size > MAX_STATE_BYTES:
                raise ValueError('слишком большой last_observations.json')
            previous = json.loads(observed_path.read_text(encoding='utf-8'))
            if not isinstance(previous, dict):
                raise ValueError('повреждён last_observations.json')
        latest = dict(previous)
        with private_open(args.output / 'takeover_candidates.jsonl') as candidates, \
             private_open(args.output / 'errors.jsonl') as errors, \
             private_open(run_dir / 'observations.jsonl') as observations, \
             private_open(args.output / 'changes.jsonl') as changes:
            def error(stage, reason, **extra):
                counts['errors'] += 1
                row = {'timestamp': now(), 'cycle': cycle_id, 'stage': stage, 'reason': reason, **extra}
                write_line(errors, row)
                self.message('[!]', row, Fore.YELLOW)
            try:
                for root in roots:
                    if not scope.contains(root):
                        continue
                    discovered.add(root)
                    if args.roots_only:
                        continue
                    self.message('[RECON]', root)
                    if args.tool == 'subfinder':
                        argv = [args.tool, '-d', root, '-silent', '-nc', '-duc', '-rl', str(args.recon_rate)]
                    else:
                        argv = [args.tool, '--subs-only', root]
                    folder = run_dir / 'recon' / root
                    result = await run_recon(argv, folder, args.recon_timeout, args.max_log_bytes)
                    if result['state'] != 'ok':
                        error('recon', result['state'], root=root, details=result)
                        continue
                    with (folder / 'stdout.log').open(encoding='utf-8') as stream:
                        for raw in stream:
                            if not raw.strip():
                                continue
                            try:
                                host = domain(raw)
                            except (ValueError, UnicodeError):
                                counts['invalid_recon_lines'] += 1
                                continue
                            if not beneath(host, root) or not scope.contains(host):
                                counts['out_of_scope'] += 1
                                continue
                            discovered.add(host)
                fresh, all_known = update_history(args.output, discovered)
                atomic_write(run_dir / 'new_discovered.txt', ''.join(h+'\n' for h in sorted(fresh)))
                atomic_write(run_dir / 'discovered.txt', ''.join(h+'\n' for h in sorted(discovered)))
                for host in sorted(fresh):
                    self.message('[NEW]', host, Fore.GREEN)
                counts.update({'discovered': len(discovered), 'new': len(fresh)})
                hosts = sorted(fresh) + sorted(h for h in all_known - fresh if scope.contains(h))
                if len(hosts) > args.max_hosts:
                    error('limits', 'max_hosts', omitted=len(hosts)-args.max_hosts)
                    hosts = hosts[:args.max_hosts]
                counts['scheduled'] = len(hosts)
                resolver = PinnedResolver(scope)
                dns = DNS(self.gate, args.timeout)
                iterator = iter(hosts)
                try:
                    connector = aiohttp.TCPConnector(resolver=resolver, limit=args.concurrency,
                                use_dns_cache=False, family=socket.AF_UNSPEC, force_close=True)
                    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=args.timeout),
                                headers={'User-Agent': 'Scope-Subdomain-Monitor/1.0'},
                                cookie_jar=aiohttp.DummyCookieJar(), trust_env=False) as session:
                        async def worker():
                            for host in iterator:
                                try:
                                    record = await dns.inspect(host, scope)
                                    responses = []
                                    if public_addresses(record['addresses']):
                                        resolver.pins[host] = record['addresses']
                                        for scheme in ('https', 'http'):
                                            response = await http_get(session, self.gate, scope, host, scheme, args.max_bytes)
                                            responses.append(response)
                                            if response['error']:
                                                error('http', response['error'], host=host, url=response['url'])
                                    elif record['addresses']:
                                        error('scope', 'non_public_address', host=host)
                                    if record['state'] in {'dns_error', 'partial_dns_error', 'chain_limit', 'cname_loop', 'unresolved'}:
                                        error('dns', record['state'], host=host)
                                    signals = detect(record, responses)
                                    observation = {'timestamp': now(), 'cycle': cycle_id, 'host': host,
                                                   'dns': record, 'http': [{k:v for k,v in r.items() if k!='text'} for r in responses]}
                                    write_line(observations, observation)
                                    for candidate in signals:
                                        row = {'timestamp': now(), 'cycle': cycle_id, 'host': host, 'state': 'candidate',
                                               **candidate, 'cname_chain': record['chain'],
                                               'note': 'Регистрация и возможность перехвата не проверялись. Требуется ручной анализ.'}
                                        write_line(candidates, row)
                                        counts['candidates'] += 1
                                        self.message('[TAKEOVER candidate]', {'host': host, 'kind': row['kind'], 'provider': row['provider']}, Fore.LIGHTRED_EX)
                                    snapshot = {'chain': record['chain'], 'addresses': record['addresses'], 'dns_state': record['state'],
                                                'http': {r['url']: {'status': r['status'], 'error': r['error']} for r in responses}}
                                    if host in previous and snapshot != previous[host]:
                                        write_line(changes, {'timestamp': now(), 'cycle': cycle_id, 'host': host,
                                                            'previous': previous[host], 'current': snapshot})
                                        counts['changed'] += 1
                                    latest[host] = snapshot
                                    counts['checked'] += 1
                                except (ValueError, aiohttp.ClientError, aiodns.error.DNSError) as exc:
                                    error('host', type(exc).__name__, host=host)
                                finally:
                                    resolver.pins.pop(host, None)
                        workers = [asyncio.create_task(worker()) for _ in range(min(args.concurrency, len(hosts)))]
                        try:
                            await asyncio.gather(*workers)
                        finally:
                            for task in workers:
                                task.cancel()
                            await asyncio.gather(*workers, return_exceptions=True)
                finally:
                    await dns.close()
                summary['status'] = 'completed_with_errors' if counts['errors'] else 'completed'
            except asyncio.CancelledError:
                summary['status'] = 'interrupted'
                raise
            finally:
                # История не очищается при сбое Recon или временном исчезновении имени.
                if discovered and summary['status'] in {'failed', 'interrupted'}:
                    atomic_write(run_dir / 'partial_discovered.txt', ''.join(h+'\n' for h in sorted(discovered)))
                atomic_write(observed_path, json.dumps(latest, ensure_ascii=True, indent=2)+'\n')
                summary.update(finished=now(), counts=dict(counts), requests=dict(self.gate.counts-before))
                encoded = json.dumps(summary, ensure_ascii=True, indent=2)+'\n'
                atomic_write(run_dir / 'summary.json', encoded)
                atomic_write(args.output / 'summary.json', encoded)
        self.message('[DONE]', summary)
        return 0 if summary['status']=='completed' else 1


async def run(args):
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    monitor = Monitor(args, stop)
    code = 0
    try:
        while not stop.is_set():
            task = asyncio.create_task(monitor.cycle())
            stopped = asyncio.create_task(stop.wait())
            try:
                await asyncio.wait({task, stopped}, return_when=asyncio.FIRST_COMPLETED)
                if stop.is_set():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    return 130
                code = await task
            finally:
                stopped.cancel()
                await asyncio.gather(stopped, return_exceptions=True)
            if not args.interval:
                return code
            try:
                await asyncio.wait_for(stop.wait(), timeout=args.interval)
            except asyncio.TimeoutError:
                pass
        return 130
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)


def positive(value):
    n = float(value)
    if not math.isfinite(n) or n <= 0:
        raise argparse.ArgumentTypeError('нужно конечное положительное число')
    return n


def bounded(low, high):
    def parse(value):
        n = int(value)
        if not low <= n <= high:
            raise argparse.ArgumentTypeError(f'число вне диапазона {low}…{high}')
        return n
    return parse


def arguments(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog='targets: корни с разрешёнными поддоменами. --rate ограничивает начала DNS/HTTP операций монитора; '
               'лимиты внешнего Recon задаются отдельно. Отсутствие имени в Recon не означает его удаления.')
    p.add_argument('--targets', type=Path, default=Path.home()/'bugbounty/targets.txt')
    p.add_argument('-o','--output', type=Path, default=Path.home()/'bugbounty/monitor_results')
    p.add_argument('--rate', type=positive, default=10)
    p.add_argument('--concurrency', type=bounded(1,100), default=20)
    p.add_argument('--roots-only', action='store_true', help='проверять только точные имена из targets, без сбора поддоменов')
    p.add_argument('--tool', choices=('subfinder','assetfinder'), default='subfinder')
    p.add_argument('--recon-rate', type=bounded(1,1000), default=10, help='HTTP requests/s для subfinder; assetfinder не поддерживает этот флаг')
    p.add_argument('--exclude-host', action='append', default=[], help='исключить hostname и его поддомены; можно повторять')
    p.add_argument('--timeout', type=positive, default=10)
    p.add_argument('--recon-timeout', type=positive, default=600)
    p.add_argument('--interval', type=bounded(0,604800), default=0, help='пауза между циклами в секундах; 0 — один цикл')
    p.add_argument('--max-hosts', type=bounded(1,100000), default=10000)
    p.add_argument('--max-bytes', type=bounded(1024,10000000), default=1000000)
    p.add_argument('--max-log-bytes', type=bounded(1024,MAX_STATE_BYTES), default=4000000)
    p.add_argument('--no-color', action='store_true')
    args = p.parse_args(argv)
    args.targets = args.targets.expanduser().resolve()
    args.output = args.output.expanduser().resolve()
    try:
        if not args.targets.is_file():
            raise ValueError('targets-файл не найден')
        args.exclude_host = [domain(h) for h in args.exclude_host]
        roots = load_domains(args.targets)
        if not roots or len(roots)>100:
            raise ValueError('нужно от 1 до 100 корневых доменов')
        if args.interval and args.interval<60:
            raise ValueError('--interval: минимум 60 секунд')
        if not args.roots_only and not shutil.which(args.tool):
            raise ValueError(f'инструмент {args.tool} не найден в PATH')
    except (ValueError, OSError, UnicodeError) as exc:
        p.error(str(exc))
    return args


def main():
    os.umask(0o077)
    try:
        args = arguments()
        args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
        just_fix_windows_console()
        with private_open(args.output / '.monitor.lock') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError('эта папка результатов уже используется другим монитором') from exc
            return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        print('[ERROR] '+json.dumps(str(exc), ensure_ascii=True), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
