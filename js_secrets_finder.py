#!/usr/bin/env python3
"""Асинхронный поиск потенциальных секретов и endpoint-ов в JS."""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import ipaddress
import math
import os
from pathlib import Path
import random
import re
import signal
import sys
import tempfile
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

import aiohttp
from colorama import Fore, Style, just_fix_windows_console


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    confidence: str
    note: str


RULES = (
    Rule('google_firebase_api_key', re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b'),
         'candidate', 'Firebase/Google key может быть публичным; проверь ограничения доступа.'),
    Rule('aws_access_key_id', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
         'high', 'Access Key ID без Secret Access Key не доказывает возможность доступа.'),
    Rule('stripe_secret_key', re.compile(r'\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b'),
         'high', 'Проверь окружение live/test и принадлежность ключа.'),
    Rule('slack_bot_token', re.compile(r'\bxox[baprs]-[0-9A-Za-z-]{10,}\b'),
         'high', 'Потенциальный Slack token; действительность не проверяется.'),
    Rule('slack_webhook', re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+'),
         'high', 'Потенциальный webhook; запросы на него не отправляются.'),
    Rule('paypal_credential', re.compile(
        r'''(?i)["']?paypal[_\w]{0,40}(?:secret|client[_-]?id|token)["']?\s*[:=]\s*["'](?P<value>[^"'\r\n]{12,512})["']'''),
         'candidate', 'PayPal client ID может быть публичным; secret/token требуют проверки.'),
    Rule('bearer_token', re.compile(r'(?i)\bBearer\s+(?P<value>[A-Za-z0-9._~+/=-]{16,2048})'),
         'candidate', 'Потенциальный Bearer token.'),
    Rule('generic_assignment', re.compile(
        r'''(?i)(?<![\w$])["']?(?:[\w$]{0,40})?(?:api[_-]?key|secret|password|passwd|token|authorization)(?:[\w$]{0,30})?["']?\s*[:=]\s*["'](?P<value>[^"'\r\n]{8,2048})["']'''),
         'candidate', 'Эвристика: строка может быть примером или публичной настройкой.'),
)
STRINGS = re.compile(r'''(?P<q>["'`])(?P<value>(?:\\[^\r\n]|(?!(?P=q))[^\\\r\n]){1,2048})(?P=q)''')
ASSET_SUFFIXES = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico', '.avif',
                  '.woff', '.woff2', '.ttf', '.otf', '.eot', '.css', '.map', '.js',
                  '.mp4', '.mp3', '.pdf'}
PLACEHOLDERS = {'undefined', 'null', 'changeme', 'your_api_key', 'your_token',
                'your_password', 'password', 'xxxxxxxx', 'example', 'placeholder'}
USER_AGENTS = (
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0',
)


def normalize_url(value: str) -> str:
    if not value or any(ord(c) < 33 or ord(c) == 127 for c in value) or '\\' in value:
        raise ValueError('некорректный URL')
    p = urlsplit(value)
    if p.scheme.lower() not in {'http', 'https'} or not p.hostname or p.username is not None or p.password is not None:
        raise ValueError('нужен HTTP(S) URL без userinfo')
    host = p.hostname.encode('idna').decode('ascii').lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.rstrip('.').split('.')):
            raise ValueError('некорректный hostname')
    port = p.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('некорректный порт')
    if ':' in host:
        host = '[' + host + ']'
    if port is not None and port != (443 if p.scheme.lower() == 'https' else 80):
        host += ':' + str(port)
    return urlunsplit((p.scheme.lower(), host, p.path or '/', p.query, ''))


def load_urls(path: Path, max_urls: int) -> tuple[list[str], Counter]:
    urls, seen, counts = [], set(), Counter()
    with path.open(encoding='utf-8-sig') as source:
        for line in source:
            raw = line.strip()
            if not raw or raw.startswith('#'):
                continue
            counts['input'] += 1
            try:
                url = normalize_url(raw)
            except (ValueError, UnicodeError):
                counts['invalid'] += 1
                continue
            if not urlsplit(url).path.lower().endswith('.js'):
                counts['not_js'] += 1
                continue
            if url in seen:
                counts['duplicates'] += 1
                continue
            if len(urls) >= max_urls:
                counts['over_limit'] += 1
                continue
            seen.add(url)
            urls.append(url)
    return urls, counts


def decode_js_slashes(text: str) -> str:
    return re.sub(r'\\(?:/|u002f|x2f)', '/', text, flags=re.IGNORECASE)


def find_secrets(text: str):
    text = decode_js_slashes(text)
    seen = set()
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            value = match.groupdict().get('value') or match.group(0)
            if value.lower() in PLACEHOLDERS or '${' in value:
                continue
            identity = (rule.name, value)
            if identity in seen:
                continue
            seen.add(identity)
            yield {'type': rule.name, 'value': value, 'confidence': rule.confidence,
                   'note': rule.note, 'offset': match.start()}


def extract_endpoints(text: str, js_url: str) -> set[str]:
    endpoints = set()
    p = urlsplit(js_url)
    origin = urlunsplit((p.scheme, p.netloc, '/', '', ''))
    for match in STRINGS.finditer(text):
        value = decode_js_slashes(match.group('value'))
        if '${' in value or any(c in value for c in '{}<>') or len(value) > 2048:
            continue
        absolute = value.startswith(('http://', 'https://', '//'))
        relative = value.startswith(('/', './', '../'))
        bare = bool(re.match(r'^(?:_?auth|api|wp-json|graphql|rest|v[0-9]+)[/ ?]', value, re.I))
        if not (absolute or relative or bare) or value in {'/', '//', './', '../'}:
            continue
        try:
            base = js_url if value.startswith(('./', '../')) else origin
            endpoint = normalize_url(urljoin(base, value))
            path = unquote(urlsplit(endpoint).path).lower()
            if Path(path).suffix in ASSET_SUFFIXES:
                continue
            endpoints.add(endpoint)
        except (ValueError, UnicodeError):
            continue
    return endpoints


class RateLimiter:
    def __init__(self, rate: float):
        self.interval = 1 / rate
        self.lock = asyncio.Lock()
        self.next_start = 0.0

    async def wait(self):
        async with self.lock:
            loop = asyncio.get_running_loop()
            await asyncio.sleep(max(0, self.next_start - loop.time()))
            self.next_start = loop.time() + self.interval


class HttpClient:
    def __init__(self, session: aiohttp.ClientSession, concurrency: int, rate: float, max_bytes: int):
        self.session = session
        self.semaphore = asyncio.Semaphore(concurrency)
        self.limiter = RateLimiter(rate)
        self.max_bytes = max_bytes

    async def download(self, url: str) -> str:
        async with self.semaphore:
            await self.limiter.wait()
            async with self.session.get(url, allow_redirects=False,
                                        headers={'User-Agent': random.choice(USER_AGENTS)}) as response:
                if not 200 <= response.status < 300:
                    raise ValueError(f'HTTP {response.status}; редиректы не выполняются')
                if 'text/html' in response.headers.get('Content-Type', '').lower():
                    raise ValueError('HTML вместо JavaScript')
                data = bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    if len(data) + len(chunk) > self.max_bytes:
                        raise ValueError('файл превышает --max-bytes')
                    data.extend(chunk)
                encoding = response.charset or 'utf-8'
                try:
                    return data.decode(encoding, errors='replace')
                except LookupError:
                    return data.decode('utf-8', errors='replace')


def private_append(path: Path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, 'a', encoding='utf-8')


def atomic_write(path: Path, text: str):
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


async def run(args) -> int:
    urls, counts = load_urls(args.list, args.max_urls)
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    endpoints, stop = set(), asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    queue = asyncio.Queue(maxsize=args.concurrency * 2)
    colored = sys.stdout.isatty() and not args.no_color
    just_fix_windows_console()
    print(f'[i] JS-файлов: {len(urls)}; пропущено: {dict(counts)}', flush=True)
    tasks = []
    finished = False
    with private_append(output / 'secrets.jsonl') as secrets, private_append(output / 'errors.jsonl') as errors:
        async def worker(client):
            while True:
                url = await queue.get()
                try:
                    if url is None:
                        return
                    text = await client.download(url)
                    counts['downloaded'] += 1
                    for finding in find_secrets(text):
                        row = {'url': url, **finding, 'timestamp': datetime.now(timezone.utc).isoformat()}
                        secrets.write(json.dumps(row, ensure_ascii=True) + '\n')
                        secrets.flush()
                        counts['secrets'] += 1
                        value = finding['value']
                        display = value if args.show_secrets else value[:6] + '…' + value[-4:]
                        message = '[SECRET] ' + json.dumps({'type': finding['type'], 'url': url,
                                                          'value': display}, ensure_ascii=True)
                        print((Fore.LIGHTRED_EX if colored else '') + message +
                              (Style.RESET_ALL if colored else ''), flush=True)
                    endpoints.update(extract_endpoints(text, url))
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, UnicodeError) as exc:
                    counts['errors'] += 1
                    error = {'url': url, 'error': type(exc).__name__, 'reason': str(exc)}
                    errors.write(json.dumps(error, ensure_ascii=True) + '\n')
                    errors.flush()
                    print('[!] ' + json.dumps(error, ensure_ascii=True), file=sys.stderr, flush=True)
                finally:
                    queue.task_done()

        async def produce():
            for url in urls:
                await queue.put(url)
            for _ in range(args.concurrency):
                await queue.put(None)

        try:
            timeout = aiohttp.ClientTimeout(total=args.timeout)
            connector = aiohttp.TCPConnector(limit=args.concurrency, limit_per_host=args.concurrency)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector, trust_env=False,
                                             cookie_jar=aiohttp.DummyCookieJar()) as session:
                client = HttpClient(session, args.concurrency, args.rate, args.max_bytes)
                tasks = [asyncio.create_task(worker(client)) for _ in range(args.concurrency)]
                tasks.append(asyncio.create_task(produce()))
                complete = asyncio.gather(*tasks)
                stopped = asyncio.create_task(stop.wait())
                try:
                    await asyncio.wait({complete, stopped}, return_when=asyncio.FIRST_COMPLETED)
                    if stop.is_set():
                        complete.cancel()
                        await asyncio.gather(complete, return_exceptions=True)
                    else:
                        await complete
                        finished = True
                finally:
                    stopped.cancel()
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(stopped, *tasks, return_exceptions=True)
        finally:
            atomic_write(output / 'extracted_endpoints.txt', ''.join(x + '\n' for x in sorted(endpoints)))
            status = ('interrupted' if stop.is_set() else 'failed' if not finished else
                      'completed_with_errors' if counts['errors'] or counts['over_limit'] else 'completed')
            summary = {'status': status,
                       'js_urls': len(urls), 'endpoints': len(endpoints), 'counts': dict(counts)}
            atomic_write(output / 'summary.json', json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
            for signum in (signal.SIGINT, signal.SIGTERM):
                loop.remove_signal_handler(signum)
    print(f'[+] Секретов-кандидатов: {counts["secrets"]}; эндпоинтов: {len(endpoints)}; '
          f'ошибок: {counts["errors"]}; отчёты: {output}', flush=True)
    return 130 if stop.is_set() else (1 if counts['errors'] or counts['over_limit'] else 0)


def positive_float(value):
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError('нужно конечное положительное число')
    return result


def bounded_int(low, high):
    def parse(value):
        result = int(value)
        if not low <= result <= high:
            raise argparse.ArgumentTypeError(f'нужно число от {low} до {high}')
        return result
    return parse


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-l', '--list', required=True, type=lambda x: Path(x).expanduser())
    parser.add_argument('-o', '--output', type=Path, default=Path.home() / 'bugbounty/js_results')
    parser.add_argument('--concurrency', type=bounded_int(1, 200), default=20)
    parser.add_argument('--timeout', type=positive_float, default=10)
    parser.add_argument('--rate', type=positive_float, default=5, help='максимум начал запросов/с')
    parser.add_argument('--max-bytes', type=bounded_int(1024, 50_000_000), default=5_000_000)
    parser.add_argument('--max-urls', type=bounded_int(1, 1_000_000), default=100000)
    parser.add_argument('--show-secrets', action='store_true', help='полные значения также в терминале')
    parser.add_argument('--no-color', action='store_true')
    args = parser.parse_args(argv)
    if not args.list.is_file():
        parser.error('входной UTF-8 файл не найден')
    return args


def main():
    os.umask(0o077)
    try:
        return asyncio.run(run(arguments()))
    except KeyboardInterrupt:
        return 130
    except (OSError, UnicodeError, RuntimeError) as exc:
        print('Ошибка: ' + json.dumps(str(exc), ensure_ascii=True), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
