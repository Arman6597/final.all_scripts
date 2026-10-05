#!/usr/bin/env python3
"""IDOR: сравнение ответов двух тестовых аккаунтов, GET и POST для чтения данных."""
from __future__ import annotations

import argparse
import asyncio
import base64
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import signal
import sys
import tempfile
import uuid
from urllib.parse import parse_qsl, quote_plus, urlsplit, urlunsplit

import aiohttp
from colorama import Fore, Style, just_fix_windows_console
from yarl import URL

NUMBER = re.compile(r'-?\d{1,20}\Z')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z', re.I)
TOKEN = re.compile(r'[\w]+|[^\w\s]', re.UNICODE)
DENIED = {401, 403, 404, 410}


def strict_json(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError('повторяющийся JSON-ключ')
            result[key] = item
        return result
    def reject(value):
        raise ValueError('NaN/Infinity не поддерживаются')
    return json.loads(value, object_pairs_hook=pairs, parse_constant=reject)


def valid_url(value):
    if any(ord(c) < 33 or ord(c) == 127 for c in value) or '\\' in value:
        raise ValueError('URL содержит пробелы или управляющие символы')
    p = urlsplit(value)
    if p.scheme not in {'https', 'http'} or not p.hostname or p.username is not None or p.fragment:
        raise ValueError('нужен HTTP(S) URL без userinfo и fragment')
    host = p.hostname.encode('idna').decode('ascii')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', x)
                                      for x in host.rstrip('.').split('.')):
            raise ValueError('некорректный hostname')
    if p.port is not None and not 1 <= p.port <= 65535:
        raise ValueError('некорректный порт')
    return str(URL(value, encoded=True))


def id_value(value):
    return not isinstance(value, bool) and isinstance(value, (str, int)) and bool(NUMBER.fullmatch(str(value)) or UUID.fullmatch(str(value)))


def pointer(path):
    return '/' + '/'.join(str(x).replace('~', '~0').replace('/', '~1') for x in path)


@dataclass(frozen=True)
class Parameter:
    location: str
    name: str
    path: tuple
    original: str | int

    @property
    def selector(self):
        suffix = pointer(self.path) if self.location == 'json' else f'{self.name}#{self.path[0]}'
        return f'{self.location}:{suffix}'


@dataclass
class Request:
    url: str
    body: str | None


class Template:
    def __init__(self, url, data=None, json_mode=False):
        self.url, self.data, self.json_mode = url, data, json_mode
        self.method = 'POST' if data is not None else 'GET'
        self.parts = urlsplit(url)
        self.parsed = strict_json(data) if json_mode else None
        if json_mode and not isinstance(self.parsed, (dict, list)):
            raise ValueError('JSON-тело должно быть объектом или массивом')
        self.fields = self.form_fields(self.parts.query, 'query')
        if json_mode:
            self.walk(self.parsed)
        elif data is not None:
            self.fields.extend(self.form_fields(data, 'form'))

    @staticmethod
    def form_fields(raw, location):
        result = []
        for index, chunk in enumerate(raw.split('&')):
            pair = parse_qsl(chunk, keep_blank_values=True)
            if pair and pair[0][0]:
                result.append(Parameter(location, pair[0][0], (index,), pair[0][1]))
        return result

    def walk(self, value, path=()):
        if isinstance(value, dict):
            for key, item in value.items():
                self.walk(item, (*path, key))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                self.walk(item, (*path, index))
        else:
            self.fields.append(Parameter('json', str(path[-1]), path, value))

    def build(self, changes=None):
        changes = changes or {}
        query = self.parts.query.split('&')
        body = self.data.split('&') if self.data is not None and not self.json_mode else None
        parsed = strict_json(self.data) if self.json_mode and changes else None
        body_changed = False
        for param in self.fields:
            if param.selector not in changes:
                continue
            value = changes[param.selector]
            if param.location in {'query', 'form'}:
                chunks = query if param.location == 'query' else body
                index = param.path[0]
                chunks[index] = chunks[index].partition('=')[0] + '=' + quote_plus(str(value))
            else:
                cursor = parsed
                for key in param.path[:-1]:
                    cursor = cursor[key]
                cursor[param.path[-1]] = int(value) if isinstance(param.original, int) and not isinstance(param.original, bool) else str(value)
                body_changed = True
        data = json.dumps(parsed, ensure_ascii=False, separators=(',', ':'), allow_nan=False) if body_changed else self.data
        if body is not None:
            data = '&'.join(body)
        return Request(urlunsplit(self.parts._replace(query='&'.join(query))), data)


def select(template, names, mapping):
    fields = [p for p in template.fields if id_value(p.original) and
              (not names or p.name in names or p.selector in names or pointer(p.path) in names)]
    if names:
        missing = [name for name in names if not any(name in {p.name, p.selector, pointer(p.path)} for p in fields)]
        if missing:
            raise ValueError('параметры не найдены или не являются числом/UUID: ' + ', '.join(missing))
    if not fields:
        raise ValueError('числовых ID или UUID не найдено')
    if len(fields) > 20:
        raise ValueError('найдено более 20 ID; ограничь выбор через --id-params')
    known = {alias for p in fields for alias in (p.selector, p.name, pointer(p.path))}
    if set(mapping) - known:
        raise ValueError('--attacker-ids содержит неизвестные параметры')
    own = {}
    for p in fields:
        key = next((x for x in (p.selector, pointer(p.path), p.name) if x in mapping), None)
        if key is None or not id_value(mapping[key]):
            raise ValueError(f'укажи собственный ID второго аккаунта: --attacker-ids для {p.selector}')
        value = mapping[key]
        if bool(NUMBER.fullmatch(str(value))) != bool(NUMBER.fullmatch(str(p.original))):
            raise ValueError('тип ID второго аккаунта должен совпадать с исходным')
        if str(value) == str(p.original):
            raise ValueError('ID двух аккаунтов должны различаться')
        own[p.selector] = value
    return fields, own


@dataclass
class Response:
    url: str
    status: int | None = None
    headers: list = field(default_factory=list)
    body: bytes = b''
    text: str = ''
    error: str | None = None

    @property
    def usable(self):
        return self.error is None and self.status is not None

    @property
    def success(self):
        return self.usable and 200 <= self.status < 300 and bool(self.body)

    @property
    def sha256(self):
        return hashlib.sha256(self.body).hexdigest()

    def evidence(self):
        return {'url': self.url, 'status': self.status, 'headers': self.headers,
                'size': len(self.body), 'sha256': self.sha256, 'text': self.text,
                'body_base64': base64.b64encode(self.body).decode('ascii'), 'error': self.error}


def canonical(response):
    try:
        return json.dumps(strict_json(response.text), sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    except (ValueError, TypeError, RecursionError):
        return re.sub(r'\s+', ' ', response.text).strip()


def structure(response):
    def shape(value):
        if isinstance(value, dict):
            return tuple(sorted((key, shape(item)) for key, item in value.items()))
        if isinstance(value, list):
            return ('list', tuple(shape(item) for item in value[:10]))
        return type(value).__name__
    try:
        return shape(strict_json(response.text))
    except (ValueError, RecursionError):
        return None


def compare(reference, response):
    if not reference.success or not response.success or reference.status != response.status:
        return {'similar': False, 'exact': False, 'score': 0.0}
    a, b = canonical(reference), canonical(response)
    exact = a == b
    counts_a, counts_b = Counter(TOKEN.findall(a[:100000])), Counter(TOKEN.findall(b[:100000]))
    total = sum(counts_a.values()) + sum(counts_b.values())
    score = 2 * sum((counts_a & counts_b).values()) / total if total else 0
    size_ok = abs(len(response.body) - len(reference.body)) <= len(reference.body) * .05
    sa, sb = structure(reference), structure(response)
    schema_ok = sa == sb if sa is not None or sb is not None else True
    return {'similar': size_ok and schema_ok and score >= .9, 'exact': exact, 'score': round(score, 4)}


def assess(victim, own, invalid, attack, repeat, marker=None, enumeration=False):
    responses = (victim, own, invalid, attack, repeat)
    if not all(r.usable for r in responses):
        return None
    if not victim.success or not own.success or canonical(victim) == canonical(own):
        return None
    if invalid.status not in DENIED:
        return None
    match = compare(victim, attack)
    stable = compare(attack, repeat)
    if not match['similar'] or not stable['similar'] or canonical(attack) == canonical(own):
        return None
    if marker and (marker not in victim.text or marker not in attack.text or marker not in repeat.text or marker in own.text):
        return None
    identity = match['exact'] and compare(victim, repeat)['exact']
    return {'state': 'candidate', 'confidence': 'high' if not enumeration and (identity or marker) else 'low',
            'similarity': match, 'ownership': 'unverified' if enumeration else 'user_supplied_victim_id',
            'reason': ('similar_object_requires_ownership_verification' if enumeration else
                       'victim_response_reproduced_under_second_account'),
            'note': 'Проверь принадлежность объекта, действительность сессий и политику доступа вручную.'}


class BudgetExhausted(Exception):
    pass


class HttpClient:
    def __init__(self, session, args, method, json_mode):
        self.session, self.args, self.method = session, args, method
        self.content_type = 'application/json' if json_mode else 'application/x-www-form-urlencoded'
        self.semaphore = asyncio.Semaphore(args.concurrency)
        self.rate_lock = asyncio.Lock()
        self.next_start, self.requests = 0.0, 0

    async def send(self, request, cookie):
        async with self.semaphore:
            async with self.rate_lock:
                if self.requests >= self.args.max_requests:
                    raise BudgetExhausted
                loop = asyncio.get_running_loop()
                await asyncio.sleep(max(0, self.next_start - loop.time()))
                self.next_start = loop.time() + 1 / self.args.rate
                self.requests += 1
            result = Response(request.url)
            headers = {'Cookie': cookie, 'User-Agent': 'IDOR-Differential-Scanner/1.0', 'Accept': '*/*'}
            if request.body is not None:
                headers['Content-Type'] = self.content_type
            try:
                async with self.session.request(self.method, URL(request.url, encoded=True), headers=headers,
                                                data=request.body.encode('utf-8') if request.body is not None else None,
                                                allow_redirects=False) as response:
                    result.status = response.status
                    result.headers = list(response.headers.items())
                    data = bytearray()
                    async for chunk in response.content.iter_chunked(65536):
                        if len(data) + len(chunk) > self.args.max_bytes:
                            result.error = 'response_too_large'
                            return result
                        data.extend(chunk)
                    result.body = bytes(data)
                    try:
                        result.text = result.body.decode(response.charset or 'utf-8', errors='replace')
                    except LookupError:
                        result.text = result.body.decode('utf-8', errors='replace')
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
                result.error = type(exc).__name__
            return result


def open_private(path):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, 'a', encoding='utf-8')


class Reports:
    def __init__(self, output):
        self.output = output
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.findings = open_private(output / 'findings.jsonl')
        try:
            self.checks = open_private(output / 'checks.jsonl')
        except BaseException:
            self.findings.close()
            raise
        self.counts = Counter()

    def record(self, row, finding=False):
        self.counts['findings' if finding else row['state']] += 1
        stream = self.findings if finding else self.checks
        stream.write(json.dumps(row, ensure_ascii=True) + '\n')
        stream.flush()

    def close(self, status, requests):
        self.findings.close()
        self.checks.close()
        summary = {'status': status, 'requests': requests, 'counts': dict(self.counts)}
        fd, temporary = tempfile.mkstemp(dir=self.output, prefix='.summary-')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(summary, stream, ensure_ascii=False, indent=2)
                stream.write('\n')
            os.replace(temporary, self.output / 'summary.json')
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


async def scan_parameter(param, template, own_ids, client, reports, args):
    info = {'method': template.method, 'parameter': param.selector}
    async def fetch(request, cookie, purpose):
        response = await client.send(request, cookie)
        if response.error:
            reports.record({**info, 'state': 'inconclusive', 'reason': response.error, 'purpose': purpose})
        return response
    try:
        victim = await fetch(template.build(), args.cookie_victim, 'victim_baseline')
        own = await fetch(template.build(own_ids), args.cookie_attacker, 'attacker_own_baseline')
        if not victim.success or not own.success or canonical(victim) == canonical(own):
            reports.record({**info, 'state': 'inconclusive', 'reason': 'baselines_failed_or_identical'})
            return
        unknown = str(10**19 + uuid.uuid4().int % (10**18)) if NUMBER.fullmatch(str(param.original)) else str(uuid.uuid4())
        invalid = await fetch(template.build({**own_ids, param.selector: unknown}), args.cookie_attacker, 'nonexistent_control')
        if not invalid.usable or invalid.status not in DENIED:
            reports.record({**info, 'state': 'inconclusive', 'reason': 'negative_control_not_denied'})
            return
        ids = [str(param.original)]
        if args.mode in {'increment', 'both'} and NUMBER.fullmatch(str(param.original)):
            center = int(param.original)
            ids.extend(str(i) for i in range(max(0, center - args.steps), center + args.steps + 1)
                       if i != center and str(i) != str(own_ids[param.selector]))
        elif args.mode in {'increment', 'both'}:
            reports.record({**info, 'state': 'skipped', 'reason': 'UUID_has_no_increment_range'})
        for tested_id in ids:
            request = template.build({**own_ids, param.selector: tested_id})
            attack = await fetch(request, args.cookie_attacker, 'cross_account_probe')
            if not compare(victim, attack)['similar'] or canonical(attack) == canonical(own):
                state = 'denied' if attack.usable and attack.status in DENIED else 'inconclusive'
                reports.record({**info, 'id': tested_id, 'state': state, 'reason': 'no_matching_victim_response'})
                continue
            repeat = await fetch(request, args.cookie_attacker, 'repeat_probe')
            enumeration = tested_id != str(param.original)
            outcome = assess(victim, own, invalid, attack, repeat,
                             marker=args.victim_marker if not enumeration else None, enumeration=enumeration)
            if outcome is None:
                reports.record({**info, 'id': tested_id, 'state': 'inconclusive', 'reason': 'confirmation_failed'})
                continue
            row = {**info, **outcome, 'id': tested_id, 'timestamp': datetime.now(timezone.utc).isoformat(),
                   'request': {'url': request.url, 'body': request.body},
                   'responses': {'victim_baseline': victim.evidence(), 'attacker_baseline': own.evidence(),
                                 'invalid_control': invalid.evidence(), 'attack': attack.evidence(),
                                 'repeat': repeat.evidence()}}
            reports.record(row, finding=True)
            message = '[IDOR candidate] ' + json.dumps({**info, 'id': tested_id, 'status': attack.status,
                                                       'confidence': outcome['confidence']}, ensure_ascii=True)
            color = sys.stdout.isatty() and not args.no_color
            print((Fore.LIGHTRED_EX if color else '') + message + (Style.RESET_ALL if color else ''), flush=True)
    except BudgetExhausted:
        reports.record({**info, 'state': 'inconclusive', 'reason': 'request_budget_exhausted'})


async def run(args):
    template = Template(args.url, args.data, args.json)
    fields, own = select(template, args.id_params, args.attacker_ids)
    reports = Reports(args.output.expanduser().resolve())
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    status, client = 'failed', None
    just_fix_windows_console()
    try:
        timeout = aiohttp.ClientTimeout(total=args.timeout)
        connector = aiohttp.TCPConnector(limit=args.concurrency, limit_per_host=args.concurrency)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector,
                                         cookie_jar=aiohttp.DummyCookieJar(), trust_env=False) as session:
            client = HttpClient(session, args, template.method, args.json)
            jobs = [asyncio.create_task(scan_parameter(p, template, own, client, reports, args)) for p in fields]
            complete = asyncio.gather(*jobs)
            stopped = asyncio.create_task(stop.wait())
            try:
                await asyncio.wait({complete, stopped}, return_when=asyncio.FIRST_COMPLETED)
                if stop.is_set():
                    complete.cancel()
                    await asyncio.gather(complete, return_exceptions=True)
                    status = 'interrupted'
                else:
                    await complete
                    status = 'completed_with_inconclusive' if reports.counts['inconclusive'] else 'completed'
            finally:
                stopped.cancel()
                for job in jobs:
                    job.cancel()
                await asyncio.gather(stopped, *jobs, return_exceptions=True)
    finally:
        reports.close(status, client.requests if client else 0)
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)
    print(f'[+] {status}; кандидатов: {reports.counts["findings"]}; отчёты: {reports.output}', flush=True)
    return 130 if status == 'interrupted' else (0 if status == 'completed' else 1)


def positive(value):
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError('нужно конечное положительное число')
    return result


def bounded(low, high):
    def parse(value):
        n = int(value)
        if not low <= n <= high:
            raise argparse.ArgumentTypeError(f'нужно целое число {low}…{high}')
        return n
    return parse


def cookie(value):
    value = Path(value[1:]).expanduser().read_text(encoding='utf-8').strip() if value.startswith('@') else value
    if not value or '=' not in value or any(ord(c) < 32 or ord(c) > 126 for c in value):
        raise ValueError('Cookie должен содержать ASCII пары name=value без переводов строк')
    return value


def arguments(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('-u', '--url', required=True)
    body_input = p.add_mutually_exclusive_group()
    body_input.add_argument('-d', '--data', help='тело POST; без тела используется GET')
    body_input.add_argument('--data-file', type=Path, help='UTF-8 файл с телом POST')
    p.add_argument('--json', action='store_true')
    p.add_argument('--cookie-victim', required=True, help='Cookie первого тестового аккаунта или @файл')
    p.add_argument('--cookie-attacker', required=True, help='Cookie второго тестового аккаунта или @файл')
    p.add_argument('--id-params', default='', help='имена или точные селекторы через запятую')
    p.add_argument('--attacker-ids', required=True, help='JSON с собственными ID второго аккаунта, например {"id":200}')
    p.add_argument('--mode', choices=('direct', 'increment', 'both'), default='direct', help='increment/both: известный ID плюс соседние числовые ID')
    p.add_argument('--steps', type=bounded(1, 20), default=20)
    p.add_argument('--victim-marker', help='уникальный несекретный маркер объекта первого аккаунта')
    p.add_argument('--rate', type=positive, default=5)
    p.add_argument('--concurrency', type=bounded(1, 100), default=10)
    p.add_argument('--timeout', type=positive, default=10)
    p.add_argument('--max-requests', type=bounded(1, 10000), default=500)
    p.add_argument('--max-bytes', type=bounded(1024, 20_000_000), default=2_000_000)
    p.add_argument('-o', '--output', type=Path, default=Path.home() / 'bugbounty/idor_results')
    p.add_argument('--no-color', action='store_true')
    args = p.parse_args(argv)
    try:
        if args.data_file is not None:
            path = args.data_file.expanduser()
            if path.stat().st_size > 2_000_000:
                raise ValueError('data-file превышает 2 MB')
            args.data = path.read_text(encoding='utf-8')
        args.url = valid_url(args.url)
        args.cookie_victim, args.cookie_attacker = cookie(args.cookie_victim), cookie(args.cookie_attacker)
        if args.cookie_victim == args.cookie_attacker:
            raise ValueError('нужны разные Cookie двух тестовых аккаунтов')
        if args.json and args.data is None:
            raise ValueError('--json требует --data или --data-file')
        args.id_params = [x.strip() for x in args.id_params.split(',') if x.strip()]
        args.attacker_ids = strict_json(args.attacker_ids)
        if not isinstance(args.attacker_ids, dict):
            raise ValueError('--attacker-ids должен быть JSON-объектом')
        template = Template(args.url, args.data, args.json)
        select(template, args.id_params, args.attacker_ids)
    except (ValueError, OSError, UnicodeError, RecursionError) as exc:
        p.error(str(exc))
    return args


def main():
    os.umask(0o077)
    try:
        return asyncio.run(run(arguments()))
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RuntimeError) as exc:
        print('Ошибка: ' + json.dumps(str(exc), ensure_ascii=True), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
