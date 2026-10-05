"""Общие результаты, CLI-валидация и журнал OAST. Только стандартная библиотека."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
import math
from pathlib import Path
import re
import unicodedata
from typing import Any, Literal

MODULES = ('xss', 'lfi', 'redirect', 'sqli', 'ssrf', 'ssti', 'crlf')
ADVANCED_MODULES = frozenset(('sqli', 'ssrf', 'ssti', 'crlf'))


def validate_oast_domain(value: str | None, modules) -> str | None:
    if not value:
        if 'ssrf' in modules:
            raise ValueError('--oast-domain обязателен при --modules ssrf')
        return None
    if value != value.strip() or any(c in value for c in '/:@?#\\*'):
        raise ValueError('--oast-domain: только DNS-имя, без схемы, порта и пути')
    try:
        domain = value.removesuffix('.').encode('idna').decode('ascii').lower()
    except UnicodeError as exc:
        raise ValueError('--oast-domain: некорректное DNS-имя') from exc
    labels = domain.split('.')
    # Для UUID оставляем 32 символа плюс точку в полном DNS-имени.
    if len(domain) > 220 or len(labels) < 2 or not all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels
    ):
        raise ValueError('--oast-domain: некорректное DNS-имя или нет места для UUID')
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError('--oast-domain: нужен домен сервера взаимодействий, а не IP')


def body_complete(response) -> bool:
    """HTTP 4xx/5xx с полным телом пригоден для анализа SQL-ошибок."""
    return (response.status is not None and not response.truncated
            and response.error in (None, f'HTTP {response.status}'))


def headers_received(response) -> bool:
    # aiohttp устанавливает status только после разбора полного блока заголовков.
    # Последующий таймаут тела не уничтожает уже полученные заголовки.
    return response.status is not None


def baseline_ready(module: str, response) -> bool:
    if module in ('crlf', 'ssrf'):
        return headers_received(response)
    if module in ('sqli', 'ssti'):
        return body_complete(response)
    return body_complete(response) and 200 <= response.status < 400


def strict_json(raw: str):
    """Не допускает неоднозначные ключи и не-JSON числа, включая 1e999."""
    def constant(_value):
        raise ValueError('JSON не допускает NaN/Infinity')

    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError('JSON содержит слишком большое число')
        return result

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('JSON содержит повторяющиеся ключи')
            result[key] = value
        return result

    try:
        result = json.loads(raw, parse_constant=constant, parse_float=number,
                            object_pairs_hook=pairs)
        json.dumps(result, ensure_ascii=False, allow_nan=False).encode('utf-8')
        return result
    except (RecursionError, UnicodeError) as exc:
        raise ValueError('JSON: слишком большая вложенность или некорректный Unicode') from exc


def failure_reason(response) -> str:
    return 'response_truncated' if response.truncated else response.error or 'no_response'


def header_value(response, name: str) -> str | None:
    return next((value for key, value in response.headers.items() if key.lower() == name.lower()), None)


@dataclass
class Signal:
    payload: str
    evidence: str
    response: Any
    confidence: str = 'candidate'
    note: str = ''
    confirmation_payload: str | None = None


@dataclass
class Outcome:
    state: Literal['confirmed', 'negative', 'skipped', 'inconclusive', 'oast_pending'] = 'negative'
    reason: str = 'no_matching_signal'
    signals: list[Signal] = field(default_factory=list)


ProbeResult = Outcome  # Совместимость с импортами предыдущей версии.


def quoted_log(value) -> str:
    raw = json.dumps(value, ensure_ascii=False)
    return ''.join(f'\\u{ord(char):04x}' if unicodedata.category(char) in {'Cc', 'Cf', 'Cs', 'Zl', 'Zp'}
                   else char for char in raw)


def log_line(state: str, module: str, method: str, url: str, parameter: str,
             payload: str, evidence: str = '') -> str:
    values = {'url': url, 'parameter': parameter, 'payload': payload, 'evidence': evidence}
    return f'[{state.upper()}] {module.upper()} {method} | ' + ' | '.join(
        f'{key}={quoted_log(value)}' for key, value in values.items())


class OastJournal:
    """Две записи на UUID: попытка перед отправкой и наблюдаемый результат HTTP."""
    def __init__(self, folder: Path):
        self.path = folder / 'oast_probes.jsonl'
        self.path.touch(mode=0o600, exist_ok=True)
        self.latest: dict[str, dict] = {}

    async def register_probe(self, *, nonce: str, metadata: dict) -> None:
        self.record({**metadata, 'uuid': nonce, 'nonce': nonce}, 'attempted')

    def record(self, metadata: dict, state: str, **details) -> None:
        event = {**metadata, 'state': state, 'time': datetime.now(timezone.utc).isoformat(), **details}
        with self.path.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(event, ensure_ascii=False) + '\n')
        self.latest[event['uuid']] = event
