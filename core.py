"""Общие структуры, работа с URL и ограниченный асинхронный HTTP-клиент."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import inspect
import ipaddress
import math
import random
import re
import time
from urllib.parse import quote, unquote_plus, urlsplit, urlunsplit

import aiohttp
from yarl import URL
from .probes import OastJournal

USER_AGENTS = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
)


def normalize_url(value: str) -> str:
    """Нормализует hostname, сохраняя существующие percent-encoding и порядок query."""
    if not isinstance(value, str) or not value or any(ord(c) < 33 or ord(c) == 127 for c in value) or '\\' in value:
        raise ValueError(f'Некорректный URL: {value!r}')
    parts = urlsplit(value)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username is not None:
        raise ValueError('Нужен HTTP/HTTPS URL без логина/пароля в адресе.')
    name = parts.hostname.lower().removesuffix('.')
    try:
        name = ipaddress.ip_address(name).compressed
    except ValueError:
        name = name.encode('idna').decode('ascii')
        if len(name) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                       for label in name.split('.')):
            raise ValueError('Некорректный hostname.')
    port = parts.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('Некорректный порт.')
    netloc = f'[{name}]' if ':' in name else name
    if port and port != (443 if parts.scheme == 'https' else 80):
        netloc += f':{port}'
    path = quote(parts.path or '/', safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="%/?@!$&'()*+,;=:-._~")
    return urlunsplit((parts.scheme, netloc, path, query, ''))


def origin(url: str) -> str:
    """Origin — scheme + hostname + port; поддомены считаются разными origin."""
    parts = urlsplit(url)
    return f'{parts.scheme}://{parts.netloc}'


def parameters(url: str) -> list[tuple[int, str]]:
    """Возвращает индекс query-компонента и имя; дубликаты не объединяются."""
    result = []
    for index, raw in enumerate(urlsplit(url).query.split('&')):
        if raw:
            name = unquote_plus(raw.partition('=')[0])
            if name and len(name) <= 128 and all(c.isprintable() for c in name):
                result.append((index, name))
    return result


def replace_parameter(url: str, index: int, value: str, *, preserve_percent: bool = False) -> str:
    """Меняет только одно вхождение параметра, остальные query-байты сохраняет."""
    parts = urlsplit(url)
    chunks = parts.query.split('&')
    key = chunks[index].partition('=')[0]
    chunks[index] = key + '=' + quote(value, safe='%' if preserve_percent else '')
    return urlunsplit((parts.scheme, parts.netloc, parts.path, '&'.join(chunks), ''))


def add_parameters(url: str, names: list[str]) -> str:
    """Явно заданные --params добавляются с пустым значением, если их ещё нет."""
    current = {name for _, name in parameters(url)}
    parts = urlsplit(url)
    extras = [quote(name, safe='') + '=' for name in names if name not in current]
    query = '&'.join(filter(None, [parts.query, *extras]))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ''))


@dataclass
class Response:
    url: str
    status: int | None = None
    text: str = ''
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    truncated: bool = False
    sha256: str = ''

    @property
    def usable(self) -> bool:
        """Ошибки HTTP не считаются отрицательным результатом проверки."""
        return self.error is None and self.status is not None and 200 <= self.status < 400


@dataclass
class Context:
    url: str
    index: int
    parameter: str
    baseline: Response
    user_agent: str


@dataclass
class Finding:
    module: str
    status: str
    url: str
    parameter: str
    parameter_index: int
    payload: str
    evidence: str
    response_status: int | None
    response_sha256: str
    confirmation_url: str = ''
    note: str = ''


@dataclass
class CheckResult:
    module: str
    url: str
    parameter: str
    parameter_index: int
    state: str = 'negative'
    reason: str = ''
    findings: list[Finding] = field(default_factory=list)


def check_result(module: str, context: Context, state: str = 'negative', reason: str = '') -> CheckResult:
    return CheckResult(module, context.url, context.parameter, context.index, state, reason)


class RequestBudgetReached(Exception):
    """Общий бюджет исчерпан: новые HTTP-запросы не отправляются."""


class TransportFailure(aiohttp.ClientError):
    """Разрыв соединения, который нельзя незаметно повторять сверх бюджета."""


async def single_attempt(request, handler):
    """Публичный middleware исключает внутренний повтор GET после разрыва связи.

    Преобразование исключения оставляет ошибку видимой клиенту, но не позволяет
    aiohttp послать второй GET в рамках одного учтённого запроса.
    """
    try:
        return await handler(request)
    except (aiohttp.ClientOSError, aiohttp.ServerDisconnectedError) as exc:
        raise TransportFailure(type(exc).__name__) from exc


class HttpClient:
    def __init__(self, args, allowed_origins: set[str], cookie_origin: str | None):
        self.args = args
        self.allowed_origins = allowed_origins
        self.cookie_origin = cookie_origin
        self.request_count = 0
        self.budget_rejections = 0
        self.events: list[dict] = []
        self._gate = asyncio.Lock()
        self._slots = asyncio.Semaphore(args.workers)
        self._next_request = 0.0
        self.session: aiohttp.ClientSession | None = None
        self.oast = OastJournal(args.output) if 'ssrf' in args.modules else None

    async def __aenter__(self):
        # Один пул соединений; автоматические cookies и .netrc/proxy-env выключены.
        timeout = aiohttp.ClientTimeout(total=self.args.timeout, ceil_threshold=float('inf'))
        self.session = aiohttp.ClientSession(timeout=timeout,
            connector=aiohttp.TCPConnector(limit=self.args.workers),
            cookie_jar=aiohttp.DummyCookieJar(), trust_env=False,
            middlewares=(single_attempt,))
        return self

    async def __aexit__(self, *exc):
        await self.session.close()

    async def fetch(self, url: str, user_agent: str, purpose: str, on_start=None) -> Response:
        """GET без перехода по Location; таймаут охватывает весь сетевой запрос."""
        if origin(url) not in self.allowed_origins:
            return Response(url, error='out_of_scope_origin')
        async with self._slots:
            # Блокировка объединяет глобальный rate limit и счётчик бюджета.
            async with self._gate:
                if self.request_count >= self.args.max_requests:
                    self.budget_rejections += 1
                    raise RequestBudgetReached
                await asyncio.sleep(max(0.0, self._next_request - time.monotonic()))
                self.request_count += 1
                self._next_request = time.monotonic() + 1 / self.args.rate
            if on_start is not None:
                callback = on_start()
                if inspect.isawaitable(callback):
                    await callback
            headers = {'User-Agent': user_agent, 'Accept': '*/*'}
            if self.args.cookies and origin(url) == self.cookie_origin:
                headers['Cookie'] = self.args.cookies
            response = Response(url)
            started = time.monotonic()
            try:
                # encoded=True сохраняет построенную query-строку; params не передаётся.
                async with self.session.get(URL(url, encoded=True), headers=headers,
                                            allow_redirects=False) as raw:
                    response.status = raw.status
                    response.headers = {key.lower(): value for key, value in raw.headers.items()}
                    body = bytearray()
                    async for chunk in raw.content.iter_chunked(16384):
                        remaining = self.args.max_bytes - len(body)
                        body.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            response.truncated = True
                            break
                    response.sha256 = hashlib.sha256(body).hexdigest()
                    try:
                        response.text = body.decode(raw.charset or 'utf-8', errors='replace')
                    except LookupError:
                        response.text = body.decode('utf-8', errors='replace')
                    if raw.status >= 400:
                        response.error = f'HTTP {raw.status}'
            except asyncio.TimeoutError:
                response.error = 'timeout'
            except aiohttp.ClientError as exc:
                response.error = type(exc).__name__
            except asyncio.CancelledError:
                response.error = 'cancelled'
                raise
            finally:
                self.events.append({'method': 'GET', 'url': url, 'purpose': purpose, 'status': response.status,
                    'error': response.error, 'truncated': response.truncated,
                    'seconds': round(time.monotonic() - started, 3), 'sha256': response.sha256})
            return response


def choose_agent(args) -> str:
    """Случайный UA для URL; одинаковый в baseline, пробе и контроле этого URL."""
    return args.user_agent or random.choice(USER_AGENTS)


async def safe_fetch(client, url, user_agent, purpose, on_start=None):
    """Сохраняет уже найденного кандидата, если бюджет закончился на подтверждении."""
    try:
        return await client.fetch(url, user_agent, purpose, on_start=on_start)
    except RequestBudgetReached:
        return Response(url, error='request_budget')


def operational_error(event: dict) -> bool:
    """Ожидаемый 404 у отсутствующего контрольного файла не является сбоем сканера."""
    expected_missing = (event.get('purpose') == 'lfi_negative_control'
                        and event.get('status') == 404 and event.get('error') == 'HTTP 404')
    return bool(event.get('error')) and not expected_missing


def positive_float(value: str) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise ValueError('нужно число') from exc
    if not math.isfinite(result) or not 0 < result <= 10000:
        raise ValueError('число должно быть больше 0 и не больше 10000')
    return result
