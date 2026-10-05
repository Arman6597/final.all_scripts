#!/usr/bin/env python3
"""Асинхронная проверка XSS, LFI, Redirect, SQLi, SSRF, SSTI и CRLF в POST-параметрах."""

from __future__ import annotations

import argparse
import asyncio
import copy
import contextlib
from collections import Counter
from datetime import datetime, timezone
import hashlib
import inspect
import json
import os
import random
import re
import signal
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote_plus, unquote_plus, urljoin, urlsplit

import aiohttp
from colorama import Fore, Style, init as colorama_init
from yarl import URL
from bbscanner.core import normalize_url as canonical_url, operational_error
from bbscanner.checks.crlf import run as crlf_run
from bbscanner.checks.sqli import run as sqli_run
from bbscanner.checks.ssrf import run as ssrf_run
from bbscanner.checks.ssti import run as ssti_run
from bbscanner.probes import (MODULES, OastJournal, baseline_ready, body_complete,
                              failure_reason, log_line, quoted_log, strict_json, validate_oast_domain)
from bbscanner.runtime import bounded


USER_AGENTS = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 Version/18.6 Safari/605.1.15",
)
REDIRECT_NAMES = {
    "callback",
    "continue",
    "dest",
    "destination",
    "next",
    "redirect",
    "redirect_uri",
    "return",
    "return_to",
    "return_url",
    "target",
    "url",
    "uri",
    "view",
}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
PASSWD_RE = re.compile(r"(?m)^root:x:0:0:")
WIN_INI_RE = re.compile(r"(?im)^\[extensions\]\s*$")
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class BudgetExhausted(Exception):
    """Общий лимит запросов исчерпан."""


@dataclass(frozen=True)
class Field:
    path: tuple[str | int, ...]
    name: str
    value: Any

    @property
    def pointer(self) -> str:
        return '/' + '/'.join(str(part).replace('~', '~0').replace('/', '~1') for part in self.path)


@dataclass(frozen=True)
class BodyTemplate:
    raw: str
    json_mode: bool
    fields: tuple[Field, ...]
    parsed: Any

    def mutate(self, field: Field, payload: str, *, preserve_percent: bool = False) -> str:
        if not self.json_mode:
            chunks = self.raw.split('&')
            index = int(field.path[0])
            key = chunks[index].partition('=')[0]
            chunks[index] = key + '=' + quote_plus(payload, safe='%' if preserve_percent else '')
            return '&'.join(chunks)

        value = copy.deepcopy(self.parsed)
        cursor = value
        for part in field.path[:-1]:
            cursor = cursor[part]
        cursor[field.path[-1]] = payload
        return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


@dataclass
class ResponseData:
    url: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    sha256: str = ""
    error: str | None = None
    truncated: bool = False
    elapsed: float = 0.0

    @property
    def usable(self) -> bool:
        return self.error is None and self.status is not None and self.status < 500


@dataclass
class Finding:
    vulnerability: str
    confidence: str
    target: str
    parameter: str
    payload: str
    evidence: str
    status: int | None
    response_sha256: str
    mode: str
    note: str = ""
    parameter_path: tuple[str | int, ...] = ()
    confirmation_payload: str | None = None


@dataclass
class CheckRecord:
    vulnerability: str
    target: str
    parameter: str
    state: str
    reason: str = ""
    parameter_path: tuple[str | int, ...] = ()


def number(minimum: int, maximum: int):
    def parse(value: str) -> int:
        try:
            result = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("нужно целое число") from exc
        if not minimum <= result <= maximum:
            raise argparse.ArgumentTypeError(f"допустимый диапазон: {minimum}…{maximum}")
        return result

    return parse


def positive_float(value: str) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("нужно число") from exc
    if not 0 < result <= 10_000:
        raise argparse.ArgumentTypeError("число должно быть больше 0 и не больше 10000")
    return result


def normalize_url(value: str) -> str:
    normalized = canonical_url(value)
    if urlsplit(value).fragment:
        raise ValueError('URL не должен содержать fragment')
    return normalized


def origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def parse_headers(values: Iterable[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in values:
        if item.lstrip().startswith("{"):
            try:
                parsed = strict_json(item)
            except json.JSONDecodeError as exc:
                raise ValueError(f"--headers: некорректный JSON: {exc.msg}") from exc
            if not isinstance(parsed, dict):
                raise ValueError("--headers JSON должен быть объектом")
            pairs = parsed.items()
        else:
            if ":" not in item:
                raise ValueError(f"--headers: ожидается 'Name: Value': {item!r}")
            name, value = item.split(":", 1)
            pairs = ((name, value),)
        for name, value in pairs:
            if not isinstance(name, str) or not isinstance(value, str):
                raise ValueError("имена и значения заголовков должны быть строками")
            name = name.strip(' ')
            value = value.strip(' ')
            if not HEADER_NAME_RE.fullmatch(name) or any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise ValueError(f"некорректный заголовок: {name!r}")
            if name.lower() in {"host", "content-length", "transfer-encoding", "connection"}:
                raise ValueError(f"заголовок {name} запрещён для безопасности клиента")
            headers[name.lower()] = value
    return headers


def parse_body(raw: str, json_mode: bool) -> BodyTemplate:
    if not raw.strip():
        raise ValueError("тело POST не может быть пустым")
    if json_mode:
        try:
            parsed = strict_json(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSON-тело некорректно: {exc.msg}, позиция {exc.pos}") from exc
        if not isinstance(parsed, (dict, list)):
            raise ValueError("JSON-тело должно быть объектом или массивом")
        fields = tuple(iter_json_fields(parsed))
        if not fields:
            raise ValueError("JSON не содержит изменяемых scalar-параметров")
        return BodyTemplate(raw, True, fields, parsed)

    fields = []
    pairs = []
    for index, component in enumerate(raw.split('&')):
        if not component:
            continue
        key, _, value = component.partition('=')
        key, value = unquote_plus(key), unquote_plus(value)
        pairs.append((key, value))
        if key:
            fields.append(Field((index,), key, value))
    if not fields:
        raise ValueError("form-urlencoded тело не содержит параметров")
    return BodyTemplate(raw, False, tuple(fields), pairs)


def iter_json_fields(value: Any, path: tuple[str | int, ...] = ()) -> Iterable[Field]:
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str):
                yield from iter_json_fields(child, path + (key,))
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_json_fields(child, path + (index,))
        return
    label = ".".join(str(part) for part in path)
    if path:
        yield Field(path, label, value)


def filter_fields(fields: Iterable[Field], names: set[str], limit: int) -> list[Field]:
    selected = [field for field in fields if not names or field.name in names
                or field.pointer in names or str(field.path[-1]) in names]
    return selected[:limit]


class RateLimiter:
    def __init__(self, rate: float):
        self.delay = 1.0 / rate
        self.next_slot = 0.0
        self.lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self.lock:
            now = time.monotonic()
            delay = max(0.0, self.next_slot - now)
            if delay:
                await asyncio.sleep(delay)
            self.next_slot = time.monotonic() + self.delay


class HttpClient:
    def __init__(self, args, headers: dict[str, str]):
        self.args = args
        self.headers = headers
        self.semaphore = asyncio.Semaphore(args.concurrency)
        self.rate_limiter = RateLimiter(args.rate)
        self.budget_lock = asyncio.Lock()
        self.requests = 0
        self.budget_exhausted = False
        self.events: list[dict[str, Any]] = []
        self.oast = OastJournal(args.output) if "ssrf" in args.modules else None
        self.session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "HttpClient":
        timeout = aiohttp.ClientTimeout(total=self.args.timeout, ceil_threshold=float('inf'))
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=aiohttp.TCPConnector(limit=self.args.concurrency),
            cookie_jar=aiohttp.DummyCookieJar(),
            trust_env=False,
        )
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        assert self.session is not None
        await self.session.close()

    async def post(self, url: str, body: str, json_mode: bool, user_agent: str, purpose: str, on_start=None) -> ResponseData:
        async with self.semaphore:
            async with self.budget_lock:
                if self.requests >= self.args.max_requests:
                    self.budget_exhausted = True
                    raise BudgetExhausted
                await self.rate_limiter.wait()
                self.requests += 1
            if on_start is not None:
                callback = on_start()
                if inspect.isawaitable(callback):
                    await callback

            bound = getattr(self.args, 'headers_origin', None)
            request_headers = dict(self.headers) if not bound or origin(url) == bound else {}
            request_headers.setdefault("user-agent", user_agent)
            request_headers.setdefault("accept", "*/*")
            request_headers.setdefault(
                "content-type",
                "application/json" if json_mode else "application/x-www-form-urlencoded",
            )
            started = time.monotonic()
            result = ResponseData(url=url)
            try:
                assert self.session is not None
                async with self.session.post(
                    URL(url, encoded=True),
                    data=body.encode("utf-8"),
                    headers=request_headers,
                    allow_redirects=False,
                ) as response:
                    result.status = response.status
                    result.headers = {key.lower(): value for key, value in response.headers.items()}
                    data_buffer = bytearray()
                    async for chunk in response.content.iter_chunked(16384):
                        remaining = self.args.max_bytes - len(data_buffer)
                        data_buffer.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            result.truncated = True
                            break
                    data = bytes(data_buffer)
                    result.sha256 = hashlib.sha256(data).hexdigest()
                    try:
                        result.text = data.decode(response.charset or "utf-8", errors="replace")
                    except LookupError:
                        result.text = data.decode("utf-8", errors="replace")
                    if response.status >= 400:
                        result.error = f"HTTP {response.status}"
            except asyncio.TimeoutError:
                result.error = "timeout"
            except aiohttp.ClientError as exc:
                result.error = type(exc).__name__
            except UnicodeError:
                result.error = "response_decode_error"
            except asyncio.CancelledError:
                result.error = 'cancelled'
                raise
            finally:
                result.elapsed = round(time.monotonic() - started, 3)
                self.events.append({
                    "method": "POST",
                    "url": url,
                    "purpose": purpose,
                    "status": result.status,
                    "error": result.error,
                    "truncated": result.truncated,
                    "seconds": result.elapsed,
                    "sha256": result.sha256,
                })
            return result


def external_destination(nonce: str) -> str:
    return f"https://bb-{nonce}.example.invalid/probe/{nonce}"


def external_redirect(response: ResponseData, expected_host: str) -> bool:
    if response.status not in REDIRECT_STATUSES or not response.headers.get("location"):
        return False
    destination = urljoin(response.url, response.headers["location"])
    parts = urlsplit(destination)
    return parts.scheme in {"http", "https"} and parts.hostname == expected_host


def html_response(response: ResponseData) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    return "text/html" in content_type or "application/xhtml+xml" in content_type


class PostScanner:
    def __init__(self, args, targets: list[str], body: BodyTemplate, headers: dict[str, str]):
        self.args = args
        self.targets = targets
        self.body = body
        self.headers = headers
        self.findings: list[Finding] = []
        self.checks: list[CheckRecord] = []
        self.errors: list[dict[str, Any]] = []
        self.client: HttpClient | None = None
        self.interrupted = False
        self.stop_event = asyncio.Event()

    def record_finding(self, item: Finding) -> None:
        self.findings.append(item)
        text = finding_line(item)
        color = not self.args.no_color and sys.stdout.isatty()
        shade = Fore.LIGHTRED_EX if item.confidence in ('confirmed', 'confirmed_signal') else Fore.LIGHTYELLOW_EX
        print((shade if color else '') + text + (Style.RESET_ALL if color else ''), flush=True)
        # Находка сохраняется сразу, включая случай остановки процесса таймаутом Pipeline.
        for name, content in (('vulns_report.txt', text),
                              ('findings.jsonl', json.dumps(asdict(item), ensure_ascii=True))):
            path = self.args.output / name
            with path.open('a', encoding='utf-8') as stream:
                path.chmod(0o600)
                stream.write(content + '\n')

    async def safe_post(self, *args: Any, **kwargs: Any) -> ResponseData:
        assert self.client is not None
        try:
            return await self.client.post(*args, **kwargs)
        except BudgetExhausted:
            return ResponseData(url=args[0], error="request_budget")

    async def scan_target(self, target: str) -> None:
        if self.stop_event.is_set():
            return
        user_agent = self.args.user_agent or random.choice(USER_AGENTS)
        baseline = await self.safe_post(target, self.body.raw, self.body.json_mode, user_agent, "baseline")
        fields = filter_fields(self.body.fields, set(self.args.params), self.args.max_parameters)
        if not fields:
            self.checks.append(CheckRecord("all", target, "", "skipped", "нет подходящих параметров"))
            return

        async def execute(job):
            module, field = job
            if not baseline_ready(module, baseline):
                self.checks.append(CheckRecord(module, target, field.name, 'inconclusive',
                    'baseline_' + failure_reason(baseline), field.path))
                return
            if self.client.requests >= self.args.max_requests:
                self.client.budget_exhausted = True
                self.checks.append(CheckRecord(module, target, field.name, 'skipped', 'request_budget', field.path))
                return
            try:
                await self.scan_field(module, target, field, baseline, user_agent)
            except Exception as exc:
                self.errors.append({'target': target, 'stage': module, 'parameter': field.name,
                                    'error': type(exc).__name__})
                self.checks.append(CheckRecord(module, target, field.name, 'inconclusive',
                                                'module_error:' + type(exc).__name__, field.path))

        jobs = ((module, item) for item in fields for module in self.args.modules)
        await bounded(jobs, execute, self.args.concurrency)

    async def scan_field(
        self,
        module: str,
        target: str,
        field: Field,
        baseline: ResponseData,
        user_agent: str,
    ) -> None:
        if module == "xss":
            await self.check_xss(target, field, baseline, user_agent)
        elif module == "lfi":
            await self.check_lfi(target, field, baseline, user_agent)
        elif module == "redirect":
            await self.check_redirect(target, field, user_agent)
        elif module == "sqli":
            await self.check_generic(sqli_run, "sqli", target, field, baseline, user_agent)
        elif module == "ssti":
            await self.check_generic(ssti_run, "ssti", target, field, baseline, user_agent)
        elif module == "crlf":
            await self.check_generic(crlf_run, "crlf", target, field, baseline, user_agent)
        elif module == "ssrf":
            await self.check_ssrf(target, field, baseline, user_agent)

    async def check_generic(self, checker, label: str, target: str, field: Field,
                            baseline: ResponseData, user_agent: str) -> None:
        preserve_percent = bool(label in {"crlf", "CRLF Injection"})

        async def send(payload: str | None, purpose: str, on_start=None) -> ResponseData:
            body = self.body.raw if payload is None else self.body.mutate(
                field, payload, preserve_percent=preserve_percent)
            return await self.safe_post(target, body, self.body.json_mode, user_agent,
                                        purpose, on_start=on_start)

        outcome = await checker(send, baseline)
        self.checks.append(CheckRecord(label, target, field.name, outcome.state, outcome.reason, field.path))
        for sig in outcome.signals:
            confidence = getattr(sig, "confidence", "candidate") or "candidate"
            if confidence == "confirmed_signal":
                confidence = "confirmed"
            response = sig.response
            self.record_finding(Finding(
                vulnerability=label,
                confidence=confidence,
                target=target,
                parameter=field.name,
                payload=sig.payload,
                evidence=sig.evidence,
                status=response.status,
                response_sha256=getattr(response, "sha256", ""),
                mode="json" if self.body.json_mode else "form",
                note=getattr(sig, "note", "") or "",
                parameter_path=field.path,
                confirmation_payload=getattr(sig, "confirmation_payload", None),
            ))

    async def check_ssrf(self, target: str, field: Field, baseline: ResponseData, user_agent: str) -> None:
        async def send(payload: str | None, purpose: str, on_start=None) -> ResponseData:
            body = self.body.raw if payload is None else self.body.mutate(field, payload)
            return await self.safe_post(target, body, self.body.json_mode, user_agent,
                                        purpose, on_start=on_start)

        outcome = await ssrf_run(
            send,
            baseline,
            domain=self.args.oast_domain,
            journal=self.client.oast,
            defer_registration=True,
            metadata={"method": "POST", "url": target, "parameter": field.name,
                      "parameter_index": list(field.path)},
        )
        self.checks.append(CheckRecord("ssrf", target, field.name, outcome.state, outcome.reason, field.path))

    async def check_xss(self, target: str, field: Field, baseline: ResponseData, user_agent: str) -> None:
        nonce = uuid.uuid4().hex[:12]
        payload = f'idxss_{nonce}">' + "<"
        body = self.body.mutate(field, payload)
        response = await self.safe_post(target, body, self.body.json_mode, user_agent, "xss")
        if not body_complete(response) or response.error:
            self.checks.append(CheckRecord("xss", target, field.name, "inconclusive", failure_reason(response), field.path))
            return
        if not html_response(response):
            self.checks.append(CheckRecord("xss", target, field.name, "negative", "ответ не HTML"))
            return
        if payload not in response.text or payload in baseline.text:
            self.checks.append(CheckRecord("xss", target, field.name, "negative", "маркер не отражён"))
            return

        repeat_nonce = uuid.uuid4().hex[:12]
        repeat_payload = f'idxss_{repeat_nonce}">' + "<"
        repeat = await self.safe_post(
            target,
            self.body.mutate(field, repeat_payload),
            self.body.json_mode,
            user_agent,
            "xss_repeat",
        )
        repeated = body_complete(repeat) and repeat.usable and html_response(repeat) and repeat_payload in repeat.text
        repeat_state = "подтверждено повторным отражением" if repeated else "повтор не получен"
        self.record_finding(
            Finding(
                vulnerability="Reflected XSS",
                confidence="candidate",
                target=target,
                parameter=field.name,
                payload=payload,
                evidence="уникальный неисполняемый маркер отражён в raw HTML",
                status=response.status,
                response_sha256=response.sha256,
                mode="json" if self.body.json_mode else "form",
                note=f"{repeat_state}; выполнение JavaScript не проверялось",
                parameter_path=field.path,
                confirmation_payload=repeat_payload,
            )
        )
        self.checks.append(CheckRecord("xss", target, field.name, "candidate", "raw reflection"))

    async def check_lfi(self, target: str, field: Field, baseline: ResponseData, user_agent: str) -> None:
        probes = (
            ("../../../../etc/passwd", PASSWD_RE, "Linux passwd signature"),
            ("../../../../windows/win.ini", WIN_INI_RE, "Windows win.ini signature"),
        )
        matched = False
        failures = []
        confirmed_any = False
        for payload, signature, label in probes:
            response = await self.safe_post(target, self.body.mutate(field, payload), self.body.json_mode, user_agent, "lfi")
            if not body_complete(response) or response.error:
                failures.append(failure_reason(response))
                continue
            if signature.search(baseline.text):
                failures.append('signature_already_in_baseline')
                continue
            if not signature.search(response.text):
                continue
            control_payload = f"../../../../bb_missing_{uuid.uuid4().hex[:12]}"
            control = await self.safe_post(
                target,
                self.body.mutate(field, control_payload),
                self.body.json_mode,
                user_agent,
                "lfi_negative_control",
            )
            repeat = await self.safe_post(
                target,
                self.body.mutate(field, payload),
                self.body.json_mode,
                user_agent,
                "lfi_repeat",
            )
            if body_complete(control) and signature.search(control.text):
                failures.append('signature_in_negative_control')
                continue
            matched = True
            repeated = bool(body_complete(repeat) and repeat.usable and signature.search(repeat.text))
            clean_control = bool(body_complete(control) and (control.usable or control.status == 404)
                                 and not signature.search(control.text))
            structure = (bool(re.search(r'root:x:0:0:[^:\r\n<]*:/[^:\r\n<]*:/[^\r\n<]+', response.text))
                         if 'passwd' in payload else
                         bool(re.search(r'(?im)^\s*\[(?:fonts|files|mci extensions|windows)\]\s*$', response.text)))
            confidence = "confirmed" if repeated and clean_control and structure else "candidate"
            confirmed_any |= confidence == 'confirmed'
            note = "повтор и negative-control прошли" if confidence == "confirmed" else "нужна ручная проверка контекста"
            self.record_finding(
                Finding(
                    vulnerability="LFI / Path Traversal",
                    confidence=confidence,
                    target=target,
                    parameter=field.name,
                    payload=payload,
                    evidence=label,
                    status=response.status,
                    response_sha256=response.sha256,
                    mode="json" if self.body.json_mode else "form",
                    note=note,
                    parameter_path=field.path,
                    confirmation_payload=payload,
                )
            )
        self.checks.append(
            CheckRecord("lfi", target, field.name,
                        'confirmed' if confirmed_any else 'candidate' if matched else 'inconclusive' if failures else 'negative',
                        ';'.join(failures) if failures else 'signature_check', field.path)
        )

    async def check_redirect(self, target: str, field: Field, user_agent: str) -> None:
        if not self.args.redirect_all and field.name.lower() not in REDIRECT_NAMES:
            self.checks.append(CheckRecord("redirect", target, field.name, "skipped", "имя не похоже на redirect-параметр"))
            return
        nonce = uuid.uuid4().hex[:12]
        payload = external_destination(nonce)
        response = await self.safe_post(target, self.body.mutate(field, payload), self.body.json_mode, user_agent, "redirect")
        expected_host = urlsplit(payload).hostname
        if response.error:
            self.checks.append(CheckRecord('redirect', target, field.name, 'inconclusive', response.error, field.path))
            return
        if not expected_host or not external_redirect(response, expected_host):
            self.checks.append(CheckRecord("redirect", target, field.name, "negative", "Location не указывает на внешний host"))
            return

        repeat_nonce = uuid.uuid4().hex[:12]
        repeat_payload = external_destination(repeat_nonce)
        repeat = await self.safe_post(
            target,
            self.body.mutate(field, repeat_payload),
            self.body.json_mode,
            user_agent,
            "redirect_repeat",
        )
        repeat_host = urlsplit(repeat_payload).hostname
        confirmed = bool(repeat.error is None and repeat_host and external_redirect(repeat, repeat_host))
        self.record_finding(
            Finding(
                vulnerability="Open Redirect",
                confidence="confirmed" if confirmed else "candidate",
                target=target,
                parameter=field.name,
                payload=payload,
                evidence="POST-ответ содержит 3xx Location на контролируемый внешний hostname",
                status=response.status,
                response_sha256=response.sha256,
                mode="json" if self.body.json_mode else "form",
                note="две разные внешние цели подтвердили управление Location" if confirmed else "нужна повторная ручная проверка",
                parameter_path=field.path,
                confirmation_payload=repeat_payload,
            )
        )
        self.checks.append(CheckRecord("redirect", target, field.name, "confirmed" if confirmed else "candidate", "external Location"))

    async def run(self) -> dict[str, Any]:
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.client = HttpClient(self.args, self.headers)
        loop = asyncio.get_running_loop()
        current = asyncio.current_task()
        installed: list[signal.Signals] = []

        def request_stop() -> None:
            self.interrupted = True
            self.stop_event.set()
            current.cancel()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, request_stop)
                installed.append(sig)
            except (NotImplementedError, RuntimeError):
                pass

        try:
            async with self.client:
                async def execute(target):
                    try:
                        await self.scan_target(target)
                    except Exception as exc:
                        self.errors.append({'target': target, 'stage': 'target', 'error': type(exc).__name__})
                        self.checks.append(CheckRecord('all', target, '', 'inconclusive', 'target_error'))
                await bounded(self.targets, execute, min(4, self.args.concurrency))
        except asyncio.CancelledError:
            self.interrupted = True
        except Exception as exc:
            self.errors.append({'stage': 'run', 'error': type(exc).__name__})
        finally:
            for sig in installed:
                with contextlib.suppress(Exception):
                    loop.remove_signal_handler(sig)

        self.errors.extend(event for event in self.client.events if operational_error(event))
        return self.summary()

    def summary(self) -> dict[str, Any]:

        if self.interrupted:
            status = "interrupted"
        elif self.client and self.client.budget_exhausted:
            status = "budget_exhausted"
        elif not self.checks:
            status = 'failed'
        elif all(item.state in ('inconclusive', 'skipped') for item in self.checks):
            status = 'inconclusive'
        elif self.errors or any(item.state == 'inconclusive' for item in self.checks):
            status = "completed_with_errors"
        elif self.findings or any(item.state == 'oast_pending' for item in self.checks):
            status = "completed"
        else:
            status = "completed_no_findings"
        return {
            "status": status,
            "started_at": getattr(self, 'started_at', None),
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "targets": len(self.targets),
            "requests": self.client.requests if self.client else 0,
            "findings": len(self.findings),
            "confirmed": sum(item.confidence in ('confirmed', 'confirmed_signal') for item in self.findings),
            "confirmed_signals": sum(item.confidence in ('confirmed', 'confirmed_signal') for item in self.findings),
            "candidates": sum(item.confidence == "candidate" for item in self.findings),
            "oast_probes_pending": len(self.client.oast.latest) if self.client and self.client.oast else 0,
            "mode": "json" if self.body.json_mode else "form",
            "parameters": [item.name for item in self.body.fields],
            "errors": len(self.errors),
            "check_states": dict(Counter(item.state for item in self.checks)),
            "settings": {"rate": self.args.rate, "concurrency": self.args.concurrency,
                         "modules": self.args.modules, "timeout": self.args.timeout,
                         "headers_origin": self.args.headers_origin},
        }


def atomic_write(path: Path, content: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open('w', encoding='utf-8') as stream:
        temporary.chmod(0o600)
        stream.write(content)
    os.replace(temporary, path)
    path.chmod(0o600)


def finding_line(item: Finding) -> str:
    module = {'Reflected XSS': 'xss', 'LFI / Path Traversal': 'lfi',
              'Open Redirect': 'redirect'}.get(item.vulnerability, item.vulnerability)
    state = 'confirmed_signal' if item.confidence == 'confirmed' else item.confidence
    path = '/' + '/'.join(str(part).replace('~', '~0').replace('/', '~1') for part in item.parameter_path)
    return log_line(state, module, 'POST', item.target, f'{item.parameter} [{path}]', item.payload, item.evidence)


def write_reports(output: Path, scanner: PostScanner, summary: dict[str, Any]) -> None:
    findings = [asdict(item) for item in scanner.findings]
    checks = [asdict(item) for item in scanner.checks]
    atomic_write(output / "findings.json", json.dumps(findings, ensure_ascii=False, indent=2))
    atomic_write(output / "summary.json", json.dumps(summary, ensure_ascii=False, indent=2))
    atomic_write(output / "errors.json", json.dumps(scanner.errors, ensure_ascii=False, indent=2))
    if scanner.client is not None:
        atomic_write(output / "requests.jsonl", "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in scanner.client.events))
    atomic_write(output / "checks.jsonl", "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in checks))

    atomic_write(output / 'findings.jsonl', ''.join(json.dumps(item, ensure_ascii=True) + '\n' for item in findings))
    lines = [finding_line(item) + '\nnote: ' + quoted_log(item.note) for item in scanner.findings]
    lines.append('Итог: ' + quoted_log(summary))
    atomic_write(output / "vulns_report.txt", '\n'.join(lines) + '\n')


def print_results(scanner: PostScanner, summary: dict[str, Any], no_color: bool) -> None:
    print(
        f"\nГотово: status={summary['status']} targets={summary['targets']} "
        f"requests={summary['requests']} findings={summary['findings']} "
        f"confirmed={summary['confirmed']} candidates={summary['candidates']} "
        f"oast_pending={summary['oast_probes_pending']}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Асинхронная проверка POST-параметров только на разрешённых Bug Bounty целях.",
        allow_abbrev=False,
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-u", "--url", action="append", help="POST endpoint; можно повторять")
    source.add_argument("-l", "--list", type=Path, help="UTF-8 файл с endpoint-ами, по одному на строку")
    body = parser.add_mutually_exclusive_group(required=True)
    body.add_argument("--body", help="исходное тело POST")
    body.add_argument("--body-file", type=Path, help="файл с исходным телом POST")
    parser.add_argument("--json", action="store_true", help="разбирать тело как application/json")
    parser.add_argument("--headers", action="append", default=[], help="Name: Value; можно повторять или передать JSON-объект")
    parser.add_argument('--headers-origin', help='origin для пользовательских заголовков; обязателен при нескольких origin')
    parser.add_argument("--cookies", help="значение Cookie header")
    parser.add_argument("--user-agent", help="фиксированный User-Agent вместо случайного")
    parser.add_argument("--modules", default="xss,lfi,redirect", help=','.join(MODULES))
    parser.add_argument("--oast-domain", help="домен вашего OAST/DNS-логгера; обязателен для ssrf")
    parser.add_argument("--params", default="", help="имена/пути параметров через запятую")
    parser.add_argument("--redirect-all", action="store_true", help="проверять redirect для всех параметров")
    parser.add_argument("--concurrency", type=number(1, 100), default=10, help="максимум одновременных запросов")
    parser.add_argument("--rate", type=positive_float, default=5, help="глобальный лимит начала запросов в секунду")
    parser.add_argument("--timeout", type=positive_float, default=5, help="таймаут одного запроса в секундах")
    parser.add_argument("--max-requests", type=number(1, 100000), default=1000)
    parser.add_argument("--max-parameters", type=number(1, 200), default=50)
    parser.add_argument('--max-targets', type=number(1, 10000), default=1000)
    parser.add_argument("--max-bytes", type=number(1024, 50_000_000), default=1_048_576)
    parser.add_argument("-o", "--output", type=Path, default=Path("post_scan_results"))
    parser.add_argument("--no-color", action="store_true")
    return parser


def load_args(argv: list[str] | None = None):
    parser = build_parser()
    args = parser.parse_args(argv)
    modules = list(dict.fromkeys(item.strip().lower() for item in args.modules.split(",") if item.strip()))
    if not modules or any(item not in MODULES for item in modules):
        parser.error("--modules допускает только " + ",".join(MODULES))
    args.modules = modules
    try:
        args.oast_domain = validate_oast_domain(args.oast_domain, args.modules)
    except ValueError as exc:
        parser.error(str(exc))
    args.params = [item.strip() for item in args.params.split(",") if item.strip()]

    try:
        raw_targets = args.url or [
            line.strip()
            for line in args.list.expanduser().read_text(encoding="utf-8-sig").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        targets = list(dict.fromkeys(normalize_url(item.strip()) for item in raw_targets))
        if not targets or len(targets) > args.max_targets:
            raise ValueError('нужен непустой список URL в пределах --max-targets')
        raw_body = args.body
        if args.body_file:
            raw_body = args.body_file.expanduser().read_text(encoding="utf-8")
        template = parse_body(raw_body or "", args.json)
        template.raw.encode('utf-8')
        headers = parse_headers(args.headers)
        if args.cookies:
            if any(ord(char) < 32 or ord(char) == 127 for char in args.cookies):
                raise ValueError("Cookie не должен содержать управляющие символы")
            headers["cookie"] = args.cookies
        if args.user_agent and any(ord(char) < 32 or ord(char) == 127 for char in args.user_agent):
            raise ValueError("User-Agent не должен содержать управляющие символы")
        origins = {origin(url) for url in targets}
        if args.headers_origin:
            selected = normalize_url(args.headers_origin)
            if selected != origin(selected) + '/' or origin(selected) not in origins:
                raise ValueError('--headers-origin: только scheme://host[:port] из списка URL')
            args.headers_origin = origin(selected)
        elif headers:
            if len(origins) > 1:
                raise ValueError('при нескольких origin укажи --headers-origin для пользовательских заголовков')
            args.headers_origin = next(iter(origins))
        media = headers.get('content-type', '').partition(';')[0].strip().lower()
        if media and ((args.json and media != 'application/json' and not media.endswith('+json'))
                      or (not args.json and media != 'application/x-www-form-urlencoded')):
            raise ValueError('Content-Type не соответствует выбранному типу тела (--json / форма)')
        output = args.output.expanduser().resolve()
        if output.exists() and (not output.is_dir() or any(output.iterdir())):
            raise ValueError("папка --output должна быть новой или пустой")
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        args.output = output
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        parser.error(str(exc))
    return args, targets, template, headers


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    args, targets, template, headers = load_args(argv)
    colorama_init(strip=args.no_color or not sys.stdout.isatty())
    scanner = PostScanner(args, targets, template, headers)
    try:
        summary = asyncio.run(scanner.run())
    except KeyboardInterrupt:
        scanner.interrupted = True
        summary = scanner.summary()
    except (OSError, ValueError) as exc:
        print(f'Ошибка: {exc}', file=sys.stderr)
        return 2
    try:
        write_reports(args.output, scanner, summary)
    except OSError as exc:
        print(f'Ошибка записи отчёта: {exc}', file=sys.stderr)
        return 2
    print_results(scanner, summary, args.no_color)
    print(f"Отчёт: {args.output / 'vulns_report.txt'}")
    if summary['status'] == 'interrupted':
        return 130
    return 0 if summary['status'] in ('completed', 'completed_no_findings', 'completed_with_errors') else 1


if __name__ == "__main__":
    raise SystemExit(main())
