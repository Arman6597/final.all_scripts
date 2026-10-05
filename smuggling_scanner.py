#!/usr/bin/env python3
"""Осторожный HTTP/1.1 framing timeout scanner, Python 3.10+, Ubuntu.

Установка: python3 -m pip install 'colorama>=0.4.6,<1'
Запуск: python3 smuggling_scanner.py -u https://example.com/ --rate 2

Только явно разрешённые URL. OPTIONS используется по умолчанию; POST выбирается
явно для подходящего тестового эндпоинта. Редиректы не выполняются. Каждый запрос
открывает отдельное соединение. HTTP/2, прокси из окружения и cookies не используются.

Это скрининг аномалий тайминга, а не доказательство Request Smuggling. Неполное
тело может вызвать ожидание и у единственного HTTP-парсера без десинхронизации.
Повторяемый таймаут остаётся кандидатом низкой уверенности. Отсутствие кандидатов
не доказывает безопасность. Нет второго запроса/полезной нагрузки в теле, однако
даже неполный запрос может занять upstream-соединение; нулевой риск не гарантирован.

Файл exploited.jsonl сохраняет исторически запрошенное имя: записи в нём НЕ
означают успешную эксплуатацию. Права 0600 — программная защита, не шифрование.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import math
import os
import re
import signal
import socket
import ssl
import stat
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

try:
    from colorama import Fore, Style, init as color_init
except ImportError:
    raise SystemExit("Установите зависимость: python3 -m pip install 'colorama>=0.4.6,<1'")


MAX_HEADER = 32_768
MAX_URLS = 10_000
TE_VARIANTS = (
    ("standard", b"Transfer-Encoding: chunked"),
    ("lowercase", b"transfer-encoding: chunked"),
    ("double_space", b"Transfer-Encoding:  chunked"),
    ("unsupported_xchunked", b"Transfer-Encoding: xchunked"),
)
STATUS_LINE = re.compile(rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: [^\r\n]*)?\r\n")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Target:
    url: str
    hostname: str
    port: int
    tls: bool
    host_header: str
    request_target: str


def parse_target(value: str) -> Target:
    if not value or len(value) > 8192 or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ValueError("URL пустой, слишком длинный или содержит пробел/управляющий символ")
    if "\\" in value or re.search(r"%(?:0[0-9a-f]|1[0-9a-f]|7f)", value, re.I):
        raise ValueError("В URL запрещены обратные слэши и закодированные управляющие символы")
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("Требуется полный http:// или https:// URL")
    if parts.username is not None or parts.password is not None or parts.fragment:
        raise ValueError("Userinfo и fragment в URL не поддерживаются")
    hostname = parts.hostname.encode("idna").decode("ascii").lower()
    if "%" in hostname:
        raise ValueError("Zone ID в имени хоста не поддерживается")
    try:
        address = ipaddress.ip_address(hostname)
        host = f"[{address.compressed}]" if address.version == 6 else str(address)
        hostname = address.compressed
    except ValueError:
        if len(hostname) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in hostname.rstrip(".").split(".")
        ):
            raise ValueError("Некорректное имя хоста") from None
        host = hostname
    default_port = 443 if parts.scheme == "https" else 80
    port = parts.port if parts.port is not None else default_port
    if not 1 <= port <= 65535:
        raise ValueError("Порт должен быть в диапазоне 1–65535")
    authority = host if port == default_port else f"{host}:{port}"
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="/%?:@!$&'()*+,;=-._~")
    request_target = path + ("?" + query if query else "")
    return Target(urlunsplit((parts.scheme, authority, path, query, "")), hostname,
                  port, parts.scheme == "https", authority, request_target)


def packet(target: Target, method: str, body: bytes, *, cl: int | None = None,
           te: bytes | None = None) -> bytes:
    headers = [f"{method} {target.request_target} HTTP/1.1".encode("ascii"),
               f"Host: {target.host_header}".encode("ascii"),
               b"User-Agent: BountyFramingCheck/1.0", b"Accept: */*",
               b"Accept-Encoding: identity", b"Cache-Control: no-store",
               b"Connection: close", b"Content-Type: application/octet-stream"]
    if cl is not None:
        headers.append(f"Content-Length: {cl}".encode("ascii"))
    if te is not None:
        headers.append(te)
    return b"\r\n".join(headers) + b"\r\n\r\n" + body


def probe_packet(target: Target, method: str, family: str, te: bytes) -> bytes:
    if family == "CL.TE":
        # CL охватывает всё тело; chunked-парсер ожидает недостающий CRLF.
        return packet(target, method, b"1\r\nA", cl=4, te=te)
    if family == "TE.CL":
        # Завершённый zero-chunk, CL завышен на один байт; суффикса нет.
        return packet(target, method, b"0\r\n\r\n", cl=6, te=te)
    raise ValueError("Неизвестная семья проверки")


class RateLimiter:
    def __init__(self, rate: float):
        self.interval = 1.0 / rate
        self.previous = -math.inf
        self.lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self.lock:
            delay = self.previous + self.interval - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self.previous = time.monotonic()


@dataclass
class Observation:
    state: str
    phase: str
    elapsed: float
    connect_elapsed: float = 0.0
    status: int | None = None
    response_headers: str = ""
    interim_statuses: list[int] | None = None
    error: str = ""


class HeaderReader:
    def __init__(self):
        self.pending = bytearray()
        self.interim: list[int] = []
        self.total = 0

    async def read(self, reader: asyncio.StreamReader) -> tuple[int, bytes]:
        while True:
            if b"\r\n\r\n" not in self.pending:
                chunk = await reader.read(4096)
                if not chunk:
                    raise EOFError("Соединение закрыто до полного HTTP-заголовка")
                self.pending.extend(chunk)
            boundary = self.pending.find(b"\r\n\r\n")
            if boundary < 0:
                if len(self.pending) + self.total > MAX_HEADER:
                    raise ValueError("Слишком длинные заголовки ответа")
                continue
            end = boundary + 4
            block = bytes(self.pending[:end])
            del self.pending[:end]
            self.total += len(block)
            if self.total > MAX_HEADER:
                raise ValueError("Слишком длинные заголовки ответа")
            match = STATUS_LINE.match(block)
            if match is None:
                raise ValueError("Некорректная строка статуса HTTP/1.x")
            status = int(match.group(1))
            if 100 <= status < 200 and status != 101:
                self.interim.append(status)
                if len(self.interim) > 8:
                    raise ValueError("Слишком много промежуточных ответов")
                continue
            return status, block


async def resolve_target(target: Target, timeout: float) -> tuple[int, str]:
    addresses = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
        target.hostname, target.port, type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP), timeout)
    for family, _, _, _, sockaddr in addresses:
        if family in (socket.AF_INET, socket.AF_INET6):
            return family, sockaddr[0]
    raise OSError("DNS не вернул IPv4/IPv6 адрес")


class RawClient:
    def __init__(self, timeout: float, connect_timeout: float, rate: float):
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.limiter = RateLimiter(rate)
        self.semaphore = asyncio.Semaphore(1)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.set_alpn_protocols(["http/1.1"])
        self.connections = 0

    async def request(self, target: Target, peer: tuple[int, str], raw: bytes) -> Observation:
        async with self.semaphore:
            await self.limiter.wait()
            self.connections += 1
            writer = None
            phase = "connect"
            start = time.monotonic()
            connected = 0.0
            header_reader = HeaderReader()
            try:
                tls_options: dict[str, Any] = {}
                if target.tls:
                    tls_options = {"ssl": self.ssl_context,
                                   "server_hostname": target.hostname,
                                   "ssl_handshake_timeout": self.connect_timeout}
                reader, writer = await asyncio.wait_for(asyncio.open_connection(
                    peer[1], target.port, family=peer[0], limit=MAX_HEADER,
                    **tls_options), self.connect_timeout)
                connected = time.monotonic() - start
                if target.tls:
                    tls = writer.get_extra_info("ssl_object")
                    if tls is None or tls.selected_alpn_protocol() not in (None, "http/1.1"):
                        raise ValueError("Сервер не согласовал HTTP/1.1")
                phase = "write"
                writer.write(raw)
                await asyncio.wait_for(writer.drain(), self.connect_timeout)
                phase = "read"
                start = time.monotonic()
                status, head = await asyncio.wait_for(header_reader.read(reader), self.timeout)
                return Observation("response", phase, time.monotonic() - start, connected,
                                   status, head.decode("latin-1"), header_reader.interim)
            except asyncio.TimeoutError:
                state = f"{phase}_timeout"
                if phase == "read" and header_reader.pending:
                    state = "partial_response_timeout"
                return Observation(state, phase, time.monotonic() - start, connected,
                                   interim_statuses=header_reader.interim)
            except (OSError, EOFError, ValueError) as exc:
                return Observation("error", phase, time.monotonic() - start, connected,
                                   error=f"{type(exc).__name__}: {exc}")
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), 0.5)
                    except (OSError, asyncio.TimeoutError):
                        writer.transport.abort()
                    except asyncio.CancelledError:
                        writer.transport.abort()
                        raise


def protected_open(path: Path, append: bool = True):
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags | (os.O_APPEND if append else 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise ValueError(f"Ожидался обычный принадлежащий вам файл: {path}")
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, "a" if append else "w", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise


class Reports:
    def __init__(self, output: Path):
        self.run_id = uuid.uuid4().hex
        self.output = output
        self.stack = contextlib.ExitStack()
        try:
            output.mkdir(parents=True, exist_ok=True, mode=0o700)
            if output.is_symlink() or output.stat().st_uid != os.getuid():
                raise ValueError("Каталог результатов должен принадлежать вам и не быть symlink")
            self.lock = self.stack.enter_context(protected_open(output / ".scan.lock"))
            try:
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("Другой сканер уже использует этот каталог") from None
            self.files = {name: self.stack.enter_context(protected_open(output / name))
                          for name in ("exploited.jsonl", "checks.jsonl", "runs.jsonl")}
        except BaseException:
            self.stack.close()
            raise

    def write(self, name: str, record: dict[str, Any]) -> None:
        stream = self.files[name]
        stream.write(json.dumps({"time": utc_now(), "run_id": self.run_id, **record},
                                ensure_ascii=True) + "\n")
        stream.flush()
        if name == "exploited.jsonl":
            os.fsync(stream.fileno())

    def close(self) -> None:
        self.stack.close()


def healthy(samples: list[Observation], timeout: float) -> bool:
    if not samples:
        return False
    return all(s.state == "response" and s.status is not None
               and (200 <= s.status < 300 or s.status == 404)
               and s.elapsed < timeout / 4 for s in samples)


def timed_out(sample: Observation, controls: list[Observation], timeout: float) -> bool:
    return (sample.state == "read_timeout" and sample.elapsed >= timeout * 0.9
            and healthy(controls, timeout)
            and sample.elapsed >= 4 * max(s.elapsed for s in controls))


class Scanner:
    def __init__(self, client: RawClient, reports: Reports, method: str):
        self.client = client
        self.reports = reports
        self.method = method

    async def scan(self, target: Target) -> str:
        print(f"[*] {self.method} {target.url}", flush=True)
        try:
            peer = await resolve_target(target, self.client.connect_timeout)
        except (OSError, asyncio.TimeoutError) as exc:
            self.reports.write("checks.jsonl", {"url": target.url, "state": "inconclusive",
                                               "reason": "dns_error", "error": str(exc)})
            return "inconclusive"
        history: list[dict[str, Any]] = []

        async def send(label: str, raw: bytes) -> Observation:
            result = await self.client.request(target, peer, raw)
            row = {"url": target.url, "method": self.method, "peer": peer[1],
                   "label": label, "request_sha256": hashlib.sha256(raw).hexdigest(),
                   **asdict(result)}
            self.reports.write("checks.jsonl", row)
            history.append(row)
            return result

        cl_control = packet(target, self.method, b"", cl=0)
        te_control = packet(target, self.method, b"0\r\n\r\n", te=TE_VARIANTS[0][1])
        controls: list[Observation] = []
        for name, raw in (("baseline_cl_1", cl_control), ("baseline_cl_2", cl_control),
                          ("baseline_te", te_control)):
            controls.append(await send(name, raw))
            if not healthy(controls, self.client.timeout):
                print(Fore.YELLOW + "[?] Нестабильный/неподходящий baseline; цель пропущена.")
                return "inconclusive"
        if len({s.status for s in controls}) != 1:
            return "inconclusive"

        for family in ("CL.TE", "TE.CL"):
            for variant, te in TE_VARIANTS:
                raw = probe_packet(target, self.method, family, te)
                label = f"{family}/{variant}"
                first = await send(label, raw)
                if first.state == "read_timeout":
                    # Любой такой сигнал завершает проверку цели; TE.CL после него не идёт.
                    if not timed_out(first, controls, self.client.timeout):
                        return "inconclusive"
                    between = await send("control_before_repeat", cl_control)
                    if not healthy([between], self.client.timeout) or between.status != controls[0].status:
                        return "inconclusive"
                    repeat = await send(label + "/repeat", raw)
                    after = await send("control_after_repeat", cl_control)
                    reference = controls + [between, after]
                    if (timed_out(repeat, reference, self.client.timeout)
                            and after.status == controls[0].status):
                        self.reports.write("exploited.jsonl", {
                            "url": target.url, "method": self.method, "peer": peer[1],
                            "state": "candidate", "confidence": "low",
                            "signal": "repeated_framing_timeout", "probe_family": family,
                            "variant": variant, "exploitation_confirmed": False,
                            "reason": "Два read-timeout между быстрыми контрольными ответами",
                            "limitation": "Ожидание возможно в одном парсере; направление CL/TE не доказано",
                            "timeout_seconds": self.client.timeout,
                            "request_raw_latin1": raw.decode("latin-1"),
                            "request_base64": base64.b64encode(raw).decode("ascii"),
                            "request_sha256": hashlib.sha256(raw).hexdigest(),
                            "observations": history,
                        })
                        print(Fore.RED + Style.BRIGHT +
                              f"[CANDIDATE] {target.url} {label}: повторён таймаут; нужна ручная проверка.")
                        return "candidate"
                    return "inconclusive"
                if first.state != "response" or first.status == 429 or (first.status or 0) >= 500:
                    return "inconclusive"
                if first.elapsed >= self.client.timeout / 4:
                    return "inconclusive"
        last = await send("final_control", cl_control)
        if not healthy([last], self.client.timeout) or last.status != controls[0].status:
            return "inconclusive"
        print(Fore.GREEN + "[-] Повторяемых таймаутов не выявлено; это не гарантия отсутствия уязвимости.")
        return "no_signal"


def bounded_number(low: float, high: float):
    def parse(value: str) -> float:
        try:
            number = float(value)
        except ValueError:
            raise argparse.ArgumentTypeError("Требуется число") from None
        if not math.isfinite(number) or not low <= number <= high:
            raise argparse.ArgumentTypeError(f"Допустимый диапазон: {low}–{high}")
        return number
    return parse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="HTTP/1.1 time-based screening: только кандидаты, без эксплуатации.",
        epilog="Передавайте только разрешённые URL. 1 активное соединение; редиректы не выполняются.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-u", "--url", help="Один разрешённый URL")
    source.add_argument("-l", "--list", dest="url_list", type=Path, help="UTF-8 файл: один URL на строку")
    parser.add_argument("-o", "--output", type=Path, default=Path("~/bugbounty/smuggling_results"))
    parser.add_argument("--timeout", type=bounded_number(1, 30), default=6.0,
                        help="Ожидание финальных заголовков ответа, секунд (6)")
    parser.add_argument("--connect-timeout", type=bounded_number(1, 30), default=5.0,
                        help="Отдельный таймаут DNS/TCP/TLS/записи, секунд (5)")
    parser.add_argument("--rate", type=bounded_number(0.05, 10), default=2.0,
                        help="Максимум новых соединений в секунду без burst (2)")
    parser.add_argument("--method", choices=("OPTIONS", "POST"), default="OPTIONS",
                        help="Метод для всех запросов (OPTIONS); POST — только для подходящего эндпоинта")
    return parser


def load_targets(args: argparse.Namespace) -> list[Target]:
    if args.url:
        return [parse_target(args.url)]
    targets: dict[str, Target] = {}
    with args.url_list.expanduser().open(encoding="utf-8-sig") as source:
        for number, line in enumerate(source, 1):
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            try:
                target = parse_target(value)
            except (ValueError, UnicodeError) as exc:
                raise ValueError(f"Строка {number}: {exc}") from None
            targets[target.url] = target
            if len(targets) > MAX_URLS:
                raise ValueError(f"Слишком много URL: максимум {MAX_URLS}")
    if not targets:
        raise ValueError("Файл не содержит URL")
    return list(targets.values())


async def run(args: argparse.Namespace, targets: list[Target], reports: Reports) -> int:
    client = RawClient(args.timeout, args.connect_timeout, args.rate)
    scanner = Scanner(client, reports, args.method)
    summary: dict[str, Any] = {"targets": len(targets), "candidate": 0, "no_signal": 0,
                               "inconclusive": 0, "status": "running"}
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, task.cancel)
    exit_code = 0
    try:
        for target in targets:
            state = await scanner.scan(target)
            summary[state] += 1
        summary["status"] = "complete"
    except asyncio.CancelledError:
        summary["status"] = "interrupted"
        exit_code = 130
    except BaseException:
        summary["status"] = "error"
        raise
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)
        summary["connections"] = client.connections
        reports.write("runs.jsonl", summary)
        public_summary = dict(summary)
        public_summary["status"] = ("completed_with_inconclusive" if summary["inconclusive"]
                                     else "completed") if summary["status"] == "complete" else summary["status"]
        with protected_open(reports.output / "summary.json", append=False) as stream:
            stream.truncate(0)
            json.dump(public_summary, stream, ensure_ascii=True)
            stream.write("\n")
        print(f"Готово: {summary['status']}; кандидаты={summary['candidate']}, "
              f"без сигнала={summary['no_signal']}, неопределённые={summary['inconclusive']}, "
              f"соединения={client.connections}")
    return exit_code


def main() -> int:
    os.umask(0o077)
    color_init(autoreset=True, strip=not sys.stdout.isatty())
    parser = build_parser()
    args = parser.parse_args()
    try:
        targets = load_targets(args)
        reports = Reports(args.output.expanduser())
    except (OSError, ValueError, UnicodeError) as exc:
        parser.error(str(exc))
    try:
        print("Только разрешённый scope. Таймаут — кандидат, не доказанная эксплуатация.")
        return asyncio.run(run(args, targets, reports))
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 2
    finally:
        reports.close()


if __name__ == "__main__":
    raise SystemExit(main())
