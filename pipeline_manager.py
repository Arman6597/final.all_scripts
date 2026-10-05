#!/usr/bin/env python3
"""Оркестратор Recon → GET/POST Scanner для Ubuntu, Python 3.10+."""
from __future__ import annotations

import argparse
import asyncio
import contextlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shlex
import signal
import sys
import time
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit
import uuid

from bbscanner.probes import MODULES as SCANNER_MODULES, strict_json, validate_oast_domain


DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
MODULES = set(SCANNER_MODULES)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def positive_number(value: str) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("нужно число") from exc
    if not math.isfinite(result) or not 0 < result <= 604800:
        raise argparse.ArgumentTypeError("нужно конечное положительное число до 604800")
    return result


def positive_int(value: str) -> int:
    try:
        result = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("нужно целое число") from exc
    if not 1 <= result <= 100000:
        raise argparse.ArgumentTypeError("допустимый диапазон 1…100000")
    return result


def normalize_domain(value: str) -> str:
    raw = value.strip().rstrip(".").lower()
    if not raw or any(char in raw for char in "/\\:@*?#") or any(char.isspace() for char in raw):
        raise ValueError("нужен домен без схемы, пути, порта и wildcard")
    try:
        domain = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("некорректное IDN-имя") from exc
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("ожидается домен, а не IP-адрес")
    if len(domain) > 253 or "." not in domain or not all(DOMAIN_LABEL.fullmatch(label) for label in domain.split(".")):
        raise ValueError("некорректный домен")
    return domain


def normalize_url(value: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 33 or ord(char) == 127 for char in value) or "\\" in value:
        raise ValueError("некорректный URL")
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username is not None:
        raise ValueError("нужен HTTP(S) URL без userinfo")
    hostname = normalize_domain(parts.hostname)
    port = parts.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("некорректный порт")
    netloc = hostname
    if port is not None and port != (443 if parts.scheme == "https" else 80):
        netloc += f":{port}"
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="%/?@!$&'()*+,;=:-._~")
    return urlunsplit((parts.scheme, netloc, path, query, ""))


def atomic_json(path: Path, value: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


@dataclass(frozen=True)
class Scope:
    root: str
    subdomains: bool = False
    exclusions: tuple[str, ...] = ()
    ports: tuple[int, ...] = (80, 443)

    def contains(self, url: str) -> bool:
        parts = urlsplit(url)
        host = parts.hostname or ""
        matches = host == self.root or (self.subdomains and host.endswith("." + self.root))
        blocked = any(host == excluded or host.endswith("." + excluded) for excluded in self.exclusions)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return matches and not blocked and port in self.ports


@dataclass(frozen=True)
class PostRequest:
    url: str
    body: str
    json_mode: bool
    params: tuple[str, ...] = ()

    @property
    def identity(self) -> str:
        raw = json.dumps([self.url, self.body, self.json_mode, self.params], ensure_ascii=False)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class FilteredData:
    get_urls: list[str] = field(default_factory=list)
    resource_urls: list[str] = field(default_factory=list)
    post_requests: list[PostRequest] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=lambda: {
        "lines": 0, "invalid": 0, "out_of_scope": 0, "no_get_parameters": 0,
        "unsupported_method": 0, "missing_post_body": 0, "duplicates": 0,
        "over_limit": 0,
    })


def body_from_record(record: dict) -> tuple[str, bool]:
    media = record.get("content_type", "application/x-www-form-urlencoded")
    if not isinstance(media, str):
        raise ValueError("content_type должен быть строкой")
    media = media.partition(";")[0].strip().lower()
    value = record["body"]
    if media == "application/json":
        parsed = strict_json(value) if isinstance(value, str) else value
        if not isinstance(parsed, (dict, list)) or not parsed:
            raise ValueError("JSON body должен быть непустым объектом/массивом")
        encoded = json.dumps(parsed, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        # Строковое тело оставляем в исходном виде для baseline и подписей.
        return value if isinstance(value, str) else encoded, True
    if media != "application/x-www-form-urlencoded":
        raise ValueError("поддерживаются только JSON и form-urlencoded")
    if not isinstance(value, str) or not any(name for name, _ in parse_qsl(value, keep_blank_values=True)):
        raise ValueError("form body должен быть строкой с параметрами")
    return value, False


def filter_records(paths: list[Path], scope: Scope, limit: int, max_bytes: int) -> FilteredData:
    data = FilteredData()
    seen_get: set[str] = set()
    seen_resources: set[str] = set()
    seen_post: set[str] = set()
    for path in paths:
        if path.stat().st_size > max_bytes:
            raise ValueError(f"входной файл превышает {max_bytes} байт")
        with path.open(encoding="utf-8-sig") as source:
            for line in source:
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                data.counts["lines"] += 1
                try:
                    if raw.startswith("{"):
                        record = strict_json(raw)
                        if not isinstance(record, dict):
                            raise ValueError("нужен JSON-объект")
                        url = normalize_url(record.get("url", ""))
                        method = record.get("method", "GET")
                        if not isinstance(method, str):
                            raise ValueError("method должен быть строкой")
                        method = method.upper()
                    else:
                        record, method, url = {}, "GET", normalize_url(raw)
                    if not scope.contains(url):
                        data.counts["out_of_scope"] += 1
                        continue
                    if method == "GET":
                        if url not in seen_resources:
                            seen_resources.add(url)
                            if len(data.resource_urls) < limit:
                                data.resource_urls.append(url)
                            else:
                                data.counts["over_limit"] += 1
                        if not any(name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)):
                            data.counts["no_get_parameters"] += 1
                        elif url in seen_get:
                            data.counts["duplicates"] += 1
                        elif len(data.get_urls) >= limit:
                            data.counts["over_limit"] += 1
                        else:
                            seen_get.add(url)
                            data.get_urls.append(url)
                    elif method == "POST":
                        if "body" not in record:
                            data.counts["missing_post_body"] += 1
                            continue
                        if record.get("headers") or record.get("cookies"):
                            raise ValueError("авторизация из recon не принимается")
                        body, json_mode = body_from_record(record)
                        params = record.get("params", [])
                        if not isinstance(params, list) or any(not isinstance(p, str) or not p or "," in p or any(ord(c) < 32 for c in p) for p in params):
                            raise ValueError("params должен содержать имена полей")
                        request = PostRequest(url, body, json_mode, tuple(dict.fromkeys(params)))
                        if request.identity in seen_post:
                            data.counts["duplicates"] += 1
                        elif len(data.post_requests) >= limit:
                            data.counts["over_limit"] += 1
                        else:
                            seen_post.add(request.identity)
                            data.post_requests.append(request)
                    else:
                        data.counts["unsupported_method"] += 1
                except (ValueError, TypeError, RecursionError, KeyError):
                    data.counts["invalid"] += 1
    return data


@dataclass
class ProcessResult:
    stage: str
    state: str
    returncode: int | None = None
    seconds: float = 0.0
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    scanner_status: str | None = None


class ProcessRunner:
    def __init__(self, stop: asyncio.Event, grace: float = 5, max_log_bytes: int = 10 * 1024 * 1024):
        self.stop = stop
        self.grace = grace
        self.max_log_bytes = max_log_bytes

    async def terminate_group(self, process: asyncio.subprocess.Process, done: asyncio.Future) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        await asyncio.wait({done}, timeout=self.grace)
        # Потомки могли пережить родителя и держать stdout открытым.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        try:
            await asyncio.wait_for(asyncio.shield(done), timeout=self.grace)
        except asyncio.TimeoutError:
            done.cancel()
            await asyncio.gather(done, return_exceptions=True)
        await process.wait()

    async def run(self, argv: list[str], stage: str, log_dir: Path, timeout: float,
                  cwd: Path | None = None, stdin: Path | None = None) -> ProcessResult:
        log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        stdout_path, stderr_path = log_dir / "stdout.log", log_dir / "stderr.log"
        result = ProcessResult(stage, "interrupted", stdout=str(stdout_path), stderr=str(stderr_path))
        if self.stop.is_set():
            return result
        exceeded = asyncio.Event()
        started = time.monotonic()
        process = None
        complete = None
        watchers: list[asyncio.Task] = []
        with contextlib.ExitStack() as stack:
            output = stack.enter_context(stdout_path.open("wb"))
            errors = stack.enter_context(stderr_path.open("wb"))
            input_stream = stack.enter_context(stdin.open("rb")) if stdin else asyncio.subprocess.DEVNULL
            try:
                process = await asyncio.create_subprocess_exec(
                    *argv, stdin=input_stream, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE, cwd=cwd, start_new_session=True,
                )

                async def pump(stream: asyncio.StreamReader, destination) -> None:
                    saved = 0
                    while chunk := await stream.read(65536):
                        remaining = max(0, self.max_log_bytes - saved)
                        destination.write(chunk[:remaining])
                        destination.flush()
                        saved += min(len(chunk), remaining)
                        if len(chunk) > remaining:
                            exceeded.set()

                complete = asyncio.gather(process.wait(), pump(process.stdout, output), pump(process.stderr, errors))
                stopped = asyncio.create_task(self.stop.wait())
                overflow = asyncio.create_task(exceeded.wait())
                watchers = [stopped, overflow]
                done, _ = await asyncio.wait({complete, stopped, overflow}, timeout=timeout,
                                             return_when=asyncio.FIRST_COMPLETED)
                if self.stop.is_set():
                    result.state = "interrupted"
                elif exceeded.is_set():
                    result.state = "output_limit"
                elif complete in done:
                    await complete
                    result.state = "ok" if process.returncode == 0 else "nonzero"
                else:
                    result.state = "timeout"
                if result.state in {"timeout", "interrupted", "output_limit"}:
                    await self.terminate_group(process, complete)
                else:
                    # Убираем забытые фоновые процессы из той же process group.
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                result.returncode = process.returncode
            except asyncio.CancelledError:
                if process is not None and complete is not None:
                    await self.terminate_group(process, complete)
                raise
            except (OSError, RuntimeError) as exc:
                result.state, result.error = "spawn_error", type(exc).__name__
                if process is not None and complete is not None:
                    await self.terminate_group(process, complete)
            finally:
                for task in watchers:
                    task.cancel()
                if watchers:
                    await asyncio.gather(*watchers, return_exceptions=True)
        result.seconds = round(time.monotonic() - started, 3)
        return result


class Pipeline:
    def __init__(self, args):
        self.args = args
        self.stop = asyncio.Event()
        self.runner = ProcessRunner(self.stop, args.kill_grace, args.max_log_mib * 1024 * 1024)
        self.error_count = 0
        self.summary: dict = {"started": utc_now(), "status": "running", "mode": args.mode, "targets": []}
        self.run_dir: Path | None = None
        from bbscanner.pipeline_extras import ExtraStages
        self.extras = ExtraStages(self)

    def error(self, domain: str, stage: str, reason: str, **details) -> None:
        self.error_count += 1
        event = {"time": utc_now(), "domain": domain, "stage": stage, "reason": reason, **details}
        with self.args.error_log.open("a", encoding="utf-8") as log:
            log.write(json.dumps(event, ensure_ascii=False) + "\n")
        print(f"[!] {domain} / {stage}: {reason}", file=sys.stderr, flush=True)

    def checkpoint(self) -> None:
        self.summary["errors"] = self.error_count
        atomic_json(self.run_dir / "pipeline_summary.json", self.summary)

    def roots(self) -> list[str]:
        result = []
        with self.args.targets.open(encoding="utf-8-sig") as source:
            for line_number, line in enumerate(source, 1):
                raw = line.partition("#")[0].strip()
                if not raw:
                    continue
                try:
                    domain = normalize_domain(raw)
                except ValueError:
                    self.error("-", "targets", "invalid_domain", line=line_number)
                    continue
                if domain in result:
                    continue
                if len(result) >= self.args.max_roots:
                    self.error("-", "targets", "max_roots", line=line_number)
                    break
                result.append(domain)
        return result

    async def execute(self, domain: str, argv: list[str], stage: str, logs: Path,
                      timeout: float, output: Path | None = None, cwd: Path | None = None) -> ProcessResult:
        print(f"[i] {domain}: {stage}", flush=True)
        summary_path = output / "summary.json" if output is not None else None
        previous = summary_path.stat().st_mtime_ns if summary_path is not None and summary_path.is_file() else None
        result = await self.runner.run(argv, stage, logs, timeout, cwd=cwd)
        if summary_path is not None and summary_path.is_file() and summary_path.stat().st_mtime_ns != previous:
            try:
                if summary_path.stat().st_size > self.args.max_input_mib * 1024 * 1024:
                    raise ValueError("слишком большой summary")
                summary = strict_json(summary_path.read_text(encoding="utf-8"))
                valid_states = {'completed', 'completed_no_findings', 'completed_with_errors',
                                'inconclusive', 'budget_exhausted', 'failed', 'interrupted',
                                'no_testable_parameters', 'completed_with_inconclusive'}
                if (isinstance(summary, dict) and isinstance(summary.get('status'), str)
                        and summary['status'] in valid_states):
                    result.scanner_status = summary["status"]
                else:
                    raise ValueError("нет статуса сканера")
            except (OSError, UnicodeError, ValueError):
                self.error(domain, stage, "invalid_scanner_summary")
        elif summary_path is not None and result.state == "ok":
            self.error(domain, stage, "missing_scanner_summary")
        if result.state != "ok":
            self.error(domain, stage, result.state, returncode=result.returncode, error=result.error)
        elif result.scanner_status in {"completed_with_errors", "inconclusive", "budget_exhausted", "failed", "interrupted", "no_testable_parameters", "completed_with_inconclusive"}:
            self.error(domain, stage, "scanner_incomplete", status=result.scanner_status)
        return result

    def common_scanner_args(self, rate: float, budget: int) -> list[str]:
        values = ["--modules", self.args.modules, "--rate", str(rate), "--timeout", str(self.args.http_timeout),
                  "--max-requests", str(budget), "--no-color"]
        oast_domain = getattr(self.args, "oast_domain", None)
        if oast_domain:
            values.extend(["--oast-domain", oast_domain])
        return values

    async def get_scan(self, domain: str, folder: Path, data: FilteredData, rate: float,
                       workers: int, budget: int) -> list[ProcessResult]:
        if not data.get_urls or self.stop.is_set():
            return []
        output = folder / "get_results"
        argv = [self.args.python, str(self.args.get_scanner), "-l", str(folder / "get_urls.txt"),
                "--output", str(output), "--workers", str(workers), "--max-targets", str(self.args.max_records),
                "--no-discovery", *self.common_scanner_args(rate, budget)]
        return [await self.execute(domain, argv, "get", folder / "logs" / "get", self.args.scanner_timeout, output)]

    async def post_scan(self, domain: str, folder: Path, data: FilteredData, rate: float,
                        workers: int, budget: int) -> list[ProcessResult]:
        results = []
        for index, request in enumerate(data.post_requests):
            if self.stop.is_set():
                break
            # Распределение общего бюджета POST между оставшимися шаблонами.
            remaining = len(data.post_requests) - index
            current_budget = max(1, budget // remaining)
            job = folder / "post_jobs" / f"{index + 1:04d}"
            job.mkdir(parents=True, mode=0o700)
            body_file = job / "body.txt"
            body_file.write_text(request.body, encoding="utf-8")
            output = job / "results"
            argv = [self.args.python, str(self.args.post_scanner), "-u", request.url, "--body-file", str(body_file),
                    "--output", str(output), "--concurrency", str(workers),
                    *self.common_scanner_args(rate, current_budget)]
            if request.json_mode:
                argv.append("--json")
            if request.params:
                argv.extend(["--params", ",".join(request.params)])
            results.append(await self.execute(domain, argv, f"post_{index + 1:04d}", job / "logs",
                                               self.args.scanner_timeout, output))
            budget -= current_budget
            if remaining > 1 and not self.stop.is_set():
                # Новый subprocess не должен обходить rate за счёт сброса таймера.
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self.stop.wait(), timeout=1 / rate)
        return results

    async def target(self, domain: str, entry: dict) -> None:
        folder = self.run_dir / domain
        folder.mkdir(mode=0o700)
        paths = []
        if self.args.recon_input:
            paths.append(self.args.recon_input)
            entry["recon"] = {"state": "cached"}
        else:
            result_file = folder / "recon_records.jsonl"
            argv = [arg.replace("{domain}", domain).replace("{output}", str(result_file)) for arg in self.args.recon_argv]
            result = await self.execute(domain, argv, "recon", folder / "logs" / "recon", self.args.recon_timeout,
                                        cwd=self.args.recon_cwd)
            entry["recon"] = asdict(result)
            if result.state == "ok":
                candidate = Path(result.stdout) if self.args.recon_output == "stdout" else result_file
                if candidate.is_file():
                    paths.append(candidate)
                else:
                    self.error(domain, "recon", "missing_output_file")
            # Не обрабатываем частичный recon после падения/таймаута.
        if self.stop.is_set():
            entry["status"] = "interrupted"
            return
        if self.args.post_input:
            paths.append(self.args.post_input)
        scope = Scope(domain, self.args.include_subdomains, tuple(self.args.exclude_host), tuple(self.args.ports))
        data = filter_records(paths, scope, self.args.max_records, self.args.max_input_mib * 1024 * 1024)
        entry["filter"] = data.counts
        entry["js"] = await self.extras.guarded("js", domain, self.extras.js(domain, folder, data, scope))
        if any(data.counts[key] for key in ("invalid", "missing_post_body", "over_limit")):
            self.error(domain, "filter", "records_rejected", counts=data.counts)
        (folder / "get_urls.txt").write_text("".join(url + "\n" for url in data.get_urls), encoding="utf-8")
        (folder / "post_requests.jsonl").write_text("".join(json.dumps({
            "method": "POST", "url": request.url, "body": request.body,
            "content_type": "application/json" if request.json_mode else "application/x-www-form-urlencoded",
            "params": request.params,
        }, ensure_ascii=False) + "\n" for request in data.post_requests), encoding="utf-8")
        (folder / "resource_urls.txt").write_text("".join(url + "\n" for url in data.resource_urls), encoding="utf-8")
        entry.update(get_urls=len(data.get_urls), post_requests=len(data.post_requests), resource_urls=len(data.resource_urls))
        try:
            await self.core_scan(domain, folder, data, entry)
        finally:
            entry["idor"] = await self.extras.guarded("idor", domain, self.extras.idor(domain, folder, scope))
            entry["smuggling"] = await self.extras.guarded("smuggling", domain, self.extras.smuggling(domain, folder, data))
        entry['core_status'] = entry.get('status')
        extra_ran = any(entry.get(name, {}).get('state') in {'ok', 'nonzero', 'finished', 'exception'}
                        for name in ('js', 'idor', 'smuggling'))
        if extra_ran and not self.stop.is_set() and entry.get("status") == "no_testable_requests":
            entry["status"] = "finished"

    async def core_scan(self, domain: str, folder: Path, data: FilteredData, entry: dict) -> None:
        if not data.get_urls and not data.post_requests:
            entry["status"] = "no_testable_requests"
            return
        if self.args.dry_run:
            entry['status'] = 'prepared_only'
            return
        branches = int(bool(data.get_urls)) + int(bool(data.post_requests))
        if data.post_requests and self.args.max_requests < len(data.post_requests) + int(bool(data.get_urls)):
            self.error(domain, "scan", "budget_too_small_for_templates")
            entry["status"] = "budget_too_small"
            return
        if self.args.mode == "parallel" and branches == 2 and self.args.workers < 2:
            self.error(domain, "scan", "parallel_requires_two_workers")
            entry["status"] = "invalid_parallel_limits"
            return
        # В parallel суммарные rate/workers остаются в пользовательских пределах.
        concurrent_branches = branches if self.args.mode == "parallel" else 1
        rate = self.args.rate / concurrent_branches
        workers = max(1, self.args.workers // concurrent_branches)
        get_budget = self.args.max_requests // 2 if branches == 2 else self.args.max_requests
        post_budget = self.args.max_requests - get_budget if branches == 2 else self.args.max_requests
        entry["limits"] = {"rate_per_branch": rate, "workers_per_branch": workers,
                           "get_budget": get_budget if data.get_urls else 0, "post_budget": post_budget if data.post_requests else 0}
        if data.post_requests and post_budget < len(data.post_requests):
            self.error(domain, "scan", "post_budget_too_small_for_templates")
            entry["status"] = "budget_too_small"
            return
        async def run_branch(name, operation, budget):
            try:
                return [asdict(item) for item in await operation(domain, folder, data, rate, workers, budget)]
            except Exception as exc:
                self.error(domain, name, 'stage_exception', exception=type(exc).__name__)
                return [{'stage': name, 'state': 'exception'}]

        if self.args.mode == "serial":
            entry['get'] = await run_branch('get', self.get_scan, get_budget)
            entry['post'] = await run_branch('post', self.post_scan, post_budget)
        else:
            entry['get'], entry['post'] = await asyncio.gather(
                run_branch('get', self.get_scan, get_budget),
                run_branch('post', self.post_scan, post_budget),
            )
        entry["status"] = "interrupted" if self.stop.is_set() else "finished"

    async def run(self) -> dict:
        self.args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.args.error_log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.run_dir = self.args.output / (stamp + "_" + uuid.uuid4().hex[:8])
        self.run_dir.mkdir(mode=0o700)
        self.summary["directory"] = str(self.run_dir)
        loop = asyncio.get_running_loop()
        installed = []
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self.stop.set)
            installed.append(sig)
        self.checkpoint()
        try:
            domains = self.roots()
            if not domains:
                self.summary["status"] = "no_valid_targets"
            scopes = [Scope(d, self.args.include_subdomains, tuple(self.args.exclude_host), tuple(self.args.ports)) for d in domains]
            outside = sum(not any(scope.contains(job['url']) for scope in scopes) for job in self.args.idor_jobs)
            self.summary['idor_scope'] = {'configured': len(self.args.idor_jobs), 'out_of_scope': outside}
            if outside:
                self.error('-', 'idor', 'out_of_scope_templates_skipped', count=outside)
            self.summary["monitor"] = await self.extras.guarded("monitor", "-", self.extras.monitor(domains))
            self.checkpoint()
            for domain in domains:
                if self.stop.is_set():
                    break
                entry = {"domain": domain, "status": "running"}
                self.summary["targets"].append(entry)
                self.checkpoint()
                before = self.error_count
                try:
                    await self.target(domain, entry)
                except Exception as exc:
                    self.error(domain, "pipeline", "target_failed", exception=type(exc).__name__)
                    entry["status"] = "failed"
                if entry.get("status") == "finished" and self.error_count > before:
                    entry["status"] = "finished_with_errors"
                self.checkpoint()
        except Exception:
            self.summary["status"] = "failed"
            raise
        finally:
            for sig in installed:
                loop.remove_signal_handler(sig)
            self.summary["finished"] = utc_now()
            if self.stop.is_set():
                self.summary["status"] = "interrupted"
            elif self.summary["status"] == "running":
                self.summary["status"] = "completed_with_errors" if self.error_count else "completed"
            self.checkpoint()
        return self.summary


def arguments(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    base = Path.home() / "bugbounty"
    parser.add_argument("--targets", type=Path, default=base / "targets.txt")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--recon-cmd", help="команда с {domain} и/или {output}; shell не используется")
    source.add_argument("--recon-input", type=Path, help="готовый TXT/JSONL, без запуска recon")
    parser.add_argument("--recon-output", choices=("stdout", "file"), default="stdout")
    parser.add_argument("--recon-cwd", type=Path, help="рабочая папка внешнего recon")
    parser.add_argument("--post-input", type=Path, help="дополнительный JSONL с POST method/body")
    parser.add_argument("--mode", choices=("serial", "parallel"), default="serial")
    parser.add_argument("--get-scanner", type=Path, default=Path(__file__).with_name("scanner.py"))
    parser.add_argument("--post-scanner", type=Path, default=Path(__file__).with_name("post_scanner.py"))
    parser.add_argument("--python", default=sys.executable, help="Python для сканеров")
    parser.add_argument("--include-subdomains", action="store_true", help="включить поддомены корней в scope")
    parser.add_argument("--exclude-host", action="append", default=[], help="исключить hostname и его поддомены")
    parser.add_argument("--ports", default="80,443", help="разрешённые порты через запятую")
    parser.add_argument("--modules", default="xss,lfi,redirect")
    parser.add_argument("--oast-domain", help="домен вашего OAST/DNS-логгера; обязателен при ssrf")
    parser.add_argument("--rate", type=positive_number, default=5, help="лимит requests/sec для сканеров одной цели")
    parser.add_argument("--workers", type=positive_int, default=10, help="общий предел параллельных запросов сканеров")
    parser.add_argument("--max-requests", type=positive_int, default=1000, help="общий бюджет GET/POST сканеров одной цели")
    parser.add_argument("--http-timeout", type=positive_number, default=5)
    parser.add_argument("--recon-timeout", type=positive_number, default=600)
    parser.add_argument("--scanner-timeout", type=positive_number, default=1800, help="таймаут каждого процесса сканера")
    parser.add_argument("--kill-grace", type=positive_number, default=5)
    parser.add_argument("--max-roots", type=positive_int, default=100)
    parser.add_argument("--max-records", type=positive_int, default=100, help="максимум GET и POST записей на цель")
    parser.add_argument("--max-input-mib", type=positive_int, default=20)
    parser.add_argument("--max-log-mib", type=positive_int, default=20)
    parser.add_argument("--output", type=Path, default=base / "runs")
    parser.add_argument("--error-log", type=Path, default=base / "pipeline_errors.log")
    parser.add_argument("--dry-run", action="store_true", help="выполнить recon и подготовку; сканеры не запускать")
    from bbscanner.pipeline_extras import add_arguments, validate_arguments
    add_arguments(parser, base)
    args = parser.parse_args(argv)
    try:
        for name in ("targets", "recon_input", "post_input", "get_scanner", "post_scanner", "output", "error_log", "recon_cwd"):
            value = getattr(args, name)
            if value is not None:
                setattr(args, name, value.expanduser().resolve())
        for path in (args.targets, args.recon_input, args.post_input):
            if path is not None and not path.is_file():
                raise ValueError(f"файл не найден: {path}")
            if path is not None and path.stat().st_size > args.max_input_mib * 1024 * 1024:
                raise ValueError(f"файл превышает --max-input-mib: {path}")
        if not args.dry_run:
            for path in (args.get_scanner, args.post_scanner):
                if not path.is_file():
                    raise ValueError(f"сканер не найден: {path}")
        if args.recon_cwd and not args.recon_cwd.is_dir():
            raise ValueError("--recon-cwd должен быть папкой")
        args.recon_argv = shlex.split(args.recon_cmd) if args.recon_cmd else []
        if args.recon_cmd and not args.recon_argv:
            raise ValueError("пустая --recon-cmd")
        if args.recon_cmd and not any("{domain}" in arg for arg in args.recon_argv):
            raise ValueError("--recon-cmd должна содержать {domain}")
        if args.recon_cmd and args.recon_output == "file" and not any("{output}" in arg for arg in args.recon_argv):
            raise ValueError("для --recon-output file требуется {output}")
        args.exclude_host = [normalize_domain(value) for value in args.exclude_host]
        args.ports = list(dict.fromkeys(int(value.strip()) for value in args.ports.split(",")))
        if not args.ports or any(not 1 <= port <= 65535 for port in args.ports):
            raise ValueError("--ports: нужны порты 1…65535")
        selected = list(dict.fromkeys(item.strip().lower() for item in args.modules.split(",") if item.strip()))
        if not selected or any(item not in MODULES for item in selected):
            raise ValueError("--modules: " + ",".join(SCANNER_MODULES))
        args.modules = ",".join(selected)
        args.oast_domain = validate_oast_domain(args.oast_domain, selected)
        if args.workers > 100 or args.rate > 10000 or args.http_timeout > 10000:
            raise ValueError("workers <= 100, rate/http-timeout <= 10000")
        validate_arguments(args)
        if args.max_records > 10000:
            raise ValueError("--max-records <= 10000 для совместимости со scanner.py")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return args


def main(argv: list[str] | None = None) -> int:
    args = arguments(argv)
    if sys.platform != "linux":
        print("Этот оркестратор рассчитан на Ubuntu/Linux.", file=sys.stderr)
        return 2
    os.umask(0o077)
    try:
        summary = asyncio.run(Pipeline(args).run())
    except Exception as exc:
        print(f"Ошибка файлов/среды: {type(exc).__name__}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    print(f"Готово: {summary['status']}; отчёты: {summary['directory']}")
    if summary["status"] == "interrupted":
        return 130
    return 0 if summary["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
