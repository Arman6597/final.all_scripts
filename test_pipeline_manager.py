#!/usr/bin/env python3
"""Проверки конвейера на фиктивных subprocess; HTTP-запросы не отправляются."""
from __future__ import annotations

import asyncio
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import shlex
import signal
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from pipeline_manager import (
    FilteredData, Pipeline, PostRequest, ProcessResult, ProcessRunner, Scope, arguments,
    filter_records, normalize_domain, normalize_url,
)


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def records(self, values, scope=None):
        path = self.root / "records.jsonl"
        path.write_text("\n".join(json.dumps(value) if isinstance(value, dict) else value for value in values), encoding="utf-8")
        return filter_records([path], scope or Scope("example.test"), 100, 100000)

    def test_domain_and_url_validation(self):
        self.assertEqual(normalize_domain("EXAMPLE.test."), "example.test")
        self.assertTrue(normalize_domain("пример.рф").startswith("xn--"))
        for value in ("https://example.test", "*.example.test", "127.0.0.1", "bad..test", "-bad.test", "example.test;touch /tmp/x"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_domain(value)
        self.assertEqual(normalize_url("https://EXAMPLE.test:443/path?q=A%2fb#part"), "https://example.test/path?q=A%2fb")
        for value in ("ftp://example.test/", "https://alice:secret@example.test/", "https://example.test:99999/", "https://example.test/\r\nother"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_url(value)

    def test_query_encoding_order_and_duplicate_keys_are_preserved(self):
        first = "https://example.test/path?q=A%2fb&q=two&sig=%3d"
        second = "https://example.test/path?sig=%3d&q=A%2fb&q=two"
        data = self.records([first, first, second, "https://example.test/without_query"])
        self.assertEqual(data.get_urls, [first, second])
        self.assertEqual(data.counts["duplicates"], 1)
        self.assertEqual(data.counts["no_get_parameters"], 1)

    def test_scope_boundary_subdomains_exclusions_and_ports(self):
        records = [
            "https://example.test/?q=1", "https://api.example.test/?q=1",
            "https://evil-example.test/?q=1", "https://example.test.evil.test/?q=1",
            "https://private.example.test/?q=1", "https://example.test:8443/?q=1",
        ]
        self.assertEqual(len(self.records(records).get_urls), 1)
        scope = Scope("example.test", True, ("private.example.test",), (80, 443, 8443))
        self.assertEqual(len(self.records(records, scope).get_urls), 3)

    def test_post_requires_explicit_method_body_and_supported_format(self):
        records = [
            {"method": "POST", "url": "https://example.test/form", "body": "q=one&q=two&keep=A%2fb"},
            {"method": "POST", "url": "https://example.test/json", "content_type": "application/json", "body": {"q": "x", "keep": [1, True]}},
            {"method": "POST", "url": "https://example.test/missing"},
            {"method": "POST", "url": "https://example.test/bad", "content_type": "application/json", "body": "{bad"},
            {"method": "DELETE", "url": "https://example.test/delete"},
            "https://example.test/looks-like-post?q=x",
        ]
        data = self.records(records)
        self.assertEqual(len(data.post_requests), 2)
        self.assertEqual(data.post_requests[0].body, "q=one&q=two&keep=A%2fb")
        self.assertTrue(data.post_requests[1].json_mode)
        self.assertEqual(data.counts["missing_post_body"], 1)
        self.assertEqual(data.counts["invalid"], 1)
        self.assertEqual(data.counts["unsupported_method"], 1)
        self.assertEqual(len(data.get_urls), 1)

    def test_post_dedup_uses_body_and_does_not_import_credentials(self):
        first = {"method": "POST", "url": "https://example.test/form", "body": "q=one"}
        second = {**first, "body": "q=two"}
        data = self.records([first, first, second, {**first, "headers": {"Authorization": "test-only"}}])
        self.assertEqual(len(data.post_requests), 2)
        self.assertEqual(data.counts["duplicates"], 1)
        self.assertEqual(data.counts["invalid"], 1)

    def test_duplicate_json_keys_are_rejected(self):
        data = self.records([
            '{"method":"POST","url":"https://example.test/","body":"q=a","body":"q=b"}',
            {"method": "POST", "url": "https://example.test/", "content_type": "application/json",
             "body": '{"q":1,"q":2}'},
        ])
        self.assertEqual(data.post_requests, [])
        self.assertEqual(data.counts['invalid'], 2)


class ProcessTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.stop = asyncio.Event()
        self.runner = ProcessRunner(self.stop, grace=.15, max_log_bytes=1024)

    async def asyncTearDown(self):
        self.temporary.cleanup()

    async def test_exit_codes_and_separate_logs(self):
        result = await self.runner.run([sys.executable, "-c", "import sys; print('out'); print('err',file=sys.stderr);sys.exit(7)"], "mock", self.root / "log", 3)
        self.assertEqual(result.state, "nonzero")
        self.assertEqual(result.returncode, 7)
        self.assertEqual(Path(result.stdout).read_text().strip(), "out")
        self.assertEqual(Path(result.stderr).read_text().strip(), "err")

    async def test_timeout_kills_group_including_ignoring_descendant(self):
        pid_file = self.root / "descendant.pid"
        descendant = "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"
        code = (
            "import subprocess,sys,signal,time;from pathlib import Path;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            f"child=subprocess.Popen([sys.executable,'-c',{descendant!r}]);"
            f"Path({str(pid_file)!r}).write_text(str(child.pid));time.sleep(60)"
        )
        result = await self.runner.run([sys.executable, "-c", code], "hang", self.root / "timeout", .4)
        self.assertEqual(result.state, "timeout")
        self.assertLess(result.seconds, 2)
        child_pid = int(pid_file.read_text())
        status = Path(f"/proc/{child_pid}/stat")
        if status.exists():
            self.assertEqual(status.read_text().split(") ", 1)[1].split()[0], "Z")

    async def test_bounded_output_and_spawn_error(self):
        result = await self.runner.run([sys.executable, "-c", "print('x'*10000)"], "noise", self.root / "noise", 3)
        self.assertEqual(result.state, "output_limit")
        self.assertEqual(Path(result.stdout).stat().st_size, 1024)
        result = await self.runner.run([str(self.root / "not-an-executable")], "missing", self.root / "missing", 3)
        self.assertEqual(result.state, "spawn_error")

    async def test_cancellation_and_literal_arguments(self):
        literal = "$(touch do-not-create); echo unsafe"
        result = await self.runner.run([sys.executable, "-c", "import sys;print(sys.argv[1])", literal], "literal", self.root / "literal", 3, cwd=self.root)
        self.assertEqual(Path(result.stdout).read_text().strip(), literal)
        self.assertFalse((self.root / "do-not-create").exists())
        task = asyncio.create_task(self.runner.run([sys.executable, "-c", "import time;time.sleep(60)"], "stop", self.root / "stop", 30))
        await asyncio.sleep(.1)
        self.stop.set()
        result = await asyncio.wait_for(task, 2)
        self.assertEqual(result.state, "interrupted")


class PipelineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pipeline test ")
        self.root = Path(self.temporary.name)
        self.targets = self.root / "targets.txt"
        self.targets.write_text("example.test\n", encoding="utf-8")
        self.timeline = self.root / "timeline.jsonl"
        self.recon = self.root / "recon.py"
        self.recon.write_text(
            "import json,sys\n"
            "domain=sys.argv[1]\n"
            "if domain.startswith('broken'): sys.exit(9)\n"
            "print('https://'+domain+'/get?q=original&sig=A%2fb')\n"
            "print('https://'+domain+'/get?q=original&sig=A%2fb')\n"
            "print('https://outside.test/path?q=out')\n"
            "print(json.dumps({'method':'POST','url':'https://'+domain+'/post','content_type':'application/json','body':{'q':'original','keep':True},'params':['q']}))\n",
            encoding="utf-8",
        )
        self.scanner = self.root / "scanner.py"
        self.scanner.write_text(
            "import argparse,json,time,sys\nfrom pathlib import Path\n"
            "p=argparse.ArgumentParser()\n"
            "p.add_argument('-l');p.add_argument('-u');p.add_argument('--body-file');p.add_argument('--output');p.add_argument('--rate');p.add_argument('--max-requests');p.add_argument('--workers');p.add_argument('--concurrency');p.add_argument('--params');p.add_argument('--json',action='store_true')\n"
            "a,_=p.parse_known_args();kind='get' if a.l else 'post'\n"
            f"timeline=Path({str(self.timeline)!r})\n"
            "def event(phase):\n"
            " with timeline.open('a') as stream:stream.write(json.dumps({'kind':kind,'phase':phase,'time':time.monotonic()})+'\\n')\n"
            "event('start');time.sleep(.2)\n"
            "o=Path(a.output);o.mkdir(parents=True,exist_ok=True)\n"
            "details={'status':'completed','mode':kind,'rate':float(a.rate),'budget':int(a.max_requests),'workers':int(a.workers or a.concurrency),'params':a.params}\n"
            "if a.l:details['urls']=Path(a.l).read_text().splitlines()\n"
            "else:details.update(url=a.u,body=Path(a.body_file).read_text(),json=a.json)\n"
            "(o/'summary.json').write_text(json.dumps(details))\n"
            "event('end');print(kind)\n"
            f"if kind=='get' and Path({str(self.root / 'fail_get')!r}).exists():sys.exit(8)\n",
            encoding="utf-8",
        )

    async def asyncTearDown(self):
        self.temporary.cleanup()

    def args(self, *extra):
        command = shlex.join([sys.executable, str(self.recon), "{domain}"])
        return arguments([
            "--targets", str(self.targets), "--recon-cmd", command,
            "--get-scanner", str(self.scanner), "--post-scanner", str(self.scanner),
            "--output", str(self.root / "runs"), "--error-log", str(self.root / "errors.log"),
            "--recon-timeout", "5", "--scanner-timeout", "5", "--kill-grace", ".2", *extra,
        ])

    async def run_pipeline(self, *extra):
        pipeline = Pipeline(self.args(*extra))
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            summary = await pipeline.run()
        return summary, Path(summary["directory"])

    def events(self):
        return [json.loads(line) for line in self.timeline.read_text().splitlines()]

    async def test_serial_transfers_data_preserves_post_body_and_budgets(self):
        summary, run = await self.run_pipeline("--mode", "serial", "--max-requests", "20")
        entry = summary["targets"][0]
        self.assertEqual(summary["status"], "completed")
        self.assertEqual((entry["get_urls"], entry["post_requests"]), (1, 1))
        events = self.events()
        self.assertEqual([(event["kind"], event["phase"]) for event in events], [("get", "start"), ("get", "end"), ("post", "start"), ("post", "end")])
        get = json.loads((run / "example.test/get_results/summary.json").read_text())
        post = json.loads((run / "example.test/post_jobs/0001/results/summary.json").read_text())
        self.assertEqual(get["urls"], ["https://example.test/get?q=original&sig=A%2fb"])
        self.assertEqual(json.loads(post["body"]), {"q": "original", "keep": True})
        self.assertEqual(post["params"], "q")
        self.assertTrue(post["json"])
        self.assertEqual(get["budget"] + post["budget"], 20)

    async def test_parallel_overlaps_and_splits_rate_workers(self):
        summary, run = await self.run_pipeline("--mode", "parallel", "--rate", "6", "--workers", "8")
        events = self.events()
        self.assertEqual([event["phase"] for event in events[:2]], ["start", "start"])
        self.assertEqual({event["kind"] for event in events[:2]}, {"get", "post"})
        get = json.loads((run / "example.test/get_results/summary.json").read_text())
        post = json.loads((run / "example.test/post_jobs/0001/results/summary.json").read_text())
        self.assertEqual(get["rate"] + post["rate"], 6)
        self.assertEqual(get["workers"] + post["workers"], 8)
        self.assertEqual(summary["status"], "completed")

    async def test_get_crash_does_not_block_post_or_next_target(self):
        (self.root / "fail_get").write_text("yes")
        self.targets.write_text("example.test\nsecond.test\n")
        summary, _ = await self.run_pipeline()
        self.assertEqual(summary["status"], "completed_with_errors")
        self.assertEqual(len(summary["targets"]), 2)
        for entry in summary["targets"]:
            self.assertEqual(entry["get"][0]["state"], "nonzero")
            self.assertEqual(entry["post"][0]["state"], "ok")
        errors = [json.loads(line) for line in (self.root / "errors.log").read_text().splitlines()]
        self.assertTrue(any(item["reason"] == "nonzero" for item in errors))

    async def test_recon_crash_continues_next_root(self):
        self.targets.write_text("broken.test\nexample.test\n")
        summary, _ = await self.run_pipeline()
        self.assertEqual(summary["targets"][0]["status"], "recon_failed")
        self.assertEqual(summary["targets"][1]["status"], "finished")

    async def test_serial_branch_exception_does_not_block_post(self):
        with patch.object(Pipeline, 'get_scan', new=AsyncMock(side_effect=RuntimeError('test'))):
            summary, _ = await self.run_pipeline('--mode', 'serial')
        entry = summary['targets'][0]
        self.assertEqual(entry['get'][0]['state'], 'exception')
        self.assertEqual(entry['post'][0]['state'], 'ok')
        self.assertEqual(summary['status'], 'completed_with_errors')

    async def test_dry_run_does_not_require_scanner_budget(self):
        summary, run = await self.run_pipeline('--dry-run', '--mode', 'parallel',
                                               '--workers', '1', '--max-requests', '1')
        self.assertEqual(summary['targets'][0]['status'], 'prepared_only')
        self.assertTrue((run / 'example.test/post_requests.jsonl').is_file())
        self.assertFalse(self.timeline.exists())

    async def test_invalid_scanner_status_is_logged_without_losing_branch(self):
        original = self.scanner.read_text()
        for state in (['invalid'], 'unknown'):
            self.scanner.write_text(original.replace("'status':'completed'", f"'status':{state!r}"))
            summary, _ = await self.run_pipeline()
            entry = summary['targets'][0]
            self.assertEqual(entry['get'][0]['state'], 'ok')
            self.assertEqual(entry['post'][0]['state'], 'ok')
            self.assertEqual(summary['status'], 'completed_with_errors')
        errors = [json.loads(line) for line in (self.root / 'errors.log').read_text().splitlines()]
        self.assertEqual(sum(item['reason'] == 'invalid_scanner_summary' for item in errors), 4)

    async def test_cached_dry_run_and_invalid_targets_do_not_spawn_scanners(self):
        self.targets.write_text("https://bad.test\nEXAMPLE.test\nexample.test\n")
        cached = self.root / "cached.txt"
        cached.write_text("https://example.test/?id=7\n")
        args = self.args("--dry-run")
        args.recon_input, args.recon_cmd, args.recon_argv = cached, None, []
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            summary = await Pipeline(args).run()
        self.assertEqual(len(summary["targets"]), 1)
        self.assertEqual(summary["targets"][0]["status"], "prepared_only")
        self.assertFalse(self.timeline.exists())

    async def test_recon_file_channel_uses_file_instead_of_stdout(self):
        self.recon.write_text(
            "import sys\nfrom pathlib import Path\n"
            "Path(sys.argv[2]).write_text('https://'+sys.argv[1]+'/?id=2\\n')\n"
            "print('diagnostics must not become a URL')\n"
        )
        args = self.args()
        args.recon_output = "file"
        args.recon_argv = [sys.executable, str(self.recon), "{domain}", "{output}"]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            summary = await Pipeline(args).run()
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(summary["targets"][0]["filter"]["invalid"], 0)
        self.assertEqual(summary["targets"][0]["get_urls"], 1)

    async def test_multiple_post_bodies_get_separate_jobs_and_shared_budget(self):
        extra = self.root / "post.jsonl"
        extra.write_text(json.dumps({"method": "POST", "url": "https://example.test/post", "body": "q=different&keep=x"}) + "\n")
        summary, run = await self.run_pipeline("--post-input", str(extra), "--max-requests", "20", "--rate", "100")
        self.assertEqual(summary["targets"][0]["post_requests"], 2)
        first = json.loads((run / "example.test/post_jobs/0001/results/summary.json").read_text())
        second = json.loads((run / "example.test/post_jobs/0002/results/summary.json").read_text())
        get = json.loads((run / "example.test/get_results/summary.json").read_text())
        self.assertNotEqual(first["body"], second["body"])
        self.assertEqual(first["budget"] + second["budget"] + get["budget"], 20)

    async def test_zero_exit_without_scanner_summary_is_reported(self):
        self.scanner.write_text("print('exit 0 without report')\n")
        summary, _ = await self.run_pipeline()
        self.assertEqual(summary["status"], "completed_with_errors")
        errors = [json.loads(line) for line in (self.root / "errors.log").read_text().splitlines()]
        self.assertTrue(any(item["reason"] == "missing_scanner_summary" for item in errors))

    async def test_real_get_and_post_argument_interfaces(self):
        try:
            from scanner import arguments as get_arguments
            from post_scanner import load_args as post_arguments
        except ImportError as exc:
            self.skipTest(f"зависимости сканеров не установлены: {exc.name}")
        args = self.args('--modules', 'sqli,ssrf,ssti,crlf', '--oast-domain', 'callback.example')
        pipeline = Pipeline(args)
        folder = self.root / "compatibility"
        folder.mkdir()
        (folder / "get_urls.txt").write_text("https://example.test/?q=x\n")
        data = FilteredData(
            get_urls=["https://example.test/?q=x"],
            post_requests=[PostRequest("https://example.test/post", '{"q":"x","keep":1}', True, ("q",))],
        )
        parsed = []

        async def capture(_domain, argv, stage, _logs, _timeout, output=None, cwd=None):
            if stage == "get":
                actual, roots, _bound = get_arguments(argv[2:])
                self.assertEqual(roots, data.get_urls)
                self.assertTrue(actual.no_discovery)
            else:
                actual, targets, template, _headers = post_arguments(argv[2:])
                self.assertEqual(targets, [data.post_requests[0].url])
                self.assertEqual(template.raw, data.post_requests[0].body)
                self.assertTrue(template.json_mode)
                self.assertEqual(actual.params, ["q"])
            self.assertEqual(actual.output, output)
            self.assertEqual(actual.modules, ['sqli', 'ssrf', 'ssti', 'crlf'])
            self.assertEqual(actual.oast_domain, 'callback.example')
            parsed.append(stage)
            return ProcessResult(stage, "ok", returncode=0)

        pipeline.execute = capture
        await pipeline.get_scan("example.test", folder, data, 2.5, 5, 50)
        await pipeline.post_scan("example.test", folder, data, 2.5, 5, 50)
        self.assertEqual(parsed, ["get", "post_0001"])

    async def test_cli_sigint_saves_partial_and_stops_subprocess(self):
        slow = self.root / "slow.py"
        marker = self.root / "started"
        slow.write_text(f"import time\nfrom pathlib import Path\nPath({str(marker)!r}).write_text('yes')\ntime.sleep(60)\n")
        script = Path(__file__).with_name("pipeline_manager.py")
        command = [sys.executable, str(script), "--targets", str(self.targets),
                   "--recon-cmd", shlex.join([sys.executable, str(slow), "{domain}"]),
                   "--get-scanner", str(self.scanner), "--post-scanner", str(self.scanner),
                   "--output", str(self.root / "runs"), "--error-log", str(self.root / "errors.log"), "--kill-grace", ".2"]
        child = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        deadline = asyncio.get_running_loop().time() + 5
        while not marker.exists() and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(.02)
        self.assertTrue(marker.exists())
        child.send_signal(signal.SIGINT)
        stdout, stderr = await asyncio.wait_for(child.communicate(), 5)
        self.assertEqual(child.returncode, 130, stdout.decode() + stderr.decode())
        paths = list((self.root / "runs").glob("*/pipeline_summary.json"))
        self.assertEqual(len(paths), 1)
        self.assertEqual(json.loads(paths[0].read_text())["status"], "interrupted")
        self.assertEqual(paths[0].stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
