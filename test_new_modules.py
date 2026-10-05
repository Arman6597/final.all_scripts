"""Локальные тесты новых модулей; внешние домены и OAST-сервисы не используются."""
import asyncio
import json
import re
from pathlib import Path
import tempfile
import unittest
from urllib.parse import parse_qs

from aiohttp import web

from scanner import arguments
from bbscanner.engine import run_scan
from post_scanner import PostScanner, load_args


class NewModuleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        app = web.Application()
        app.router.add_get("/{tail:.*}", self.get_handler)
        app.router.add_post("/{tail:.*}", self.post_handler)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await self.site.start()
        port = self.site._server.sockets[0].getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"

    async def asyncTearDown(self):
        await self.runner.cleanup()

    @staticmethod
    def result_for(value: str) -> str:
        match = re.search(r"(\d+)\*(\d+)", value)
        return str(int(match.group(1)) * int(match.group(2))) if match else "ok"

    async def get_handler(self, request):
        value = request.query.get("q", "")
        if request.path == "/sqli" and any(char in value for char in "'\")"):
            return web.Response(status=500, text="You have an error in your SQL syntax")
        if request.path == "/ssti":
            return web.Response(text=self.result_for(value), content_type="text/html")
        if request.path == "/crlf" and "X-CRLF-Scan" in value:
            return web.Response(text="ok", headers={"X-CRLF-Scan": "True"})
        return web.Response(text="ok", content_type="text/html")

    async def post_handler(self, request):
        raw = await request.text()
        values = parse_qs(raw, keep_blank_values=True)
        value = values.get("q", [""])[0]
        if request.path == "/sqli" and any(char in value for char in "'\")"):
            return web.Response(status=500, text="pg_query(): query error")
        if request.path == "/ssti":
            return web.Response(text=self.result_for(value), content_type="text/html")
        if request.path == "/crlf" and "X-CRLF-Scan" in value:
            return web.Response(text="ok", headers={"X-CRLF-Scan": "True"})
        return web.Response(text="ok", content_type="text/html")

    async def test_get_error_based_and_baseline_guard(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / "get"
            out.mkdir()
            args, roots, _ = arguments(["-u", self.base + "/sqli?q=ok", "--modules", "sqli",
                                        "--output", str(out), "--rate", "1000"])
            summary = await run_scan(args, roots, None)
            self.assertEqual(summary["candidates"], 1)
            self.assertEqual(summary["oast_probes_pending"], 0)

    async def test_get_ssti_and_crlf(self):
        with tempfile.TemporaryDirectory() as folder:
            for path, module in (("/ssti?q=ok", "ssti"), ("/crlf?q=ok", "crlf")):
                out = Path(folder) / module
                out.mkdir()
                args, roots, _ = arguments(["-u", self.base + path, "--modules", module,
                                            "--output", str(out), "--rate", "1000"])
                summary = await run_scan(args, roots, None)
                self.assertEqual(summary["findings"], 1, module)

    async def test_post_sqli_ssti_crlf_and_oast_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            for path, module in (("/sqli", "sqli"), ("/ssti", "ssti"), ("/crlf", "crlf")):
                out = Path(folder) / module
                args, targets, body, headers = load_args(["-u", self.base + path, "--body", "q=ok",
                    "--modules", module, "--output", str(out), "--rate", "1000"])
                scanner = PostScanner(args, targets, body, headers)
                summary = await scanner.run()
                self.assertEqual(summary["findings"], 1, module)

        with self.assertRaises(SystemExit):
            arguments(["-u", self.base + "/?q=x", "--modules", "ssrf"])

    async def test_get_and_post_ssrf_are_logged_as_pending(self):
        with tempfile.TemporaryDirectory() as folder:
            get_out = Path(folder) / "get-ssrf"
            get_out.mkdir()
            args, roots, _ = arguments(["-u", self.base + "/fetch?q=x", "--modules", "ssrf",
                "--oast-domain", "oast.example.org", "--output", str(get_out), "--rate", "1000"])
            summary = await run_scan(args, roots, None)
            self.assertEqual(summary["oast_probes_pending"], 1)
            self.assertEqual(len((get_out / "oast_probes.jsonl").read_text().splitlines()), 2)

            post_out = Path(folder) / "post-ssrf"
            args, targets, body, headers = load_args(["-u", self.base + "/fetch", "--body", "url=x",
                "--modules", "ssrf", "--oast-domain", "oast.example.org",
                "--output", str(post_out), "--rate", "1000"])
            scanner = PostScanner(args, targets, body, headers)
            post_summary = await scanner.run()
            self.assertEqual(post_summary["oast_probes_pending"], 1)
            records = (post_out / "oast_probes.jsonl").read_text().splitlines()
            self.assertEqual(len(records), 2)
            self.assertTrue(all("oast.example.org" in line for line in records))


if __name__ == "__main__":
    unittest.main(verbosity=2)
