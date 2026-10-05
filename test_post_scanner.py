#!/usr/bin/env python3
import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs

from aiohttp import web

from post_scanner import load_args, PostScanner, write_reports


class PostScannerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.output = str(Path(self.temp.name) / 'results')
        self.calls = []
        self.app = web.Application()
        self.app.router.add_post("/xss", self.xss)
        self.app.router.add_post("/lfi", self.lfi)
        self.app.router.add_post("/redirect", self.redirect)
        self.app.router.add_post("/json", self.json_endpoint)
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await self.site.start()
        port = self.site._server.sockets[0].getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"

    async def asyncTearDown(self):
        await self.runner.cleanup()
        self.temp.cleanup()

    async def body_values(self, request):
        raw = await request.text()
        self.calls.append((request.path, request.headers.get("Content-Type", ""), raw))
        if "application/json" in request.headers.get("Content-Type", ""):
            return json.loads(raw)
        return {key: values[-1] for key, values in parse_qs(raw, keep_blank_values=True).items()}

    async def xss(self, request):
        values = await self.body_values(request)
        value = values.get("q", "")
        return web.Response(text=f"<html><body>echo:{value}</body></html>", content_type="text/html")

    async def lfi(self, request):
        values = await self.body_values(request)
        value = str(values.get("file", ""))
        if "etc/passwd" in value:
            return web.Response(text="root:x:0:0:root:/root:/bin/bash\n", content_type="text/plain")
        if "win.ini" in value:
            return web.Response(text="[extensions]\n[mci extensions]\n", content_type="text/plain")
        if "bb_missing" in value:
            return web.Response(status=404, text="missing")
        return web.Response(text="not found", content_type="text/plain")

    async def redirect(self, request):
        values = await self.body_values(request)
        value = str(values.get("next", ""))
        if value.startswith("https://bb-"):
            raise web.HTTPFound(location=value)
        return web.Response(text="ok")

    async def json_endpoint(self, request):
        values = await self.body_values(request)
        value = values.get("q", "")
        return web.Response(text=f"<html>{value}</html>", content_type="text/html")

    async def scanner(self, endpoint, body, *extra):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "results"
            args, targets, template, headers = load_args(
                ["-u", self.base + endpoint, "--body", body, "--output", str(output), *extra]
            )
            scanner = PostScanner(args, targets, template, headers)
            summary = await scanner.run()
            write_reports(output, scanner, summary)
            return summary, scanner, output

    async def test_form_xss_mutates_one_parameter(self):
        args, targets, template, headers = load_args(
            ["-u", self.base + "/xss", "--body", "q=hello&keep=original", "--modules", "xss", "--rate", "1000", '--output', self.output]
        )
        scanner = PostScanner(args, targets, template, headers)
        summary = await scanner.run()
        self.assertEqual(summary["findings"], 1)
        self.assertEqual(scanner.findings[0].confidence, "candidate")
        mutated = [parse_qs(raw, keep_blank_values=True) for path, _, raw in self.calls if path == "/xss"]
        self.assertTrue(any("idxss_" in item["q"][0] and item["keep"] == ["original"] for item in mutated))
        self.assertTrue(any(item["q"] == ["hello"] and "idxss_" in item["keep"][0] for item in mutated))

    async def test_json_xss_and_content_type(self):
        summary, scanner, _ = await self.scanner("/json", '{"q":"hello","nested":{"keep":true}}', "--json", "--modules", "xss")
        self.assertEqual(summary["findings"], 1)
        self.assertEqual(scanner.findings[0].mode, "json")
        self.assertTrue(all("application/json" in content_type for _, content_type, _ in self.calls))

    async def test_lfi_repeat_and_negative_control(self):
        summary, scanner, _ = await self.scanner("/lfi", "file=default", "--modules", "lfi")
        self.assertEqual(summary["findings"], 2)
        self.assertTrue(all(item.confidence == "confirmed" for item in scanner.findings))
        self.assertGreaterEqual(summary["requests"], 7)

    async def test_open_redirect_does_not_follow_external_location(self):
        summary, scanner, _ = await self.scanner("/redirect", "next=/home&name=alice", "--modules", "redirect")
        self.assertEqual(summary["findings"], 1)
        self.assertEqual(scanner.findings[0].confidence, "confirmed")
        self.assertTrue(all(not path.startswith("https://bb-") for path, _, _ in self.calls))

    async def test_max_requests_and_custom_headers(self):
        args, targets, template, headers = load_args(
            ["-u", self.base + "/xss", "--body", "q=hello", "--modules", "xss", "--headers", "Authorization: Bearer test", "--max-requests", "1", '--output', self.output]
        )
        scanner = PostScanner(args, targets, template, headers)
        summary = await scanner.run()
        self.assertEqual(summary["requests"], 1)
        self.assertEqual(summary["status"], "budget_exhausted")
        self.assertEqual(len(scanner.findings), 0)

    def test_invalid_json_and_url(self):
        with self.assertRaises(SystemExit):
            load_args(["-u", "https://example.com", "--body", "{bad", "--json"])
        with self.assertRaises(SystemExit):
            load_args(["-u", "ftp://example.com", "--body", "q=x"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
