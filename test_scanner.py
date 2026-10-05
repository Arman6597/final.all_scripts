"""Интеграционные тесты: только локальный aiohttp-сайт и вымышленные ответы."""
import asyncio
from contextlib import redirect_stdout
import html
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from aiohttp import web

from scanner import arguments
from bbscanner.core import Context, HttpClient, normalize_url, origin, replace_parameter
from bbscanner.engine import run_scan

PASSWD = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'


class ScannerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='bb-scanner-test-')
        self.root = Path(self.temp.name)
        self.calls, self.active, self.peak = [], 0, 0
        self.runners = []
        self.base = await self.server()

    async def asyncTearDown(self):
        for runner in self.runners:
            await runner.cleanup()
        self.temp.cleanup()

    async def server(self):
        app = web.Application()
        app.router.add_get('/{tail:.*}', self.handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '127.0.0.1', 0)
        await site.start()
        self.runners.append(runner)
        return f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}'

    async def handler(self, request):
        self.calls.append({'path': request.path, 'raw_path': request.raw_path,
            'cookie': request.headers.get('Cookie'), 'agent': request.headers.get('User-Agent'),
            'host': request.host, 'time': time.monotonic()})
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            path = request.path
            value = request.query.get('q', request.query.get('file', ''))
            if path == '/raw':
                return web.Response(text=f'<html><input value="{value}"></html>', content_type='text/html')
            if path == '/escaped':
                return web.Response(text=f'<html>{html.escape(value)}</html>', content_type='text/html')
            if path == '/json':
                return web.json_response({'q': value})
            if path == '/linux':
                if value.endswith('/etc/passwd'):
                    return web.Response(text=PASSWD)
                if 'missing.txt' in value:
                    return web.Response(status=404, text='file not found')
                return web.Response(text='default')
            if path in ('/windows', '/windows-weak'):
                if value.endswith('/windows/win.ini'):
                    body = '[extensions]\n' + ('[fonts]\nfont=example\n' if path == '/windows' else '')
                    return web.Response(text=body)
                return web.Response(text='not a file')
            if path == '/static-passwd':
                return web.Response(text=PASSWD)
            if path == '/fake-passwd':
                return web.Response(text=PASSWD if '../' in value else 'OK')
            if path == '/redirect':
                dest = request.query.get('next', '/home')
                return web.Response(status=302, headers={'Location': dest})
            if path == '/wrapped-redirect':
                # Внешний адрес лежит внутри query; реальный hostname остаётся своим.
                return web.Response(status=302, headers={'Location': self.base + '/safe?next=' + request.query.get('next', '')})
            if path == '/static-redirect':
                return web.Response(status=302, headers={'Location': 'https://fixed.example.invalid/'})
            if path == '/discover':
                return web.Response(text='''<html>
<a href="/raw?q=hello">query</a><a href="http://[bad">broken</a>
<a href="https://outside.example.invalid/raw?q=hello">outside</a>
<form method="get" action="/linux"><input name="file" value="default"></form>
<form method="post" action="/post-only"><input name="q"></form>
</html>''', content_type='text/html')
            if path == '/error':
                return web.Response(status=500, text='temporary failure')
            if path == '/slow':
                await asyncio.sleep(.3)
                return web.Response(text='late')
            if path == '/broken':
                request.transport.close()
                return web.Response(text='not delivered')
            if path == '/delay':
                await asyncio.sleep(.05)
                return web.Response(text=f'<html>{value}</html>', content_type='text/html')
            if path == '/auth':
                if request.headers.get('Cookie') != 'session=test-only':
                    return web.Response(status=401, text='login required')
                return web.Response(text=f'<html>{value}</html>', content_type='text/html')
            if path == '/large':
                return web.Response(text='<html>' + 'x' * 5000 + value + '</html>', content_type='text/html')
            return web.Response(text='<html>No query inputs</html>', content_type='text/html')
        finally:
            self.active -= 1

    def args(self, paths, extra=()):
        values = []
        for path in paths:
            values.extend(['-u', path if path.startswith('http') else self.base + path])
        values += ['--output', str(self.root / 'output'), '--rate', '1000', '--no-color', *extra]
        return arguments(values)

    async def scan(self, paths, extra=()):
        args, roots, cookie_origin = self.args(paths, extra)
        args.output.mkdir(exist_ok=True)
        with redirect_stdout(io.StringIO()):
            summary = await run_scan(args, roots, cookie_origin)
        findings = json.loads((args.output / 'findings.json').read_text())
        return summary, findings, args.output

    async def test_01_raw_xss_is_candidate_not_execution_proof(self):
        summary, findings, folder = await self.scan(['/raw?q=hello'], ['--modules', 'xss'])
        self.assertEqual(summary['requests'], 3)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['status'], 'candidate')
        self.assertNotIn('<script', findings[0]['payload'])
        self.assertIn('Повторилось'.lower(), findings[0]['note'].lower())
        self.assertIn('[CANDIDATE] XSS GET', (folder / 'vulns_report.txt').read_text())

    async def test_02_escaped_and_json_reflections_not_xss(self):
        _, findings, _ = await self.scan(['/escaped?q=test', '/json?q=test'], ['--modules', 'xss'])
        self.assertEqual(findings, [])

    async def test_03_linux_signature_confirmed_with_negative_control(self):
        summary, findings, _ = await self.scan(['/linux?file=default'], ['--modules', 'lfi'])
        self.assertEqual(summary['status'], 'completed')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['status'], 'confirmed_signal')
        self.assertIn('root:x:0:0:', findings[0]['evidence'])
        self.assertTrue(any('missing.txt' in x['raw_path'] for x in self.calls))

    async def test_04_windows_strong_and_weak_markers(self):
        _, findings, _ = await self.scan(['/windows?file=default', '/windows-weak?file=default'], ['--modules', 'lfi'])
        states = {f['url'].split('?')[0].split('/')[-1]: f['status'] for f in findings}
        self.assertEqual(states, {'windows': 'confirmed_signal', 'windows-weak': 'candidate'})

    async def test_05_static_or_generic_file_text_is_not_confirmed(self):
        _, findings, _ = await self.scan(['/static-passwd?file=default', '/fake-passwd?file=default'], ['--modules', 'lfi'])
        self.assertEqual(findings, [])

    async def test_06_controlled_external_redirect_without_following(self):
        summary, findings, _ = await self.scan(['/redirect?next=/home'], ['--modules', 'redirect'])
        self.assertEqual(summary['requests'], 3)
        self.assertEqual(findings[0]['status'], 'confirmed_signal')
        self.assertIn('.example.invalid', findings[0]['evidence'])
        self.assertTrue(all(x['path'] == '/redirect' for x in self.calls))

    async def test_07_wrapped_and_static_redirects_are_not_findings(self):
        _, findings, _ = await self.scan(['/wrapped-redirect?next=/home', '/static-redirect?next=/home'], ['--modules', 'redirect'])
        self.assertEqual(findings, [])

    async def test_08_discovery_stays_in_origin_and_excludes_post_forms(self):
        summary, findings, folder = await self.scan(['/discover'], ['--modules', 'xss,lfi'])
        targets = json.loads((folder / 'targets.json').read_text())
        self.assertIn(self.base + '/raw?q=hello', targets)
        self.assertIn(self.base + '/linux?file=default', targets)
        self.assertTrue(all(x.startswith(self.base + '/') for x in targets))
        self.assertFalse(any(x['path'] == '/post-only' for x in self.calls))
        self.assertEqual({f['module'] for f in findings}, {'xss', 'lfi'})

    async def test_09_errors_do_not_cancel_other_targets(self):
        summary, findings, folder = await self.scan(['/error?q=x', '/slow?q=x', '/broken?q=x', '/raw?q=x'],
                                                   ['--modules', 'xss', '--timeout', '.08'])
        self.assertEqual(len(findings), 1)
        errors = json.loads((folder / 'errors.json').read_text())
        self.assertIn('timeout', {x['error'] for x in errors})
        self.assertIn('HTTP 500', {x['error'] for x in errors})
        self.assertEqual(summary['status'], 'completed_with_errors')

    async def test_10_query_order_duplicates_and_encoding_preserved(self):
        url = normalize_url('https://example.com/path?q=a%2Bb&sig=A%2fb%3d&q=second&blank=')
        mutated = replace_parameter(url, 2, 'x">')
        self.assertIn('q=a%2Bb&sig=A%2fb%3d&q=x%22%3E&blank=', mutated)
        _, findings, _ = await self.scan(['/raw?q=one&q=two'], ['--modules', 'xss'])
        self.assertEqual([f['parameter_index'] for f in findings], [0])

    async def test_11_cookies_bound_to_one_origin_and_not_logged(self):
        second = await self.server()
        summary, findings, folder = await self.scan(['/auth?q=x', second + '/auth?q=x'],
            ['--modules', 'xss', '--cookies', 'session=test-only', '--cookie-origin', self.base])
        for request in self.calls:
            expected = 'session=test-only' if request['host'] == self.base.split('://')[1] else None
            self.assertEqual(request['cookie'], expected)
        self.assertEqual(len(findings), 1)
        self.assertTrue(summary['settings']['authenticated'])
        self.assertNotIn('session=test-only', '\n'.join(x.read_text() for x in folder.iterdir()))

    async def test_12_cookies_multiorigin_needs_explicit_binding(self):
        second = await self.server()
        with patch('sys.stderr', io.StringIO()), self.assertRaises(SystemExit):
            self.args(['/auth?q=x', second + '/auth?q=x'], ['--cookies', 'session=test-only'])

    async def test_13_budget_exhaustion_keeps_candidate(self):
        summary, findings, _ = await self.scan(['/raw?q=x'], ['--modules', 'xss', '--max-requests', '2'])
        self.assertEqual(summary['requests'], 2)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(summary['status'], 'budget_exhausted')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['status'], 'candidate')

    async def test_14_concurrency_and_global_rate(self):
        await self.scan(['/delay?q=a', '/delay?q=b', '/delay?q=c'], ['--modules', 'xss', '--workers', '3', '--rate', '50'])
        self.assertGreaterEqual(self.peak, 2)
        starts = sorted(x['time'] for x in self.calls)
        self.assertGreaterEqual(starts[-1] - starts[0], (len(starts) - 1) / 50 - .025)

    async def test_15_truncated_baseline_is_inconclusive(self):
        summary, findings, _ = await self.scan(['/large?q=x'], ['--modules', 'xss', '--max-bytes', '1024'])
        self.assertEqual(summary['status'], 'inconclusive')
        self.assertEqual(findings, [])

    async def test_16_explicit_params_and_no_parameters_status(self):
        summary, findings, _ = await self.scan(['/raw'], ['--modules', 'xss', '--params', 'q', '--no-discovery'])
        self.assertEqual(len(findings), 1)
        args, roots, bound = self.args(['/'], ['--no-discovery', '--output', str(self.root / 'empty')])
        args.output.mkdir()
        with redirect_stdout(io.StringIO()):
            summary = await run_scan(args, roots, bound)
        self.assertEqual(summary['status'], 'no_testable_parameters')

    async def test_17_invalid_headers_and_numeric_args(self):
        for values in (['--workers', '0'], ['--rate', 'nan'], ['--timeout', '-5'], ['--cookies', 'a=1\r\nHost: other'], ['--modules', 'unknown']):
            with patch('sys.stderr', io.StringIO()), self.assertRaises(SystemExit):
                self.args(['/'], values)

    async def test_18_cli_cancellation_saves_partial_report(self):
        output = self.root / 'interrupted'
        command = [sys.executable, str(Path(__file__).with_name('scanner.py')), '-u', self.base + '/slow?q=x',
                   '--output', str(output), '--modules', 'xss', '--rate', '100']
        child = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE,
                                                     stderr=asyncio.subprocess.PIPE, env=os.environ.copy())
        deadline = time.monotonic() + 5
        while not self.calls and time.monotonic() < deadline:
            await asyncio.sleep(.01)
        self.assertTrue(self.calls)
        child.send_signal(signal.SIGINT)
        stdout, stderr = await asyncio.wait_for(child.communicate(), timeout=5)
        self.assertEqual(child.returncode, 130, stdout.decode() + stderr.decode())
        summary = json.loads((output / 'summary.json').read_text())
        self.assertEqual(summary['status'], 'interrupted')
        self.assertTrue((output / 'vulns_report.txt').exists())
        self.assertEqual((output / 'vulns_report.txt').stat().st_mode & 0o777, 0o600)

    async def test_19_connection_drop_does_not_bypass_request_budget(self):
        summary, _, _ = await self.scan(['/broken?q=x'], ['--modules', 'xss', '--max-requests', '1'])
        self.assertEqual(summary['requests'], 1)
        self.assertEqual(len(self.calls), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
