"""Регрессии ревью v1.2. Только localhost, фиктивные ответы и тестовые токены."""
import asyncio
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import re
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from aiohttp import web

from bbscanner.checks.ssti import contains_number
from bbscanner.core import replace_parameter
from bbscanner.engine import run_scan
from bbscanner.probes import log_line, strict_json, validate_oast_domain
from bbscanner.runtime import bounded
from post_scanner import (PostScanner, filter_fields, load_args, normalize_url,
                          parse_body, parse_headers, write_reports)
from scanner import arguments


class InputRegressions(unittest.TestCase):
    def test_crlf_keeps_other_form_bytes_and_duplicate_fields(self):
        raw = 'q=one&&q=two&keep=%2526&space=a%20b&flag&literal=%25'
        template = parse_body(raw, False)
        changed = template.mutate(template.fields[1], '%0d%0aX-CRLF-Scan:+True', preserve_percent=True)
        self.assertEqual(changed.split('&')[:2], raw.split('&')[:2])
        self.assertEqual(changed.split('&')[3:], raw.split('&')[3:])
        self.assertEqual(parse_qs(changed)['keep'], ['%26'])
        self.assertIn('\r\nX-CRLF-Scan', parse_qs(changed)['q'][1])

    def test_json_mutation_preserves_siblings_and_supports_pointer(self):
        raw = '{"q":"x","nested":{"a/b":[0,true,null]},"a.b":"other"}'
        template = parse_body(raw, True)
        selected = filter_fields(template.fields, {'/nested/a~1b/1'}, 20)
        self.assertEqual(len(selected), 1)
        value = json.loads(template.mutate(selected[0], "probe"))
        self.assertEqual(value, {'q': 'x', 'nested': {'a/b': [0, 'probe', None]}, 'a.b': 'other'})
        self.assertTrue(parse_body('{"":"value"}', True).fields)

    def test_ambiguous_or_nonfinite_json_is_rejected(self):
        for raw in ('{"q":1,"q":2}', '{"q":NaN}', '{"q":Infinity}', '{"q":1e999}', '{"q":"\\ud800"}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                strict_json(raw)

    def test_ipv6_and_invalid_hosts(self):
        self.assertEqual(normalize_url('http://[::1]:8080/?q=A%2fb'), 'http://[::1]:8080/?q=A%2fb')
        for value in ('https://bad..example/', 'https://-bad.example/', 'https://example.org/\x7f', 'https://user:pass@example.org/'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_url(value)

    def test_case_insensitive_headers_and_controls(self):
        self.assertEqual(parse_headers(['content-type: application/json', 'Content-Type: text/plain']),
                         {'content-type': 'text/plain'})
        for header in ('X-Test: a\n', 'X-Test: \rvalue', 'HoSt: wrong.example'):
            with self.subTest(header=header), self.assertRaises(ValueError):
                parse_headers([header])

    def test_numbers_are_isolated_and_sign_matters(self):
        for text in ('1490', '-49', '49.0', '.49', 'abc49', '49def'):
            self.assertFalse(contains_number(text, 49), text)
        self.assertTrue(contains_number('<p>49</p>', 49))
        self.assertTrue(contains_number('-49', -49))

    def test_oast_domain_length_and_format(self):
        self.assertEqual(validate_oast_domain('OAST.Example.', ['ssrf']), 'oast.example')
        for value in (None, 'https://oast.example', 'a..example', '127.0.0.1', 'oast.example:443', '*.example'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_oast_domain(value, ['ssrf'])
        self.assertIsNone(validate_oast_domain(None, ['xss']))

    def test_get_mutation_preserves_query_bytes(self):
        source = 'https://example.org/?q=a&q=b&sig=A%2fb&percent=%2526'
        changed = replace_parameter(source, 1, '%0d%0aX-CRLF-Scan:+True', preserve_percent=True)
        self.assertEqual(urlsplit(changed).query.split('&')[2:], urlsplit(source).query.split('&')[2:])

    def test_logs_escape_control_characters_but_keep_russian_readable(self):
        value = log_line('candidate', 'crlf', 'POST', 'https://example.org/', 'q',
                         '\r\nX-Test: 1', 'Проверка\x1b[31m\u202e\u2028')
        self.assertIn('Проверка', value)
        self.assertIn(r'\r\nX-Test', value)
        self.assertIn(r'\u202e', value)
        self.assertEqual(len(value.splitlines()), 1)
        self.assertNotIn('\x1b', value)


class NetworkRegressions(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.calls = []
        self.active = self.peak = 0
        self.serial = 0
        self.probe_seen = asyncio.Event()
        app = web.Application()
        app.router.add_route('*', '/{tail:.*}', self.handler)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, '127.0.0.1', 0)
        await site.start()
        self.base = f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}'

    async def asyncTearDown(self):
        await self.runner.cleanup()
        self.temp.cleanup()

    async def handler(self, request):
        raw = await request.text()
        if request.method == 'GET':
            values = dict(request.query)
        elif request.content_type == 'application/json':
            values = json.loads(raw)
        else:
            values = {key: value[-1] for key, value in parse_qs(raw, keep_blank_values=True).items()}
        value = str(values.get('q', values.get('file', values.get('next', ''))))
        self.calls.append({'method': request.method, 'values': values, 'raw': raw, 'raw_path': request.raw_path,
                           'path': request.path, 'headers': dict(request.headers), 'time': time.monotonic()})
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            if request.path == '/sql-baseline':
                return web.Response(status=500, text='You have an error in your SQL syntax')
            if request.path == '/sql':
                return web.Response(status=500, text='pg_query(): query error') if value != 'ok' else web.Response(text='ok')
            if request.path == '/ssti-baseline':
                return web.Response(text='49')
            if request.path in ('/ssti', '/ssti-minus'):
                match = re.fullmatch(r'<%=- (\d+)\*(\d+) %>' if request.path.endswith('minus')
                                    else r'\{\{(\d+)\*(\d+)\}\}', value)
                answer = int(match[1]) * int(match[2]) if match else None
                if answer is not None and request.path.endswith('minus'):
                    answer = -answer
                return web.Response(text=str(answer) if answer is not None else 'ok')
            if request.path == '/crlf-baseline':
                return web.Response(text='ok', headers={'x-cRlF-sCaN': 'static'})
            if request.path == '/crlf-body':
                return web.Response(text=value)
            if request.path in ('/crlf', '/crlf-large'):
                match = re.search(r'\r\nX-CRLF-Scan:\s*([^\r\n]+)', value)
                return web.Response(text='x' * (3000 if request.path.endswith('large') else 1),
                    headers={'x-cRlF-sCaN': match[1]} if match else {})
            if request.path == '/weak-ini':
                return web.Response(text='[extensions]' if 'win.ini' in value else 'ok')
            if request.path == '/stream-sql':
                response = web.StreamResponse(status=500 if value != 'ok' else 200,
                                               headers={'Content-Type': 'text/plain; charset=unknown-test'})
                await response.prepare(request)
                await response.write(b'begin ')
                await asyncio.sleep(.005)
                await response.write(b'unclosed quotation mark' if value != 'ok' else b'end')
                await response.write_eof()
                return response
            if request.path in ('/slow', '/slow-probe'):
                if request.path == '/slow' or value != 'ok':
                    self.probe_seen.set()
                    await asyncio.sleep(.15)
            if request.path == '/concurrency':
                await asyncio.sleep(.03)
            return web.Response(text='<html>' + value + '</html>', content_type='text/html')
        finally:
            self.active -= 1

    async def scan(self, path, module, mode='GET', body=None, extra=()):
        self.serial += 1
        output = self.root / str(self.serial)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            if mode == 'GET':
                output.mkdir()
                args, urls, cookie = arguments(['-u', self.base + path + '?q=ok', '--modules', module,
                    '--rate', '1000', '--output', str(output), '--no-discovery', *extra])
                summary = await run_scan(args, urls, cookie)
                findings = json.loads((output / 'findings.json').read_text())
            else:
                original = body or ('{"q":"ok","keep":[1,true,null]}' if mode == 'JSON' else 'q=ok&keep=%2526&space=a%20b')
                args, urls, template, headers = load_args(['-u', self.base + path, '--body', original,
                    '--modules', module, '--rate', '1000', '--output', str(output), '--params', 'q',
                    *(['--json'] if mode == 'JSON' else []), *extra])
                scanner = PostScanner(args, urls, template, headers)
                summary = await scanner.run()
                write_reports(output, scanner, summary)
                findings = json.loads((output / 'findings.json').read_text())
        return summary, findings, output

    async def test_baseline_sql_number_and_header_never_become_findings(self):
        for mode in ('GET', 'POST', 'JSON'):
            for path, module in (('/sql-baseline', 'sqli'), ('/ssti-baseline', 'ssti'), ('/crlf-baseline', 'crlf')):
                with self.subTest(mode=mode, module=module):
                    summary, findings, _ = await self.scan(path, module, mode)
                    self.assertEqual(findings, [])

    async def test_json_sql_500_is_detected_and_neighbors_preserved(self):
        summary, findings, _ = await self.scan('/sql', 'sqli', 'JSON')
        self.assertEqual(summary['candidates'], 1)
        self.assertTrue(all(call['values']['keep'] == [1, True, None] for call in self.calls))
        self.assertEqual(findings[0]['status'], 500)

    async def test_post_confirmed_counts_and_incremental_report(self):
        for module in ('ssti', 'crlf'):
            summary, findings, output = await self.scan('/' + module, module, 'POST')
            self.assertEqual(summary['confirmed'], 1)
            self.assertEqual(summary['confirmed_signals'], 1)
            self.assertEqual(len((output / 'findings.jsonl').read_text().splitlines()), 1)
            self.assertIn('[CONFIRMED_SIGNAL]', (output / 'vulns_report.txt').read_text())

    async def test_negative_arithmetic_is_not_positive_49(self):
        for mode in ('GET', 'JSON'):
            summary, findings, _ = await self.scan('/ssti-minus', 'ssti', mode)
            self.assertEqual(summary['confirmed_signals'], 1)
            self.assertIn('-49', findings[0]['evidence'])

    async def test_crlf_body_is_not_a_header_and_large_body_does_not_hide_header(self):
        for mode in ('GET', 'POST', 'JSON'):
            _, findings, _ = await self.scan('/crlf-body', 'crlf', mode)
            self.assertEqual(findings, [])
            _, findings, _ = await self.scan('/crlf-large', 'crlf', mode, extra=('--max-bytes', '1024'))
            self.assertEqual(len(findings), 1)

    async def test_weak_ini_is_only_candidate(self):
        summary, findings, _ = await self.scan('/weak-ini', 'lfi', 'POST', body='file=ok', extra=('--params', 'file'))
        self.assertEqual(summary['confirmed'], 0)
        self.assertEqual(summary['candidates'], 1)

    async def test_streamed_error_and_unknown_charset(self):
        summary, _, _ = await self.scan('/stream-sql', 'sqli', 'POST')
        self.assertEqual(summary['candidates'], 1)

    async def test_broken_url_does_not_hide_working_target(self):
        summary, findings, output = await self.scan('/slow-probe', 'redirect', 'POST',
            body='next=ok', extra=('--params', 'next', '--timeout', '.02', '-u', self.base + '/ssti'))
        self.assertNotEqual(summary['status'], 'completed_no_findings')
        self.assertTrue(any(event['error'] == 'timeout' for event in json.loads((output / 'errors.json').read_text())))
        self.assertEqual(findings, [])

    async def test_baseline_timeout_is_inconclusive(self):
        summary, findings, _ = await self.scan('/slow', 'sqli', 'POST', extra=('--timeout', '.02'))
        self.assertEqual(summary['status'], 'inconclusive')
        self.assertEqual(findings, [])

    async def test_small_budget_does_not_wait_for_another_rate_slot(self):
        started = time.monotonic()
        summary, _, _ = await asyncio.wait_for(self.scan('/plain', 'sqli,ssrf', 'POST',
            extra=('--oast-domain', 'callback.example', '--rate', '.1', '--max-requests', '1')), 1)
        self.assertEqual(summary['requests'], 1)
        self.assertEqual(summary['oast_probes_pending'], 0)
        self.assertEqual(summary['status'], 'budget_exhausted')
        self.assertLess(time.monotonic() - started, 1)

    async def test_oast_timeouts_stay_pending_but_report_errors(self):
        for mode in ('GET', 'POST'):
            summary, findings, output = await self.scan('/slow-probe', 'ssrf', mode,
                extra=('--oast-domain', 'callback.example', '--timeout', '.02'))
            self.assertEqual(summary['status'], 'completed_with_errors')
            self.assertEqual(findings, [])
            self.assertEqual(summary['oast_probes_pending'], 1)
            events = [json.loads(line) for line in (output / 'oast_probes.jsonl').read_text().splitlines()]
            self.assertEqual(events[-1]['state'], 'delivery_unknown')

    async def test_headers_are_case_insensitive_and_bound_to_origin(self):
        other = self.base.replace('127.0.0.1', 'localhost') + '/plain'
        await self.scan('/plain', 'xss', 'JSON', extra=(
            '-u', other, '--headers', 'authorization: Bearer LOCAL-TEST',
            '--headers', 'content-type: application/json', '--headers-origin', self.base))
        for call in self.calls:
            if call['headers']['Host'].startswith('127.'):
                self.assertEqual(call['headers']['Authorization'], 'Bearer LOCAL-TEST')
            else:
                self.assertNotIn('Authorization', call['headers'])
            self.assertEqual(call['headers']['Content-Type'], 'application/json')

    async def test_output_expansion_and_credential_scope_validation(self):
        with patch('os.path.expanduser', return_value=str(self.root)):
            args, *_ = load_args(['-u', self.base, '--body', 'q=x', '-o', '~/expanded'])
        self.assertEqual(args.output, self.root / 'expanded')
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            load_args(['-u', self.base, '-u', 'https://example.invalid', '--body', 'q=x',
                       '--headers', 'Authorization: Bearer LOCAL-TEST', '-o', str(self.root / 'reject')])

    async def test_post_concurrency_and_rate_limits(self):
        await self.scan('/concurrency', 'sqli', 'POST', body='q=ok&keep=ok',
                        extra=('--params', 'q,keep', '--concurrency', '2', '--rate', '20'))
        self.assertLessEqual(self.peak, 2)
        # Лимит задаёт старт клиента: отдельные приходы на сервер имеют джиттер.
        # Длительность серии проверяет rate с допуском в один интервал.
        elapsed = self.calls[-1]['time'] - self.calls[0]['time']
        self.assertGreaterEqual(elapsed, (len(self.calls) - 2) / 20)

    async def test_cancelled_workers_are_drained(self):
        active = set()
        async def operation(value):
            active.add(value)
            try:
                if value == 0:
                    await asyncio.sleep(.01)
                    raise RuntimeError('test')
                await asyncio.sleep(1)
            finally:
                active.remove(value)
        with self.assertRaises(RuntimeError):
            await bounded(range(4), operation, 2)
        self.assertFalse(active)

    async def test_cli_interrupt_saves_summary_and_exits_130(self):
        output = self.root / 'interrupt'
        child = await asyncio.create_subprocess_exec(sys.executable, str(Path(__file__).with_name('post_scanner.py')),
            '-u', self.base + '/slow-probe', '--body', 'q=ok', '--modules', 'ssrf',
            '--oast-domain', 'callback.example', '--output', str(output), '--rate', '1000',
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            await asyncio.wait_for(self.probe_seen.wait(), 3)
            child.send_signal(signal.SIGINT)
            stdout, stderr = await asyncio.wait_for(child.communicate(), 3)
            self.assertEqual(child.returncode, 130, stderr.decode())
            summary = json.loads((output / 'summary.json').read_text())
            self.assertEqual(summary['status'], 'interrupted')
            self.assertEqual(summary['oast_probes_pending'], 1)
            self.assertEqual((output / 'summary.json').stat().st_mode & 0o777, 0o600)
        finally:
            if child.returncode is None:
                child.kill()
                await child.wait()


if __name__ == '__main__':
    unittest.main()
