"""Контракт run(send, baseline, **kwargs); фиктивный транспорт, без сети."""
import asyncio
from contextlib import redirect_stdout
from dataclasses import is_dataclass
import inspect
import io
import re
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock
from urllib.parse import urlsplit

from bbscanner.checks import crlf, sqli, ssrf, ssti
from bbscanner.probes import Outcome, Signal
from post_scanner import ResponseData


def response(text='ok', *, headers=None, status=200, error=None, truncated=False):
    return ResponseData('http://test.invalid/', status=status, text=text,
                        headers=headers or {}, error=error, truncated=truncated)


class ContractTests(unittest.IsolatedAsyncioTestCase):
    def test_all_entrypoints_and_dataclasses(self):
        for module in (sqli, ssrf, ssti, crlf):
            self.assertTrue(inspect.iscoroutinefunction(module.run))
            parameters = inspect.signature(module.run).parameters
            self.assertEqual(list(parameters), ['send', 'baseline', 'kwargs'])
            self.assertEqual(parameters['kwargs'].kind, inspect.Parameter.VAR_KEYWORD)
        self.assertTrue(is_dataclass(Outcome))
        self.assertTrue(is_dataclass(Signal))
        self.assertIsNot(Outcome().signals, Outcome().signals)

    async def test_negative_and_unused_kwargs(self):
        for module in (sqli, ssti, crlf):
            send = AsyncMock(return_value=response())
            result = await module.run(send, response(), future_option='ignored')
            self.assertIsInstance(result, Outcome)
            self.assertEqual(result.state, 'negative')
            self.assertTrue(result.reason)
            self.assertFalse(result.signals)

    async def test_unusable_baseline_does_not_send(self):
        for module in (sqli, ssti, crlf, ssrf):
            send = AsyncMock()
            result = await module.run(send, response(status=None, error='timeout'),
                                      domain='oast.example', journal=SimpleNamespace(register_probe=AsyncMock()))
            self.assertEqual(result.state, 'inconclusive')
            send.assert_not_awaited()

    async def test_sqli_all_families_and_http_500(self):
        for family, text in (
            ('MySQL', 'You have an error in your SQL syntax'),
            ('PostgreSQL', 'pg_query(): query error'),
            ('MSSQL', 'Unclosed quotation mark after the character string'),
            ('Oracle', 'ORA-00933: SQL command not properly ended'),
        ):
            async def send(payload, purpose):
                return response() if payload is None else response(text, status=500, error='HTTP 500')
            outcome = await sqli.run(send, response())
            self.assertEqual(outcome.state, 'confirmed')
            self.assertEqual(outcome.signals[0].confidence, 'candidate')
            self.assertIn(family, outcome.signals[0].evidence)
            self.assertIn(outcome.signals[0].payload, sqli.PAYLOADS)

    async def test_sqli_existing_error_and_dynamic_control(self):
        text = 'You have an error in your SQL syntax'
        send = AsyncMock(return_value=response(text))
        result = await sqli.run(send, response(text))
        self.assertEqual(result.state, 'skipped')
        send.assert_not_awaited()
        result = await sqli.run(send, response())
        self.assertEqual(result.state, 'inconclusive')
        self.assertFalse(result.signals)

    async def test_sqli_incomplete_confirmation_preserves_candidate(self):
        send = AsyncMock(side_effect=[response('unclosed quotation mark'), response(),
                                      response(status=None, error='timeout')])
        result = await sqli.run(send, response())
        self.assertEqual(result.state, 'inconclusive')
        self.assertEqual(result.signals[0].confidence, 'candidate')

    async def test_ssti_literal_reflection_is_negative(self):
        async def send(payload, purpose):
            return response(str(payload))
        result = await ssti.run(send, response())
        self.assertEqual(result.state, 'negative')

    async def test_ssti_positive_and_negative_products(self):
        for prefix, sign in (('{{', 1), ('${', 1), ('<%=- ', -1)):
            async def send(payload, purpose):
                match = re.search(r'(\d+)\*(\d+)', payload or '')
                return response(str(sign * int(match[1]) * int(match[2]))) if match and payload.startswith(prefix) else response()
            result = await ssti.run(send, response())
            self.assertEqual(result.state, 'confirmed')
            self.assertEqual(result.signals[0].confidence, 'confirmed_signal')
            self.assertIn(str(sign * 49), result.signals[0].evidence)

    async def test_ssti_baseline_and_nonisolated_numbers(self):
        send = AsyncMock(return_value=response('49'))
        result = await ssti.run(send, response('<p>49</p>'))
        self.assertEqual(result.state, 'skipped')
        send.assert_not_awaited()
        for value in ('1490', '49.0', 'abc49', '-149'):
            result = await ssti.run(AsyncMock(return_value=response(value)), response())
            self.assertEqual(result.state, 'negative')

    async def test_ssti_http_500_is_not_successful_evaluation(self):
        result = await ssti.run(AsyncMock(return_value=response('49', status=500, error='HTTP 500')), response())
        self.assertEqual(result.state, 'inconclusive')
        self.assertFalse(result.signals)

    async def test_crlf_case_insensitive_header_and_changed_marker(self):
        async def send(payload, purpose):
            if payload is None:
                return response()
            return response(headers={'X-cRlF-sCaN': payload.split(':', 1)[1].strip(' +')})
        result = await crlf.run(send, response())
        self.assertEqual(result.state, 'confirmed')
        self.assertEqual(result.signals[0].confidence, 'confirmed_signal')
        self.assertEqual(result.signals[0].payload, '%0d%0aX-CRLF-Scan:+True')

    async def test_crlf_baseline_and_body_are_not_findings(self):
        send = AsyncMock(return_value=response('x-crlf-scan: True'))
        result = await crlf.run(send, response(headers={'X-CRLF-SCAN': 'True'}))
        self.assertEqual(result.state, 'skipped')
        send.assert_not_awaited()
        result = await crlf.run(send, response())
        self.assertEqual(result.state, 'negative')

    async def test_crlf_static_header_in_fresh_control_is_suppressed(self):
        result = await crlf.run(AsyncMock(return_value=response(headers={'x-crlf-scan': 'True'})), response())
        self.assertEqual(result.state, 'inconclusive')
        self.assertFalse(result.signals)

    async def test_transport_error_is_inconclusive(self):
        for module in (sqli, ssti, crlf):
            result = await module.run(AsyncMock(return_value=response(status=None, error='timeout')), response())
            self.assertEqual(result.state, 'inconclusive')
            self.assertFalse(result.signals)

    async def test_ssrf_missing_domain_skips_without_sending(self):
        send = AsyncMock()
        result = await ssrf.run(send, response())
        self.assertEqual(result.state, 'skipped')
        send.assert_not_awaited()

    async def test_ssrf_registers_before_send_and_preserves_metadata(self):
        original = {'method': 'POST', 'url': 'http://test.invalid/', 'parameter': 'next'}
        journal = SimpleNamespace(register_probe=AsyncMock())
        captured = []
        async def send(payload, purpose):
            self.assertEqual(journal.register_probe.await_count, 1)
            captured.append(payload)
            return response()
        with redirect_stdout(io.StringIO()):
            result = await ssrf.run(send, response(), domain='OAST.Example', journal=journal, metadata=original)
        self.assertEqual(result.state, 'oast_pending')
        self.assertFalse(result.signals)
        registered = journal.register_probe.await_args.kwargs
        self.assertRegex(registered['nonce'], r'^[0-9a-f]{32}$')
        parsed = urlsplit(captured[0])
        self.assertEqual(parsed.hostname, registered['nonce'] + '.oast.example')
        self.assertEqual(parsed.path, '/probe')
        for key, value in original.items():
            self.assertEqual(registered['metadata'][key], value)
        self.assertNotIn('nonce', original)

    async def test_ssrf_each_probe_gets_a_unique_nonce(self):
        journal = SimpleNamespace(register_probe=AsyncMock())
        with redirect_stdout(io.StringIO()):
            for _ in range(3):
                await ssrf.run(AsyncMock(return_value=response()), response(), domain='oast.example', journal=journal)
        tokens = [call.kwargs['nonce'] for call in journal.register_probe.await_args_list]
        self.assertEqual(len(set(tokens)), 3)

    async def test_ssrf_timeout_is_pending(self):
        journal = SimpleNamespace(register_probe=AsyncMock())
        with redirect_stdout(io.StringIO()):
            result = await ssrf.run(AsyncMock(side_effect=TimeoutError), response(), domain='oast.example', journal=journal)
        self.assertEqual(result.state, 'oast_pending')
        journal.register_probe.assert_awaited_once()

    async def test_ssrf_journal_failure_prevents_sending(self):
        journal = SimpleNamespace(register_probe=AsyncMock(side_effect=OSError))
        send = AsyncMock()
        result = await ssrf.run(send, response(), domain='oast.example', journal=journal)
        self.assertEqual(result.state, 'inconclusive')
        send.assert_not_awaited()

    async def test_ssrf_deferred_budget_does_not_register(self):
        journal = SimpleNamespace(register_probe=AsyncMock())
        result = await ssrf.run(AsyncMock(return_value=response(status=None, error='request_budget')),
            response(), domain='oast.example', journal=journal, defer_registration=True)
        self.assertEqual(result.state, 'inconclusive')
        journal.register_probe.assert_not_awaited()

    async def test_cancellation_is_propagated(self):
        for module in (sqli, ssti, crlf, ssrf):
            with redirect_stdout(io.StringIO()), self.assertRaises(asyncio.CancelledError):
                await module.run(AsyncMock(side_effect=asyncio.CancelledError), response(),
                    domain='oast.example', journal=SimpleNamespace(register_probe=AsyncMock()))


if __name__ == '__main__':
    unittest.main()
