"""SSRF: асинхронная регистрация UUID; подтверждение только по OAST-логам."""
import asyncio
from typing import Any
import uuid

import aiohttp

from ..probes import Outcome, failure_reason, headers_received, log_line, validate_oast_domain
from .adapter import run_get


class JournalFailure(Exception):
    pass


async def run(send, baseline, **kwargs) -> Outcome:
    domain: str | None = kwargs.get('domain')
    journal: Any = kwargs.get('journal')
    metadata: dict = kwargs.get('metadata') or {}
    if not domain:
        return Outcome('skipped', 'oast_domain_not_configured')
    try:
        domain = validate_oast_domain(domain, ('ssrf',))
    except (ValueError, TypeError, AttributeError):
        return Outcome('skipped', 'invalid_oast_domain')
    if not (baseline.usable or headers_received(baseline)):
        return Outcome('inconclusive', 'baseline_' + failure_reason(baseline))
    if not isinstance(metadata, dict) or not callable(getattr(journal, 'register_probe', None)):
        return Outcome('inconclusive', 'invalid_oast_journal_or_metadata')

    nonce = uuid.uuid4().hex
    payload = f'http://{nonce}.{domain}/probe'
    metadata = {**metadata, 'uuid': nonce, 'nonce': nonce, 'payload': payload, 'module': 'ssrf'}
    attempted = False

    async def register():
        nonlocal attempted
        try:
            await journal.register_probe(nonce=nonce, metadata=metadata)
        except Exception as exc:
            raise JournalFailure(type(exc).__name__) from exc
        attempted = True
        print(log_line('oast_pending', 'ssrf', metadata.get('method', 'HTTP'),
                       metadata.get('url', ''), metadata.get('parameter', ''),
                       payload, f'uuid={nonce}'), flush=True)

    def finish(state, **details):
        # Минимальному внешнему журналу достаточно одного register_probe().
        recorder = getattr(journal, 'record', None)
        if callable(recorder):
            try:
                recorder(metadata, state, **details)
            except Exception as exc:
                return ':journal_update_error=' + type(exc).__name__
        return ''

    try:
        if kwargs.get('defer_registration', False):
            # Движок вызывает callback после проверки бюджета/rate, перед HTTP.
            response = await send(payload, 'ssrf_probe', on_start=register)
        else:
            await register()
            response = await send(payload, 'ssrf_probe')
    except JournalFailure as exc:
        return Outcome('inconclusive', 'journal_registration_failed:' + str(exc))
    except asyncio.CancelledError:
        if attempted:
            finish('delivery_unknown', error='cancelled')
        raise
    except (TimeoutError, OSError, aiohttp.ClientError) as exc:
        if not attempted:
            return Outcome('inconclusive', 'not_sent:' + type(exc).__name__)
        note = finish('delivery_unknown', error=type(exc).__name__)
        return Outcome('oast_pending', 'verify_dns_http_logs:' + nonce + note)

    if not attempted:
        return Outcome('inconclusive', response.error or 'not_sent')
    if response.error == 'request_budget':
        finish('not_sent', error='request_budget')
        return Outcome('inconclusive', 'request_budget')
    note = finish('response_received' if headers_received(response) else 'delivery_unknown',
                  status=response.status, error=response.error)
    return Outcome('oast_pending', 'verify_dns_http_logs:' + nonce + note)


async def scan(client, context):
    return await run_get('ssrf', run, client, context, domain=client.args.oast_domain,
        journal=client.oast, defer_registration=True,
        metadata={'method': 'GET', 'url': context.url,
                  'parameter': context.parameter, 'parameter_index': context.index})
