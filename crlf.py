"""CRLF: маркер в заголовках ответа, чистый контроль и новый маркер при повторе."""
import uuid

from ..probes import Outcome, Signal, failure_reason, header_value, headers_received
from .adapter import run_get

HEADER = 'X-CRLF-Scan'
PAYLOADS = ('%0d%0aX-CRLF-Scan:+True', '%%0d%%0aX-CRLF-Scan:+True', '\r\nX-CRLF-Scan: True')


def readable(response) -> bool:
    # Полный блок заголовков пригоден и при ошибке/усечении последующего тела.
    return response.usable or headers_received(response)


async def run(send, baseline, **kwargs) -> Outcome:
    if not readable(baseline):
        return Outcome('inconclusive', 'baseline_' + failure_reason(baseline))
    if header_value(baseline, HEADER) is not None:
        return Outcome('skipped', 'header_already_in_baseline')
    result = Outcome(reason='no_injected_response_header')
    for payload in PAYLOADS:
        response = await send(payload, 'crlf_probe')
        if not readable(response):
            result.state, result.reason = 'inconclusive', failure_reason(response)
            if response.error == 'request_budget':
                break
            continue
        value = header_value(response, HEADER)
        if value is None:
            continue
        control = await send(None, 'crlf_control')
        if readable(control) and header_value(control, HEADER) is not None:
            result.state, result.reason = 'inconclusive', 'header_in_control'
            continue
        marker = uuid.uuid4().hex
        confirmation_payload = payload.replace('True', marker)
        repeat = await send(confirmation_payload, 'crlf_confirmation')
        confirmed = (readable(control) and readable(repeat)
                     and (header_value(repeat, HEADER) or '').strip(' +') == marker)
        confidence = 'confirmed_signal' if confirmed else 'candidate'
        return Outcome('confirmed' if confirmed else 'inconclusive', 'injected_response_header', [Signal(payload,
            f'{HEADER}: {value}', response, confidence,
            f'Заголовка нет в baseline; подтверждение новым значением={confirmed}.', confirmation_payload)])
    return result


async def scan(client, context):
    return await run_get('crlf', run, client, context)
