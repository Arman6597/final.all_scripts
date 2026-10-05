"""SSTI: только арифметика; baseline, свежий контроль и другое произведение."""
import re
import secrets

from ..probes import Outcome, Signal, body_complete, failure_reason
from .adapter import run_get

TEMPLATES = ('{{%d*%d}}', '${%d*%d}', '<%%= %d*%d %%>', '<%%=- %d*%d %%>')


def contains_number(text: str, value: int) -> bool:
    return bool(re.search(r'(?<![\w.+-])' + re.escape(str(value)) + r'(?![\w.])', text))


def readable(response) -> bool:
    return response.usable and body_complete(response) and 200 <= response.status < 400


async def run(send, baseline, **kwargs) -> Outcome:
    if not readable(baseline):
        return Outcome('inconclusive', 'baseline_' + failure_reason(baseline))
    if contains_number(baseline.text, 49):
        return Outcome('skipped', 'number_49_already_in_baseline')
    result = Outcome(reason='no_computed_number')
    for template in TEMPLATES:
        sign = -1 if '=- ' in template else 1
        expected = sign * 49
        if contains_number(baseline.text, expected):
            result.state, result.reason = 'inconclusive', 'number_already_in_baseline'
            continue
        payload = template % (7, 7)
        response = await send(payload, 'ssti_probe')
        if not readable(response):
            result.state, result.reason = 'inconclusive', failure_reason(response)
            if response.error == 'request_budget':
                break
            continue
        if not contains_number(response.text, expected):
            continue
        control = await send(None, 'ssti_control')
        if readable(control) and contains_number(control.text, expected):
            result.state, result.reason = 'inconclusive', 'number_in_control'
            continue
        left, right = secrets.randbelow(80) + 11, secrets.randbelow(80) + 11
        confirmation_payload = template % (left, right)
        answer = sign * left * right
        repeat = await send(confirmation_payload, 'ssti_confirmation')
        confirmed = (readable(control) and readable(repeat)
                     and not contains_number(baseline.text, answer)
                     and not contains_number(control.text, answer)
                     and not contains_number(response.text, answer)
                     and contains_number(repeat.text, answer))
        confidence = 'confirmed_signal' if confirmed else 'candidate'
        note = (f'В baseline нет {expected}; контроль={readable(control)}; '
                f'проверка {confirmation_payload!r} -> {answer}: {confirmed}. '
                'Проверялась только арифметика, серверное выполнение кода не проверялось.')
        return Outcome('confirmed' if confirmed else 'inconclusive', 'arithmetic_result', [Signal(payload,
            f'Изолированное число {expected} в ответе', response, confidence, note, confirmation_payload)])
    return result


async def scan(client, context):
    return await run_get('ssti', run, client, context)
