"""Reflected XSS: неисполняемый уникальный маркер и проверка точного отражения."""
import secrets

from ..core import Finding, check_result, replace_parameter, safe_fetch


def reflected(response, payload: str) -> bool:
    # Не декодируем &quot; / &gt;: экранированная строка не равна исходному payload.
    mime = response.headers.get('content-type', '').split(';', 1)[0].strip().lower()
    return response.usable and mime in ('text/html', 'application/xhtml+xml') and payload in response.text


async def scan(client, context):
    result = check_result('xss', context)
    payload = f'idxss_{secrets.token_hex(8)}">'
    url = replace_parameter(context.url, context.index, payload)
    first = await safe_fetch(client, url, context.user_agent, 'xss_probe')
    if not first.usable:
        result.state, result.reason = 'inconclusive', first.error or 'unsupported_status'
        return result
    if not reflected(first, payload):
        if first.truncated:
            result.state, result.reason = 'inconclusive', 'response_truncated'
        return result
    # Новый nonce проверяет воспроизводимость, а не случайное совпадение/старый кэш.
    second_payload = f'idxss_{secrets.token_hex(8)}">'
    second_url = replace_parameter(context.url, context.index, second_payload)
    second = await safe_fetch(client, second_url, context.user_agent, 'xss_confirmation')
    repeated = reflected(second, second_payload)
    position = first.text.find(payload)
    evidence = first.text[max(0, position - 80):position + len(payload) + 80]
    result.state = 'candidate'
    result.reason = 'raw_reflection_repeated' if repeated else 'raw_reflection_not_reconfirmed'
    result.findings.append(Finding('xss', 'candidate', url, context.parameter, context.index,
        payload, evidence, first.status, first.sha256, second_url,
        'Точный маркер отражён в HTML. Нужна ручная оценка контекста и CSP; исполнение JavaScript не проверялось. '
        + ('Отражение повторилось с новым nonce.' if repeated else 'Повторное отражение не подтверждено.')))
    return result
