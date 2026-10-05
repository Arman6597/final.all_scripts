"""LFI/Path Traversal: только два заданных файла и отрицательный контроль."""
import re
import secrets

from ..core import Finding, check_result, replace_parameter, safe_fetch

PROBES = (
    ('Linux', '../../../../etc/passwd', re.compile(r'\broot:x:0:0:')),
    ('Windows', '../../../../windows/win.ini', re.compile(r'\[extensions\]', re.I)),
)
PASSWD_LINE = re.compile(r'root:x:0:0:[^:\r\n<]*:/[^:\r\n<]*:/[^\r\n<]+')
INI_SECTION = re.compile(r'^\s*\[(?:fonts|files|mci extensions|windows)\]\s*$', re.I | re.M)


async def scan(client, context):
    result = check_result('lfi', context)
    for system, payload, signature in PROBES:
        # Документация/пример passwd на обычной странице не считается новой находкой.
        if signature.search(context.baseline.text):
            result.state, result.reason = 'inconclusive', f'{system}: signature_already_in_baseline'
            continue
        url = replace_parameter(context.url, context.index, payload)
        probe = await safe_fetch(client, url, context.user_agent, 'lfi_' + system.lower())
        if not probe.usable:
            result.state, result.reason = 'inconclusive', probe.error or 'unsupported_status'
            continue
        match = signature.search(probe.text)
        if not match:
            if probe.truncated:
                result.state, result.reason = 'inconclusive', 'response_truncated'
            continue
        missing = f'../../../../bbscan_{secrets.token_hex(10)}_missing.txt'
        control_url = replace_parameter(context.url, context.index, missing)
        control = await safe_fetch(client, control_url, context.user_agent, 'lfi_negative_control')
        # 404 допустим: у несуществующего файла это ожидаемый исход.
        control_ok = (control.usable or (control.status == 404 and control.error == 'HTTP 404')) and not control.truncated
        if control_ok and signature.search(control.text):
            result.state, result.reason = 'inconclusive', 'signature_present_in_negative_control'
            continue
        repeated = await safe_fetch(client, url, context.user_agent, 'lfi_confirmation')
        repeat_ok = repeated.usable and bool(signature.search(repeated.text))
        # Один [extensions] — слабый признак, его не повышаем до сильного без INI-контекста.
        structure_ok = bool(PASSWD_LINE.search(probe.text)) if system == 'Linux' else bool(INI_SECTION.search(probe.text))
        confirmed = control_ok and repeat_ok and structure_ok
        status = 'confirmed_signal' if confirmed else 'candidate'
        position = match.start()
        evidence = probe.text[max(0, position - 40):position + 200]
        result.findings.append(Finding('lfi', status, url, context.parameter, context.index,
            payload, evidence, probe.status, probe.sha256, url,
            f'{system}: сигнатура отсутствует в baseline; '
            f'отрицательный контроль={control_ok}; повтор={repeat_ok}; структура файла={structure_ok}. '
            'Это признак чтения файла; конкретную серверную причину и impact нужно проверить вручную.'))
    if result.findings:
        result.state = 'confirmed_signal' if any(x.status == 'confirmed_signal' for x in result.findings) else 'candidate'
        result.reason = 'file_signature_detected'
    return result
