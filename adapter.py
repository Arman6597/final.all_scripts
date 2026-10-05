"""Адаптер общих проверок к GET-транспорту и его формату отчётов."""
from ..core import Finding, check_result, replace_parameter, safe_fetch


async def run_get(module, runner, client, context, **options):
    async def send(payload, purpose, on_start=None):
        preserve_percent = module == 'crlf'
        url = (context.url if payload is None else
               replace_parameter(context.url, context.index, payload,
                                 preserve_percent=preserve_percent))
        return await safe_fetch(client, url, context.user_agent, purpose, on_start=on_start)

    outcome = await runner(send, context.baseline, **options)
    result = check_result(module, context, outcome.state, outcome.reason)
    for signal in outcome.signals:
        confirmation = (replace_parameter(context.url, context.index, signal.confirmation_payload,
                                           preserve_percent=module == 'crlf')
                        if signal.confirmation_payload is not None else '')
        result.findings.append(Finding(module, signal.confidence,
            replace_parameter(context.url, context.index, signal.payload,
                              preserve_percent=module == 'crlf'), context.parameter,
            context.index, signal.payload, signal.evidence, signal.response.status,
            signal.response.sha256, confirmation, signal.note))
    return result
