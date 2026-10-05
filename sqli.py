"""Error-based SQLi: новый класс SQL-ошибки, контроль и повтор без извлечения данных."""
import re

from ..probes import Outcome, Signal, body_complete, failure_reason
from .adapter import run_get

PAYLOADS = ("'", '"', ')', "';", '";', '/*')
SQL_ERRORS = {
    'MySQL': re.compile(r'you have an error in your sql syntax|'
                       r'warning\s*:\s*(?:mysqli?|mysqli?_[a-z_]+)\s*\(|'
                       r'MySqlException\b', re.I),
    'PostgreSQL': re.compile(r'pg_(?:query|exec|prepare)(?:_params)?\s*\(\).*?query (?:error|failed)|'
                            r'PostgreSQL.*?ERROR\s*:|'
                            r'org\.postgresql\.util\.PSQLException|'
                            r'psycopg(?:2)?\.(?:errors\.SyntaxError|ProgrammingError)|'
                            r'ERROR\s*:\s*(?:syntax error at or near|unterminated quoted string)', re.I),
    'MSSQL': re.compile(r'unclosed quotation mark|'
                       r'Microsoft (?:OLE DB Provider|ODBC SQL Server Driver)|'
                       r'(?:System\.Data|Microsoft\.Data)\.SqlClient\.SqlException', re.I),
    'Oracle': re.compile(r'\bORA-(?:00900|00907|00917|00920|00923|00933|00936|01756)\b|'
                        r'oracle\.jdbc\.[\w.]*SQLException', re.I),
}


def signatures(text: str) -> dict[str, str]:
    return {name: match.group(0)[:200] for name, pattern in SQL_ERRORS.items()
            if (match := pattern.search(text))}


def readable(response) -> bool:
    # SQL-ошибка часто приходит с HTTP 500, для которого usable=False.
    return body_complete(response) and (response.usable or response.status >= 400)


async def run(send, baseline, **kwargs) -> Outcome:
    if not readable(baseline):
        return Outcome('inconclusive', 'baseline_' + failure_reason(baseline))
    original = signatures(baseline.text)
    if original:
        return Outcome('skipped', 'sql_error_already_in_baseline:' + ','.join(original))
    result = Outcome(reason='no_new_sql_error')
    for payload in PAYLOADS:
        response = await send(payload, 'sqli_probe')
        if not readable(response):
            result.state, result.reason = 'inconclusive', failure_reason(response)
            if response.error == 'request_budget':
                break
            continue
        new = {key: value for key, value in signatures(response.text).items() if key not in original}
        if not new:
            continue
        control = await send(None, 'sqli_control')
        if readable(control):
            new = {key: value for key, value in new.items() if key not in signatures(control.text)}
        if not new:
            result.state, result.reason = 'inconclusive', 'sql_error_in_control'
            continue
        repeat = await send(payload, 'sqli_confirmation')
        repeated = readable(repeat) and bool(set(new) & set(signatures(repeat.text)))
        confirmed = readable(control) and repeated
        note = (f'Новая SQL-ошибка; чистый контроль={readable(control)}; повтор={repeated}. '
                'Ошибка БД — кандидат SQLi; выполнение произвольного SQL не проверялось.')
        return Outcome('confirmed' if confirmed else 'inconclusive', 'new_sql_error', [Signal(payload,
            '; '.join(f'{name}: {text}' for name, text in new.items()), response,
            note=note, confirmation_payload=payload)])
    return result


async def scan(client, context):
    return await run_get('sqli', run, client, context)
