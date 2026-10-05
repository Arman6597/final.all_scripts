"""Open Redirect: проверка Location; внешний адрес никогда не запрашивается."""
import secrets
from urllib.parse import urljoin, urlsplit

from ..core import Finding, check_result, replace_parameter, safe_fetch

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
REDIRECT_NAMES = {'next', 'redirect', 'redirecturl', 'redirecturi', 'redirectto',
    'return', 'returnurl', 'returnto', 'continue', 'dest', 'destination', 'url',
    'uri', 'out', 'callback', 'r', 'go', 'link', 'target', 'to', 'forward'}


def looks_like_redirect_parameter(name: str) -> bool:
    return ''.join(c for c in name.lower() if c.isalnum()) in REDIRECT_NAMES


def destination():
    token = secrets.token_hex(8)
    # .invalid предназначен для несуществующих адресов; переход не выполняется.
    return f'https://bb-{token}.example.invalid/probe/{token}'


def points_to(response, expected: str) -> bool:
    if not response.usable or response.status not in REDIRECT_STATUSES:
        return False
    location = response.headers.get('location', '')
    if not location or any(ord(c) < 33 for c in location) or '\\' in location:
        return False
    try:
        parsed = urlsplit(urljoin(response.url, location))
        return parsed.scheme in ('http', 'https') and parsed.hostname == urlsplit(expected).hostname
    except ValueError:
        return False


async def scan(client, context):
    result = check_result('redirect', context)
    if not client.args.redirect_all_params and not looks_like_redirect_parameter(context.parameter):
        result.state, result.reason = 'skipped', 'parameter_name_not_in_redirect_set'
        return result
    payload = destination()
    url = replace_parameter(context.url, context.index, payload)
    first = await safe_fetch(client, url, context.user_agent, 'redirect_probe')
    if not first.usable:
        result.state, result.reason = 'inconclusive', first.error or 'unsupported_status'
        return result
    if not points_to(first, payload):
        return result
    second_payload = destination()
    second_url = replace_parameter(context.url, context.index, second_payload)
    second = await safe_fetch(client, second_url, context.user_agent, 'redirect_confirmation')
    confirmed = points_to(second, second_payload)
    result.state = 'confirmed_signal' if confirmed else 'candidate'
    result.reason = 'controlled_external_location' if confirmed else 'redirect_not_reconfirmed'
    result.findings.append(Finding('redirect', result.state, url, context.parameter, context.index,
        payload, 'Location: ' + first.headers.get('location', ''), first.status, first.sha256,
        second_url, 'Проверялся hostname в Location. '
        + ('Управление редиректом повторилось с другим внешним hostname. ' if confirmed else
           'Повтор с другим внешним hostname не подтвердился. ')
        + 'Переходы не выполнялись.'))
    return result
