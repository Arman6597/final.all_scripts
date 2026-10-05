"""Поиск URL с query и GET-форм на одной исходной странице, без рекурсивного crawl."""
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from .core import normalize_url, origin, parameters


def discover(source: str, text: str, limit: int = 50) -> list[str]:
    """Берёт только тот же origin. POST-формы не превращает в GET-запросы."""
    soup = BeautifulSoup(text, 'html.parser')
    base_tag = soup.find('base', href=True)
    try:
        base = urljoin(source, base_tag['href']) if base_tag else source
    except ValueError:
        base = source
    found = []

    def add(value, relative_to=source):
        try:
            url = normalize_url(urljoin(relative_to, value))
        except (ValueError, UnicodeError):
            return
        if origin(url) == origin(source) and parameters(url) and url not in found and len(found) < limit:
            found.append(url)

    for tag in soup.find_all(href=True):
        add(tag['href'], base)
    for form in soup.find_all('form'):
        if str(form.get('method', 'get')).lower() != 'get':
            continue
        action = form.get('action')
        try:
            action = urljoin(base, action) if action and action.strip() else source
        except ValueError:
            continue
        fields = []
        for tag in form.find_all(['input', 'textarea', 'select'], attrs={'name': True}):
            if tag.has_attr('disabled'):
                continue
            kind = str(tag.get('type', '')).lower()
            if kind in ('file', 'submit', 'button', 'reset') or (kind in ('checkbox', 'radio') and not tag.has_attr('checked')):
                continue
            if tag.name == 'select':
                selected = tag.find('option', selected=True) or tag.find('option')
                value = selected.get('value', selected.get_text()) if selected else ''
            else:
                value = tag.get_text() if tag.name == 'textarea' else tag.get('value', '')
            fields.append((str(tag['name']), str(value)))
        parts = urlsplit(action)
        query = '&'.join(filter(None, [parts.query, urlencode(fields)]))
        add(urlunsplit((parts.scheme, parts.netloc, parts.path, query, '')))
    return found
