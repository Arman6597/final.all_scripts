#!/usr/bin/env python3
"""CLI для разрешённых GET-проверок XSS, LFI, Redirect, SQLi, SSRF, SSTI и CRLF.

Python 3.10+. Примеры:
  python scanner.py -u 'https://example.com/search?q=test'
  python scanner.py -l urls.txt --workers 10 --rate 5 --timeout 5
"""
import argparse
import asyncio
import os
from pathlib import Path
import sys

try:
    from bbscanner.core import normalize_url, origin, positive_float
    from bbscanner.engine import run_scan
    from bbscanner.probes import MODULES, validate_oast_domain
except ImportError as exc:
    raise SystemExit('Установи зависимости: python -m pip install -r requirements.txt\n' + str(exc))


def number(low, high):
    def convert(value):
        try:
            result = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError('нужно целое число') from exc
        if not low <= result <= high:
            raise argparse.ArgumentTypeError(f'диапазон {low}…{high}')
        return result
    return convert


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('-u', '--url', action='append', help='URL; можно повторять -u')
    source.add_argument('-l', '--list', type=Path, help='UTF-8 файл: один URL на строку')
    parser.add_argument('-o', '--output', type=Path, default=Path('scan_results'), help='новая/пустая папка результатов')
    parser.add_argument('--workers', type=number(1, 100), default=10)
    parser.add_argument('--rate', type=positive_float, default=5, help='общий лимит начала запросов/с')
    parser.add_argument('--timeout', type=positive_float, default=5, help='общий сетевой таймаут одного запроса, секунды')
    parser.add_argument('--max-requests', type=number(1, 100000), default=1000)
    parser.add_argument('--max-targets', type=number(1, 10000), default=100)
    parser.add_argument('--max-parameters', type=number(1, 200), default=20)
    parser.add_argument('--max-bytes', type=number(1024, 50000000), default=1048576)
    parser.add_argument('--modules', default='xss,lfi,redirect', help=','.join(MODULES))
    parser.add_argument('--oast-domain', help='домен вашего OAST/DNS-логгера; обязателен для ssrf')
    parser.add_argument('--params', default='', help='выбрать/добавить query-параметры через запятую')
    parser.add_argument('--no-discovery', action='store_true', help='не искать URL и GET-формы на странице без query')
    parser.add_argument('--redirect-all-params', action='store_true', help='проверять редирект для всех имён параметров')
    cookies = parser.add_mutually_exclusive_group()
    cookies.add_argument('--cookies', help='Cookie header, например session=...; pref=...')
    cookies.add_argument('--cookies-file', type=Path, help='файл со значением Cookie header')
    parser.add_argument('--cookie-origin', help='единственный origin для cookies; обязателен для нескольких origin')
    parser.add_argument('--user-agent', help='фиксированный UA вместо случайного выбора на URL')
    parser.add_argument('--no-color', action='store_true')
    args = parser.parse_args(argv)
    args.modules = list(dict.fromkeys(x.strip().lower() for x in args.modules.split(',') if x.strip()))
    if not args.modules or any(x not in MODULES for x in args.modules):
        parser.error('--modules: ' + ','.join(MODULES))
    try:
        args.oast_domain = validate_oast_domain(args.oast_domain, args.modules)
    except ValueError as exc:
        parser.error(str(exc))
    args.params = list(dict.fromkeys(x.strip() for x in args.params.split(',') if x.strip()))
    if any(len(x) > 128 or not all(c.isprintable() and not c.isspace() for c in x) for x in args.params):
        parser.error('--params: имена до 128 символов, без пробелов/управляющих символов')
    try:
        raw = args.url if args.url else [x.strip() for x in args.list.expanduser().read_text(encoding='utf-8-sig').splitlines()
                                       if x.strip() and not x.lstrip().startswith('#')]
        roots = list(dict.fromkeys(normalize_url(x.strip()) for x in raw))
        if not roots or len(roots) > args.max_targets:
            raise ValueError('Нужен непустой список в пределах --max-targets.')
        if args.cookies_file:
            args.cookies = args.cookies_file.expanduser().read_text(encoding='utf-8').strip()
        for value in (args.cookies, args.user_agent):
            if value and any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise ValueError('Заголовки не должны содержать управляющие символы.')
        origins = {origin(url) for url in roots}
        cookie_origin = None
        if args.cookies:
            if args.cookie_origin:
                normalized = normalize_url(args.cookie_origin)
                if normalized != origin(normalized) + '/' or origin(normalized) not in origins:
                    raise ValueError('--cookie-origin: только scheme://host[:port] из входного списка.')
                cookie_origin = origin(normalized)
            elif len(origins) == 1:
                cookie_origin = next(iter(origins))
            else:
                raise ValueError('Для нескольких origin задай --cookie-origin: cookies отправляются только ему.')
        args.output = args.output.expanduser().resolve()
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
    return args, roots, cookie_origin


def main(argv=None):
    args, roots, cookie_origin = arguments(argv)
    try:
        if args.output.exists() and (not args.output.is_dir() or any(args.output.iterdir())):
            raise ValueError('Папка результатов непустая. Выбери новую через --output.')
        os.umask(0o077)
        args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
        summary = asyncio.run(run_scan(args, roots, cookie_origin))
    except (OSError, ValueError) as exc:
        print(f'Ошибка: {exc}', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    if summary['status'] == 'interrupted':
        return 130
    return 0 if summary['status'] in ('completed', 'completed_with_errors') else 1


if __name__ == '__main__':
    raise SystemExit(main())
