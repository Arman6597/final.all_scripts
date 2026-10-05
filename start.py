#!/usr/bin/env python3
"""Одна команда для всех этапов: python3 start.py --all."""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys


def has_option(argv: list[str], name: str) -> bool:
    return any(item == name or item.startswith(name + '=') for item in argv)


def pipeline_args(argv: list[str], base: Path) -> list[str]:
    result = list(argv)
    all_stages = '--all' in result
    result = [item for item in result if item != '--all']
    for stage in ('js', 'monitor', 'smuggling', 'idor'):
        disable = '--without-' + stage
        option = '--idor-config' if stage == 'idor' else '--with-' + stage
        if disable in result and has_option(result, option):
            raise ValueError(f'{disable} и {option} нельзя использовать вместе')
        if all_stages and disable not in result and not has_option(result, option):
            if stage == 'idor':
                config = base / 'idor_requests.jsonl'
                if config.is_file() and config.stat().st_size:
                    result += [option, str(config)]
            else:
                result.append(option)
        result = [item for item in result if item != disable]
    if not any(has_option(argv, name) for name in ('--recon-cmd', '--recon-input')):
        result += [
            '--recon-cmd', 'gau --providers wayback --threads 2 --o {output} {domain}',
            '--recon-output', 'file',
        ]
    if not has_option(argv, '--mode'):
        result += ['--mode', 'parallel']
    if not has_option(argv, '--modules'):
        modules = 'xss,lfi,redirect,sqli,ssti,crlf'
        if has_option(argv, '--oast-domain'):
            modules += ',ssrf'
        result += ['--modules', modules]
    without_post = '--without-post' in result
    if without_post and has_option(argv, '--post-input'):
        raise ValueError('--without-post и --post-input нельзя использовать вместе')
    result = [item for item in result if item != '--without-post']
    post = base / 'post_requests.jsonl'
    if not without_post and not has_option(argv, '--post-input') and post.is_file() and post.stat().st_size:
        result += ['--post-input', str(post)]
    return result


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    root = Path(__file__).resolve().parent
    if '--help' in argv or '-h' in argv:
        print('Запуск: python3 start.py --all [опции pipeline_manager.py]\n'
              '--all: подключить JS, монитор, Smuggling и IDOR при наличии конфигурации.\n'
              '--with-js / --with-monitor / --with-smuggling: выбрать отдельные этапы.\n'
              '--without-js / --without-monitor / --without-smuggling / --without-idor: исключить из --all.\n'
              '--idor-config FILE: JSONL с URL, cookie-файлами и attacker_ids.\n'
              'IDOR по умолчанию с --all: ~/bugbounty/idor_requests.jsonl, если существует.\n'
              'Монитор без --include-subdomains проверяет только точные имена из targets.\n'
              'Дополнительные этапы последовательны; --mode относится к GET/POST.\n'
              'По умолчанию: gau → GET/POST параллельно, шесть модулей.\n'
              'Цели: ~/bugbounty/targets.txt\n'
              'POST: ~/bugbounty/post_requests.jsonl, если существует и не пуст.\n'
              '--without-post: не подключать этот дополнительный POST-файл.\n'
              '--oast-domain DOMAIN: также включить SSRF (если --modules не задан).\n'
              '--dry-run: выполнить Recon и подготовку без сканирования.\n'
              'Остальные параметры: python3 pipeline_manager.py --help')
        return 0
    try:
        from pipeline_manager import arguments
        forwarded = pipeline_args(argv, Path.home() / 'bugbounty')
        args = arguments(forwarded)
        if sys.platform != 'linux':
            raise ValueError('Нужна Ubuntu/Linux')
        if args.recon_argv and not shutil.which(args.recon_argv[0]):
            raise ValueError(f'Recon-инструмент не найден: {args.recon_argv[0]}. '
                             'Добавь его в PATH или передай --recon-input FILE.')
        local_python = root / '.venv' / 'bin' / 'python'
        python = str(local_python) if local_python.is_file() else sys.executable
        if not args.dry_run:
            scanner_python = args.python if has_option(argv, '--python') else python
            imports = 'import aiohttp, bs4, colorama' + ('; import aiodns' if args.with_monitor else '')
            check = subprocess.run([scanner_python, '-c', imports],
                                   capture_output=True, text=True, timeout=15)
            if check.returncode:
                raise ValueError('Не удалось загрузить зависимости сканеров. Выполни в папке проекта:\n'
                                 'python3 -m venv .venv\n'
                                 '.venv/bin/python -m pip install -r requirements.txt')
        if not args.post_input:
            print('[i] Дополнительный POST-файл не подключён. POST из Recon JSONL обрабатывается.', flush=True)
        if '--all' in argv and not args.idor_config:
            print('[i] IDOR пропущен: добавь ~/bugbounty/idor_requests.jsonl с двумя тестовыми сессиями.', flush=True)
        print(f'[i] JS={args.with_js}; Monitor={args.with_monitor}; '
              f'Smuggling={args.with_smuggling}; IDOR-шаблонов={len(args.idor_jobs)}', flush=True)
        print(f'[i] Модули: {args.modules}; режим: {args.mode}; отчёты: {args.output}', flush=True)
        command = [python, '-u', str(root / 'pipeline_manager.py'), *forwarded]
        # exec сохраняет сигналы Ctrl+C и код завершения оркестратора.
        os.execv(python, command)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f'Ошибка запуска: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
