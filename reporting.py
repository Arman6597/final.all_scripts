"""Понятный терминал и отчёты; Cookie никогда не записывается в журнал запросов."""
from dataclasses import asdict
import json
from pathlib import Path
import sys

from colorama import Fore, Style, just_fix_windows_console

from .core import operational_error
from .probes import log_line


def safe(value) -> str:
    return ''.join(c if c.isprintable() else ' ' for c in str(value))


class Reporter:
    def __init__(self, folder: Path, color: bool = True):
        self.folder = folder
        self.color = color and sys.stdout.isatty()
        self.findings, self.checks = [], []
        just_fix_windows_console()
        self.report = (folder / 'vulns_report.txt').open('w', encoding='utf-8')
        self.check_file = (folder / 'checks.jsonl').open('w', encoding='utf-8')
        self.report.write('Bug Bounty Scanner — автоматические признаки уязвимостей\n'
            'confirmed_signal = воспроизводимый технический признак; candidate = нужна проверка.\n'
            'Отражение маркера не доказывает выполнение JS. Impact оценивается вручную.\n\n')
        self.report.flush()

    def message(self, text):
        print(safe(text), flush=True)

    def record(self, result):
        record = asdict(result)
        self.checks.append(record)
        self.check_file.write(json.dumps(record, ensure_ascii=False) + '\n')
        self.check_file.flush()
        for finding in result.findings:
            data = asdict(finding)
            self.findings.append(data)
            text = log_line(finding.status, finding.module, 'GET', finding.url,
                            f'{finding.parameter}#{finding.parameter_index}', finding.payload, finding.evidence)
            shade = Fore.LIGHTRED_EX if finding.status == 'confirmed_signal' else Fore.LIGHTYELLOW_EX
            print((shade if self.color else '') + safe(text) + (Style.RESET_ALL if self.color else ''), flush=True)
            self.report.write(text + '\n')
            for name, value in data.items():
                # JSON-строки не дают управляющим символам подделать структуру TXT-отчёта.
                self.report.write(f'{name}: {json.dumps(value, ensure_ascii=False)}\n')
            self.report.write('\n')
            self.report.flush()

    def finish(self, summary, requests, targets):
        for name, value in (('summary.json', summary), ('findings.json', self.findings),
                            ('targets.json', targets), ('errors.json', [x for x in requests if operational_error(x)])):
            (self.folder / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        with (self.folder / 'requests.jsonl').open('w', encoding='utf-8') as stream:
            for event in requests:
                stream.write(json.dumps(event, ensure_ascii=False) + '\n')
        self.report.write('Итог: ' + json.dumps(summary, ensure_ascii=False) + '\n')
        self.report.close()
        self.check_file.close()
