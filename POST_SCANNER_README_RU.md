# POST Vulnerability Scanner 1.3

`post_scanner.py` — асинхронный CLI для разрешённых Bug Bounty endpoint-ов. Он проверяет только явно переданные POST URL и не переходит по редиректам.

Контракт четырёх модулей `run(send, baseline, **kwargs) -> Outcome` и пример подключения: [MODULES_API_RU.md](MODULES_API_RU.md). Встроенный OAST-журнал поддерживает `await register_probe(...)`.

## Установка

Нужен Python 3.10+. Распакуй архив целиком: скрипт использует соседний пакет `bbscanner`.

```bash
cd bug_bounty_scanner
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Form-urlencoded

```bash
python post_scanner.py \
  -u 'https://target.example/account/update' \
  --body 'name=Arman&next=%2Fdashboard&file=avatar.png' \
  --headers 'Authorization: Bearer YOUR_TOKEN' \
  --modules xss,lfi,redirect,sqli \
  --rate 5 --concurrency 5 --timeout 5 \
  --output post_results
```

## JSON

```bash
python post_scanner.py \
  -u 'https://target.example/api/profile' \
  --body '{"name":"Arman","redirect":"/dashboard","meta":{"file":"avatar.png"}}' \
  --json \
  --headers 'Authorization: Bearer YOUR_TOKEN' \
  --modules xss,redirect
```

JSON-поля изменяются по пути (`meta.file`); для неоднозначных имён используй JSON Pointer: `--params /meta/file` или `/items/0/name`. В Pointer символ `/` внутри имени записывается как `~1`, символ `~` — как `~0`. Для форм и JSON за один запрос меняется только одно поле. В форме остальные части исходного тела сохраняются побайтно, включая percent-encoding и повторяющиеся имена. JSON при мутации сериализуется заново; значения соседних полей сохраняются, форматирование может измениться. Повторяющиеся JSON-ключи, NaN/Infinity и некорректный Unicode отклоняются.

## Файл endpoint-ов и тело

```bash
python post_scanner.py -l endpoints.txt --body-file request.json --json \
  --headers 'Authorization: Bearer YOUR_TOKEN' \
  --headers-origin 'https://target.example' --output post_batch
```

`endpoints.txt` содержит по одному `http://` или `https://` URL на строку. Пустые строки и строки с `#` пропускаются. Пользовательские заголовки, включая Authorization/Cookie, привязываются к origin (схема, хост и порт). При нескольких origin укажи `--headers-origin` из входного списка: заголовки отправятся только туда. Для единственного origin привязка автоматическая. Тело POST остаётся общим для всех URL этого запуска.

## Полезные параметры

| Флаг | Назначение |
|---|---|
| `--body` / `--body-file` | исходное тело POST; требуется ровно один вариант |
| `--json` | JSON-разбор и `Content-Type: application/json` |
| `--headers` | `Name: Value`; можно повторять или передать JSON-объект |
| `--headers-origin` | origin для пользовательских заголовков и cookies |
| `--cookies` | значение Cookie; действует та же привязка к origin |
| `--params` | ограничить имена/пути проверяемых полей |
| `--modules` | `xss,lfi,redirect,sqli,ssrf,ssti,crlf` или подмножество |
| `--oast-domain` | домен вашего OAST/DNS-логгера; обязателен при `ssrf` |
| `--redirect-all` | проверять Open Redirect для всех имён полей |
| `--concurrency` | максимум одновременно выполняемых запросов |
| `--rate` | глобальный лимит начала запросов в секунду |
| `--timeout` | таймаут одного запроса |
| `--max-requests` | общий бюджет baseline, probes и повторов |
| `--max-targets` | максимум уникальных URL, по умолчанию 1000 |
| `--max-parameters` | максимум полей на URL, по умолчанию 50 |
| `--max-bytes` | максимум тела ответа для анализа |
| `--output` | новая или пустая папка отчётов |

`--headers` нужно заключать в кавычки. Имена заголовков сравниваются без учёта регистра; последний вариант побеждает. Переданный Content-Type должен соответствовать `--json` или форме. Значения Authorization/Cookie не записываются в настройки и журнал запросов. URL и короткие доказательства в отчётах всё равно могут содержать чувствительные данные.

## Логика проверок

- **XSS:** отправляется уникальный неисполняемый маркер и проверяется его точное отражение в raw HTML. Это `candidate`, а не доказательство выполнения JavaScript; `<script>` и event-handler payload не используются.
- **LFI:** проверяются ограниченные пути `/etc/passwd` и `win.ini`, baseline, повтор и negative-control. Один `[extensions]` даёт только кандидата; для подтверждённого сигнала нужна структура файла. `confirmed` означает воспроизводимый технический сигнал, который нужно проверить вручную.
- **Open Redirect:** отправляются два разных hostname из зоны `.example.invalid`; проверяется только 3xx и разобранный `Location`. Внешний адрес не запрашивается.
- **SQLi:** error-based пробы для MySQL/PostgreSQL/MSSQL/Oracle; полные HTTP 500 анализируются отдельно от сетевых ошибок.
- **SSRF:** для каждого поля создаётся уникальный UUID-поддомен вашего `--oast-domain`. UUID записывается в `oast_probes.jsonl`; подтверждение делается только по DNS/HTTP-логам OAST.
- **SSTI:** `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` и `<%=- 7*7 %>` с baseline-контролем (`49` и `-49`).
- **CRLF:** проверяется заголовок `X-CRLF-Scan` в HTTP-ответе, включая повтор с новым значением.

Baseline выполняется для каждого URL. Исходные сигнатуры не становятся находками. Отражение текста CRLF-заголовка в теле также не считается его внедрением. SQLi остаётся кандидатом даже при повторяемой ошибке БД; SSTI подтверждается другим арифметическим выражением. В `summary.json` счётчики `confirmed` и `confirmed_signals` включают все модули.

Ошибки timeout/connection/HTTP 500 не останавливают остальные цели. Redirect follow отключён, cookie jar и переменные окружения proxy отключены. Используй скрипт только на endpoint-ах, явно разрешённых программой; не отправляй чужие токены и не тестируй production-операции, которые меняют данные.

## Отчёты

В папке `--output` создаются:

- `vulns_report.txt` — читаемый список находок;
- `findings.json` — машинный формат находок;
- `findings.jsonl` — находки, добавляемые сразу по мере обнаружения;
- `checks.jsonl` — результат каждой проверки;
- `requests.jsonl` — метод, URL, назначение, статус, время и SHA-256 тела;
- `errors.json` и `summary.json` — ошибки и сводка.

При `ssrf` создаётся `oast_probes.jsonl`. UUID записывается перед запросом; таймаут или отмена отмечаются как `delivery_unknown`, а не подтверждение/опровержение SSRF. Неотправленные из-за бюджета пробы в журнал не попадают.

Терминал и TXT используют единый формат `[СОСТОЯНИЕ] МОДУЛЬ POST | url=… | parameter=… | payload=… | evidence=…`; управляющие символы экранируются. Ctrl+C/SIGTERM сохраняют частичный итог и завершают дочерние asyncio-задачи. Файлы отчётов создаются с правами 600.

Коды выхода: `0` — завершённый проход (включая `completed_with_errors`, подробности в сводке); `1` — неполный проход/исчерпанный бюджет/все проверки неопределённы; `2` — аргументы или файловая ошибка; `130` — прерывание. Сетевой сбой не выдаётся за отсутствие уязвимостей.

Тесты локального стенда:

```bash
python -m unittest discover -v
```
