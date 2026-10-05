# Все скрипты одной командой

В этом архиве `start.py` подключает четыре дополнительных инструмента:
`js_secrets_finder.py`, `subdomain_monitor.py`, `idor_scanner.py`, `smuggling_scanner.py`.
Они также сохраняют самостоятельный CLI.

## Установка и запуск

Распакуй обновлённый архив целиком в отдельную папку, затем открой папку
`bug_bounty_scanner`. Старую `.venv` копировать не нужно; свои входные данные и
отчёты оставь в `~/bugbounty/`.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 start.py --all
```

`gau` должен быть установлен и доступен через PATH. Для сбора поддоменов также
нужен `subfinder` (либо `--monitor-tool assetfinder`). При точном scope без
`--include-subdomains` монитор не вызывает эти программы.

По умолчанию Recon выполняет:

```text
gau --providers wayback --threads 2 --o {output} {domain}
```

При готовом Recon-файле `gau` не нужен:

```bash
python3 start.py --all --recon-input ~/bugbounty/recon_urls.txt
```

## Что предоставить

| Файл / параметр | Содержимое |
|---|---|
| `~/bugbounty/targets.txt` | Разрешённые точные домены, по одному на строку. URL и пути сюда не добавляй. |
| `~/bugbounty/post_requests.jsonl` | Реальные POST-шаблоны; при наличии подключаются автоматически. |
| `~/bugbounty/idor_requests.jsonl` | IDOR-конфигурация с URL, ID двух аккаунтов и путями к Cookie-файлам; автоматически подключается с `--all`. |
| Cookie-файлы из IDOR-конфигурации | По одной строке `session=...`, без префикса `Cookie:`. Используй два своих тестовых аккаунта. |
| `--oast-domain DOMAIN` | Твой OAST-домен для SSRF. Без него SSRF по умолчанию не запускается. |

Шаблоны находятся в `pipeline_examples/`. Подставь свои разрешённые цели и
реальные значения. Эти примеры не являются готовыми целями для сканирования.

Пример POST JSONL (один JSON-объект на физическую строку):

```json
{"method":"POST","url":"https://app.example.test/search","content_type":"application/json","body":{"query":"hello","page":1},"params":["query"]}
```

Пример IDOR JSONL для GET:

```json
{"url":"https://app.example.test/orders?id=100","cookie_victim_file":"cookies/account1.txt","cookie_attacker_file":"cookies/account2.txt","attacker_ids":{"id":200},"id_params":["id"],"mode":"direct"}
```

Здесь объект `100` принадлежит первому аккаунту, объект `200` — второму. Относительные
пути к Cookie-файлам отсчитываются от папки `idor_requests.jsonl`, а не от cwd.

Пример IDOR для POST, выполняющего чтение:

```json
{"url":"https://app.example.test/orders/read","data":{"order_id":100},"json":true,"cookie_victim_file":"cookies/account1.txt","cookie_attacker_file":"cookies/account2.txt","attacker_ids":{"order_id":200},"id_params":["order_id"],"mode":"direct"}
```

Для form POST укажи `"data":"order_id=100"`, без `"json":true`.
Режимы IDOR: `direct`, `increment`, `both`; `steps` от 1 до 20. Исходный ID
первого аккаунта берётся из URL/тела. Cookie передаются дочернему процессу через
`@файл`, POST-тело — через отдельный файл с правами 0600.

```bash
chmod 600 ~/bugbounty/idor_requests.jsonl ~/bugbounty/cookies/*.txt
```

## Порядок работы

1. `start.py` проверяет настройки и передаёт управление `pipeline_manager.py`.
2. `subdomain_monitor.py` выполняет один цикл DNS/HTTP/Takeover. Без
   `--include-subdomains` проверяются только точные имена из targets. С этим флагом
   разрешается сбор и проверка их поддоменов. Постоянная история разделяется по scope.
3. Для каждого корня запускается Recon либо читается `--recon-input`. Scope,
   `--exclude-host` и `--ports` применяются ко всем URL, которые уходят сканерам.
4. `js_secrets_finder.py` получает разрешённые `.js` URL, в том числе без query.
   Он сохраняет секреты-кандидаты и извлечённые эндпоинты. Эндпоинты повторно
   фильтруются по scope, затем ссылки с параметрами добавляются в GET-вход.
5. `scanner.py` проверяет GET, `post_scanner.py` — реальные POST-шаблоны.
   `--mode parallel` запускает эти две ветки одновременно, `serial` — по очереди.
6. `idor_scanner.py` обрабатывает подходящие по scope шаблоны из IDOR JSONL,
   последовательно, без повторения одного шаблона на пересекающихся корнях.
7. `smuggling_scanner.py` последовательно проверяет подготовленные URL методом
   OPTIONS. Он выполняется после других сканеров и сохраняет таймауты как кандидатов.

Монитор не расширяет targets автоматически и не превращает найденные поддомены
в новые корневые цели Recon. JS-этап выполняется один раз: рекурсивной загрузки
скриптов, повторных кругов сканирования и исполнения JavaScript нет.

Если нет POST-тела, JS URL или IDOR-конфигурации, соответствующий этап пропускается
с причиной в сводке. `--all` не может создать две авторизованные сессии или угадать
корректные POST-запросы. Падение одного дочернего процесса записывается в ошибки,
последующие независимые этапы продолжаются. Невалидные CLI/файлы конфигурации
останавливают запуск до сканирования.

## Модули и параметры

`scanner.py` и `post_scanner.py` импортируют семь проверок из `bbscanner/checks/`:
`xss.py`, `lfi.py`, `redirect.py`, `sqli.py`, `ssrf.py`, `ssti.py`, `crlf.py`.
Это Python-модули внутри сканеров, а не семь дополнительных процессов.
По умолчанию включены шесть проверок без SSRF; `--oast-domain` автоматически
добавляет SSRF, если ты не задал свой `--modules`.

```bash
# Все этапы; поддомены должны быть разрешены программой
python3 start.py --all --include-subdomains --mode parallel \
  --idor-config ~/bugbounty/idor_requests.jsonl \
  --oast-domain YOUR-OAST-DOMAIN

# Выборочно подключить JS и монитор
python3 start.py --with-js --with-monitor

# Все этапы кроме Smuggling
python3 start.py --all --without-smuggling

# Исключить IDOR и автоматический дополнительный POST-файл
python3 start.py --all --without-idor --without-post

# Не выполнять сетевые операции: подготовка из уже готового файла
python3 start.py --all --dry-run --recon-input ~/bugbounty/recon_urls.txt

python3 start.py --help
python3 pipeline_manager.py --help
```

`--dry-run` с `--recon-cmd` по-прежнему запускает Recon, но не сканеры и не монитор.
Для полностью офлайн-подготовки нужен `--recon-input`.

| Опция | По умолчанию / смысл |
|---|---|
| `--all` | Подключить все дополнительные этапы; только в `start.py`. Без флага остаётся прежний GET/POST-конвейер. |
| `--with-js`, `--with-monitor`, `--with-smuggling` | Выбор отдельных этапов. |
| `--without-js`, `--without-monitor`, `--without-smuggling`, `--without-idor` | Исключить этап из `--all`; только в `start.py`. |
| `--idor-config FILE` | Явно подключить IDOR JSONL. |
| `--rate 5`, `--workers 10` | Лимиты активного сканера; GET/POST делят их между ветками в parallel. |
| `--max-requests 1000` | Общий бюджет GET+POST на корень. |
| `--extra-max-requests 200` | Отдельный бюджет JS, IDOR и Smuggling на корень. Не общий лимит всего конвейера. |
| `--max-records 100` | Предел GET, POST, resource URL, IDOR-шаблонов и проверяемых монитором хостов. |
| `--smuggling-timeout 6` | Таймаут ожидания заголовков. Smuggling rate не выше 2, одно соединение одновременно. |
| `--monitor-output DIR` | `~/bugbounty/monitor_results`; внутри подпапка с идентификатором scope. |
| `--monitor-recon-rate 2` | Отдельный лимит внешнего subfinder; assetfinder его не поддерживает. |
| `--scanner-timeout 1800` | Общий таймаут каждого дочернего сканера, включая один цикл монитора. |
| `--output DIR` | Папка запусков, по умолчанию `~/bugbounty/runs`. |

JS отправляет не больше выделенного количества загрузок. IDOR делит дополнительный
бюджет между шаблонами корня. Для Smuggling резервируется до 14 соединений на URL:
при бюджете 200 выбираются максимум 14 URL. Монитор имеет свой rate и лимит хостов;
внешний Recon не включён в `--max-requests`. Таймаут процесса может завершить этап
раньше его внутреннего бюджета. Неопределённые результаты не считаются чистым сканом.

## Файлы проекта и результаты

Главные исполняемые файлы: `start.py`, `pipeline_manager.py`, `scanner.py`,
`post_scanner.py`, `js_secrets_finder.py`, `subdomain_monitor.py`, `idor_scanner.py`,
`smuggling_scanner.py`. Вспомогательный `bbscanner/pipeline_extras.py` связывает
дополнительные этапы с оркестратором. Старый Bash-конвейер с nuclei не запускается
внутри этой цепочки: это другой конвейер, который дублировал бы Recon и проверки.

В `~/bugbounty/runs/<запуск>/`:

- `pipeline_summary.json` — общая сводка, состояния/причины пропусков всех этапов.
- `logs/monitor/` — stdout/stderr монитора.
- `<домен>/get_urls.txt`, `post_requests.jsonl`, `resource_urls.txt` — подготовленные входы.
- `<домен>/js_urls.txt`, `js_endpoints_in_scope.txt`, `js_results/` — JS-вход, scope и находки.
- `<домен>/get_results/`, `post_jobs/`, `idor_jobs/` — результаты основных проверок.
- `<домен>/smuggling_urls.txt`, `smuggling_results/` — кандидаты десинхронизации и пакеты.
- `<домен>/logs/` — отдельные stdout/stderr стадий; IDOR/POST логи лежат внутри job.

История монитора находится отдельно в `~/bugbounty/monitor_results/<scope-id>/`.
Ошибки дописываются в `~/bugbounty/pipeline_errors.log`. Новые отчёты создаются
с приватными правами. Секреты и полные IDOR-ответы могут содержать чувствительные
данные: не публикуй папку результатов целиком.

Проверка интеграции: `python3 -m unittest -v test_integration_all` — 10 локальных
тестов с имитацией дочерних инструментов; внешние сайты не сканируются.
