> Обновление единого запуска: JS, монитор, IDOR и Smuggling подключены через `start.py --all`. Полная актуальная инструкция — [RUN_ALL_RU.md](RUN_ALL_RU.md).

# Pipeline Manager — комплект 1.3

`pipeline_manager.py` соединяет внешний Recon, готовый `scanner.py` и `post_scanner.py`. Работает на Ubuntu/Linux и Python 3.10+. Сам оркестратор использует только стандартную библиотеку; зависимости сканеров перечислены в `requirements.txt`.

Порядок: `targets.txt` → Recon → scope/нормализация/дедупликация → GET и POST → отчёты. Корневые домены обрабатываются последовательно. `--mode` задаёт порядок двух сканеров внутри одной цели.

## Быстрый запуск

Распакуй весь архив и установи зависимости:

```bash
cd bug_bounty_scanner
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
mkdir -p ~/bugbounty
```

Создай `~/bugbounty/targets.txt` и внеси только разрешённые домены, по одному на строку. Формат:

```text
# Это пример, замени на разрешённую цель.
example.invalid
```

Домен передаётся без `https://`, пути и порта. Пустые строки/комментарии пропускаются, повторы удаляются, неверные строки записываются в error log. IDN преобразуются в punycode.

Если установлен `gau`, последовательный проход:

```bash
python pipeline_manager.py \
  --recon-cmd 'gau --providers wayback --threads 2 {domain}' \
  --mode serial \
  --rate 5 --workers 10 --max-requests 1000
```

Этот вариант получает архивные URL как GET-кандидаты. Метод и тело POST из обычного URL-списка восстановить нельзя.

Для POST добавь файл собственных запросов:

```bash
python pipeline_manager.py \
  --recon-cmd 'gau --providers wayback --threads 2 {domain}' \
  --post-input ~/bugbounty/post_requests.jsonl \
  --modules xss,lfi,redirect,sqli,ssti,crlf \
  --mode parallel \
  --rate 5 --workers 10 --max-requests 1000
```

`post_requests.jsonl` — JSON Lines: каждый запрос занимает одну строку. Если POST-записей нет, запускается только GET. Название пути, расширение `.php` или слово `login` не превращают GET в POST.

Для SSRF добавь собственный домен взаимодействий и передай его оркестратору:

```bash
python pipeline_manager.py \
  --recon-cmd 'gau --providers wayback {domain}' \
  --modules ssrf --oast-domain 'your-issued-oast.example' \
  --mode parallel
```

`--oast-domain` обязателен только если выбран `ssrf`. UUID-пробы попадут в отчёты соответствующего GET/POST-сканера (`oast_probes.jsonl`); наличие HTTP-ответа от цели не является доказательством SSRF.

## Внешний Recon

`--recon-cmd` разбирается через `shlex.split`, после чего аргументы передаются `asyncio.create_subprocess_exec`. Shell не запускается. `|`, `>`, `&&`, `$()` и переменные shell не раскрываются. Для команд-конвейеров используй собственный wrapper-скрипт.

Два placeholders:

- `{domain}` — текущий нормализованный корневой домен; обязателен;
- `{output}` — абсолютный путь нового файла результатов; обязателен для `--recon-output file`.

Если твой Recon пишет URL в stdout:

```bash
python pipeline_manager.py \
  --recon-cmd 'python3 /absolute/path/my_recon.py --domain {domain}'
```

Если он пишет в файл:

```bash
python pipeline_manager.py \
  --recon-cmd 'python3 /absolute/path/my_recon.py --domain {domain} --output {output}' \
  --recon-output file
```

Имена опций `--domain/--output` здесь условные: замени их на опции своего скрипта. Путь скрипта указывай абсолютным. Для ресурсов относительно рабочей папки есть `--recon-cwd /absolute/path`.

Recon должен вернуть exit code `0`; результат находится в stdout либо в указанном файле. Диагностику направляй в stderr. При падении, таймауте или превышении лимита stdout частичный recon не передаётся GET-сканеру. Дополнительные POST-записи могут обрабатываться независимо.

## Формат данных

TXT-строка трактуется как GET-кандидат:

```text
https://example.invalid/search?q=test&lang=en
```

Recon может отдавать смешанный JSONL:

```jsonl
{"method":"GET","url":"https://example.invalid/search?q=test"}
{"method":"POST","url":"https://example.invalid/search","content_type":"application/x-www-form-urlencoded","body":"q=test&lang=en","params":["q"]}
{"method":"POST","url":"https://example.invalid/api/search","content_type":"application/json","body":{"query":"test","limit":10},"params":["query"]}
```

Для POST требуется `body`. Поддерживаются JSON-объект/массив или строка JSON для `application/json`, а для form-urlencoded — строка в исходной кодировке. Повторяющиеся ключи, NaN/Infinity и некорректный Unicode отклоняются. Каждый POST endpoint с отдельным телом получает собственный запуск сканера. `params` необязателен; он ограничивает проверяемые поля. Все остальные значения остаются исходными при мутации сканером.

Подписанные JSON-тела лучше передавать строкой: исходная строка сохраняется для baseline. GET query не сортируется; percent-encoding, порядок параметров и повторные имена сохраняются. GET дедуплицируется по нормализованному URL, POST — по URL, телу, формату и `params`.

Автоматическая авторизация, обновление CSRF и импорт заголовков из recon в этой версии не реализованы. POST-записи с `headers`/`cookies` отклоняются. Для авторизованных сценариев нужен отдельный адаптер с привязкой credentials к origin. Изменяющие состояние операции проверяй на собственных тестовых данных в соответствии с правилами программы.

`pipeline_examples/` содержит вымышленные шаблоны, а не результаты разведки. Подготовку можно проверить без внешнего Recon и запуска сканеров:

```bash
python pipeline_manager.py \
  --targets pipeline_examples/targets.example.txt \
  --recon-input pipeline_examples/recon.example.jsonl \
  --post-input pipeline_examples/post_requests.example.jsonl \
  --dry-run
```

`--dry-run` отключает только сканеры. Если указан `--recon-cmd`, внешняя команда Recon всё равно выполняется. `--recon-input` использует уже готовый файл без subprocess Recon.

## Scope

По умолчанию разрешён только точный hostname из `targets.txt` и порты 80/443. Поддомены включаются явным `--include-subdomains`. `example.invalid.evil.test` и `evil-example.invalid` не принимаются за поддомены.

```bash
python pipeline_manager.py \
  --recon-cmd 'gau --subs {domain}' \
  --include-subdomains \
  --exclude-host private.example.invalid \
  --ports 80,443
```

`--exclude-host` можно повторять; исключается указанный hostname и его поддомены. Здесь реализован scope по hostname/порту. При ограничениях программы по путям заранее фильтруй input своим Recon/adaptor. GET запускается с `--no-discovery`, чтобы не расширять переданный набор endpoint-ов. Оба готовых сканера отключают переходы по Location.

Scope-фильтр применяется к данным перед сканерами. Внешний Recon сам отвечает за свои сетевые запросы и ограничения программы; оркестратор не анализирует его внутреннюю работу.

## Serial, parallel и лимиты

| Опция | По умолчанию | Поведение |
|---|---:|---|
| `--mode` | serial | GET завершается, затем POST; parallel запускает две ветки вместе |
| `--rate` | 5 | rate для сканеров одной цели; в parallel делится между активными ветками |
| `--workers` | 10 | максимум запросов одновременно; в parallel делится между ветками |
| `--max-requests` | 1000 | общий бюджет сканеров одной цели, включая baseline/контроли |
| `--http-timeout` | 5 | сетевой таймаут, переданный сканерам |
| `--recon-timeout` | 600 | таймаут одного процесса Recon, секунды |
| `--scanner-timeout` | 1800 | таймаут каждого процесса GET/POST, секунды |
| `--kill-grace` | 5 | время на мягкое завершение, затем SIGKILL |
| `--max-roots` | 100 | максимум корневых доменов |
| `--max-records` | 100 | максимум GET и отдельно POST записей на цель |
| `--max-input-mib` | 20 | максимальный размер входного файла |
| `--max-log-mib` | 20 | лимит каждого stdout/stderr процесса |
| `--modules` | xss,lfi,redirect | `xss,lfi,redirect,sqli,ssrf,ssti,crlf` через запятую |
| `--oast-domain` | — | OAST/DNS-домен; обязателен при `ssrf` |

В `serial` активный сканер получает полный rate/workers. Если работают обе ветки `parallel`, каждая получает половину rate и половину workers; нечётное число workers округляется вниз. Например, `--rate 6 --workers 8` даёт каждой ветке 3 req/s и 4 worker. Таймеры у процессов независимы, поэтому два старта могут совпасть; это разделение rate, а не единая глобальная очередь HTTP-запросов.

POST-шаблоны выполняются по очереди внутри POST-ветки. Между ними выдерживается пауза не меньше `1 / rate_ветки`, чтобы новый процесс не обходил лимит сбросом таймера.

Если есть обе ветки, бюджет запросов разделяется между ними. POST-бюджет дальше распределяется между шаблонами. Неиспользованный бюджет не перераспределяется. Поэтому `--max-requests` — верхняя граница, а не требуемое число запросов. Лимит внешнего Recon задаётся его собственными аргументами.

## Ошибки, процессы и файлы

У каждого процесса отдельные `stdout.log`/`stderr.log`. Вывод читается потоками с ограничением размера, не копится целиком в памяти. При таймауте/остановке оркестратор посылает SIGTERM всей новой process group, ждёт `--kill-grace`, затем SIGKILL. Это завершает и обычных потомков wrapper-скрипта; процессы, намеренно покинувшие группу, требуют внешнего supervisor/container.

Сбой GET, включая исключение внутри его ветки, не блокирует POST; сбой Recon не блокирует следующую корневую цель. Ошибки записываются JSON-строками в `~/bugbounty/pipeline_errors.log`. Orchestrator summary различает состояние процесса и статус отчёта сканера; exit code `0` без `summary.json` или с неизвестным статусом также отмечается как ошибка интеграции. Логи дочерних процессов сбрасываются на диск по мере чтения.

`--dry-run` запускает Recon и подготавливает входные файлы без сканеров. Поэтому маленький HTTP-бюджет или один worker при `parallel` не мешают подготовке данных; для реального запуска ограничения проверяются.

Новый запуск создаёт уникальную папку в `~/bugbounty/runs/`. В ней находятся:

- `pipeline_summary.json` — сводка и состояния стадий;
- `<domain>/get_urls.txt` и `post_requests.jsonl` — подготовленные данные;
- `<domain>/logs/recon/` и `logs/get/` — логи;
- `<domain>/get_results/` — отчёты GET;
- `<domain>/post_jobs/0001/body.txt`, `logs/`, `results/` — отдельный POST-запрос.

Сводка сохраняется после каждой цели и при Ctrl+C/SIGTERM. Завершённые отчёты сохраняются; незавершённый scanner при SIGKILL может не успеть записать свой отчёт. Новые файлы CLI создаются с правами 600 и каталоги 700. Inputs/body/логи могут содержать чувствительные значения; не включай рабочую папку runs в публичный репозиторий.

`completed` в pipeline означает завершение автоматизации, а не отсутствие уязвимостей. `no_testable_requests` означает, что подходящих записей не было. Коды выхода: `0` — выполнение без ошибок оркестратора; `1` — ошибки/неполный проход; `2` — аргументы/среда; `130` — остановка.

## Тесты

```bash
python -m unittest -v test_pipeline_manager.py
```

Тесты запускают фиктивные локальные Recon/Scanner-процессы. Проверяют передачу данных, GET/POST разделение, нормализацию/scope, crash/timeout, ограничение stdout, уничтожение потомков, serial/parallel и частичное сохранение. Они не сканируют внешние сайты.

Описание интерфейсов subprocess: [Python 3.10 asyncio subprocess](https://docs.python.org/3.10/library/asyncio-subprocess.html). Формат запуска `gau`: [официальный репозиторий](https://github.com/lc/gau).
