# Подробный запуск всех скриптов на Ubuntu

Проверено по обновлённому архиву `bug_bounty_scanner_v1.3.zip` от 5 октября 2026 года,
который содержит `bbscanner/pipeline_extras.py` и четыре дополнительных сканера.
Работай с целями и типами проверки, разрешёнными выбранной программой.

Главная команда после настройки — `python3 start.py --all`. Но для выполнения
всех этапов нужны реальные входные данные. Флаг не создаёт POST-запросы, Cookie
двух аккаунтов, идентификаторы объектов или JS-ссылки. Отсутствующий вход означает
пропуск соответствующей проверки; это будет видно в сводке.

Все `example.test`, ID 100/200 и значения Cookie ниже — образцы. Замени их своими
данными. Не запускай образцы как реальные цели.

## 1. Что входит в запуск

| Компонент | Что делает | Что ему требуется |
|---|---|---|
| `start.py` | Выбирает настройки и Python, передаёт управление оркестратору | Распакованный проект целиком |
| `pipeline_manager.py` | Проверяет scope, запускает процессы, передаёт данные, собирает статусы | `targets.txt` и Recon |
| `subdomain_monitor.py` | DNS/HTTP, новые имена, кандидаты Takeover | Разрешённые домены; subfinder для сбора поддоменов |
| `gau` | Получает архивные URL | Доступ к архивному провайдеру либо готовый Recon-файл |
| `js_secrets_finder.py` | Ищет секреты и эндпоинты в JS | Доступные `.js` URL в Recon |
| `scanner.py` | XSS, LFI, Redirect, SQLi, SSTI, CRLF и SSRF в GET | URL с query-параметрами |
| `post_scanner.py` | Те же модули в POST | Реальные form/JSON тела |
| `idor_scanner.py` | Сравнивает доступ двух тестовых пользователей | Две Cookie-сессии, endpoint и ID объектов |
| `smuggling_scanner.py` | Ищет повторяемые framing-таймауты | Подготовленные нестатические URL, HTTP/1.1 |

Семь файлов `bbscanner/checks/{xss,lfi,redirect,sqli,ssrf,ssti,crlf}.py` импортируются
GET/POST-сканерами. Отдельно запускать их не нужно. `nuclei` и старый Bash-конвейер
в эту цепочку не входят.

## 2. Установить системные пакеты

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip unzip jq screen nano ca-certificates
python3 --version
go version
```

Python должен быть версии 3.10+. Если Go уже установлен и инструменты доступны,
переустанавливать его не нужно. Если `go` отсутствует либо сборка инструмента
требует более свежую версию, установи актуальный Go по официальной инструкции:
<https://go.dev/doc/install>. Не распаковывай новую версию поверх старого дерева Go.
Subfinder рекомендует актуальный Go; точную требуемую версию проверяет сборщик.

## 3. Распаковать именно новый комплект

Скачай обновлённый архив из сообщения. Для этой инструкции выделим отдельную папку,
чтобы не смешивать новые скрипты со старой копией проекта:

```bash
umask 077
mkdir -p ~/bugbounty/scanner_all
unzip ~/Downloads/bug_bounty_scanner_v1.3.zip -d ~/bugbounty/scanner_all
cd ~/bugbounty/scanner_all/bug_bounty_scanner
ls start.py pipeline_manager.py scanner.py post_scanner.py
ls js_secrets_finder.py subdomain_monitor.py idor_scanner.py smuggling_scanner.py
ls bbscanner/pipeline_extras.py
```

Если браузер сохранил файл в `~/Загрузки/` или изменил его имя, подставь настоящий
путь в `unzip`. Команда предполагает, что `scanner_all` ещё не содержит другой
копии комплекта. Не запускай старый `start.py` из соседней папки.

## 4. Создать виртуальное окружение

Из папки проекта:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pip check
python3 -c 'import aiohttp, bs4, colorama, aiodns; print("Python-зависимости готовы")'
python3 start.py --help
```

`(.venv)` в начале строки терминала означает, что окружение включено. Скрипты
запускай своим обычным пользователем, без `sudo python3`.

## 5. Установить внешние инструменты

```bash
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

При стандартном GOPATH бинарники окажутся в `~/go/bin`. Добавь этот каталог в PATH:

```bash
export PATH="$HOME/go/bin:$PATH"
printf '\nexport PATH="$HOME/go/bin:$PATH"\n' >> ~/.bashrc
command -v gau subfinder interactsh-client
gau --version
subfinder -version
interactsh-client -version
```

Строку в `.bashrc` достаточно добавить один раз. Если настраивал `GOBIN`/`GOPATH`,
проверь `go env GOBIN GOPATH` и используй фактическую папку бинарников.

`gau` не требуется при `--recon-input`. `subfinder` не требуется, когда монитор
проверяет только точные имена без `--include-subdomains`. `interactsh-client`
нужен только для выбранного здесь способа получения OAST-домена; можно использовать
свой совместимый логгер. Некоторые источники subfinder работают только с API-ключами,
но наличие ключей для всех источников не является условием запуска.

## 6. Заполнить targets.txt — список разрешённых хостов

```bash
mkdir -p ~/bugbounty/cookies
chmod 700 ~/bugbounty/cookies
nano ~/bugbounty/targets.txt
```

Пример точного scope:

```text
app.example.test
api.example.test
```

Пиши по одному hostname на строку, без `https://`, `/path`, `:443` и `*.`.
`~` означает домашнюю папку твоего пользователя: обычно `/home/arman`.
Таким образом, `~/bugbounty/targets.txt` — обычный текстовый файл на твоём ноутбуке.

В nano: Ctrl+O, Enter — сохранить; Ctrl+X — выйти.

Если разрешены только шесть конкретных доменов, впиши эти шесть имён и не добавляй
`--include-subdomains`. Если явно разрешено `*.example.test`, можно указать
`example.test` и включить `--include-subdomains`, однако этот флаг включает и сам
корень. Если корень не разрешён, безопаснее перечислить разрешённые конкретные
хосты. `--exclude-host` исключает имя вместе с его поддоменами.

## 7. Подготовить Recon так, чтобы были GET и JS

По умолчанию launcher сам вызывает gau для каждого имени из targets. Архив может
не содержать нужных текущих URL; отсутствие GET или JS-входа приводит к пропуску
соответствующего этапа.

Для первого контролируемого запуска удобно подготовить файл заранее:

```bash
gau --providers wayback --threads 2 \
  --o ~/bugbounty/recon_urls.txt < ~/bugbounty/targets.txt
nano ~/bugbounty/recon_urls.txt
```

В этот же файл добавь реальные ссылки, которые видишь в браузере: GET-запросы
с параметрами и JS-файлы. Пример формата:

```text
https://app.example.test/search?q=hello
https://app.example.test/assets/main.js
https://app.example.test/assets/app.js?v=2026
https://api.example.test/items?page=1
```

Откуда брать ссылки: открой разрешённый сайт, нажми F12 → Network, обнови страницу.
Для JS выбери фильтр JS и скопируй Request URL. Для API используй Fetch/XHR и
посмотри запросы при поиске, открытии списка или карточки объекта.

GET-сканер получает URL с именованными query-параметрами. JS-сканер выбирает путь,
оканчивающийся на `.js`, при этом `?v=...` ему не мешает. Файлы `.mjs`, inline JS
и выполнение JavaScript браузером в текущий этап не входят. Ссылки на сторонний
CDN вне scope будут отфильтрованы.

`--recon-input` заменяет автоматический gau на этот файл; POST-файл подключается
отдельно. Найденные в JS эндпоинты проходят повторный scope-фильтр. В GET добавляются
только ссылки с параметрами. Парсить страницы рекурсивным crawler этот launcher
не начинает: GET здесь запускается с `--no-discovery`.

## 8. Подготовить POST-шаблоны

```bash
nano ~/bugbounty/post_requests.jsonl
```

Одна строка — один полный JSON-объект. Пример обычной формы:

```json
{"method":"POST","url":"https://app.example.test/search","content_type":"application/x-www-form-urlencoded","body":"query=hello&page=1","params":["query"]}
```

Пример JSON POST:

```json
{"method":"POST","url":"https://api.example.test/search","content_type":"application/json","body":{"query":"hello","page":1},"params":["query"]}
```

В Network выбери реальный POST, скопируй Request URL, Content-Type и Request Payload
либо Form Data. Оставь необходимые серверу поля. `params` задаёт поля, которые будут
мутироваться; остальные поля остаются исходными. Не вставляй команду «Copy as cURL»
целиком в JSONL и не придумывай endpoint, которого на сайте нет.

Для проверки формата:

```bash
jq -c . ~/bugbounty/post_requests.jsonl >/dev/null
```

Успешный `jq` проверяет только синтаксис JSON, а не работоспособность запроса.
Не используй для таких повторных проверок операции покупки, удаления или изменения
профиля; выбери разрешённый endpoint, который читает данные или выполняет поиск.

Ограничение текущей версии: обычные GET/POST через `start.py` не получают Cookie
из IDOR-конфига и не принимают `headers`/`cookies` в POST JSONL. Эти поля будут
отклонены. Если endpoint требует Bearer или Cookie-заголовок, запуск процесса сам
по себе не означает тестирование за авторизацией. Для такого сценария нужна
отдельная настройка авторизованного сканера; этот гайд не добавляет отсутствующую
в launcher передачу заголовков.

## 9. Подготовить два тестовых аккаунта для IDOR

Создай два своих аккаунта там, где программа разрешает тестовые регистрации.
Удобно открыть первый в обычном профиле браузера, второй — в отдельном профиле.
Создай по тестовому объекту у каждого: например, документ или запись.

Допустим, первый аккаунт владеет объектом `100`, второй — `200`.
Эти значения должны быть реальными ID, а не номерами из примера.

В DevTools → Network выбери авторизованный запрос чтения объекта. В Request Headers
найди `Cookie` и скопируй только его значение:

```text
session=REAL_SESSION_VALUE; another_cookie=REAL_VALUE
```

Создай файлы:

```bash
nano ~/bugbounty/cookies/account1.txt
nano ~/bugbounty/cookies/account2.txt
chmod 600 ~/bugbounty/cookies/account1.txt ~/bugbounty/cookies/account2.txt
```

В каждом должна быть одна строка, без префикса `Cookie:` и без внешних кавычек.
Нужны действительные разные сессии. Не выходи из этих аккаунтов перед проверкой:
logout может аннулировать Cookie. Если сессии истекли, скопируй новые значения.

Теперь создай IDOR-конфигурацию:

```bash
nano ~/bugbounty/idor_requests.jsonl
```

Пример GET:

```json
{"url":"https://app.example.test/orders?id=100","cookie_victim_file":"cookies/account1.txt","cookie_attacker_file":"cookies/account2.txt","attacker_ids":{"id":200},"id_params":["id"],"mode":"direct"}
```

Смысл: URL содержит ID объекта первого аккаунта; `attacker_ids` содержит собственный
ID второго аккаунта. Это нужно, чтобы сравнение действительно имело контрольные
ответы. Пути `cookies/...` отсчитываются от папки конфигурации, то есть здесь от
`~/bugbounty/`, а не от папки скриптов.

Если проверяемое чтение реализовано POST, пример другой строки:

```json
{"url":"https://api.example.test/orders/read","data":{"order_id":100},"json":true,"cookie_victim_file":"cookies/account1.txt","cookie_attacker_file":"cookies/account2.txt","attacker_ids":{"order_id":200},"id_params":["order_id"],"mode":"direct"}
```

Используй только подходящий реальный вариант. Начни с `direct`. `increment`/`both`
дополнительно проверяют соседние числовые ID; для первого запуска они не нужны.
Текущая IDOR-интеграция использует Cookie, не отдельные Bearer/CSRF-заголовки.

```bash
chmod 600 ~/bugbounty/post_requests.jsonl ~/bugbounty/idor_requests.jsonl
jq -c . ~/bugbounty/idor_requests.jsonl >/dev/null
```

## 10. Подготовить OAST для SSRF

В отдельном терминале запусти Interactsh и оставь его работающим:

```bash
umask 077
mkdir -p ~/bugbounty/oast
interactsh-client \
  -sf ~/bugbounty/oast/session.json \
  -json -o ~/bugbounty/oast/interactions.jsonl
```

Клиент покажет индивидуальный домен вида `<session-id>.oast.…`. Если используемая
версия/сервер запрашивает авторизацию, выполни настройку по документации Interactsh
или используй свой разрешённый OAST-сервер. Продолжай после получения действующего
домена и подключения клиента.

В сканер передаётся полный индивидуальный домен: без `http://`, `/probe`, порта
и без выдуманного UUID. Не передавай просто общий `oast.pro` и не используй домен
чужой сессии. Скрипт сам добавит уникальный nonce перед этим доменом.

Второй терминал позже спросит этот домен через `read`. Cookie от тестируемого сайта
к OAST-домену отношения не имеют.

SSRF-модуль сохраняет факт попытки и nonce, но не опрашивает Interactsh автоматически.
`oast_pending` означает «сопоставь с DNS/HTTP-журналом», а не «SSRF подтверждён».
Журнал сохраняется в `~/bugbounty/oast/interactions.jsonl`; session-файл позволяет
клиенту попытаться продолжить ту же сессию, пока она действительна.

## 11. Подготовка без сканирования и локальные тесты

В папке проекта и с активированной `.venv`:

```bash
python3 start.py --all \
  --targets ~/bugbounty/targets.txt \
  --recon-input ~/bugbounty/recon_urls.txt \
  --post-input ~/bugbounty/post_requests.jsonl \
  --idor-config ~/bugbounty/idor_requests.jsonl \
  --dry-run
```

Эта команда читает готовые файлы и готовит входы без запуска сетевых сканеров.
Она не доказывает, что сессии ещё действуют или сервер принимает тела запросов.
Один `--dry-run` без `--recon-input` всё равно запустил бы внешний Recon.

При желании один раз выполни уже включённые 10 локальных интеграционных тестов:

```bash
python3 -m unittest -v test_integration_all
```

Ожидается `Ran 10 tests` и `OK`. Это проверки связки процессов и CLI на имитациях,
а не доказательство обнаружения уязвимостей реальных сайтов.

## 12. Полный запуск

Для работы в фоне сначала создай screen-сессию:

```bash
screen -S bounty_pipeline
```

Внутри неё:

```bash
cd ~/bugbounty/scanner_all/bug_bounty_scanner
source .venv/bin/activate
read -r -p 'Твой индивидуальный OAST-домен: ' OAST_DOMAIN

python3 start.py --all \
  --targets ~/bugbounty/targets.txt \
  --recon-input ~/bugbounty/recon_urls.txt \
  --post-input ~/bugbounty/post_requests.jsonl \
  --idor-config ~/bugbounty/idor_requests.jsonl \
  --oast-domain "$OAST_DOMAIN" \
  --modules xss,lfi,redirect,sqli,ssrf,ssti,crlf \
  --mode serial \
  --rate 2 \
  --workers 4 \
  --max-requests 1000 \
  --extra-max-requests 200 \
  --http-timeout 10 \
  --smuggling-timeout 6 \
  --scanner-timeout 3600
```

Enter после `read`: вставь домен из работающего Interactsh. Без screen можно выполнить
те же команды в обычном терминале. Для автоматического gau вместо готового Recon
удали строку `--recon-input ...`; остальные входные файлы останутся подключены.

`serial` выбран для понятного первого прохода. Для одновременных GET и POST поставь
`--mode parallel`. Другие этапы продолжают выполняться последовательно.

Ctrl+A, затем D — отсоединиться от screen, оставив процесс работающим.

```bash
screen -ls
screen -r bounty_pipeline
```

Ctrl+C внутри сессии останавливает конвейер. Screen не сохраняет выполнение после
выключения, перезагрузки или сна ноутбука. Не закрывай работающий OAST-клиент;
его тоже можно запустить в отдельной screen-сессии.

### Если разрешены поддомены

К полной команде можно добавить `--include-subdomains`. При готовом Recon это
разрешит соответствующие ссылки из файла и включит сбор поддоменов монитором.

Если нужен автоматический архивный Recon с поддоменами, убери `--recon-input` и
добавь все три параметра:

```text
--include-subdomains
--recon-cmd 'gau --providers wayback --subs --threads 2 --o {output} {domain}'
--recon-output file
```

`--include-subdomains` управляет scope, но сам не добавляет `--subs` в команду gau.
Монитор не передаёт найденные имена обратно в gau автоматически. Смешанный scope
«у одних корней поддомены разрешены, у других нет» лучше разделить на разные запуски.

### Как действуют лимиты

`--rate` — частота активных сканеров, а `--workers` — конкурентность. В parallel
GET/POST делят эти лимиты между ветками. Они не ограничивают абсолютно весь DNS/HTTP
трафик внешних программ. `--monitor-recon-rate` отдельно задаёт rate subfinder;
gau использует собственные настройки.

`--max-requests` — общий бюджет GET/POST на корень. `--extra-max-requests` — отдельный
бюджет каждого из JS, IDOR и Smuggling, не всего конвейера сразу. При значении 200
Smuggling резервирует до 14 соединений на URL и выбирает максимум 14 URL.

По умолчанию `--max-records 100`: длинные архивные списки будут ограничены. Если
вход упирается в предел, сначала выбери релевантные URL либо осознанно увеличь лимит.
Увеличение лимитов не гарантирует полного прохода: есть таймауты, бюджеты и ошибки
серверов. Сообщение о неполной проверке нужно читать, а не трактовать как ноль багов.

## 13. Проверить, что этапы действительно выполнились

В начале запуска ожидаются настройки наподобие:

```text
JS=True; Monitor=True; Smuggling=True; IDOR-шаблонов=1
Модули: xss,lfi,redirect,sqli,ssrf,ssti,crlf
```

Это только включённые этапы. Затем должны появляться сообщения о запуске `monitor`,
`recon` (если он автоматический), `js`, `get`, `post_0001`, `idor_0001`, `smuggling`.
При готовом Recon его состояние будет `cached`. Детальный вывод дочерних сканеров
изолирован в stdout/stderr-файлах, поэтому не все находки видны прямо в общем терминале.

В конце будет путь к папке запуска. Либо после завершения можно выбрать последнюю:

```bash
RUN_DIR="$(python3 - <<'PY'
from pathlib import Path
folders = [p.parent for p in (Path.home()/'bugbounty/runs').glob('*/pipeline_summary.json')]
if not folders:
    raise SystemExit('Запусков пока нет')
print(max(folders, key=lambda p: p.name))
PY
)"

jq '{status,errors,monitor,idor_scope,targets:[.targets[] | {domain,status,get_urls,post_requests,resource_urls,js,get,post,idor,smuggling}]}' \
  "$RUN_DIR/pipeline_summary.json"
```

Если задан нестандартный `--output`, используй фактический путь из последней строки
конвейера: `RUN_DIR='/полный/путь/к/запуску'`. Автовыбор может выбрать dry-run, если
именно он был последним; проверяй `status` и `prepared_only`.

| Значение | Как понимать |
|---|---|
| `state: ok` | Процесс завершился с кодом 0; также проверь scanner_status и результаты |
| `state: skipped` | Этап не выполнялся; смотри reason |
| `get: []` или `post: []` | Для этой ветки не было входов либо она не была выполнена |
| `state: nonzero` | Ошибка дочернего процесса или неполное сканирование; смотри stderr/summary |
| `state: timeout` | Процесс остановлен по общему таймауту оркестратора |
| `completed_with_errors` | Конвейер дошёл до конца, но часть работы неполна |
| `oast_pending` | SSRF-проверка ждёт ручного сопоставления с журналом OAST |
| `candidate` | Автоматический признак, который требует ручной проверки |

Успешный запуск не означает, что найдены уязвимости. Повторяемый таймаут Smuggling
не доказывает десинхронизацию; файл `exploited.jsonl` содержит кандидатов. IDOR,
Takeover и найденные секреты также требуют проверки контекста.

## 14. Где смотреть результаты

| Путь относительно папки запуска | Содержимое |
|---|---|
| `pipeline_summary.json` | Сводка всех этапов |
| `<домен>/get_results/summary.json` | Полнота GET-проверки |
| `<домен>/get_results/findings.json` | GET-находки |
| `<домен>/post_jobs/0001/results/` | Результаты первого POST-шаблона |
| `<домен>/js_results/secrets.jsonl` | Секреты-кандидаты |
| `<домен>/js_results/extracted_endpoints.txt` | Все извлечённые ссылки, включая сторонние |
| `<домен>/js_endpoints_in_scope.txt` | Ссылки после scope-фильтра |
| `<домен>/idor_jobs/0001/results/findings.jsonl` | IDOR-кандидаты и ответы |
| `<домен>/smuggling_results/exploited.jsonl` | Кандидаты Smuggling и точные пакеты |
| `<домен>/logs/` | Логи Recon/JS/GET/Smuggling; у POST/IDOR — внутри job |

История монитора: `~/bugbounty/monitor_results/<scope-id>/`, в том числе
`known_subdomains.txt`, `new_discovered.txt`, `takeover_candidates.jsonl`.
Точный output монитора есть в общей сводке. Журнал ошибок конвейера:
`~/bugbounty/pipeline_errors.log`.

```bash
jq -r '.. | objects | .stderr? // empty' "$RUN_DIR/pipeline_summary.json"
tail -n 50 ~/bugbounty/pipeline_errors.log
```

Первая команда покажет пути к stderr. Открой нужный файл через `less ПУТЬ`.
Для текущего лога можно использовать `tail -f ПУТЬ_К_stdout.log`; Ctrl+C завершит
просмотр, если он открыт в отдельном терминале.

## 15. Частые причины пропуска или ошибки

| Проблема | Что проверить |
|---|---|
| `gau` / `subfinder` не найден | `command -v`, PATH, установка нужного инструмента |
| `No module named ...` | Активирована ли .venv; `python3 -m pip install -r requirements.txt` |
| `unrecognized arguments: --all` | Используется старый start.py или флаг передан напрямую pipeline_manager.py |
| `no_js_urls...` | В Recon есть доступные `.js` URL того же scope и они не отрезаны лимитом |
| GET не выполняется | Есть ли URL с query-параметрами; путь `/orders/100` сам по себе не query |
| POST не выполняется | Непустой JSONL, method POST, корректное body, URL в scope |
| `no_idor_config` | Файл IDOR существует/не пуст, передан --idor-config или используется --all |
| `no_matching_idor_templates` | Хост IDOR соответствует targets, исключениям и портам |
| HTTP 401/403 или login page | Cookie истекли, запрос требует авторизацию; обычные GET/POST не берут IDOR Cookie |
| `records_rejected` / `over_limit` | Формат записей и лимит --max-records; подробности в pipeline_summary.json |
| `oast_pending`, но нет callback | Действителен ли домен/клиент; отсутствие взаимодействий само по себе не ошибка запуска |
| Монитор долго работает | Он первый и делает DNS/HTTP; смотри logs/monitor/stdout.log |
| Таймаут сканера | Отличай сетевой --http-timeout от общего --scanner-timeout; читай stderr и summary |

Скрипты в этой версии не используют Tor автоматически. Запуск под sudo, смена
текущей папки или использование старой копии архива часто меняют HOME/PATH/venv и
приводят к поиску неправильных файлов.

При последующих запусках установка не повторяется: перейди в папку проекта,
активируй `.venv`, обнови истёкшие Cookie и используй действующий OAST-домен.

## Официальные инструкции для внешних инструментов

- gau: <https://github.com/lc/gau>
- Subfinder: <https://docs.projectdiscovery.io/opensource/subfinder/install>
- Interactsh CLI: <https://github.com/projectdiscovery/interactsh>
- Запуск Interactsh: <https://docs.projectdiscovery.io/opensource/interactsh/running>
- Go: <https://go.dev/doc/install>
