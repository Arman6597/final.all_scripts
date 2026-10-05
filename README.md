Главное: --all включает все этапы, но для их выполнения нужны реальные входные данные. Без POST-запросов пропустится POST, без двух сессий — IDOR, без JS-ссылок — JS-анализ.
1. Установи необходимые пакеты Ubuntu
sudo apt update
sudo apt install -y python3 python3-venv python3-pip unzip jq screen nano ca-certificates

python3 --version
go version

Нужен Python 3.10 или новее. Если Go отсутствует или установленная версия слишком старая для сборки инструментов, установи актуальную версию по официальной инструкции Go. The Go Programming Language
2. Распакуй новый архив
Чтобы не смешивать старые и новые файлы, используй отдельную папку:
umask 077
mkdir -p ~/bugbounty/scanner_all

unzip ~/Downloads/bug_bounty_scanner_v1.3.zip \
  -d ~/bugbounty/scanner_all

cd ~/bugbounty/scanner_all/bug_bounty_scanner

Если архив находится в ~/Загрузки/, замени путь в команде.
Проверь наличие основных файлов:
ls start.py pipeline_manager.py scanner.py post_scanner.py
ls js_secrets_finder.py subdomain_monitor.py idor_scanner.py smuggling_scanner.py
ls bbscanner/pipeline_extras.py

3. Создай виртуальное окружение
Выполняй из папки проекта:
python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install -r requirements.txt
python3 -m pip check

Проверь зависимости:
python3 -c 'import aiohttp, bs4, colorama, aiodns; print("Зависимости готовы")'
python3 start.py --help

Скрипты запускай обычным пользователем, без sudo python3.
4. Установи внешние инструменты
Для архивных URL нужен gau, для сбора поддоменов — subfinder:
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

Это команды установки из документации проектов. Subfinder рекомендует актуальную версию Go. GitHub
Для SSRF через Interactsh:
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

Добавь стандартную папку Go-инструментов в PATH:
export PATH="$HOME/go/bin:$PATH"

Чтобы настройка сохранялась в новых терминалах, один раз выполни:
printf '\nexport PATH="$HOME/go/bin:$PATH"\n' >> ~/.bashrc

Проверь:
command -v gau subfinder interactsh-client

Должны появиться пути к трём программам. Если настраивал нестандартный GOBIN или GOPATH, используй фактическую папку бинарников.
5. Создай targets.txt
mkdir -p ~/bugbounty/cookies
chmod 700 ~/bugbounty/cookies

nano ~/bugbounty/targets.txt

Внутри — разрешённые домены, по одному на строку:
app.example.test
api.example.test

Замени примеры своими доменами из scope. Пиши без https://, путей и *..
В nano:
- Ctrl+O, затем Enter — сохранить.
- Ctrl+X — выйти.
~ — домашняя папка пользователя. Поэтому ~/bugbounty/targets.txt — обычный текстовый файл на твоём ноутбуке.
Если разрешены только конкретные шесть хостов, впиши именно их. Флаг --include-subdomains используй только при разрешении проверять их поддомены.
6. Подготовь URL для GET и JS
Для первого запуска удобно собрать Recon заранее:
gau --providers wayback --threads 2 \
  --o ~/bugbounty/recon_urls.txt \
  < ~/bugbounty/targets.txt

Открой результат:
nano ~/bugbounty/recon_urls.txt

Формат:
https://app.example.test/search?q=hello
https://app.example.test/assets/main.js
https://app.example.test/assets/app.js?v=2026
https://api.example.test/items?page=1

Здесь тоже нужны реальные ссылки твоей цели.
Если архив не нашёл нужные ссылки, добавь их из браузера:
1. Открой разрешённый сайт.
2. Нажми F12 → Network.
3. Обнови страницу.
4. Для JavaScript выбери фильтр JS, скопируй Request URL.
5. Для API посмотри Fetch/XHR при поиске или открытии списка.
Для GET нужны ссылки с параметрами вроде ?id=100. Для JS нужен путь, заканчивающийся на .js; параметры вроде ?v=2026 допустимы.
Сторонние CDN вне scope будут отфильтрованы. Текущий launcher не запускает рекурсивный crawler страниц.
7. Подготовь POST-запросы
nano ~/bugbounty/post_requests.jsonl

Каждый запрос — один JSON-объект на одной строке.
Пример обычной формы:
{"method":"POST","url":"https://app.example.test/search","content_type":"application/x-www-form-urlencoded","body":"query=hello&page=1","params":["query"]}

Пример JSON:
{"method":"POST","url":"https://api.example.test/search","content_type":"application/json","body":{"query":"hello","page":1},"params":["query"]}

Бери данные из реального запроса в Network:
- Request URL → url.
- Content-Type → content_type.
- Request Payload / Form Data → body.
- Поля для проверки → params.
Например, params:["query"] означает: менять только query, сохраняя остальные поля.
Проверка синтаксиса:
jq -c . ~/bugbounty/post_requests.jsonl >/dev/null

Выбирай подходящий запрос чтения или поиска, который можно повторять.
Ограничение текущей версии: обычные GET/POST через start.py не получают Cookie из IDOR-конфига. Поля headers и cookies в POST JSONL отклоняются. Поэтому авторизованный endpoint может возвращать 401/403, даже если IDOR-сессии настроены правильно.
8. Подготовь два аккаунта для IDOR
Нужны два твоих тестовых аккаунта и объекты, принадлежащие каждому из них.
Например:
- Первый аккаунт владеет объектом 100.
- Второй аккаунт владеет объектом 200.
Это должны быть настоящие ID твоих тестовых объектов.
Открой аккаунты в разных профилях браузера. Для каждого:
1. Открой его объект.
2. В Network выбери запрос чтения.
3. Найди Request Headers → Cookie.
4. Скопируй значение заголовка.
Создай файлы:
nano ~/bugbounty/cookies/account1.txt
nano ~/bugbounty/cookies/account2.txt

Содержимое каждого — одна строка:
session=РЕАЛЬНОЕ_ЗНАЧЕНИЕ; another_cookie=ЗНАЧЕНИЕ

Без префикса Cookie: и без внешних кавычек.
chmod 600 ~/bugbounty/cookies/account1.txt
chmod 600 ~/bugbounty/cookies/account2.txt

Теперь конфигурация:
nano ~/bugbounty/idor_requests.jsonl

Пример GET:
{"url":"https://app.example.test/orders?id=100","cookie_victim_file":"cookies/account1.txt","cookie_attacker_file":"cookies/account2.txt","attacker_ids":{"id":200},"id_params":["id"],"mode":"direct"}

Здесь:
- id=100 — объект первого аккаунта.
- attacker_ids: {"id":200} — собственный объект второго аккаунта.
- cookie_victim_file — сессия первого аккаунта.
- cookie_attacker_file — сессия второго.
Относительные пути cookies/... считаются от папки конфигурации — здесь от ~/bugbounty/.
Пример POST-чтения:
{"url":"https://api.example.test/orders/read","data":{"order_id":100},"json":true,"cookie_victim_file":"cookies/account1.txt","cookie_attacker_file":"cookies/account2.txt","attacker_ids":{"order_id":200},"id_params":["order_id"],"mode":"direct"}

Используй подходящий реальный вариант. Для начала оставь "mode":"direct".
chmod 600 ~/bugbounty/post_requests.jsonl ~/bugbounty/idor_requests.jsonl
jq -c . ~/bugbounty/idor_requests.jsonl >/dev/null

Если Cookie истекли — обнови файлы. Эта IDOR-интеграция поддерживает Cookie, но не отдельные Bearer-заголовки.
9. Запусти OAST для SSRF
В отдельном терминале:
umask 077
mkdir -p ~/bugbounty/oast

interactsh-client \
  -sf ~/bugbounty/oast/session.json \
  -json -o ~/bugbounty/oast/interactions.jsonl

Клиент выдаст индивидуальный домен. Скопируй его целиком и оставь клиент работающим. Флаг -sf сохраняет сведения о сессии, а -json записывает взаимодействия в JSON Lines. Если сервер требует авторизацию, сначала настрой её по документации Interactsh. GitHub
В сканер нужно передать свой индивидуальный домен, без https:// и пути. Не просто общий oast.pro.
Сканер сам добавляет nonce. Его oast_pending означает: проверь соответствующее взаимодействие в OAST-журнале. Автоматического подтверждения SSRF по журналу здесь нет.
10. Проверь подготовку без сканирования
Вернись в папку проекта с активированной .venv:
python3 start.py --all \
  --targets ~/bugbounty/targets.txt \
  --recon-input ~/bugbounty/recon_urls.txt \
  --post-input ~/bugbounty/post_requests.jsonl \
  --idor-config ~/bugbounty/idor_requests.jsonl \
  --dry-run

Так будут подготовлены входы без сетевых сканеров. Это не проверка действительности Cookie.
Важно: без --recon-input режим --dry-run всё равно запускает внешний Recon.
При желании один раз выполни 10 локальных интеграционных тестов:
python3 -m unittest -v test_integration_all

Ожидаемый итог — Ran 10 tests и OK.
11. Запусти все этапы
Чтобы процесс продолжал работать после закрытия SSH-соединения, сначала:
screen -S bounty_pipeline

Внутри screen:
cd ~/bugbounty/scanner_all/bug_bounty_scanner
source .venv/bin/activate

read -r -p 'Твой индивидуальный OAST-домен: ' OAST_DOMAIN

Вставь домен из работающего Interactsh, затем выполни:
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

Эта команда включает все семь GET/POST-модулей и дополнительные сканеры.
serial удобен для первого прохода. Для одновременных GET и POST замени на --mode parallel. Остальные этапы выполняются последовательно.
Чтобы использовать автоматический gau, убери строку --recon-input ....
Если разрешены поддомены, добавь --include-subdomains. При автоматическом gau для включения архивных URL поддоменов также нужны:
--recon-cmd 'gau --providers wayback --subs --threads 2 --o {output} {domain}'
--recon-output file

Сам --include-subdomains не добавляет --subs в gau. GitHub
12. Как отсоединиться и вернуться
В screen нажми Ctrl+A, затем D.
Вернуться:
screen -r bounty_pipeline

Посмотреть сессии:
screen -ls

Остановить сканирование — Ctrl+C внутри сессии. Screen не сохраняет выполнение после выключения или сна ноутбука.
13. Как убедиться, что всё действительно выполнилось
В начале должны появиться настройки примерно такого вида:
JS=True; Monitor=True; Smuggling=True; IDOR-шаблонов=1
Модули: xss,lfi,redirect,sqli,ssrf,ssti,crlf

Это означает, что этапы включены. Их фактическое выполнение смотри в pipeline_summary.json.
В конце скрипт напечатает папку:
~/bugbounty/runs/ПАПКА_ЗАПУСКА/

Результат	Значение
state: ok	Процесс завершился успешно; дополнительно смотри scanner_status
state: skipped	Проверка пропущена; причина находится в reason
get: [] / post: []	Ветка не выполнялась
nonzero / timeout	Ошибка или превышение таймаута
completed_with_errors	Конвейер завершён, но часть работы неполна


Детальный вывод дочерних сканеров сохраняется в отдельных логах, поэтому общий терминал не показывает каждую находку.
Основные результаты:
- GET: <домен>/get_results/findings.json.
- POST: <домен>/post_jobs/0001/results/.
- JS: <домен>/js_results/secrets.jsonl.
- IDOR: <домен>/idor_jobs/0001/results/findings.jsonl.
- Smuggling: <домен>/smuggling_results/exploited.jsonl.
- Монитор: ~/bugbounty/monitor_results/<scope-id>/.
- Ошибки: ~/bugbounty/pipeline_errors.log.
Нулевое количество находок и пропущенный этап — разные результаты. В скачиваемом гайде также есть команды просмотра сводки, объяснение лимитов и таблица типичных ошибок.
