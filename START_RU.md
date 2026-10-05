# Единый запуск

Полная актуальная инструкция: [RUN_ALL_RU.md](RUN_ALL_RU.md).

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 start.py --all
```

Нужен `~/bugbounty/targets.txt`. Реальные POST-шаблоны берутся из
`~/bugbounty/post_requests.jsonl`. IDOR требует `~/bugbounty/idor_requests.jsonl`
с двумя Cookie-файлами и собственными ID двух тестовых аккаунтов.

`--all` подключает JS Secrets, Subdomain Monitor, IDOR (при наличии конфигурации),
HTTP Request Smuggling и прежние GET/POST-сканеры. SSRF включается с
`--oast-domain DOMAIN`. Поддомены разрешаются только через `--include-subdomains`.
Без `--all` сохраняется прежний GET/POST-запуск; дополнительные этапы можно выбрать
через `--with-js`, `--with-monitor`, `--with-smuggling`, `--idor-config`.
