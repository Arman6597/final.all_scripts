# Асинхронные модули проверок — версия 1.3

Четыре независимые проверки находятся в `bbscanner/checks/sqli.py`, `ssrf.py`, `ssti.py` и `crlf.py`. Общие dataclasses `Outcome` и `Signal` импортируются из `bbscanner/probes.py`. Модули не создают HTTP-сессии: отправку, изолированную мутацию, cookies, timeout, rate и конкурентность обеспечивает переданный `send`.

## Интерфейс

У всех четырёх модулей одна точка входа:

```python
async def run(send, baseline, **kwargs) -> Outcome:
    ...
```

Как в текущем `PostScanner`, `send` принимает два позиционных аргумента:

```python
response = await send(payload, "sqli_probe")
control = await send(None, "sqli_control")  # Исходное тело без мутации.
```

`response` и `baseline` — объекты `ResponseData`: `.usable`, `.status`, `.text`, `.headers`, `.error`, `.truncated`. Ошибки HTTP-клиента текущий движок преобразует в `ResponseData(error=...)`; некорректное или неполное тело не считается отрицательным результатом. Отмена через `asyncio.CancelledError` продолжает распространяться для корректной остановки.

`Outcome` содержит:

```python
@dataclass
class Outcome:
    state: str = "negative"
    reason: str = "no_matching_signal"
    signals: list[Signal] = field(default_factory=list)
```

Значения `state`: `confirmed`, `negative`, `skipped`, `inconclusive`; у SSRF дополнительно `oast_pending`. Это статус проверки. `confirmed` подтверждает воспроизведение сигнала детектора с контрольным запросом; степень уверенности в самой находке хранится отдельно.

У `Signal` есть все требуемые поля: `confidence`, `payload`, `evidence`, `response`, `note`. Дополнительно сохранён `confirmation_payload`, который использует существующий движок. `confidence="candidate"` означает кандидата, `confidence="confirmed_signal"` — воспроизводимый технический признак. Неопределённое подтверждение может вернуть `inconclusive` вместе с первоначальным кандидатом в `signals`, чтобы находка не потерялась.

`ProbeResult` оставлен как псевдоним `Outcome` для совместимости старых импортов. GET-обёртки `scan(client, context)` также сохранены.

## Логика детекторов

| Модуль | Проверка |
|---|---|
| SQLi | Пробы `'`, `"`, `)`, `';`, `";`, `/*`; сигнатуры MySQL, PostgreSQL, MSSQL, Oracle. Ошибки в baseline дают `skipped`. Совпадение проверяется чистым контролем и повтором. Находка остаётся кандидатом SQLi. |
| SSTI | `{{7*7}}`, `${7*7}`, `<%=- 7*7 %>`; сохранён и положительный вариант `<%= 7*7 %>`. Baseline и свежий контроль должны быть чистыми. Подтверждение использует другие множители. |
| CRLF | `%0d%0aX-CRLF-Scan:+True`, `%%0d%%0aX-CRLF-Scan:+True`; сохранён дополнительный вариант с буквальными CRLF для JSON-тел. Имена заголовков сравниваются без учёта регистра. Контроль исключает статический заголовок; повтор меняет его значение. |
| SSRF | Уникальный UUID, `http://<nonce>.<domain>/probe`, асинхронная регистрация и `oast_pending`. HTTP-ответ цели не подтверждает взаимодействие. |

Выражение `<%=- 7*7 %>` вычисляет **−49**. Проверяется именно −49; оно не принимается за положительное 49. Числа внутри `1490`, `49.0` или идентификатора также не совпадают. Для SSTI требуется успешный полный ответ.

У SQLi учитываются полные HTTP 4xx/5xx с сигнатурами: в текущем `ResponseData` они имеют `usable=False`, но часто содержат нужную ошибку БД. Сетевые сбои и усечённые ответы исключаются. Для CRLF полный блок заголовков остаётся пригодным даже при последующем таймауте чтения тела.

## SSRF и журнал

Минимальный внешний журнал должен предоставлять асинхронный метод:

```python
class Journal:
    async def register_probe(self, *, nonce: str, metadata: dict) -> None:
        # Сохрани nonce и metadata в своём журнале.
        ...
```

Вызов:

```python
from bbscanner.checks.ssrf import run as check_ssrf

outcome = await check_ssrf(
    send,
    baseline,
    domain="your-issued-oast.example",
    journal=journal,
    metadata={"method": "POST", "url": target, "parameter": field.name},
)
```

Без `domain` возвращается `skipped`, запрос не отправляется. Входные metadata копируются; в копию добавляются `nonce`, `uuid`, `payload` и `module`. Перед отправкой выполняется `await journal.register_probe(nonce=nonce, metadata=metadata)`. Если запись не удалась, запрос не отправляется. Таймаут после регистрации даёт `oast_pending`: проверь nonce в DNS/HTTP-логах своего сервера.

Если журнал также предоставляет обычный метод `record(metadata, state, **details)`, модуль сохраняет состояние доставки. Для минимального внешнего журнала этот метод необязателен.

В комплектном GET/POST-движке используется дополнительный внутренний параметр `defer_registration=True`. Он переносит регистрацию в асинхронный `on_start` перед HTTP, после выделения бюджета и rate-слота. Поэтому пробы, которые движок не отправил из-за бюджета, не попадают в OAST-журнал. Оба HTTP-клиента теперь дожидаются этого callback; синхронные callbacks тоже поддерживаются.

## Подключение и обновление

Импорты для собственного `PostScanner`:

```python
from bbscanner.checks.sqli import run as check_sqli
from bbscanner.checks.ssti import run as check_ssti
from bbscanner.checks.crlf import run as check_crlf
from bbscanner.checks.ssrf import run as check_ssrf

outcome = await check_sqli(send, baseline)
for signal in outcome.signals:
    # Передай signal в свой существующий механизм отчётов.
    print(signal.confidence, signal.payload, signal.evidence)
```

Для готового сканера распакуй весь комплект 1.3. Помимо четырёх модулей изменены общие типы, журнал, реестр импортов и поддержка async-callback в GET/POST-клиентах. Обновление только четырёх файлов поверх старого общего пакета недостаточно.

```bash
cd bug_bounty_scanner
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -v
```

Тесты используют фиктивный транспорт, локальный aiohttp-сервер и локальные subprocess. Проверяются точная сигнатура `run`, dataclasses, baseline, отрицательные ответы, SQL HTTP 500, изоляция чисел, регистр заголовков, OAST-регистрация до отправки, уникальность UUID, бюджет и отмена. Реальные OAST-сервисы и сторонние цели не запрашиваются.

В комплекте 1.3 прошли **98 тестов**, включая 21 проверку нового интерфейса. Выполнение проверено на Python 3.12; все 25 Python-файлов дополнительно разобраны с грамматикой Python 3.10. Отдельный запуск на интерпретаторе 3.10 не выполнялся.
