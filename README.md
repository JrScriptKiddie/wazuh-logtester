# Wazuh Logtester

**Русский** · [English](README.en.md)

Офлайн-стенд для отладки декодеров и правил Wazuh + прогон датасетов логов с
вердиктами по корреляции. Всё в Docker, без внешней сети во время работы.

## Что внутри

- **`wlogtest`** — Python-пакет (только stdlib): клиент протокола logtest
  (сокет `/var/ossec/queue/sockets/logtest`), модель датасета, движок вердиктов,
  раннер с поддержкой stateful-сессий (frequency / if_matched_sid / firedtimes),
  отчёты (console / JSON / JUnit) и CLI `wlogtest`.
- **`manager`** — контейнер `wlogtest-manager:4.14.7` (собирается из
  `docker/Dockerfile`, стадия `manager`): настоящий analysisd 4.14.7 из RPM
  wazuh-manager, без framework/API/wodles — только движок разбора логов
  (декодеры → правила → корреляция). Студенческие декодеры/правила монтируются
  в `/var/ossec/etc/decoders` и `/var/ossec/etc/rules`.
- **`runner`** — контейнер `python:3.12-slim` с пакетом `wlogtest`, общается с
  manager через общий volume `/var/ossec/queue` (там живёт unix-сокет logtest).
- **`examples/`** — эталонные декодер/правила и датасеты: `basic` (всё зелёное),
  `correlation` (stateful-сессия, frequency-правило), `fail_demo` (учебный FAIL).
- **`vendor/wazuh/`** — форк исходников Wazuh v4.14.7 (GPL-2.0) как эталон протокола.
- **`skills/`** — скилы для ИИ-агентов проекта (из skills.sh + собственные).

## Быстрый старт (по нарастающей)

Требования: **docker + compose v2**
(https://docs.docker.com/engine/install/).

### Apple Silicon (arm64)

RPM `wazuh-manager` собран только под x86_64, поэтому на Apple Silicon (и
других arm64-хостах) сборка без флага падает с ошибкой
`package wazuh-manager-4.14.7-1.x86_64 is intended for a different
architecture`. Перед командами стека включите amd64-платформу — образ
соберётся и запустится под эмуляцией (Rosetta в Docker Desktop):

```bash
export DOCKER_DEFAULT_PLATFORM=linux/amd64   # один раз в сессии
docker compose -f docker/docker-compose.yml build
```

либо добавляйте `DOCKER_DEFAULT_PLATFORM=linux/amd64` к каждой команде
`docker compose ...`. На x86-хостах ничего указывать не нужно; `runner` и
`runner-test` тоже собираются под amd64 — для них это не критично, но стек
должен быть одной платформы.

```bash
# 1) Клонировать проект
git clone https://github.com/JrScriptKiddie/wazuh-logtester.git
cd wazuh-logtester

# 2) Собрать образы (один раз, нужен интернет: RPM wazuh-manager ~513 МБ)
docker compose -f docker/docker-compose.yml build

# 3) Поднять движок (analysisd) — дождитесь healthcheck (появится сокет logtest)
docker compose -f docker/docker-compose.yml up -d manager

# 4) Первый прогон: датасет basic.json — 3/3 PASS
docker compose -f docker/docker-compose.yml run --rm runner run /data/datasets/basic.json

# 5) Корреляция: frequency-правило на stateful-сессии — 3/3 PASS
docker compose -f docker/docker-compose.yml run --rm runner run /data/datasets/correlation.json

# 6) Одно событие вручную (3-фазный вывод, как у оригинального wazuh-logtest)
docker compose -f docker/docker-compose.yml run --rm runner \
  logtest -e "Aug 27 10:00:00 myserver myapp[1234]: login user=alice status=failed"
```

Все последующие прогоны работают без сети. Вывод `logtest` — те же три
фазы, что и у оригинального `wazuh-logtest` (pre-decoding → decoding →
rule matching):

```
**Phase 1: Completed pre-decoding.
	full event: 'Aug 27 10:00:00 myserver myapp[1234]: login user=alice status=failed'
	timestamp: 'Aug 27 10:00:00'
	hostname: 'myserver'
	program_name: 'myapp'

**Phase 2: Completed decoding.
	name: 'myapp_decoder'
	dstuser: 'alice'
	status: 'failed'

**Phase 3: Completed filtering (rules).
	id: '100101'
	level: '6'
	description: 'myapp: user login failed.'
	groups: '['hw', 'local']'
	firedtimes: '1'
	mail: 'False'
**Alert to be generated.
```

Флаг `--json` печатает сырой JSON-ответ протокола (полезно для отладки).
Флаг `--debug` включает трассировку правил (`**Rule debugging:` в выводе).

Интерактивный режим с постоянной сессией:

```bash
docker compose -f docker/docker-compose.yml run --rm runner logtest -i
```

## Формат датасета

```json
{
  "name": "hw1",
  "description": "проверка ДЗ по корреляции",
  "session_mode": "per_test",        // или "shared" — одна сессия на все кейсы
  "default_location": "stdin",
  "default_log_format": "syslog",
  "tests": [
    {
      "name": "ssh failed password",
      "event": "Aug 27 10:00:00 myserver sshd[1234]: Failed password ...",
      "location": "auth.log",         // переопределяет default (опционально)
      "session": "bruteforce",        // именованная сессия (опционально)
      "skip": false,
      "expect": {
        "decoder.name": "sshd",
        "data.srcip": "1.2.3.4",
        "rule.id": "5710",
        "alert": true
      }
    }
  ]
}
```

`expect` проверяет поля ответа logtest: `decoder.name`, `rule.id`, `rule.level`,
`rule.description`, `rule.firedtimes`, `data.<field>`, `full_log`, `alert`,
`messages`, `token`.

### Матчеры

| Формат | Семантика |
|---|---|
| `"значение"` / число / `true` / `null` | точное равенство (`null` — поле отсутствует) |
| `{"eq": v}` / `{"ne": v}` | равно / не равно |
| `{"gt": n}` / `{"gte": n}` / `{"lt": n}` / `{"lte": n}` | сравнения |
| `{"in": [...]}` / `{"nin": [...]}` | в списке / не в списке |
| `{"contains": "строка"}` | подстрока (или элемент/подстрока в списке `messages`) |
| `{"regex": "шаблон"}` | `re.search` по строковому представлению |
| `{"exists": true|false}` | поле присутствует / отсутствует |
| `{"any": [m1, m2]}` / `{"all": [m1, m2]}` | ИЛИ / И по вложенным матчерам |

Простое значение (без объекта-матчера) для `messages` работает как `contains`
по любому элементу списка — например `"messages": "No decoder matched"`.

### Корреляция

Правила с состоянием (`<frequency>`, `if_matched_sid`, счётчик firedtimes)
работают только когда кейсы живут в одной сессии. Включите `"session_mode":
"shared"` — раннер один раз получит токен и прогонит все события через него
(пример — `examples/datasets/correlation.json`: на третьем одинаковом событии
срабатывает frequency-правило 100102). Именованные сессии (`"session": "name"`)
работают в любом режиме и позволяют гонять несколько независимых цепочек
корреляции в одном датасете.

Выход: консольный отчёт `[PASS]/[FAIL]/[ERROR]` с причинами расхождений,
`--json` — полный отчёт, `--junit` — XML для CI, `-o report.txt` — в файл.
Код возврата: 0 — все кейсы PASS, 1 — есть FAIL/ERROR.

## Свои декодеры и правила

Положите файлы в `examples/decoders/` и `examples/rules/` (или смонтируйте свои
директории в `docker/docker-compose.yml`), перезапустите manager:

```bash
docker compose -f docker/docker-compose.yml restart manager
```

Ошибки XML видны в поле `messages` ответа (например
`ERROR: (1203): Invalid configuration ...`) и в отчёте как status `error`.

## Полностью офлайн (air-gapped класс)

1. На машине с сетью: `docker compose -f docker/docker-compose.yml build manager runner runner-test`
   (для manager это скачает RPM wazuh-manager 4.14.7 ~513 МБ — только один раз).
2. `docker save wlogtest-manager:4.14.7 wlogtest-runner wlogtest-runner-builder python:3.12-slim | gzip > wlogtest-images.tar.gz`
3. В классе: `docker load < wlogtest-images.tar.gz` — всё готово.

## Разработка и тесты

```bash
make test          # юнит-тесты (python3 -m pytest), Docker не нужен
make cov           # покрытие wlogtest (гейт >= 85%)
make test-docker   # полный прогон внутри Docker (build, compose, pytest, датасеты)
make build up down # управление стеком
```

`tests/integration/` подключаются автоматически, когда доступен сокет logtest
(env `WAZUH_LOGTEST_SOCKET`); `docker/test.sh` прогоняет юнит + интеграционные
тесты внутри контейнеров и проверяет все три датасета.

## Структура проекта

См. `AGENTS.md` (правила для ИИ-агентов) и `docs/DESIGN.md` (контракты API и
протокол). Вендорные исходники Wazuh: `vendor/wazuh/README.md`.
