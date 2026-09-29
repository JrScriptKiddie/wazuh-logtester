# Экзамен L2 — Detection Engineering: Alert Fatigue + LOLBAS

Практический экзамен для аналитика L2 на стенде
[wazuh-logtester](../../README.md): изолированный Wazuh manager (analysisd + logtest),
датасет из 1000 событий Sysmon Event ID 1, 30 unit-кейсов и автогрейдер 0–100.

## Что проверяет экзамен

1. **Тюнинг шумного правила 100250** (`level 8` на любой запуск
   powershell.exe / cmd.exe / wmic.exe): снижение потока ложных срабатываний
   дочерними правилами `level="0"` — без ослепления: подозрительная активность
   (blind-spot-кейсы) обязана алертить.
2. **Разработка детектов LOLBAS 100801–100804** на базе корневого правила
   100001: certutil (T1105/T1140), rundll32 (T1218.011), mshta (T1218.005),
   regsvr32 (T1218.010).
3. **Прогон тестов**: 30 unit-кейсов `test_suite.json` (ориентир — 30/30) и
   самопроверка автогрейдером.
4. **Аналитическая записка** `ANALYST_REPORT.md`: обоснование критериев
   подавления, риски слепых зон, MITRE-маппинг, разбор evasion-обходов.

Регламент выполнения для аналитика — [docs/EXAM_BRIEF.md](docs/EXAM_BRIEF.md).
Ключ проверки для инструктора — [docs/INSTRUCTOR_KEY.md](docs/INSTRUCTOR_KEY.md).

## Требования

- Docker + Compose v2.
- Apple Silicon (arm64): без `DOCKER_DEFAULT_PLATFORM=linux/amd64` сборка
  падает с ошибкой `package wazuh-manager-… is intended for a different
  architecture` — RPM Wazuh собран только под x86_64. Указывайте переменную
  перед каждой командой либо сделайте `export DOCKER_DEFAULT_PLATFORM=linux/amd64`
  один раз в сессии: образ соберётся и запустится под эмуляцией (Rosetta в
  Docker Desktop). Проверено на M-серии.
- Первый запуск собирает образы; полный прогон грейдера (1000 событий +
  30 unit-кейсов) — ~5–6 минут на Apple Silicon, на x86 быстрее.

## Быстрый старт

Все команды выполняются из корня репозитория wazuh-logtester.

### 1. Manager с рабочими правилами аналитика

```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam.yml up -d manager
```

Правила монтируются read-only из `exam/l2-detection/rules/local_rules.xml`.
После правки правил перечитайте их — перезапуск manager:

```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam.yml restart manager
```

(равнозначная альтернатива — `... up -d --force-recreate manager`)

### 2. Unit-кейсы (30)

```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam.yml run --rm runner \
  run /exam/test_dataset/test_suite.json
```

### 3. Автогрейдер (0–100, порог 80)

```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam.yml run --rm \
  --entrypoint python3 runner /exam/tests/grade_exam.py
```

Грейдер прогоняет 1000 событий `exam_dataset.json` и 30 unit-кейсов, проверяет
XML правил и печатает рубрику (FP Suppression / LOLBAS Detection / Evasion /
XML-Architecture / Analyst Report); код возврата 0 при итоге ≥ 80.

## Структура каталога

| Путь | Назначение |
|------|------------|
| `rules/local_rules.xml` | Стартовые правила аналитика: 100001, шумное 100250, заготовки TODO 100801–100804. Основной файл, который правится при выполнении. |
| `test_dataset/generate_dataset.py` | Генератор датасета (SEED фиксирован, только stdlib, детерминированный). |
| `test_dataset/exam_dataset.json` | 1000 событий: 950 легитимный шум + 50 LOLBAS-атак (12 evasion). |
| `test_dataset/test_suite.json` | 30 unit-кейсов: 10 suppression (7 шумовых + 3 blind-spot), 15 LOLBAS, 5 evasion. |
| `tests/run_tests.py` | Прогон unit-кейсов; код возврата 0 при 30/30 PASS. |
| `tests/grade_exam.py` | Автогрейдер 0–100: рубрика, `--json`, параметр `--rules`. |
| `docs/EXAM_BRIEF.md` | Регламент выполнения экзамена для аналитика L2. |
| `docs/INSTRUCTOR_KEY.md` | Ключ проверки: эталон, стартовое состояние, античит, ограничения. |
| `solution/` | Эталонные правила (`solution_rules.xml`) и пояснение; каталог вне git — только локально у инструктора. |
| `docker/compose.exam.yml` | Оверрайд базового стека: рабочие правила вместо examples + монтирование каталога экзамена в runner. |
| `docker/compose.exam-solution.yml` | Оверрайд для проверки эталона: эталонные правила вместо рабочих. |
| `ANALYST_REPORT.md` | Аналитическая записка (задача 4) — создаётся при выполнении в корне `exam/l2-detection/`. |

## Примечание для инструктора

Эталон поднимается через `compose.exam-solution.yml`; XML-блок грейдера читает
активный файл правил через `--rules` (пример — проверка эталона):

```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam-solution.yml up -d --force-recreate manager

DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam-solution.yml run --rm \
  --entrypoint python3 runner /exam/tests/grade_exam.py \
  --rules /exam/solution/solution_rules.xml
```

Полный порядок проверки и разбор эталона — в
[docs/INSTRUCTOR_KEY.md](docs/INSTRUCTOR_KEY.md).
