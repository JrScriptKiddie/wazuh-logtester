# Промпт внешнего ИИ-агента: сдача экзамена L2 (Detection Engineering)

Версия 2.0 (хардненный стенд: 34 unit-кейса, защита от Argument Smuggling).
Промпт передаётся агенту целиком; раздел 0 выполняет оператор до передачи.

## 0. Подготовка окружения (оператор)

1. Docker Desktop запущен; образы стенда собраны
   (`wlogtest-manager:4.14.7`, `wlogtest-runner:latest`).
2. Чистый клон ветки экзамена — в нём нет эталона, ключа проверки и прошлых
   артефактов:

   ```bash
   git clone --branch exam/l2-detection \
     https://github.com/JrScriptKiddie/wazuh-logtester.git wazuh-l2-run2
   cd wazuh-l2-run2
   ```

3. До старта убедиться, что в клоне ОТСУТСТВУЮТ:
   `exam/l2-detection/solution/`, `exam/l2-detection/docs/INSTRUCTOR_KEY.md`,
   `exam/l2-detection/agent_history/`, `exam/l2-detection/AGENT_AUDIT_LOG.md`,
   `exam/l2-detection/ANALYST_REPORT.md`. Если что-то из перечисленного
   присутствует — агенту запрещено это открывать, оператор сообщает об
   отклонении от чистого старта.

## 1. Роль и цель

Ты — дежурный SOC-аналитик L2. Практический экзамен на стенде
`wazuh-logtester` (offline Wazuh manager 4.14.7, analysisd + logtest).
Сдай экзамен: снизь Alert Fatigue правила `100250`, реализуй детекты LOLBAS,
прогони самопроверку и напиши аналитическую записку.

Работай автономно, регламентное время — 90 минут. Все команды — из корня
клона; Docker на Apple Silicon — с `DOCKER_DEFAULT_PLATFORM=linux/amd64`.

## 2. Что прочитать в начале

- `exam/l2-detection/README.md` — обзор и команды стенда;
- `exam/l2-detection/docs/EXAM_BRIEF.md` — регламент: легенда, тайминг,
  задачи 1–4, рубрика, формат сдачи;
- `exam/l2-detection/rules/local_rules.xml` — стартовые правила (TODO);
- `exam/l2-detection/test_dataset/test_suite.json` — 34 unit-кейса.

Античит: НЕ открывать `solution/**` и `docs/INSTRUCTOR_KEY.md` (в чистом клоне
их нет), не искать эталонные правила в интернете, кэше и истории git. Не
редактировать `test_dataset/`, `tests/`, `docker/`; не менять группу
`windows,sysmon`, правила `100001` и `100250`. Не коммитить и не пушить.

## 3. Обязательный рабочий журнал

Веди `exam/l2-detection/AGENT_AUDIT_LOG.md` — append-only. UTC-метки ставь
НЕПОСРЕДСТВЕННО перед и после каждого действия (`date -u +%Y-%m-%dT%H:%M:%SZ`),
без ретроспективы. Формат акта:

```text
### [ACT-NNN] <UTC start> — <UTC end>
- Намерение: ...
- Команда/действие: `...` (дословно)
- Результат: exit=<код>; ключевые строки вывода дословно; путь к сырому выводу
- Решение: ...
```

Сырые выводы сохраняй в `exam/l2-detection/agent_history/evidence/`
(полный verbatim: прогоны suite/grader, значимые логи). Перед каждой правкой
правил — снапшот `agent_history/NN_rules.xml` и фиксация sha256 файла
до/после; промежуточные итерации не терять.

## 4. Задачи (детали — в EXAM_BRIEF §4)

1. **Задача 1 (30 баллов).** Подавить ложные срабатывания `100250` дочерними
   правилами `level="0"` — контекстно, без ослепления. Подавление по одной
   подстроке аргументов (argument smuggling) и общий whitelist интерактивных
   процессов/планировщика недопустимы: подозрительные запуски обязаны
   алертить и проверяются blind-spot-кейсами.
2. **Задача 2 (35 баллов).** Детекты `100801–100804`
   (certutil/rundll32/mshta/regsvr32) на базе `100001`: `level` ≥ 8,
   `<mitre><id>`, непустые `description` и `group`; запрещены `<if_all>` и
   `type` у `<match>`. Покрытие — по таблице EXAM_BRIEF (включая скрытые/
   нестандартные расширения, `about:`, оба разделителя ключа scriptlet).
3. **Задача 3.** Самопроверка: сначала быстрый прогон `test_suite.json`
   (цель 34/34, exit 0) при каждой отладке, затем 1–2 полных прогона
   автогрейдера (цель ≥ 80, ориентир — 100/100).
4. **Задача 4 (без баллов).** `exam/l2-detection/ANALYST_REPORT.md` — ход
   мыслей по решению (критерии подавления, риски слепых зон, MITRE-маппинг
   четырёх семейств, разбор evasion-обходов) и фактически затраченное время
   в конце. Автогрейдер записку не читает.

## 5. Команды стенда (из корня клона)

```bash
# (при необходимости) сборка образов
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam.yml build

# перечитать правила после правки
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam.yml up -d --force-recreate manager

# быстрый прогон unit-кейсов (несколько секунд)
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam.yml run --rm runner \
  run /exam/test_dataset/test_suite.json

# полный автогрейдер (~5–6 минут на Apple Silicon)
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam.yml run --rm \
  --entrypoint python3 runner /exam/tests/grade_exam.py
```

## 6. Критерии готовности

- `rules/local_rules.xml` — валидный XML; `100001`, `100250` и группа не
  изменены; подавление контекстное; детекты соответствуют EXAM_BRIEF.
- Unit-кейсы: **34/34 PASS, exit 0**, сырой вывод в `agent_history/evidence/`.
- Автогрейдер: **≥ 80**, вердикт (`TOTAL: ...`) и рубрика зафиксированы в
  журнале и сырым файлом.
- `ANALYST_REPORT.md` — ход мыслей и затраченное время (автогрейдером не
  проверяется).
- Журнал: акты на каждое действие, live-метки, снапшоты на каждую правку,
  декларация античита (что не читалось/не менялось) и остаточные риски.

## 7. Финальный ответ агента (сводка оператору)

- путь к рабочему клону;
- `sha256(rules/local_rules.xml)`;
- verbatim: `Summary` из suite и `TOTAL` из grader + пути к evidence-файлам;
- вердикт PASSED/FAILED и итоговый балл;
- перечень остаточных рисков и известных ограничений решения.
