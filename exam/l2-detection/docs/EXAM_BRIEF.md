# Регламент выполнения экзамена L2 — Detection Engineering: Alert Fatigue + LOLBAS

**Роль:** SOC-аналитик, уровень L2
**Формат:** практический, индивидуальный, на стенде wazuh-logtester
**Время:** до 90 минут
**Порог сдачи:** 80 из 100 (автогрейдер)

## 1. Легенда

Вы — дежурный аналитик L2. Смена L1 перегружена штормом алертов правила
`100250` («Administrative tool executed», level 8): оно срабатывает на каждый
запуск powershell.exe / cmd.exe / wmic.exe без учёта контекста. На 950 легитимных
событий Sysmon Event ID 1 приходит порядка 700 ложных алертов — это инвентаризация
SCCM, бэкапы Veeam, мониторинг Zabbix и регламентные скрипты обслуживания
(health_check.ps1, certutil -pulse/-verifyctl, панель управления через
rundll32 shell32.dll,Control_RunDLL).

Параллельно в телеметрии развивается активность LOLBAS — certutil, rundll32,
mshta, regsvr32 — включая варианты с обфускацией аргументов и склейкой команд
(argument smuggling). Задача смены: снизить Alert Fatigue, не ослепнув, и
закрыть слепые зоны новыми детектами.

## 2. Стенд и исходные данные

- Инструмент: wazuh-logtester — offline-стенд Wazuh manager (analysisd + logtest).
- **Актуальная ветка экзамена:** `exam/l2-detection` —
  https://github.com/JrScriptKiddie/wazuh-logtester/tree/exam/l2-detection
  (каталог экзамена — `exam/l2-detection/`).
- Требования: Docker + Compose v2; на Apple Silicon каждая команда выполняется
  с `DOCKER_DEFAULT_PLATFORM=linux/amd64` (эмуляция amd64).
- Рабочий файл: `exam/l2-detection/rules/local_rules.xml` — монтируется в
  manager как `/var/ossec/etc/rules/local_rules.xml`.
- Телеметрия: `test_dataset/exam_dataset.json` (1000 событий Sysmon EID 1:
  950 легитимных + 50 атак) и `test_dataset/test_suite.json` (34 unit-кейса).
- Все команды запускаются из корня репозитория wazuh-logtester; быстрый старт —
  в `exam/l2-detection/README.md`.

## 3. Тайминг и правила

Регламентное время — 90 минут (рекомендуемое распределение):

| Этап | Время |
|------|-------|
| Вводная, осмотр датасета и текущих правил | 10 мин |
| Задача 1 — тюнинг правила 100250 | 25 мин |
| Задача 2 — детекты LOLBAS 100801–100804 | 30 мин |
| Задача 3 — прогон тестов и грейдера, доводка | 15 мин |
| Задача 4 — аналитическая записка | 10 мин |

**Разрешено:** интернет, официальная документация Wazuh (синтаксис правил,
pcre2), чтение файлов экзамена (датасет, unit-кейсы, грейдер).

**Запрещено:**

- отключать, удалять или «глушить» правило `100250` целиком — сохранение
  детекта проверяется blind-spot-кейсами;
- менять группу `windows,sysmon` и корневое правило `100001`;
- редактировать `test_dataset/`, `tests/` и файлы эталона;
- вмешиваться в работу контейнеров в обход правил стенда.

Учтите: полный прогон грейдера занимает ~5–6 минут на Apple Silicon.
В процессе разработки и отладки правил запускайте быстрый прогон
`test_suite.json` (несколько секунд):

```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam.yml run --rm runner \
  run /exam/test_dataset/test_suite.json
```

Полный прогон автогрейдера (1000 событий) выполняйте 1–2 раза на финальном
этапе — это сэкономит 15–20 минут регламентного времени.

## 4. Задачи

### Задача 1. Снижение Alert Fatigue правила 100250 (25 баллов)

Снизьте поток ложных срабатываний `100250` дочерними правилами `level="0"` —
по доверенным родительским процессам и/или доверенным командным строкам
обслуживания. Семантика Wazuh: после срабатывания родительского правила
проверяются его дочерние; первое совпавшее дочернее правило `level="0"`
подавляет алерт родителя.

Ограничение: само правило `100250` и его детектирующее условие должны
сохраниться. Подозрительные запуски (например, родители из `C:\Users\Public`,
`AppData\Local\Temp`, `services.exe`) обязаны по-прежнему алертить — это
проверяется.

Подавление обязано быть контекстным: «доверенный родитель» и/или «доверенный
родитель + строго регламентная команда». Нельзя глушить `100250` по одной
подстроке аргументов (`-pulse`, `-verifyctl`, `health_check.ps1` и т.п.) — это
класс обхода argument smuggling: команда `cmd.exe /c "whoami & certutil.exe
-pulse"` от недоверенного родителя, ровно как и `powershell.exe -enc <payload>`
от `taskeng.exe` без регламентного скрипта, обязаны алертить. Не вносите
`explorer.exe` и `taskeng.exe` в общий whitelist доверенных родителей.

### Задача 2. Детекты LOLBAS 100801–100804 (30 баллов)

Разработайте четыре правила уровня не ниже 8 на базе `100001` (Sysmon EID 1):

| Rule ID | Инструмент | Что должен ловить | MITRE |
|---------|------------|-------------------|-------|
| 100801 | certutil.exe | загрузку (`-urlcache` с `-f`/`-split`) и декодирование (`-decode`, `/decode`, `-decodehex`) | T1105, T1140 |
| 100802 | rundll32.exe | DLL/данные из пользовательских каталогов, Temp, Public, ProgramData, PerfLogs, UNC/WebDAV; ординалы (`,#N`); скрытые и нестандартные расширения (`.dat`, `.png`, `.tmp`, `.txt`, `.bin`) | T1218.011 |
| 100803 | mshta.exe | удалённый HTA (`http(s)://`), inline `vbscript:`/`javascript:`/`about:`, локальный HTA из пользовательских каталогов/UNC и нестандартных путей | T1218.005 |
| 100804 | regsvr32.exe | Squiblydoo: `scrobj.dll` + ключ scriptlet с обоими разделителями (`/i:` и `-i:`) и сетевым или пользовательским SCT-ресурсом | T1218.010 |

Требования к каждому правилу: `level` ≥ 8, `<if_sid>100001</if_sid>`, блок
`<mitre><id>...`, непустые `description` и `group`.
Запрещённые конструкции: `<if_all>` и атрибут `type` у `<match>`.

Важно: LOLBAS-вызовы приходят и от «бытовых» родителей (explorer.exe) —
не подавляйте детекты 100801–100804 по признаку родителя. Доверенные родители
и командные строки — критерий исключительно для шумного `100250`.

### Задача 3. Прогон тестов (самопроверка)

Перечитайте правила и прогоните unit-кейсы:

```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam.yml restart manager

DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam.yml run --rm runner \
  run /exam/test_dataset/test_suite.json
```

Ориентир — 34/34 PASS (код возврата 0). Затем выполните самопроверку
автогрейдером:

```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam.yml run --rm \
  --entrypoint python3 runner /exam/tests/grade_exam.py
```

Диагностика ложных срабатываний: `test_dataset/exam_dataset.json` — обычный
датасет wazuh-logtester (у 950 шумовых событий ожидается `alert: false`).
Прогон покажет, какие именно события алертят:

```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam.yml run --rm runner \
  run /exam/test_dataset/exam_dataset.json
```

Строки `FAIL ... alert: expected False, actual True` — найденные FP (при
необходимости отфильтруйте: `| grep -B1 "expected False, actual True"`).
Мета-поля `expected_rule_id`/`mitre_id` в JSON — справочные: автогрейдер FP
считает по факту (любой алерт или `level > 0` на шуме) и мету не учитывает.

### Задача 4. Аналитическая записка (10 баллов)

Создайте файл `exam/l2-detection/ANALYST_REPORT.md`. Автогрейдер проверяет
5 чек-пунктов по 2 балла:

1. **объём** — не менее 600 символов осмысленного текста (без шаблонных
   заполнителей);
2. обоснование критериев подавления — какие сигналы доверия выбраны и почему
   (контекстная связка «родитель + регламентная команда» против argument
   smuggling);
3. риски слепых зон и способ их контроля;
4. MITRE-маппинг всех четырёх детектов (certutil / rundll32 / mshta / regsvr32;
   T1105 / T1140 / T1218);
5. разбор evasion-обходов (регистр, кавычки и пробелы, относительные пути,
   UNC/WebDAV, ординалы, скрытые расширения, about:-протокол, ключ -i:).

## 5. Рубрика автогрейдера (0–100)

| Блок | Баллы | Формула |
|------|-------|---------|
| FP Suppression | 25 | `25 × max(0, 1 − FP%/5%) × (blind-spot k/5)`; FP% — доля алертов на 950 легитимных событиях: 0% → полный балл, ≥ 5% → 0. |
| LOLBAS Detection | 30 | `30 × (обнаружено / 50)`; семейства: certutil 15, rundll32 15, mshta 10, regsvr32 10. |
| Evasion | 25 | `25 × (обнаружено / 19)`: 12 edge-кейсов датасета + 7 unit-кейсов. |
| XML/Architecture | 10 | парсинг XML (+2); 100801–100804 с `level ≥ 8` и `if_sid` (+3); MITRE-теги (+2); `description` + `group` (+1); отсутствие `<if_all>` и `type` у `<match>` (+2). |
| Analyst Report | 10 | 5 чек-пунктов по 2 балла: объём ≥ 600 символов; обоснование подавления; риски слепых зон; все LOLBAS-семейства + T1105/T1140/T1218; evasion-обходы. |
| **Итог** | **100** | **PASSED при сумме ≥ 80.** |

## 6. Формат сдачи

1. `exam/l2-detection/rules/local_rules.xml` — итоговые правила (100001 и
   100250 на месте, группа не изменена).
2. `exam/l2-detection/ANALYST_REPORT.md` — аналитическая записка.
3. Вывод грейдера с вердиктом `PASSED` и баллом (скриншот или текст) —
   приложить к сдаче.
