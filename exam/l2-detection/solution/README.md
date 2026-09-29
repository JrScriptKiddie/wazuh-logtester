# Эталон экзамена L2 (только у инструктора)

Каталог **не хранится в git** (см. `.gitignore` в корне репозитория): правила
из него доступны только локально у инструктора.

Положите сюда файл `solution_rules.xml` — полный эталонный набор правил
(корневое `100001`, шумное `100250`, правила подавления `level="0"` и детекты
LOLBAS `100801`–`100804`). Это монтируется в manager вместо рабочих правил:

```bash
docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam-solution.yml up -d manager
```

Проверка эталона:

```bash
docker compose -f docker/docker-compose.yml \
  -f exam/l2-detection/docker/compose.exam-solution.yml run --rm runner \
  run /exam/test_dataset/test_suite.json
```
