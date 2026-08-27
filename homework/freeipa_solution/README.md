# homework/freeipa_solution/ — ЭТАЛОННОЕ РЕШЕНИЕ (не коммитится!)

Этот каталог **исключён из git** (см. `.gitignore`): здесь лежат ответы к ДЗ,
которые должны быть только у преподавателя.

## Состав (локально)

```
homework/freeipa_solution/
├── decoders/freeipa_decoders.xml   # декодер с krb_user/krb_service
└── rules/freeipa_rules.xml         # 100532 (different_field) + 100533 (same_field)
```

Если каталог отсутствует (например, после `git clone`), `docker/test.sh`
пропускает проверку эталонного решения, а `docker/compose.freeipa-solution.yml`
указывает на пустой/отсутствующий путь.

## Как проверить эталон локально

1. Положите решение в этот каталог (файлы выше).
2. Запустите:

   ```bash
   docker compose -f docker/docker-compose.yml -f docker/compose.freeipa-solution.yml up -d manager
   docker compose -f docker/docker-compose.yml run --rm runner run /data/datasets/freeipa_graded.json
   ```

   Результат: 12/12 PASS.
