# ДЗ FreeIPA: Password Spraying vs Targeted Brute Force

Учебный SOC-кейс на базе реальной телеметрии FreeIPA: разделить
корреляционное правило 100532 на два независимых детекта.

## Файлы в этом каталоге

| Файл | Для кого | Что внутри |
|---|---|---|
| [`STUDENT.md`](STUDENT.md) | студенты (раздатка) | ТЗ без инструкций по Docker — развёртывание стека часть задания |
| [`HOMEWORK.md`](HOMEWORK.md) | преподаватель | ТЗ + инструкции запуска утилиты, критерии, подсказки, проверка эталона |
| `../freeipa_solution/` | преподаватель (локально) | Эталонное решение — **не хранится в git** (`.gitignore`), см. README внутри |

## Материалы студента (в репозитории)

- Стартовые декодер/правила (правятся студентом):
  `examples/decoders/8888_freeipa_decoders.xml`,
  `examples/rules/8888_freeipa_rules.xml`
- Телеметрия KDC (реальные форматы):
  `examples/telemetry/krb5kdc_samples.log`
- Датасеты:
  `examples/datasets/freeipa_intro.json` — воспроизведение жалобы SOC
  (прогоняется **до** правок);
  `examples/datasets/freeipa_graded.json` — ключ проверки решения,
  зачёт = **12/12 PASS**

## Краткое ТЗ

1. Доработать декодер `freeipa-krb5kdc`: извлекать `krb_user` и `krb_service`
   (помимо `krb_srcip`).
2. Разделить правило 100532:
   - **Password Spraying** (100532) — 5+ `PREAUTH_FAILED` за 60 с с
     **разными** пользователями: `<different_field>krb_user</different_field>`;
   - **Targeted Brute Force** (100533) — 5+ `PREAUTH_FAILED` за 60 с с
     **одним и тем же** пользователем: `<same_field>krb_user</same_field>`,
     MITRE T1110.001.

Правила 100530/100531 и группу `freeipa` (100500–100525) не трогать.
Подробности — в файлах выше.
