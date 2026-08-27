# ДЗ: FreeIPA — разделение Password Spraying и Targeted Brute Force

Сложность: средняя · Время: 60–90 мин · Проверяется утилитой `wlogtest`
(встроена в docker-стек проекта).

## Контекст (жалоба из SOC)

В SOC поступают жалобы от аналитиков: алерт **Password Spraying (100532)**
срабатывает на бухгалтера, который забыл пароль и ввёл его 5 раз подряд. При
этом реальный злоумышленник, перебирающий по 1 паролю для 20 пользователей,
падает в тот же алерт — аналитики не могут отличить ложное срабатывание от
атаки.

## Задание

1. **Доработать декодер `freeipa-krb5kdc`**, чтобы он извлекал не только
   `krb_srcip`, но и имя целевого пользователя (`krb_user`) и запрашиваемый
   SPN (`krb_service`).
2. **Разделить правило 100532 на два независимых детекта:**
   - **Password Spraying** — 5+ `PREAUTH_FAILED` за 60 секунд с **разными**
     пользователями (`<different_field>krb_user</different_field>`);
   - **Targeted Brute Force** — 5+ `PREAUTH_FAILED` за 60 секунд с **одним и
     тем же** пользователем (`<same_field>krb_user</same_field>`), новый
     id **100533** (MITRE **T1110.001**).
   Обновите описания и группы так, чтобы детекты были различимы в алерте.

Правила 100530/100531 и группу `freeipa` (100500–100525) **не трогать**.

## Файлы для правки

| Файл | Что править |
|---|---|
| `examples/decoders/8888_freeipa_decoders.xml` | декодер `freeipa-krb5kdc` (пункт 1) |
| `examples/rules/8888_freeipa_rules.xml` | правило `100532` + добавить `100533` (пункт 2) |

Эти файлы по умолчанию смонтированы в manager-контейнер
(`/var/ossec/etc/decoders` и `/var/ossec/etc/rules`).

## Исходные данные

- **Датасеты** (прогоняются утилитой — на них проверяется работа):
  - `examples/datasets/freeipa_intro.json` — исходное поведение (жалоба SOC),
    прогоняется до правок;
  - `examples/datasets/freeipa_graded.json` — целевое поведение после
    правок, зачёт = 12/12 PASS.
- **Набор правил** — `examples/rules/8888_freeipa_rules.xml`:
  - группа `freeipa` (100500–100525) — базовые детекты KDC/LDAP;
  - группа `freeipa_correlation` (100530–100532) — корреляция; 100532
    подлежит разделению.
- **Набор декодеров** — `examples/decoders/8888_freeipa_decoders.xml`:
  - `freeipa-krb5kdc` — дорабатывается (+`krb_user`, +`krb_service`);
  - `freeipa-dirsrv-*` (5 шт.) — LDAP-контекст, не меняются.
- **Телеметрия** — `examples/telemetry/krb5kdc_samples.log` (статусы
  `PREAUTH_FAILED`, `NEEDED_PREAUTH`, `ISSUE`, `CLIENT_NOT_FOUND`).

## Запуск утилиты и передача своих правил

1. Поднять стек (один раз):

   ```bash
   docker compose -f docker/docker-compose.yml up -d manager
   docker compose -f docker/docker-compose.yml build runner
   ```

2. Отредактируйте свои декодеры/правила в `examples/decoders|rules`, затем
   перезапустите manager, чтобы он перечитал файлы:

   ```bash
   docker compose -f docker/docker-compose.yml restart manager
   ```

   (logtest перечитывает правила при каждой новой сессии; перезапуск —
   самый надёжный способ применить правки.)

3. Проверка одного события (3-фазный вывод, как в оригинальном
   wazuh-logtest; `--json` — сырой ответ, `--debug` — трассировка правил):

   ```bash
   docker compose -f docker/docker-compose.yml run --rm runner \
     logtest -e "Aug 27 10:00:01 freeipa-server01 krb5kdc[1166]: AS_REQ (8 etypes {aes256-cts-hmac-sha1-96(18)}) 10.41.10.4: PREAUTH_FAILED: student05@SOC.LAN for kadmin/changepw@SOC.LAN, Preauthentication failed"
   ```

   Прогон строк из файла телеметрии (все строки — одна сессия, нужна для
   частотных правил):

   ```bash
   docker compose -f docker/docker-compose.yml run --rm -T runner logtest < examples/telemetry/krb5kdc_samples.log
   ```

4. Прогон датасетов (вердикты по корреляции):

   ```bash
   docker compose -f docker/docker-compose.yml run --rm runner run /data/datasets/freeipa_intro.json
   docker compose -f docker/docker-compose.yml run --rm runner run /data/datasets/freeipa_graded.json
   ```

   Встроенные в образ копии датасетов лежат в `/opt/datasets/` (для
   air-gapped машин без репозитория): `runner run /opt/datasets/freeipa_graded.json`.

5. Остановка стенда:

   ```bash
   docker compose -f docker/docker-compose.yml down          # остановить контейнеры
   docker compose -f docker/docker-compose.yml down -v       # ...и удалить том с сокетом/сессиями
   docker compose -f docker/docker-compose.yml stop manager  # только приостановить движок
   ```

## Телеметрия

- `examples/telemetry/krb5kdc_samples.log` — образцы строк `/var/log/krb5kdc.log`
  (формат снят с реального FreeIPA из SOC: статусы `PREAUTH_FAILED`,
  `NEEDED_PREAUTH`, `ISSUE`, `CLIENT_NOT_FOUND`).
- Сценарии в датасетах сгенерированы в том же формате:
  - **бухгалтер** — 5 неудач одного пользователя `accountant01`
    (SPN `kadmin/changepw`);
  - **спарсер** — по одной неудаче на `student01`…`student05`
    (SPN `krbtgt/SOC.LAN`).

Формат строки KDC:

```
<ts> freeipa-server01 krb5kdc[pid]: AS_REQ (...) <srcip>: <STATUS>: <user>@<REALM> for <spn>@<REALM>, <message>
```

В `TGS_REQ ... ISSUE:` между статусом и пользователем идут
`authtime ... etypes {...}` — декодер должен выдерживать оба варианта.

## Проверка и критерии оценки

1. **До правок** прогоните `freeipa_intro.json` — он воспроизводит жалобу:
   оба сценария дают неотличимый поток алертов (10/10 PASS, но одинаковых).
2. **После правок** прогоните `freeipa_graded.json`. Зачёт = **12/12 PASS**:

| # | Критерий |
|---|---|
| 1 | декодер извлекает `krb_user` и `krb_service` из `PREAUTH_FAILED` |
| 2 | декодер извлекает `krb_user` и `krb_service` из `TGS_REQ ... ISSUE` |
| 3 | 5 неудач с **разными** пользователями → **100532 Password Spraying** |
| 4 | 5 неудач с **одним** пользователем → **100533 Targeted Brute Force** |
| 5 | описания детектов содержат «different users» / «same user» |

Если на 5-м событии детект не виден в выводе — проверьте **уровень** правила:
в logtest показывается итоговое правило с максимальным level (родительское
`100501` имеет level 8).

## Подсказки

- Regex декодера — pcre2; ищите «якоря» строки: `IP: STATUS:` и
  `user@REALM for spn@REALM`. Пользователь/SPN не содержат пробелов и `@`
  внутри себя; поле `<order>` — перечисление групп захвата через запятую.
- Для частотных правил в Wazuh: `frequency` + `timeframe` + `if_matched_sid`
  на родителя; условия на поля — `<same_field>имя</same_field>` /
  `<different_field>имя</different_field>` (можно несколько).
- Частотные правила проверяются **только в рамках одной сессии** (в датасете
  это именованные сессии `spray` и `brute`; в CLI — флаг `--token` или
  интерактивный режим `-i`).
- В логтесте частотное правило 100530 (`same_field krb_srcip`, freq 3)
  срабатывает каждое 3-е событие с одного IP и сбрасывает счётчик родителя —
  поэтому детекты из задания завязаны на `krb_user`, а в сценариях датасета
  исходные IP ротируются (NAT-пул).

---

*Для преподавателя:* эталонное решение **не хранится в git** (каталог
`homework/freeipa_solution/` в `.gitignore`) — оно живёт только локально у
вас. Формат: `homework/freeipa_solution/{decoders,rules}/freeipa_*.xml`
(см. `homework/freeipa_solution/README.md`). Проверить его в docker:

```bash
docker compose -f docker/docker-compose.yml -f docker/compose.freeipa-solution.yml up -d manager
docker compose -f docker/docker-compose.yml run --rm runner run /data/datasets/freeipa_graded.json
```

`docker/test.sh` автоматически проверяет, что на стартовых файлах датасет
`freeipa_graded` красный, а на эталонном решении — зелёный (шаг пропускается,
если каталог с решением не найден).
