# AGENTS.md — wazuh-logtest-offline

Offline Wazuh logtest for students: debug decoders/rules and run log datasets with
correlation verdicts, all inside Docker with zero external network at runtime.

## Project layout

- `wlogtest/` — Python package (stdlib-only): logtest protocol client, dataset model,
  verdict engine, runner, reporters, CLI (`wlogtest`).
- `tests/unit/`, `tests/integration/` — pytest suites. Unit tests never need Docker;
  integration tests skip unless a live logtest socket is reachable.
- `docker/` — Dockerfile (multi-stage), compose stack (`manager` = wazuh/wazuh-manager,
  `runner` = our package), `config/ossec.conf`, `test.sh` (tests inside Docker).
- `examples/` — sample decoders/rules/datasets used by tests and as student templates.
- `vendor/wazuh/` — forked sources from wazuh/wazuh v4.14.7 (logtest server/client,
  protocol reference; GPL-2.0, see LICENSE there). Do not edit; treat as reference.
- `skills/` — vendored skills.sh skills + project-custom skills (SKILL.md each).

## Key facts (do not re-derive)

- Wazuh 4.14.7. Socket: `/var/ossec/queue/sockets/logtest` (AF_UNIX stream).
- Framing: 4-byte little-endian uint32 length + UTF-8 JSON. One request/response per
  connection, server closes after reply. Max payload 65536 bytes.
- Request: `{"version":1,"origin":{"name":"Logtest","module":"framework"},"command":...,
  "parameters":{...}}`; commands `log_processing`, `remove_session`.
- Sessions are stateful (token, 8 hex chars): frequency / if_matched_sid / firedtimes
  work only when cases share a session token.
- Response: `error` (0 ok, !=0 → `message`), `data`: `token`, `messages`, `output`
  (full alert JSON), `alert`, `codemsg` (-1/0/1). See `skills/wazuh-logtest-domain/`.

## Subagents and their skills

Skills live in `skills/<name>/SKILL.md`. Every subagent MUST read its assigned
skills before starting work (see `docs/DESIGN.md` for exact API contracts).

| Subagent | Type | Skills (from skills.sh) | Custom skills | Mission |
|---|---|---|---|---|
| `wazuh-domain` | explore | implementing-endpoint-detection-with-wazuh | wazuh-logtest-domain | Wazuh internals, decoders/rules XML, protocol questions |
| `implementer` | general | tdd, python-testing-patterns | wazuh-logtest-domain, dataset-runner-verdicts | Write `wlogtest/`, pyproject.toml, examples/ test-first |
| `test-engineer` | general | python-testing-patterns, verification-before-completion, pytest-coverage | dataset-runner-verdicts | pytest suites, coverage >= 85% on wlogtest, verify by running |
| `infra` | general | multi-stage-dockerfile, verification-before-completion | offline-docker-logtest | Dockerfile, compose, Makefile, docker/test.sh |
| `debugger` | general | systematic-debugging | wazuh-logtest-domain | Root-cause failures in tests/docker, never patch symptoms |
| `skills-author` | general | skill-creator, writing-great-skills | — | Author/update skills/ SKILL.md files |

### Why each vendored skill (skills.sh)

- **implementing-endpoint-detection-with-wazuh** (mukul975/anthropic-cybersecurity-skills):
  the only skill teaching Wazuh custom decoder/rule XML authoring and logtest usage —
  required for correct example decoders/rules and dataset expectations.
- **tdd** (mattpocock/skills): red-green-refactor at public seams; implementer writes
  tests at module boundaries first so unit suites stay meaningful after refactors.
- **python-testing-patterns** (wshobson/agents): canonical pytest idioms (fixtures,
  parametrization, mocking) — standardizes both implementer and test-engineer output.
- **test-driven-development** (obra/superpowers): stricter variant ("watch it fail first")
  used for the verdict engine where wrong rule matches must demonstrably fail.
- **multi-stage-dockerfile** (github/awesome-copilot): pinned bases, layer caching,
  non-root hardening — our offline image must be small and reproducible.
- **pytest-coverage** (github/awesome-copilot): the loop for eliminating untested lines
  in the dataset-runner verdict logic (coverage gate).
- **verification-before-completion** (obra/superpowers): no agent may claim "done/pass"
  without running the actual command and showing fresh output — applies to every task.
- **systematic-debugging** (obra/superpowers): root-cause-first debugging for decoder
  mismatch and docker failures in the debugger agent.
- **skill-creator** (anthropics/skills): authoring our 3 custom skills with proper
  frontmatter and triggering descriptions.
- **writing-great-skills** (mattpocock/skills): keeps skill descriptions triggerable and
  context-cheap (our AGENTS.md-mandated custom skills follow its conventions).

## Workflow rules

1. Read `docs/DESIGN.md` first — it is the single source of truth for APIs.
2. TDD: failing test → implementation → refactor. Tests at the DESIGN.md seams.
3. Never claim completion without fresh verification output (exit codes included).
4. Runtime deps of `wlogtest`: **none** (stdlib only). Dev deps: pytest, pytest-cov.
5. Docker is available on the dev host via `sudo docker` (NOPASSWD configured);
   `make test` runs locally, `make test-docker` runs the full in-docker
   validation (slim `wlogtest-manager` image: analysisd 4.14.7 from RPM, ~302MB,
   not the ~1.5GB official image).
6. Do not edit `vendor/wazuh/**`. Attribution stays in `vendor/wazuh/README.md`.
7. Commands: `python3 -m pytest` (unit), `python3 -m pytest --cov=wlogtest`,
   `python3 -m wlogtest.cli --help`.

## Skills install (for updating vendored copies)

```bash
npx skills add https://github.com/wshobson/agents --skill python-testing-patterns --copy -y
npx skills add https://github.com/mattpocock/skills --skill tdd --skill writing-great-skills --copy -y
npx skills add https://github.com/obra/superpowers --skill test-driven-development --skill systematic-debugging --skill verification-before-completion --copy -y
npx skills add https://github.com/anthropics/skills --skill skill-creator --copy -y
npx skills add https://github.com/github/awesome-copilot --skill multi-stage-dockerfile --skill pytest-coverage --copy -y
npx skills add https://github.com/mukul975/anthropic-cybersecurity-skills --skill implementing-endpoint-detection-with-wazuh --copy -y
```
