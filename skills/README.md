# Skills

Vendored skills from skills.sh GitHub repos plus project-custom skills. Every skill
lives in `<name>/SKILL.md` (YAML frontmatter: `name`, `description`) and may bundle
referenced assets (scripts/, references/, ...) that the SKILL.md links relatively.

Subagents are assigned skills in AGENTS.md; read the assigned skills before starting work.

## Vendored skills

| Skill | Source | License |
|---|---|---|
| python-testing-patterns | https://github.com/wshobson/agents (plugins/python-development/skills/python-testing-patterns) | MIT |
| tdd | https://github.com/mattpocock/skills (skills/engineering/tdd) | MIT |
| writing-great-skills | https://github.com/mattpocock/skills (skills/productivity/writing-for-agents; upstream renamed from writing-great-skills in v1.1, vendored under the original name) | MIT |
| test-driven-development | https://github.com/obra/superpowers (skills/test-driven-development) | MIT |
| systematic-debugging | https://github.com/obra/superpowers (skills/systematic-debugging) | MIT |
| verification-before-completion | https://github.com/obra/superpowers (skills/verification-before-completion) | MIT |
| skill-creator | https://github.com/anthropics/skills (skills/skill-creator) | Apache-2.0 (LICENSE.txt in skill dir; repo root has no LICENSE — see upstream repo) |
| multi-stage-dockerfile | https://github.com/github/awesome-copilot (skills/multi-stage-dockerfile) | MIT |
| pytest-coverage | https://github.com/github/awesome-copilot (skills/pytest-coverage) | MIT |
| implementing-endpoint-detection-with-wazuh | https://github.com/mukul975/anthropic-cybersecurity-skills (skills/implementing-endpoint-detection-with-wazuh) | Apache-2.0 |

Notes:

- `subagent-driven-development` (obra/superpowers) appears in AGENTS.md's `npx
  skills add` block but is not assigned to any subagent in the table; it is not
  vendored here. To add it, run the npx command from AGENTS.md and create the
  `skills/subagent-driven-development/` entry in this table.
- Vendored copies include the asset files referenced by each SKILL.md; binaries
  >1MB are excluded. Update vendored copies with the commands in AGENTS.md
  ("Skills install").

## Custom skills (project-authored)

| Skill | Purpose | Audience |
|---|---|---|
| wazuh-logtest-domain | Wazuh 4.14.7 logtest protocol facts (socket, framing, envelope, sessions, responses, `<rule_test>`, decoder/rules paths) | wazuh-domain, implementer, debugger |
| dataset-runner-verdicts | Dataset JSON spec, matcher operators, verdict + session semantics (contract for wlogtest) | implementer, test-engineer |
| offline-docker-logtest | Compose stack, healthcheck wait, offline workflow, docker/test.sh loop | infra |
