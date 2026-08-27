---
name: offline-docker-logtest
description: The docker compose stack that pairs wazuh/wazuh-manager 4.14.7 with the wlogtest runner over a shared logtest socket volume, plus the offline workflow and docker/test.sh validation loop. Use when writing or debugging docker/Dockerfile, docker-compose.yml, ossec.conf, Makefile docker targets, or running tests inside docker.
---

# Offline docker logtest

Compose stack for `wazuh-logtest-offline`. Students pull images once and then run
with zero network at runtime. `docs/DESIGN.md` is authoritative; this is the
operational summary.

## Architecture

```
host (students)                    docker network
┌─────────────────────────────┐    ┌───────────────────────────┐
│ docker compose run runner   │    │ manager (wazuh-manager)   │
│  wlogtest run /data/ds.json ├──► │ analysisd (logtest server)│
│  python:3.12-slim image     │    │ /var/ossec/etc/decoders   │
└──────────┬──────────────────┘    │ /var/ossec/etc/rules      │
           └── shared volume: /var/ossec/queue ──► socket logtest
```

## Services

- `manager`: `wazuh/wazuh-manager:4.14.7` is the logtest engine (analysisd).
  Volumes:
  - `./config/ossec.conf:/wazuh-config-mount/etc/ossec.conf:ro`
  - `../../examples/decoders:/var/ossec/etc/decoders:ro`
  - `../../examples/rules:/var/ossec/etc/rules:ro`
  - `wazuh-queue:/var/ossec/queue` (named volume carrying the logtest socket)
  Healthcheck: `test -S /var/ossec/queue/sockets/logtest` with `start_period: 60s`
  — the manager needs time to boot analysisd.
- `runner`: build context is the repo root with `dockerfile: docker/Dockerfile`
  (multi-stage: stage 1 `python:3.12-slim` runs `pip wheel . --no-deps`,
  stage 2 installs the wheel; `ENV WAZUH_LOGTEST_SOCKET=/var/ossec/queue/sockets/logtest`,
  `ENTRYPOINT ["wlogtest"]`; root user is fine — socket perms need it).
  Volumes: `wazuh-queue:/var/ossec/queue:ro`, `../../examples:/data:ro`.
  `depends_on: manager: condition: service_healthy`.
  Default command: `run /data/datasets/basic.json`.

## ossec.conf

Base is the default 4.14.7 manager config (from wazuh/wazuh-docker v4.14.7
`single-node/config/wazuh_cluster/wazuh_manager.conf`). It must keep the
`etc/decoders` + `etc/rules` ruleset dirs and contain:

```xml
<rule_test>
  <enabled>yes</enabled>
  <threads>2</threads>
  <max_sessions>64</max_sessions>
  <session_timeout>15m</session_timeout>
</rule_test>
```

Without `<rule_test>` the logtest socket never appears and the manager healthcheck
fails.

## Offline workflow for students

1. On a networked machine, once: `docker pull wazuh/wazuh-manager:4.14.7` and
   `docker compose build runner`.
2. Afterwards everything runs offline (`--network none` style); no pulls, no pip
   installs at runtime.
3. Iterate on decoders/rules by editing `examples/decoders|rules` (bind-mounted,
   manager reloads them) and re-running `docker compose run --rm runner run ...`.

## docker/test.sh loop (validation)

1. `docker compose up -d manager`
2. wait for the socket (timeout 120s)
3. `docker compose build runner`
4. `docker compose run --rm runner run /data/datasets/basic.json`
5. `docker compose run --rm runner run /data/datasets/correlation.json`
6. `docker compose run --rm -e WAZUH_LOGTEST_SOCKET=/var/ossec/queue/sockets/logtest -v $(pwd):/src runner sh -c "pytest"` (unit + integration inside docker)
7. teardown; exit code reflects test results; print fresh output of every step.

Makefile targets: `test` (local `python3 -m pytest`), `test-docker` (`docker/test.sh`),
`build`, `up`, `down`, `cov` (pytest --cov with the >= 85% gate).

## Gotchas

- Docker is NOT available on the dev host: keep `make test` green locally and
  validate `make test-docker` on a Docker-enabled machine/CI.
- Socket is per-manager; the named volume must be shared read-write by manager and
  read-only by runner, and removed between unrelated runs if sockets go stale.
- Custom decoder/rule XML errors surface in logtest responses (`codemsg: -1`), not
  in compose logs — check the runner output first.
