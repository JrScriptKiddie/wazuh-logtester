---
name: offline-docker-logtest
description: The docker compose stack that pairs the slim wlogtest-manager image (wazuh-analysisd 4.14.7 only, built from the wazuh-manager RPM) with the wlogtest runner over a shared logtest socket volume, plus the offline workflow and docker/test.sh validation loop. Use when writing or debugging docker/Dockerfile, docker-compose.yml, ossec.conf, Makefile docker targets, or running tests inside docker.
---

# Offline docker logtest

Compose stack for `wazuh-logtest-offline`. Students build/pull images once and
then run with zero network at runtime. `docs/DESIGN.md` is authoritative; this
is the operational summary.

## Architecture

```
host (students)                    docker network
┌─────────────────────────────┐    ┌───────────────────────────────┐
│ docker compose run runner   │    │ manager (wlogtest-manager)    │
│  wlogtest run /data/ds.json ├──► │ analysisd only (logtest srv)  │
│  python:3.12-slim image     │    │ /var/ossec/etc/decoders       │
└──────────┬──────────────────┘    │ /var/ossec/etc/rules          │
           └── shared volume: /var/ossec/queue ──► socket logtest
```

## Services

- `manager`: built from the `manager` stage of `docker/Dockerfile`
  (`FROM amazonlinux:2023`, downloads the pinned wazuh-manager RPM, installs,
  strips to analysisd-only), image `wlogtest-manager:4.14.7` (~302MB vs ~1.5GB
  for the official wazuh/wazuh-manager image). Engine-only: analysisd 4.14.7
  from the RPM + libs + default ruleset (`/var/ossec/ruleset/`) + lists.
  Entrypoint recreates queue subdirs (the named volume shadows the in-image
  tree), chowns them for the `wazuh` user (analysisd drops privileges), runs
  `wazuh-analysisd -f`. Volumes:
  - `./config/ossec.conf:/var/ossec/etc/ossec.conf:ro`
  - `../examples/decoders:/var/ossec/etc/decoders:ro`
  - `../examples/rules:/var/ossec/etc/rules:ro`
  - `wazuh-queue:/var/ossec/queue` (named volume carrying the logtest socket)
  Healthcheck: `test -S /var/ossec/queue/sockets/logtest` with `start_period:
  30s` (analysisd needs a few seconds to load the ruleset; expect ~15s).
  `queue/db/wdb` connect errors in ossec.log are benign — no wazuh-db runs in
  this stack and logtest does not need it.
- `runner`: build context is the repo root with `dockerfile:
  docker/Dockerfile` and explicit `target: runner` (never rely on stage
  order!). Stage 1 `builder` = python:3.12-slim + build toolchain + pytest;
  stage 2 `runner` = python:3.12-slim + the `wlogtest` wheel only;
  `ENV WAZUH_LOGTEST_SOCKET=/var/ossec/queue/sockets/logtest`,
  `ENTRYPOINT ["wlogtest"]`; root user is fine — socket perms need it.
  Volumes: `wazuh-queue:/var/ossec/queue:ro`, `../examples:/data:ro`.
  `depends_on: manager: condition: service_healthy`.
  Default command: `run /data/datasets/basic.json`.

## ossec.conf

Base is the default 4.14.7 manager config (from wazuh/wazuh-docker v4.14.7
`single-node/config/wazuh_cluster/wazuh_manager.conf`). It must keep both
ruleset dir groups (`ruleset/decoders` + `ruleset/rules` = defaults shipped in
the RPM, `etc/decoders` + `etc/rules` = user dirs) and contain:

```xml
<rule_test>
  <enabled>yes</enabled>
  <threads>2</threads>
  <max_sessions>64</max_sessions>
  <session_timeout>15m</session_timeout>
</rule_test>
```

Without `<rule_test>` the logtest socket never appears and the manager healthcheck
fails. Cluster is `<disabled>yes</disabled>` — keep it that way in the slim
image. analysisd's config read also requires `etc/shared/ar.conf` — do not
delete `etc/shared` when stripping the image (build gate `analysisd -t` catches
this).

## Offline workflow for students

1. On a networked machine, once:
   `docker compose -f docker/docker-compose.yml build manager runner runner-test`
   (the manager stage downloads the ~513MB wazuh-manager RPM; build-time only).
2. `docker save wlogtest-manager:4.14.7 wlogtest-runner wlogtest-runner-builder
   python:3.12-slim | gzip > wlogtest-images.tar.gz`
3. On the air-gapped machine: `docker load < wlogtest-images.tar.gz`.
4. Afterwards everything runs offline; no pulls, no pip installs at runtime.
5. Iterate on decoders/rules by editing `examples/decoders|rules` (bind-mounted,
   new logtest sessions pick them up) and re-running
   `docker compose run --rm runner run ...`.

## docker/test.sh loop (validation)

1. `docker compose build runner runner-test` (fail fast, no race with manager start)
2. `docker compose up -d manager` (builds the manager image on first run)
3. wait for the socket (timeout 120s)
4. `docker compose run --rm runner run /data/datasets/basic.json`
5. `docker compose run --rm runner run /data/datasets/correlation.json`
6. `docker compose run --rm runner run /data/datasets/fail_demo.json` (must exit 1)
7. `docker compose run --rm runner-test python3 -m pytest -o addopts="" --cov=wlogtest --cov-report=term-missing -q`
   (unit + integration inside docker against the live socket)
8. teardown `down -v`; exit code reflects test results; print fresh output of
   every step. Honors `DOCKER="sudo docker"` for sudo-required hosts.

Makefile targets: `test` (local `python3 -m pytest`), `test-docker`
(`docker/test.sh`, honors `DOCKER`), `build`, `up`, `down`, `cov` (pytest --cov
with the >= 85% `--cov-fail-under` gate).

## Gotchas

- The dev host's docker needs sudo: prefix `sudo docker` or export
  `DOCKER="sudo docker"` for `docker/test.sh` and make.
- Bind paths in docker-compose.yml resolve relative to the compose FILE dir
  (`docker/`), hence `../examples/...` — `../../examples` points OUTSIDE the
  repo and silently mounts nothing useful.
- Every service that `build`s must set `target:` explicitly. The Dockerfile's
  last stage is `manager`; a target-less build would package the manager stage
  into the runner image tag.
- Socket is per-manager; the named volume must be shared read-write by manager
  and read-only by runner, and removed between unrelated runs if sockets go
  stale (`down -v`).
- Custom decoder/rule XML errors surface in logtest responses (`codemsg: -1`),
  not in compose logs — check the runner output first.
- Decoder `<order>user</order>` stores the value in the alert field
  `data.dstuser` (Wazuh reserves `user` as the destination-user field) — write
  dataset expectations against `data.dstuser`.
