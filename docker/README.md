# docker/ — Wazuh logtest offline stack

A two-container stack for learning Wazuh decoders/rules completely offline:

```
host (students)                    docker network
┌─────────────────────────────┐    ┌───────────────────────────────┐
│ docker compose run runner   │    │ manager (wlogtest-manager)    │
│  wlogtest run /data/ds.json ├──► │ analysisd only (logtest srv)  │
│  wlogtest-runner image      │    │ /var/ossec/etc/decoders       │
└──────────┬──────────────────┘    │ /var/ossec/etc/rules          │
           └── shared named volume wazuh-queue:
               /var/ossec/queue/sockets/logtest (AF_UNIX)
```

* `manager` — **`wlogtest-manager:4.14.7`, built locally** from
  `docker/Dockerfile` stage `manager`: amazonlinux:2023 + the pinned
  wazuh-manager 4.14.7 RPM stripped to the logtest engine only (analysisd,
  libs, default ruleset, lists) — ~302MB instead of the ~1.5GB official image.
  `docker/config/ossec.conf` enables `<rule_test>`; your decoders/rules from
  `examples/` are bind-mounted into the user-defined ruleset dirs.
* `runner` — `wlogtest-runner:latest`, built locally (multi-stage:
  `builder` = python:3.12-slim + pinned build toolchain + pytest;
  `runner` = python:3.12-slim + the `wlogtest` wheel only). Entrypoint is
  `wlogtest`, so `compose run runner run /data/datasets/basic.json` works.
* `wazuh-queue` — named volume shared between the services; it is how the
  runner container reaches the manager's logtest socket.
* `runner-test` — the Dockerfile **builder stage** under profile `test`
  (pytest + pytest-cov preinstalled). Only used by `docker/test.sh` to run the
  full pytest suite inside docker against the live manager.

## Quickstart (networked machine)

```bash
make build          # build wlogtest-manager + wlogtest-runner + builder
make up             # start manager, wait until healthy (socket present)
make examples       # run all three example datasets
make test-docker    # full end-to-end validation (see docker/test.sh)
```

Or by hand:

```bash
docker compose -f docker/docker-compose.yml up -d manager
docker compose -f docker/docker-compose.yml run --rm runner run /data/datasets/correlation.json
```

## Offline / air-gapped workflow

The stack needs **zero network at runtime**, but images must be prepared on a
machine that has network:

1. On the networked machine (this downloads the wazuh-manager RPM ~513MB and
   the python base image once, then builds all images locally):

   ```bash
   docker compose -f docker/docker-compose.yml build
   docker save wlogtest-manager:4.14.7 wlogtest-runner:latest \
          wlogtest-runner-builder:latest python:3.12-slim -o wlogtest-images.tar
   ```

2. Move the tarball (USB stick, file server, ...) to the air-gapped classroom
   machines and:

   ```bash
   docker load -i wlogtest-images.tar
   ```

3. Now everything above works with no internet connection. Nothing pulls from
   PyPI at runtime: the builder stage has the (pinned) toolchain baked in, and
   the pytest image has dev dependencies preinstalled.

## Using your own decoders/rules

`examples/decoders/` and `examples/rules/` are mounted at the manager's
user-defined ruleset dirs. To work on your own XML:

1. Put your decoder XML in `examples/decoders/` and rule XML in
   `examples/rules/` (use the `9999_*.xml` naming convention so your ids do
   not collide with the default ruleset).
2. Re-read the ruleset: logtest picks up changes without a manager restart
   (sessions are stateful; see below). If in doubt, restart:

   ```bash
   docker compose -f docker/docker-compose.yml restart manager
   ```

3. Write a dataset in `examples/datasets/` (JSON; see the repo README for the
   matcher format) and run it:

   ```bash
   docker compose -f docker/docker-compose.yml run --rm runner run /data/datasets/mine.json
   ```

Interactive debugging of a single event also works (entrypoint = `wlogtest`):

```bash
docker compose -f docker/docker-compose.yml run --rm runner \
  logtest -e "Aug 27 10:00:00 host myapp[1234]: user alice action login"
```

## Troubleshooting

* **`socket not ready after 120s` / healthcheck stuck** — the manager boots
  analysisd in ~15s normally. Check:

  ```bash
  docker compose -f docker/docker-compose.yml ps        # health state
  docker compose -f docker/docker-compose.yml logs manager
  ```

  If the socket never appears, confirm the named volume is attached
  (`docker volume inspect wazuh-logtest-offline_wazuh-queue`).

* **Bad XML in my decoder/rule** — logtest does not crash the manager; the
  error shows up in the `messages` field of the response (and in the runner's
  verdict output). A decoder that never matches is reported as
  "no decoder matched". Test the file alone with a single-event `logtest`
  command (see above) and read `messages` carefully.

* **Correlation (frequency/if_sid) behaves oddly** — sessions are stateful.
  Cases that share a session name (or a `shared` session mode) must stay in
  the same dataset run, in order; each independent `runner` invocation is a
  fresh session.

* **Permission denied on the socket** — the runner deliberately runs as root
  because the manager creates the socket root-owned. Do not add `user:` to
  the runner service.

* **`fail_demo.json` exits 0** — that means verdicts are not enforced; the
  dataset file is misconfigured (see `examples/datasets/` for the expected
  shape). `docker/test.sh` treats this as a hard failure on purpose.
