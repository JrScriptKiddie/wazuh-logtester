#!/usr/bin/env bash
# End-to-end validation of the wazuh-logtest-offline docker stack.
# Requires: docker + compose v2. Safe to run from any CWD (paths are resolved
# to the repo root first).
#
# What this script proves, in order:
#   (a) manager container starts
#   (b) logtest socket becomes available (health gate, max 120s)
#   (c) runner images build (runner + runner-test/builder stage)
#   (d) basic.json        -> exit 0 (decoders + single rules all pass)
#   (e) correlation.json   -> exit 0 (stateful session + frequency rule)
#   (f) fail_demo.json     -> exit 1 (verdict engine really fails on mismatch)
#   (g) full pytest suite (unit + integration, live socket) + coverage, inside
#       docker -- offline-safe: the builder image already has pytest/pytest-cov
#       and an editable wlogtest install, so nothing is pip-installed here.
#   (h) teardown via trap: `docker compose down -v` always runs, even on
#       failure, and the overall exit code is preserved.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Docker CLI override for hosts where docker needs sudo:
#   DOCKER="sudo docker" bash docker/test.sh
DOCKER="${DOCKER:-docker}"

# Relative paths inside docker/docker-compose.yml are relative to docker/,
# not to this CWD, so the -f form below behaves the same from anywhere.
COMPOSE="$DOCKER compose -f docker/docker-compose.yml"

step() { printf '\n=== %s ===\n' "$1"; }

# (h) teardown on any exit path, preserving the original exit code.
cleanup() {
  local status=$?
  printf '\n=== teardown: docker compose down -v ===\n'
  $COMPOSE down -v || true
  exit "$status"
}
trap cleanup EXIT

# (a) start only the manager; runner containers are used via `compose run`.
step "start manager"
$COMPOSE up -d manager

# (b) wait up to 120s for the logtest socket to appear.
step "wait for logtest socket (max 120s)"
for i in {1..24}; do
  if $COMPOSE exec -T manager test -S /var/ossec/queue/sockets/logtest; then
    echo "socket ready after ~$((i * 5))s"
    break
  fi
  if [ "$i" -eq 24 ]; then
    echo "ERROR: logtest socket not ready after 120s" >&2
    $COMPOSE logs manager >&2 || true
    exit 1
  fi
  sleep 5
done

# (c) build both runner images (runtime image + builder stage for pytest).
step "build runner images"
$COMPOSE build runner runner-test

# (d) dataset that must fully pass; `set -e` fails the script on non-zero exit.
step "run basic.json (expect exit 0)"
$COMPOSE run --rm -T runner run /data/datasets/basic.json

# (e) correlation dataset: shared session, frequency rule 100102 fires.
step "run correlation.json (expect exit 0)"
$COMPOSE run --rm -T runner run /data/datasets/correlation.json

# (f) intentionally-wrong expectations MUST exit non-zero. If it exits 0,
# verdicts are not being enforced and the whole validation fails.
step "run fail_demo.json (expect exit 1)"
if $COMPOSE run --rm -T runner run /data/datasets/fail_demo.json; then
  echo "ERROR: fail_demo.json exited 0 -- verdicts are not enforced" >&2
  exit 1
fi
echo "fail_demo.json correctly exited non-zero"

# (g) pytest inside docker against the LIVE manager.
#     runner-test is the builder stage (profile "test"): pytest + pytest-cov
#     are baked in, the repo is mounted rw at /src with PYTHONPATH=/src (so
#     the mounted tree wins over the build-time editable install), and the
#     shared wazuh-queue volume provides the real logtest socket. Unit AND
#     integration tests therefore both run, with no `pip install` inside the
#     container (offline-safe). depends_on makes compose wait for manager
#     health before the run.
step "pytest inside docker (unit + integration + coverage)"
# -o addopts="" disables the pyproject default "-m not integration" so the
# live-socket integration tests actually run here (docker only).
$COMPOSE run --rm -T runner-test python3 -m pytest -o addopts="" --cov=wlogtest --cov-report=term-missing -q

step "all docker checks passed"
