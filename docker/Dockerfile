# wazuh-logtest-offline runner image.
#
# Build context is the REPOSITORY ROOT (see docker/docker-compose.yml:
# build.context: ..). Both stages are built without touching the network
# beyond base-image pulls: build isolation is disabled so pip never fetches
# setuptools/wheel from PyPI.
#
# Stage 1 - builder: build toolchain + dev test deps.
# Also used directly as the in-docker pytest image (compose service
# "runner-test", profile "test"): it has pytest/pytest-cov preinstalled and
# an editable install of wlogtest, so the repo can be mounted at /src and
# tested with zero `pip install` at runtime.
FROM python:3.12-slim AS builder

WORKDIR /app

# Build backend + test toolchain in one layer. --no-cache-dir keeps it slim.
RUN python3 -m pip install --no-cache-dir build setuptools wheel pytest pytest-cov

# Only what the package build needs, so unrelated repo edits do not bust the
# layer cache. (If pyproject.toml ever references README.md, add a COPY for it.)
COPY pyproject.toml ./
COPY wlogtest/ ./wlogtest/

# Editable install for the builder image. --no-build-isolation: setuptools and
# wheel are already installed above, so no PyPI access is required.
RUN python3 -m pip install --no-cache-dir --no-build-isolation -e .

# Build the wheel. --no-isolation for the same offline reason.
RUN python3 -m build --wheel --no-isolation --outdir /dist

# Stage 2 - runner: minimal runtime image (only the installed wheel).
FROM python:3.12-slim AS runner

# Copy just the wheel out of the builder; no build toolchain leaks through.
COPY --from=builder /dist /dist

# Install the wheel and delete it in the same layer (single layer stays small).
RUN python3 -m pip install --no-cache-dir /dist/*.whl && rm -rf /dist

# Wazuh logtest AF_UNIX socket as shared via the wazuh-queue volume.
ENV WAZUH_LOGTEST_SOCKET=/var/ossec/queue/sockets/logtest

# We deliberately stay root: the logtest socket in the shared queue volume is
# root-owned by the manager container, and root needs to connect to it.
ENTRYPOINT ["wlogtest"]
CMD ["--help"]
