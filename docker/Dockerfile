# wazuh-logtest-offline images.
#
# Build context is the REPOSITORY ROOT (see docker/docker-compose.yml:
# build.context: ..). The builder/runner stages are built without touching the
# network beyond base-image pulls (build isolation is disabled so pip never
# fetches setuptools/wheel from PyPI). The manager stage downloads the pinned
# wazuh-manager RPM (build-time network only) and strips it down to the
# logtest engine (wazuh-analysisd): no framework/API/wodles/remoted.
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

# Stage 3 - manager: slim logtest-only engine. wazuh-analysisd 4.14.7 is only
# distributed inside the wazuh-manager RPM, which is built for
# amazonlinux2023/el9 — hence this base. The RPM is fetched at build time and
# stripped to the minimum analysisd needs (binary, libs, default ruleset,
# lists, internal_options.conf). This replaces the ~1.5GB official
# wazuh/wazuh-manager image.
#
# NOTE: download + install + strip + tool cleanup are ONE layer on purpose.
# If they were separate layers, the full ~1.3GB unpacked RPM would stay in
# the layer history (deletions only add whiteouts) and the image would be
# ~2GB despite the slim final filesystem.
FROM amazonlinux:2023 AS manager

ARG WAZUH_VERSION=4.14.7
ARG WAZUH_RPM_URL=https://packages.wazuh.com/4.x/yum/wazuh-manager-${WAZUH_VERSION}-1.x86_64.rpm

# findutils + shadow-utils are needed by the RPM scriptlets only (find,
# groupadd, useradd); curl-minimal already ships in the base image.
# The wazuh user is required: analysisd drops privileges to it by default.
#
# Strip list — removed: python framework (557M), vulnerability-detector feed
# in tmp/ (379M), api, wodles, agentless, active-response, integrations,
# logcollector, templates, backup, sqlite DBs (wazuh-db is not run), SCA
# policies (wazuh-modulesd only), and every binary except wazuh-analysisd.
# etc/shared is KEPT: analysisd's config read requires etc/shared/ar.conf
# even with no active-response configured. Kept: bin/wazuh-analysisd, lib/
# (libwazuhext.so etc.), ruleset/decoders + ruleset/rules (default ruleset),
# etc/ (ossec.conf, internal_options.conf, lists, ssl certs), queue/, logs/,
# stats/, var/run.
RUN dnf install -y -q findutils shadow-utils && \
    groupadd -g 1000 wazuh && \
    useradd -u 1000 -g wazuh -d /var/ossec -s /sbin/nologin wazuh && \
    curl -fsSLo /tmp/wazuh-manager.rpm "${WAZUH_RPM_URL}" && \
    rpm -ivh --nodeps /tmp/wazuh-manager.rpm && \
    rm -f /tmp/wazuh-manager.rpm && \
    rm -rf /var/ossec/framework /var/ossec/api /var/ossec/wodles \
           /var/ossec/agentless /var/ossec/active-response \
           /var/ossec/integrations /var/ossec/logcollector \
           /var/ossec/templates \
           /var/ossec/tmp /var/ossec/backup \
           /var/ossec/var/db /var/ossec/var/selinux \
           /var/ossec/var/download /var/ossec/var/multigroups \
           /var/ossec/var/upgrade /var/ossec/var/wodles \
           /var/ossec/ruleset/sca && \
    find /var/ossec/bin -mindepth 1 ! -name wazuh-analysisd -delete && \
    chown -R wazuh:wazuh /var/ossec && \
    rpm -e --nodeps findutils shadow-utils libsemanage && \
    dnf clean all && \
    rm -rf /var/cache/dnf

# Our manager config (rule_test enabled) as the in-image fallback; compose
# mounts the same file over it at runtime. RPM default would leave logtest
# disabled, so the fallback must be ours.
COPY docker/config/ossec.conf /var/ossec/etc/ossec.conf

# Build-time gate: analysisd must parse the config it will boot with.
RUN /var/ossec/bin/wazuh-analysisd -t && \
    echo "analysisd config check OK"

COPY docker/manager-entrypoint.sh /usr/local/bin/manager-entrypoint.sh
RUN chmod +x /usr/local/bin/manager-entrypoint.sh

# The entrypoint recreates runtime dirs (the queue volume shadows the
# in-image tree), chowns them, and runs analysisd in the foreground.
ENTRYPOINT ["/usr/local/bin/manager-entrypoint.sh"]
CMD ["-f"]
