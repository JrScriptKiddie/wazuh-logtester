#!/bin/sh
# Boot the slim logtest engine (wazuh-analysisd) in a container.
#
# The named volume wazuh-queue shadows the in-image /var/ossec/queue tree, so
# the runtime dirs must be (re)created here. analysisd drops privileges to
# the wazuh user by default, so everything it writes must be wazuh-owned.
set -e

# Queue subdirs analysisd touches at startup. A fresh volume shadows the
# in-image tree, so recreate missing ones. `agents-timestamp` is a FILE in
# the RPM tree — leave anything that already exists untouched.
for d in agentless agents-timestamp alerts cluster db diff fim fts \
         indexer keystore logcollector rids router sockets syscollector \
         tasks vd; do
    if [ ! -e "/var/ossec/queue/$d" ]; then
        mkdir -p "/var/ossec/queue/$d"
    fi
done

mkdir -p /var/ossec/logs/alerts /var/ossec/stats /var/ossec/var/run

chown -R wazuh:wazuh /var/ossec/queue /var/ossec/logs \
                     /var/ossec/stats /var/ossec/var/run

exec /var/ossec/bin/wazuh-analysisd "$@"
