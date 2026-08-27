# vendor/wazuh — forked Wazuh sources

Origin: forked from [wazuh/wazuh](https://github.com/wazuh/wazuh) at tag **v4.14.7**
(full upstream tree archived at `/tmp/opencode/wazuh` during development; only the
logtest-relevant subset is committed here).

These files are the protocol/server reference for our offline logtest client.
They are **not** built or executed by this project — the actual logtest engine
runs inside the locally-built slim `wlogtest-manager:4.14.7` image (analysisd
4.14.7 extracted from the wazuh-manager RPM, see `docker/Dockerfile`), which
binds the logtest socket. Vendored copies let students and agents inspect the
wire protocol without network access.

| Path | Purpose |
|---|---|
| `src/analysisd/logtest.{c,h}` | Logtest server inside analysisd (sessions, framing, commands) |
| `src/config/logtest-config.{c,h}` | `<rule_test>` ossec.conf block parsing |
| `framework/scripts/wazuh_logtest.py` | Official `wazuh-logtest` CLI (Python) |
| `framework/wazuh/core/logtest.py` | API-side client used by Wazuh API `/logtest` |
| `framework/wazuh/core/wazuh_socket.py` | Socket + JSON framing implementation |
| `framework/wazuh/core/common.py` | `LOGTEST_SOCKET` path constant |
| `etc/templates/config/generic/rule_test.template` | Default `<rule_test>` config template |
| `VERSION.json` | Upstream version marker |

License: GPL-2.0 (see `LICENSE`). Wazuh and the Wazuh logo are trademarks of
Wazuh Inc. — see upstream NOTICE files. This project is not affiliated with Wazuh Inc.
