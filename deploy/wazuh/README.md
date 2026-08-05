# Wazuh integration

Sends **all** Padakhep Sentinel AV/EDR detections (file/YARA/behaviour, log-based IDS, Suricata
IDS/IPS, and operator/audit actions) into a **Wazuh** manager so they appear in Wazuh alerts and the
Wazuh dashboard alongside everything else — no separate pane of glass.

## How it works

```
control plane  ──(append JSON line per event)──▶  /var/log/padakhep-sentinel/sentinel.json
                                                            │  log_format json
                                                            ▼
                                                   Wazuh logcollector ─▶ analysisd
                                                            │  padakhep_rules.xml (ids 100200-100299)
                                                            ▼
                                                   Wazuh alerts / dashboard
```

The control plane writes one JSON object per event, namespaced under `padakhep.*`, e.g.:

```json
{"padakhep":{"producer":"log-ids","event_type":"SSH_INVALID_USER","device":"scweb",
 "severity":"HIGH","ioc":"1.2.3.4","ioc_type":"ip","mitre":["T1110"],
 "rule":"ssh_invalid_user","source":"/var/log/auth.log","timestamp":"..."}}
```

Wazuh's built-in JSON decoder exposes those as fields (`padakhep.producer`, `padakhep.severity`, …);
`padakhep_rules.xml` classifies them (base id 100200; HIGH→100201/level 8, CRITICAL→100202/level 12,
brute-force→100203, log-cleared→100204, user-created→100205, operator/audit→100206, Suricata→100207).

## Install (on the Wazuh manager host)

The Wazuh manager is co-located with the control plane in the reference deployment, so it reads the
file directly:

```bash
sudo bash deploy/wazuh/install_wazuh_integration.sh
```

This is idempotent: it creates the log file, installs the rules, adds the `<localfile>` block to
`ossec.conf` once (backing it up), and restarts `wazuh-manager`.

**Remote Wazuh manager?** Point a Wazuh *agent* on the control-plane host at the same file with the
same `<localfile>` block, and install `padakhep_rules.xml` on the manager.

## Verify

```bash
# events being written by the control plane:
tail -f /var/log/padakhep-sentinel/sentinel.json
# alerts landing in Wazuh:
grep -a padakhep /var/ossec/logs/alerts/alerts.json | tail
```

Trigger one easily: run a few failed SSH logins to a monitored Linux host and watch an
`SSH_INVALID_USER` / `BRUTE_FORCE_SOURCE` alert appear in both files.

## Configuration

| Env (control plane) | Default | Purpose |
|---|---|---|
| `SENTINEL_WAZUH_FORWARD` | `1` | Master on/off for forwarding |
| `SENTINEL_WAZUH_LOG` | `/var/log/padakhep-sentinel/sentinel.json` | File Wazuh reads |

Forwarding is best-effort and never blocks or breaks detection ingestion.
