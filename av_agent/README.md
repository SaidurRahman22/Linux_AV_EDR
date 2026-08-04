# Padakhep Sentinel — AV Agent (Increment 3+)

Stdlib-only agent (no pip deps; Linux `agent.py`, Windows `agent_win.py`). It **enrolls**
with the control plane, **pulls policy** (`/api/sync/policy` — IOC hashes/IPs, signatures,
behaviors, blocked IPs, **closed ports**), scans locally, and **reports detections**
(`/api/detections`) plus **observed listening ports** on each heartbeat. Detection is
**detect-only**; host-firewall controls (IP blocklist, endpoint isolation, closed ports)
are operator-initiated from the console and enforced locally.

## What it detects
- **Malicious file hash** — SHA-256 of files under the scan dirs vs. IOC hash list.
- **Signature match** — real YARA (if `yara`/`yara-python` installed) or a lightweight
  AND-of-strings fallback (e.g. EICAR) in file contents.
- **Brute force** — repeated failed logins per source IP (`auth.log` on Linux, Security
  event 4625 on Windows).
- **Suspicious process** — running process command lines vs. regex behavior rules.

## Realtime detection (low resource) — v0.3.0
File scanning is **event-driven** instead of a full re-walk every cycle:
- **Linux:** `inotify` via `ctypes` (stdlib) — watches the scan trees and scans only files
  as they're created/modified/moved-in. Idle CPU is ~zero (blocks in `select()`).
- **Windows:** `ReadDirectoryChangesW` via `ctypes` in a watcher thread per scan dir.
- An **incremental cache** (`size,mtime`) means the periodic safety-net full scan only
  re-hashes files that actually changed. Behavior regexes are compiled once per policy
  pull; `primary_ip` is cached. Set `SENTINEL_AV_REALTIME=0` to force periodic scanning.

## Open-port management
Each heartbeat reports the host's **listening TCP/UDP ports** (with owning process).
Operators can **close/open** ports per device from the console (**Open Ports** view);
the agent enforces closes at the host firewall (`nftables` on Linux, Windows Firewall on
Windows) within ~60s and re-opens when the rule is lifted.

## Run
```bash
export SENTINEL_API=http://127.0.0.1:8080
python3 -m av_agent.agent --once     # single pass (test)
python3 -m av_agent.agent            # daemon
```

## Config (env)
| Var | Default | Meaning |
|-----|---------|---------|
| `SENTINEL_API` | `http://127.0.0.1:8080` | control-plane URL |
| `AGENT_NAME` | hostname | fleet name |
| `SENTINEL_SCAN_DIRS` | `/tmp:/var/tmp:/home:/opt/suspect` | dirs to scan (`:`-separated) |
| `SENTINEL_AUTH_LOG` | `/var/log/auth.log` | auth log for brute-force behavior |
| `SENTINEL_AV_INTERVAL` | `60` | seconds between heartbeats / host-telemetry scans |
| `SENTINEL_AV_POLICY_INTERVAL` | `300` | seconds between policy pulls |
| `SENTINEL_AV_REALTIME` | `1` | event-driven file monitoring (`0` = periodic scan only) |
| `SENTINEL_AV_FULLSCAN` | `900` | seconds between incremental safety-net full scans |
| `SENTINEL_AV_MAXFILE` | `8388608` | max file size scanned (bytes) |
| `SENTINEL_API_TOKEN` | — | optional shared secret |

Installed as the `sentinel-av` systemd service (see `deploy/sentinel-av.service`).
