# Padakhep Sentinel — AV Agent (Increment 3, basic)

Stdlib-only Linux agent (no pip deps). It **enrolls** with the control plane, **pulls
policy** (`/api/sync/policy` — IOC hashes/IPs, signatures, behaviors), scans locally,
and **reports detections** (`/api/detections`). **Detect-only** — it never blocks
(guarded prevention is a later increment per SRS v3 §8).

## What it detects (basic)
- **Malicious file hash** — SHA-256 of files under the scan dirs vs. IOC hash list.
- **Signature match** — signature strings (e.g. EICAR) found in file contents.
- **Brute force** — repeated failed logins per source IP in `auth.log` (behavior threshold).
- **Suspicious process** — running process command lines vs. regex behavior rules
  (reverse shell, download-and-execute, etc.).

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
| `SENTINEL_AV_INTERVAL` | `60` | seconds between scan cycles |
| `SENTINEL_AV_POLICY_INTERVAL` | `300` | seconds between policy pulls |
| `SENTINEL_AV_MAXFILE` | `8388608` | max file size scanned (bytes) |
| `SENTINEL_API_TOKEN` | — | optional shared secret |

Installed as the `sentinel-av` systemd service (see `deploy/sentinel-av.service`).
