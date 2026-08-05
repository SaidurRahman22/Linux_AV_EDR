# Operations Runbook

> **Documentation set:** v1.5.1 · **Last updated:** 2026-08-05 · **Status:** Current (living)
> **Applies to:** Control plane v1.5.0 · Agents — Linux `0.3.14`, Windows `0.3.16-win`

Day-2 procedures for running Padakhep Sentinel. For first-time install see [DEPLOYMENT.md](DEPLOYMENT.md)
(Linux) and [DEPLOYMENT_WINDOWS.md](DEPLOYMENT_WINDOWS.md).

---

## Services (control-plane host)

| Unit | Role |
|---|---|
| `sentinel-api` | FastAPI control plane + web console (uvicorn, or `python -m controlplane.app.run` for TLS) |
| `sentinel-beacon` | 24/7 threat-intel + Suricata-rule collector |
| `sentinel-av` | (on Linux endpoints) the agent |

```bash
systemctl status  sentinel-api sentinel-beacon
systemctl restart sentinel-api          # after a control-plane code change
journalctl -u sentinel-beacon -f        # watch feed pulls
journalctl -u sentinel-av --since -10min # agent activity on an endpoint
```

Health checks: `GET /healthz` (liveness) and `GET /api/dashboard` (full state, HTTP 200).

---

## Threat-intel feeds

The beacon pulls every `SENTINEL_BEACON_INTERVAL` seconds (default 3600). Open feeds (ThreatFox, ET,
MalwareBazaar, Feodo *aggressive*, Cisco Talos via the FireHOL mirror, URLhaus) run each cycle; keyed
feeds (OTX, AbuseIPDB) require env keys; **AbuseIPDB is interval-gated** (`ABUSEIPDB_INTERVAL_H`,
default 12h) to stay within its free quota. VirusTotal is enrichment only (rate-limited).

- **Force a pull now:** console → *Feed Health* → **Pull now**, or `POST /api/feeds/sync`.
- **"No new Suricata rules":** expected once a source plateaus; the abuse.ch/ET feeds rotate SIDs so
  fresh rules keep arriving. Counts and per-source health are on *Feed Health*.
- **A feed shows "HEALTHY" but stale:** the card shows a cached count, not last-pull success — check
  `journalctl -u sentinel-beacon` for the real per-feed lines / errors.
- Override sources/caps via env: `SENTINEL_SURICATA_RULE_URLS`, `SENTINEL_SURICATA_RULES_MAX`,
  `SENTINEL_BEACON_MAX_PER_SOURCE`.

---

## NIDS / IPS (Suricata)

Per-agent 3-way control (console → *IDS / IPS*): **OFF / IDS / IPS**. The agent orchestrates Suricata
(af-packet for IDS, NFQUEUE for IPS) and reports `running` state on each heartbeat.

- **Custom rules** (*IDS/IPS → Custom Suricata Rules*) are **sanitised server-side** (SEN-005):
  `lua`/`dataset`/`filestore` etc. are dropped, `drop`/`reject` become `alert` unless you set
  `allow_drop`, and size is capped. The agent then validates the merged ruleset with `suricata -T` and
  keeps the last-good file if it fails.
- Suricata must be **provisioned out of band** on endpoints (`av_agent/install_suricata.sh`); the agent
  reports "engine missing" rather than silently `apt install`ing in production (SEN-013 direction).

---

## Log-based IDS

Agents run a general log **decoder + ruleset engine** and emit `producer=log-ids` detections
(visible in *SRS Logs* via the **LOG-IDS** filter chip). The ruleset is central and distributed to
agents by platform.

- **View / manage rules:** in the console under *IDS / IPS* → **Log-based IDS Rules** (list / add /
  enable-disable / delete), or via the API — `GET /api/log-rules`, `POST /api/log-rules` (regex is
  validated), `POST /api/log-rules/{id}/toggle`, `DELETE /api/log-rules/{id}`.
  A rule = `{name, platform, source, pattern, entity_group, threshold, window_sec, severity, mitre,
  event_type}`. `entity_group` is the regex capture group to correlate on (e.g. source IP);
  `threshold>1` alerts only after N matches within `window_sec`.
- **Sources:** Linux `auth` (`/var/log/auth.log`, `secure`), `syslog`, `web`
  (`SENTINEL_WEB_LOGS`, `:`-separated); Windows `winsec`/`winsys` (Security/System event logs,
  rendered to `EventID=… Account=… Address=…` lines). `any` applies everywhere.
- **Behaviour:** history is never re-alerted (offsets / event RecordIds are tracked; first sighting
  sets a baseline). 22 starter rules ship enabled by default.
- **Test it:** generate several failed SSH logins to a Linux host and watch a `log-ids`
  `SSH_INVALID_USER` / `BRUTE_FORCE_SOURCE` detection appear within one scan interval (~60 s).
- **Relation to Wazuh:** this is endpoint-local, low-latency detection; Wazuh remains the aggregate
  SIEM and can correlate these detections with its own decoders.

## Rootkit / anomaly detection (rootcheck)

Each agent runs a **rootcheck** pass and emits `producer=rootcheck` detections (visible in *SRS Logs*
via the **ROOTCHECK** filter chip; also forwarded to Wazuh). It is **consistency/trust based, not
IOC-feed based** — it finds the discrepancies a rootkit creates while hiding — so it runs **fully
locally, with no threat feed and no internet**. There is **no console rule-set to manage** (unlike
log-IDS): it is autonomous on the agent. See [DETECTIONS.md](DETECTIONS.md#host-rootkit--anomaly-detection-rootcheck)
for the full check/event/MITRE table.

- **Config (agent env):** `SENTINEL_ROOTCHECK=1` (on by default; `0` disables),
  `SENTINEL_ROOTCHECK_INTERVAL=600` (seconds between passes), Linux
  `SENTINEL_ROOTCHECK_PIDMAX=131072` (upper bound of the hidden-process brute-force sweep; raise on
  hosts with a very high `pid_max` if you need to cover high PIDs).
- **What it needs:** nothing extra — pure stdlib plus tools the agent already calls (`ss`/`ps` on
  Linux; PowerShell `Get-CimInstance` / `Get-AuthenticodeSignature` on Windows). No new service, no
  feed. The small curated known-artifact / known-driver lists are **embedded** in the agent.
- **Extending it (optional):** the control plane may distribute extra indicators in `/api/sync/policy`
  — `rootkit_artifacts` (paths, any platform) and `bad_drivers` (driver file names, Windows) — merged
  with the embedded defaults. No schema change is required; absent = embedded lists only.
- **Tuning / false positives:** the promiscuous-NIC check is auto-suppressed while Suricata IDS/IPS is
  running (it puts the capture NIC in promiscuous mode by design). `SUSPICIOUS_SUID` and
  `DELETED_BINARY_RUNNING` are scoped to world-writable paths to cut package-manager noise. Findings
  are deduped for the agent's process lifetime. Known-abused (BYOVD) driver hits can be dual-use on
  gaming/overclocking hosts — allow-list-triage via the console like any other detection.

## Allow-list, blocklist, isolation, rename

- **Allow-list** (*Allowlist*): add IP/CIDR or a trusted binary (path + optional sha256). Allow-listed
  IPs are **subtracted from the blocklist** distributed to agents (allow-list wins). Persisted; survives
  reloads.
- **Blocklist** (*Blocked IPs*): manual global/per-agent blocks. The server and agent both reject `/0`,
  over-broad CIDRs, and any range covering the control plane, so a bad entry can't strand the fleet.
- **Isolation** (*Fleet → device → Isolate*): drops all traffic except the control plane. Guarded, but
  TTL / SSH break-glass are still roadmap (SEN-010) — use deliberately.
- **Rename** (*Fleet → device → Rename*): operator-assigned name; **authoritative** — it survives agent
  re-enrolment and propagates to detection history everywhere.

---

## Agent rollout & signing

Agents self-update from **Ed25519-signed** builds. To ship a new agent:

```bash
# 1. edit av_agent/agent.py (Linux) / agent_win.py (Windows): bump VERSION
# 2. (Windows) rebuild the exe:
powershell -ExecutionPolicy Bypass -File av_agent/build_windows.ps1
# 3. sign the build(s) with the OFFLINE key (tools/keys/, never committed):
python tools/sign_agent.py sign av_agent/agent.py av_agent/dist/sentinel-av.exe
# 4. deploy the build + its .sig next to it on the control-plane host (served path),
#    and (Windows) also deploy agent_win.py so the manifest reports the new VERSION.
# 5. push-update from the console (Fleet → Update Agent) or POST /api/agents/{id}/update
```

Verify: `GET /api/agent/manifest` shows the new `version` + `sha256` + `signature`; the agent log shows
`update signature verified (Ed25519)` then re-exec; the fleet shows the new version online.

> **Windows note:** the Windows self-update swaps the exe but its relaunch can be unreliable; if a host
> stays on the old version, relaunch via its Startup `.vbs` (the process re-enrolls and updates).

### Windows install modes (`0.3.16-win`+)

Two mutually-exclusive autostart modes; pick one per host.

| Mode | Command | Runs as | SEN-011 hardening | Notes |
|---|---|---|---|---|
| **Per-user (default)** | `sentinel-av.exe --install` (or double-click) | logged-in user | self-skips (safe) | Startup `.vbs` launcher; the proven path; self-updates via the console. |
| **SYSTEM (opt-in)** | `sentinel-av.exe --install-system` *(as Administrator)* | `SYSTEM` | applied (dir locked to SYSTEM+Administrators) | Boot-start scheduled task `PadakhepSentinelAV`; most reliable update relaunch. Self-elevates once via UAC; falls back to per-user if declined. |

Choose **per-user** for a low-friction install; choose **SYSTEM** when you want the install dir hardened
and boot-time start. `--install-system` must be run from an elevated context (it will prompt UAC once).
Do **not** attempt the SYSTEM conversion by pushing an install remotely over a non-interactive session —
UAC + Defender/SmartScreen make elevated task creation unreliable that way; run `--install-system`
locally on the host instead.

**Recovery — a per-user host whose install dir got locked (or a stalled/duplicate agent):**

```powershell
# as the install-dir owner (the logged-in user):
$dir="C:\ProgramData\PadakhepSentinel"; $exe="$dir\sentinel-av.exe"
Get-Process sentinel-av -ErrorAction SilentlyContinue | Stop-Process -Force
icacls $dir /grant "$($env:USERNAME):(OI)(CI)F" /T /C        # restore access (owner can)
# ensure the current signed exe is present (copy from a fresh build if missing), then relaunch:
$vbs="$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\PadakhepSentinelAV.vbs"
Set-Content $vbs "Set sh=CreateObject(""WScript.Shell"") : sh.Run """"""$exe"""" --run"",0,False" -Encoding ASCII
wscript.exe $vbs
```

Then prune any duplicate fleet record left by the churn: **Fleet → device → Remove**
(or `DELETE /api/agents/{id}`), keeping the one with the freshest `last_seen`.

---

## Wazuh integration

Every Sentinel detection/audit event is mirrored into Wazuh so AV/EDR, log-IDS, Suricata, and
operator actions show up in Wazuh alerts — not a separate console.

- **Install once (on the Wazuh manager host):** `sudo bash deploy/wazuh/install_wazuh_integration.sh`
  — creates the JSON log, installs `padakhep_rules.xml` (ids 100200–100299), adds a `<localfile>`
  block to `ossec.conf`, and restarts `wazuh-manager`. Idempotent. Full details:
  [deploy/wazuh/README.md](../../deploy/wazuh/README.md).
- **Verify:** `tail -f /var/log/padakhep-sentinel/sentinel.json` (control plane writing) and
  `grep -a padakhep /var/ossec/logs/alerts/alerts.json` (Wazuh ingesting). Trigger with a few failed
  SSH logins → an `SSH_INVALID_USER`/`BRUTE_FORCE_SOURCE` alert appears in both.
- **Rule levels:** base 100200 (level 3), HIGH→100201 (8), CRITICAL→100202 (12), brute-force→100203
  (10), log-cleared→100204, user-created→100205, operator/audit→100206, Suricata→100207.
- **Env:** `SENTINEL_WAZUH_FORWARD` (default on), `SENTINEL_WAZUH_LOG`
  (default `/var/log/padakhep-sentinel/sentinel.json`).

## Enabling authentication

Auth is enforced only when a token is set (backward-compatible). To turn it on **without stranding the
fleet**, set the token on every agent host first, then the server:

```bash
# on EACH endpoint env (agent):   SENTINEL_API_TOKEN=<same-token>   (or a dedicated SENTINEL_AGENT_TOKEN)
# then on the control-plane env:  SENTINEL_API_TOKEN=<token>  SENTINEL_REQUIRE_AUTH=1
systemctl restart sentinel-api
# in the console, paste the token when prompted (401 → prompt), stored in localStorage.
```

The per-agent secret (SEN-007) is already enforced independently of this token.

---

## Enabling TLS

```bash
# control-plane env:
SENTINEL_SSL_CERT=/etc/padakhep-sentinel/tls/cert.pem
SENTINEL_SSL_KEY=/etc/padakhep-sentinel/tls/key.pem
SENTINEL_DB_SSLMODE=verify-full        # PostgreSQL TLS
# service runs `python -m controlplane.app.run`, which serves HTTPS when cert+key are set.
# agent env: point at https:// and pin the CA:
SENTINEL_API=https://<host>:8080
SENTINEL_CA_CERT=/etc/sentinel/ca.pem  # or system CAs if publicly trusted
```

Bind to a management interface (`SENTINEL_HOST`) and/or terminate TLS at a reverse proxy; do not leave
`0.0.0.0:8080` plaintext exposed.

---

## Troubleshooting

| Symptom | Likely cause / action |
|---|---|
| Agent `403` on heartbeat | Missing/incorrect `X-Agent-Secret`. A reinstalled agent that lost state gets a new identity; delete the stale record if needed. |
| Agent won't update | Manifest missing the `.sig`, or sha mismatch — re-sign and redeploy the build **and** its `.sig`. |
| NIDS ruleset not applying | `suricata -T` rejected it — check the agent log; the last-good ruleset stays loaded. |
| Console page looks frozen/empty | Some views render from live `/api/dashboard`; hard-refresh (Ctrl-F5). If a page is mock-only, see the engineering note in the code. |
| High RAM on the control-plane host | Check for duplicate/orphaned Suricata processes; the agent tracks its own by log-dir. |
| Feed 429 (AbuseIPDB) | Free-tier quota — the beacon gates it to `ABUSEIPDB_INTERVAL_H`; wait for the daily reset. |

