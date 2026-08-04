# Operations Runbook

> **Documentation set:** v1.0.0 · **Last updated:** 2026-08-05 · **Status:** Current (living)
> **Applies to:** Control plane v1.0.0 · Agents — Linux `0.3.11`, Windows `0.3.9-win`

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

---

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
