# Padakhep Sentinel — Control Plane (Increment 2)

The **hub** of the platform: a FastAPI backend + PostgreSQL database that the
**Threat-Intel Beacon** fills with IOCs/signatures/behaviors, the **web dashboard**
reads from, and (next increment) the **AV agents** pull policy from and report
detections to.

```
Beacon (24/7) ─▶ [ Control Plane: API + DB ] ─▶ Dashboard (view)
                          ▲            │
        AV agents ── report│            └─▶ sync/policy (push IOCs down to AV)
```

## Run locally (dev, SQLite — no DB server needed)
```bash
python -m venv .venv && . .venv/Scripts/activate      # (Linux: source .venv/bin/activate)
pip install -r controlplane/requirements.txt
export SENTINEL_DB_URL="sqlite:///./sentinel.db"       # dev only
# fill the DB from open threat feeds:
python -m controlplane.beacon.beacon --once
# serve the API + dashboard:
uvicorn controlplane.app.main:app --port 8080
# open http://localhost:8080/   (dashboard, now live)   ·   /docs for the API
```

## Install on the Wazuh VM (prod, PostgreSQL)
```bash
sudo bash controlplane/deploy/install.sh
```
Sets up a venv, PostgreSQL role/db, an env file (`/etc/padakhep-sentinel.env`), and
two systemd services: **`sentinel-api`** (dashboard + API on :8080) and
**`sentinel-beacon`** (24/7 collector). Add feed API keys to the env file and
`systemctl restart sentinel-beacon`.

## API (selected)
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/dashboard` | one-call aggregate the web UI uses for live data |
| GET | `/api/stats` | fleet/IOC/detection summary counters |
| GET/POST | `/api/iocs` | list / bulk-upsert IOCs (beacon writes here) |
| GET/POST | `/api/signatures`, GET `/api/behaviors` | detection content catalog |
| POST | `/api/enroll`, `/api/agents/{id}/heartbeat`, GET `/api/agents` | fleet |
| POST/GET | `/api/detections` | ingest (from AV / rule-gen) / list detections |
| GET | `/api/sync/policy` | **pulldown** the AV fetches: active IOCs + signatures + behaviors |
| GET | `/healthz`, `/` | health, dashboard |

## Threat-Intel Beacon
- **Open feeds active now** (no key): abuse.ch ThreatFox / Feodo / MalwareBazaar, Emerging Threats. (Reuses the validated rule-engine feed parsers.)
- **Keyed feeds = placeholders** (`VT_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`): they log-and-skip until you supply the key in the env file.
- Seeds default **signatures** (EICAR, reverse-shell YARA) and **behaviors** (multiple failed logins, download-cradle, log deletion, cron persistence).

## Config (env)
`SENTINEL_DB_URL` · `SENTINEL_PORT` (8080) · `SENTINEL_WEBUI` · `SENTINEL_BEACON_INTERVAL` (3600s) · `SENTINEL_IOC_TTL` (30d) · `SENTINEL_BEACON_MAX` · `SENTINEL_API_TOKEN` (optional shared secret) · `VT_API_KEY` / `ABUSEIPDB_API_KEY` / `OTX_API_KEY`.

> **Status:** Increment 2 MVP — auth is an optional shared token; **mTLS + signed artifacts land in a later increment** (see SRS v3 §7). Not yet production-hardened.

## Next
- **Inc 3:** the AV agent that pulls `/api/sync/policy`, scans (hash/IOC/YARA/behavior), and POSTs detections to `/api/detections`.
- **Inc 4:** dashboard-driven push to agents + AV detections → Wazuh rule generation.
