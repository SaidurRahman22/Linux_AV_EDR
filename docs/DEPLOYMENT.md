# Padakhep Sentinel — Deployment Runbook

**Scope:** deploying the **Control Plane** (dashboard + API + threat-intel beacon) and an
**initial AV instance** onto the Wazuh manager VM.
**Target host (this deployment):** `192.168.39.32` — Ubuntu 24.04 LTS, Python 3.12.
**Status:** deployed and verified 2026-08-03 (see §9).

> **Credentials note:** SSH/sudo credentials are never stored in this repository or this
> document. Substitute your own where a step needs them.

---

## 1. What gets deployed

| Component | Unit | Port | Runs as |
|-----------|------|------|---------|
| Control-plane API + Dashboard | `sentinel-api.service` | 8080 | root (uvicorn) |
| Threat-Intel Beacon (24/7) | `sentinel-beacon.service` | — | root |
| AV instance (detect-only) | `sentinel-av.service` | — | root |
| Database | PostgreSQL 16 (`sentinel` db) | 5432 (local) | postgres |

Data flow: **Beacon → PostgreSQL (IOC/signature/behavior DB) → Dashboard/API →
AV instance (pull policy, scan, report) → detections back to the DB → Dashboard.**

---

## 2. Prerequisites

- A Linux VM (Ubuntu 22.04/24.04 tested) with **root/sudo**.
- Outbound HTTPS (the beacon pulls open threat feeds; `pip` installs deps).
- Ports **8080** (dashboard) reachable from operators; **5432** stays local.
- A copy of this repository on the VM (git clone, or upload as below).

---

## 3. Deployment procedure

All commands run **on the VM** as a sudo-capable user, from the repository root
(here `/opt/padakhep-sentinel`).

### Step 1 — Remove any legacy `wazuh_rulegen` install (if present)
```bash
sudo systemctl disable --now wazuh-rulegen.service wazuh-rulegen-feedupdate.timer 2>/dev/null || true
sudo systemctl stop wazuh-rulegen-feedupdate.service 2>/dev/null || true
sudo rm -f /etc/systemd/system/wazuh-rulegen*.service /etc/systemd/system/wazuh-rulegen*.timer
sudo systemctl daemon-reload
sudo rm -rf /opt/wazuh-rulegen /etc/wazuh-rulegen /var/log/wazuh-rulegen.log
sudo rm -f /var/ossec/etc/rules/wazuh_rulegen_generated_rules.xml   # promoted rules (unloads on next manager restart)
```

### Step 2 — System dependencies
```bash
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv python3-pip postgresql
```

### Step 3 — Place the code
```bash
sudo mkdir -p /opt/padakhep-sentinel && sudo chown "$USER":"$USER" /opt/padakhep-sentinel
# then git clone into it, or copy the repo contents so you have:
#   /opt/padakhep-sentinel/{controlplane,wazuh_rulegen,webui,av_agent}
```
*(In this deployment the tree was uploaded over SSH — the repo is private, so a
deploy key or PAT is required for `git clone`.)*

### Step 4 — Install the control plane (API + beacon)
```bash
sudo bash /opt/padakhep-sentinel/controlplane/deploy/install.sh
```
This creates a venv, installs FastAPI/uvicorn/SQLAlchemy/psycopg, creates the
PostgreSQL role+database, writes `/etc/padakhep-sentinel.env`, and installs+starts
`sentinel-api` and `sentinel-beacon`. The beacon fills the IOC DB on first run
(open feeds: abuse.ch ThreatFox/Feodo/MalwareBazaar, Emerging Threats).

### Step 5 — Deploy the AV instance
```bash
# env
sudo tee /etc/sentinel-av.env >/dev/null <<'EOF'
SENTINEL_API=http://127.0.0.1:8080
AGENT_NAME=wazuh-vm-av
SENTINEL_SCAN_DIRS=/opt/suspect:/tmp:/var/tmp
SENTINEL_AUTH_LOG=/var/log/auth.log
SENTINEL_AV_INTERVAL=60
SENTINEL_AV_POLICY_INTERVAL=300
EOF
sudo mkdir -p /opt/suspect /var/lib/sentinel-av
# optional: drop the harmless EICAR test file so the agent has something to detect
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | sudo tee /opt/suspect/eicar.com >/dev/null
# service
sudo sed "s|__ROOT__|/opt/padakhep-sentinel|g" \
  /opt/padakhep-sentinel/av_agent/deploy/sentinel-av.service > /tmp/sentinel-av.service
sudo mv /tmp/sentinel-av.service /etc/systemd/system/sentinel-av.service
sudo systemctl daemon-reload && sudo systemctl enable --now sentinel-av
```

### Step 6 — Firewall (expose the dashboard)
```bash
sudo ufw allow 8080/tcp
```

### Step 7 — Verify
```bash
curl -s http://localhost:8080/healthz
curl -s http://localhost:8080/api/stats            # iocsTracked>0, endpointsTotal>=1
curl -s http://localhost:8080/api/agents           # the AV instance, status online
curl -s "http://localhost:8080/api/detections?limit=5"
journalctl -u sentinel-beacon -n 5 --no-pager      # "upserted N IOCs"
journalctl -u sentinel-av -n 8 --no-pager          # "DETECT ... EICAR" / "reported N detection(s)"
```

---

## 4. Access

- **Dashboard:** `http://<vm-ip>:8080/`  (this deployment: `http://192.168.39.32:8080/`)
- **API docs (OpenAPI):** `http://<vm-ip>:8080/docs`
- **Health:** `http://<vm-ip>:8080/healthz`

---

## 5. Operations

| Task | Command |
|------|---------|
| Service status | `systemctl status sentinel-api sentinel-beacon sentinel-av` |
| Live logs | `journalctl -u sentinel-api -f` (or `-beacon` / `-av`) |
| Restart | `sudo systemctl restart sentinel-api` |
| Trigger a beacon collection now | `sudo systemctl restart sentinel-beacon` |
| Add paid feed keys | edit `/etc/padakhep-sentinel.env` (`VT_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`) → `sudo systemctl restart sentinel-beacon` |
| Tune the AV | edit `/etc/sentinel-av.env` → `sudo systemctl restart sentinel-av` |
| Add another AV host | copy `av_agent/` + Python 3 to the host, set `SENTINEL_API=http://<vm-ip>:8080`, install `sentinel-av.service` |

Config files: `/etc/padakhep-sentinel.env` (control plane), `/etc/sentinel-av.env` (AV).

---

## 6. Security notes (read before going beyond a lab)

- This is an **MVP**. Agent/producer auth is an **optional shared token**
  (`SENTINEL_API_TOKEN`, empty = open). **mTLS + signed IOC/policy artifacts + RBAC**
  are planned (SRS v3 §7) and **not yet implemented**.
- **Do not expose port 8080 to the public Internet.** Keep it on the management LAN or
  behind a reverse proxy with TLS + auth. The 8080 firewall rule above allows *Anywhere*
  on the VM's networks — tighten it to your operator subnet in production.
- Services currently run as **root** (the AV needs to read `auth.log` and `/proc`, and
  the API binds 8080). Drop privileges / harden in a later increment.
- The AV is **detect-only** — it never blocks or quarantines (guarded prevention is a
  future increment per SRS v3 §8).

---

## 7. Uninstall / rollback
```bash
sudo systemctl disable --now sentinel-av sentinel-beacon sentinel-api
sudo rm -f /etc/systemd/system/sentinel-*.service
sudo systemctl daemon-reload
sudo rm -rf /opt/padakhep-sentinel /etc/padakhep-sentinel.env /etc/sentinel-av.env /var/lib/sentinel-av
# optional: drop the database
sudo -u postgres psql -c "DROP DATABASE sentinel;" -c "DROP ROLE sentinel;"
sudo ufw delete allow 8080/tcp
```

---

## 8. Troubleshooting

| Symptom | Fix |
|---------|-----|
| Dashboard shows mock data | API unreachable from the browser — confirm `sentinel-api` active + port 8080 open |
| `iocsTracked: 0` | check `journalctl -u sentinel-beacon` (feed/network error); restart the beacon |
| AV not appearing in fleet | check `journalctl -u sentinel-av`; confirm `SENTINEL_API` reaches the control plane |
| `pip`/venv errors | ensure `python3-venv` installed and the VM has outbound HTTPS |
| Beacon `UniqueViolation` | fixed (intra-run dedup); ensure you deployed the current `beacon.py` |

---

## 9. Verified in this deployment (2026-08-03, `192.168.39.32`)

- Legacy `wazuh_rulegen` removed (services, dirs, promoted rules).
- `sentinel-api` + `sentinel-beacon` active; **1,661 IOCs** loaded (1,005 IPs), 2 signatures, 5 behaviors seeded.
- `sentinel-av` enrolled as `wazuh-vm-av` (online), pulled policy, **detected the EICAR test file**, reported detections.
- Dashboard reachable at **http://192.168.39.32:8080/** after opening the firewall.

## Threat-intel & rule content

The beacon fills the central store on a schedule:

- **IOC feeds** (hourly): abuse.ch (ThreatFox/Feodo/MalwareBazaar), Emerging
  Threats, URLhaus (URLs+domains), AbuseIPDB blacklist, AlienVault OTX; VirusTotal
  enrichment (rate-limited).
- **Built-in rule packs** (on boot): 202 expert-authored YARA rules + 100 behavior
  patterns, shipped as AV-safe blobs (`av_content/*.b64`, decoded at load).
- **Community YARA repo sync** (daily): pulls `.yar` files from a configurable
  GitHub directory, validates each rule with libyara (rules that need modules or
  externals we don't provide are skipped), and upserts them as `source="repo:*"`
  signatures. Agents compile with a standard externals set and pass real
  `filename/filepath/extension` at match time.

Config (env on the control plane):

| Variable | Default | Meaning |
|---|---|---|
| `SENTINEL_YARA_REPO` | `1` | enable/disable the repo sync |
| `SENTINEL_YARA_REPO_API` | `.../Yara-Rules/rules/contents/malware` | comma-separated GitHub *contents* API dir URL(s) |
| `SENTINEL_YARA_REPO_MAX_FILES` | `80` | files fetched per sync |
| `SENTINEL_YARA_REPO_MAX_RULES` | `500` | new rules stored per sync |
| `SENTINEL_YARA_REPO_INTERVAL_H` | `24` | hours between syncs |
| `GITHUB_TOKEN` | (none) | optional, raises the API rate limit |

Force a sync now: `./controlplane/.venv/bin/python -m controlplane.beacon.beacon --yara-repo`

> Community rules keep their upstream license (e.g. Yara-Rules/rules is GPLv2).
> They are pulled at runtime onto your server, not redistributed in this repo.
> Point `SENTINEL_YARA_REPO_API` at any rule directory you're licensed to use.

## Remote agent updates (push-to-update)

During development you can update already-installed agents from the console:

1. Deploy the new agent build to the control plane (`av_agent/agent.py` for Linux,
   rebuild + copy `av_agent/dist/sentinel-av.exe` for Windows). `GET /api/agent/manifest`
   reports the current per-platform version + sha256.
2. Fleet page → open an endpoint → **Update Agent**. This sets a flag; the agent
   picks up the directive on its next heartbeat (~60s), downloads the build from
   `/api/agent/download/<platform>`, **verifies the sha256**, and:
   - **Linux**: compiles the new code (aborts if it doesn't), backs up the old file,
     replaces itself, and `execv`-restarts in place.
   - **Windows** (frozen exe): stages the new exe and a helper `.cmd` that swaps it
     and restarts the scheduled task (`SENTINEL_TASK_NAME`, default `PadakhepSentinelAV`).
3. The server clears the flag automatically once the agent checks in reporting the
   new version. `POST /api/agents/update-all` queues every agent.

Safety: integrity is sha256-verified and Linux code is compile-checked before
install (a broken push is refused and the agent keeps running). A `.bak` is kept.
