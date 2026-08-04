# Padakhep Sentinel

**A self-hosted Linux + Windows AV/EDR platform with a central control plane, a 24/7
threat-intel beacon, real-YARA endpoint agents, guarded network isolation, and a
single-file web console — integrated with Wazuh.**

Padakhep Sentinel started life as `wazuh_rulegen` (a Wazuh detection-rule generator,
still included — see [below](#the-wazuh-rule-generator-original-component)) and grew
into a full detect-and-respond stack: lightweight agents on your endpoints check in
to a control plane, pull IOCs + YARA signatures + behavior rules, scan, and report
detections that you triage from a browser.

> Repo: **github.com/SaidurRahman22/Linux_AV_EDR**

---

## Architecture

```
                         ┌─────────────────────────────────────────────┐
                         │              CONTROL PLANE (Linux)           │
   public threat feeds   │                                             │
   ThreatFox · Feodo ───▶│  beacon ─┐        FastAPI + PostgreSQL       │
   MalwareBazaar         │  (24/7)  ├─▶  IOCs · signatures · behaviors  │
   URLhaus · OTX         │  YARA    │        detections · agents        │──▶  Web console
   AbuseIPDB · VirusTotal│  repo    │              │        ▲            │     (single-file
   community YARA repo ──▶│  sync   ┘   /api/sync/policy  /api/detections│      dashboard)
                         │                          │        │           │
                         └──────────────────────────┼────────┼──────────┘
                                        pull policy  │        │  report + heartbeat
                                                     ▼        │
             ┌───────────────────────────┐   ┌───────────────┴───────────────┐
             │      LINUX AV AGENT        │   │        WINDOWS AV AGENT        │
             │  av_agent/agent.py         │   │  sentinel-av.exe (PyInstaller)│
             │  • SHA-256 IOC match       │   │  • SHA-256 IOC match          │
             │  • real YARA scan          │   │  • real YARA scan (bundled)   │
             │  • cmdline behaviors        │   │  • Win32_Process behaviors     │
             │  • auth.log brute force    │   │  • Security-log 4625 brute f. │
             │  • nftables isolation      │   │  • Defender-Firewall isolation│
             │  • self-update (execv)     │   │  • self-update (staged swap)  │
             └───────────────────────────┘   └───────────────────────────────┘
```

The agents speak one small HTTP protocol (enroll → pull policy → scan → report →
heartbeat). The heartbeat response can carry an **isolate** or **update** directive,
so containment and upgrades are driven from the console.

---

## Components

| Path | What it is |
|------|------------|
| [`controlplane/app/`](controlplane/app/) | FastAPI control plane — serves the dashboard, hands policy (IOCs + signatures + behaviors) to agents, ingests detections, manages the fleet. PostgreSQL in prod, SQLite for dev. |
| [`controlplane/beacon/`](controlplane/beacon/) | 24/7 threat-intel worker — pulls real feeds, enriches with VirusTotal, and syncs community YARA rules on a schedule. |
| [`av_agent/agent.py`](av_agent/agent.py) | Linux endpoint agent (stdlib + optional `yara`). |
| [`av_agent/agent_win.py`](av_agent/agent_win.py) | Windows endpoint agent → builds to a single `sentinel-av.exe`. |
| [`av_content/`](av_content/) | Detection content: **202 YARA rules + 100 behavior patterns**, shipped as AV-safe blobs. |
| [`webui/index.html`](webui/index.html) | The whole web console — one self-contained file (vanilla JS, no build step). |
| [`wazuh_rulegen/`](wazuh_rulegen/) | The original Wazuh detection-rule generator (mines `alerts.json` → Wazuh XML rules). |
| [`tools/rulepack.py`](tools/rulepack.py) | Pack/unpack the YARA + behavior rule packs. |

---

## Features

- **Real threat intelligence** — abuse.ch (ThreatFox, Feodo Tracker, MalwareBazaar),
  Emerging Threats, URLhaus (URLs + domains), AbuseIPDB blacklist, AlienVault OTX,
  and rate-limited VirusTotal hash enrichment. No fabricated data.
- **Real YARA** — agents use the actual `yara` engine when present (bundled into the
  Windows exe); a lightweight string matcher is the fallback.
- **202 expert-authored YARA rules + 100 behavior patterns** covering stealers,
  loaders, ransomware/wipers, Linux botnets/rootkits, APT/RAT/C2 frameworks, and
  script/maldoc/webshell delivery (incl. 2023–2025 families). All compile-validated.
- **Scheduled community YARA sync** — the beacon pulls `.yar` files from a
  configurable GitHub directory daily, validates each rule with libyara, and loads
  the good ones.
- **Guarded endpoint isolation** — one click network-quarantines a host (nftables on
  Linux, Windows Firewall on Windows) while keeping loopback, established connections,
  SSH/RDP management, and the control-plane channel open — so it stays reachable and
  reversible.
- **Push-to-update** — update already-installed agents from the fleet page; the agent
  downloads the new build, verifies its SHA-256, and restarts itself.
- **AV-safe rule packs** — YARA/behavior content ships as gzip+base64 blobs so
  endpoint antivirus (ESET/Defender) doesn't quarantine the repo for containing
  malware signature strings.
- **Modern console** — overview KPIs, fleet management, global IOC & rule center,
  log search with a field-by-field detail view + raw JSON, threat-intel health, and a
  manual IP blocklist. Every number is backed by real data.

---

## Quick start (control plane, dev)

Runs on SQLite with no external services:

```bash
python -m venv .venv
.venv/bin/pip install -r controlplane/requirements.txt          # Windows: .venv\Scripts\pip
SENTINEL_DB_URL="sqlite:///./sentinel.db" \
  .venv/bin/uvicorn controlplane.app.main:app --host 0.0.0.0 --port 8080
```

Open **http://localhost:8080/** for the console. Seed content (10 built-in signatures,
5 behaviors, then the 202+100 rule packs) loads on first boot.

Pull threat intel once (feeds that need keys are skipped unless set):

```bash
VT_API_KEY=... ABUSEIPDB_API_KEY=... OTX_API_KEY=... \
  .venv/bin/python -m controlplane.beacon.beacon --once
```

Force a community YARA-repo sync: `python -m controlplane.beacon.beacon --yara-repo`.

## Endpoint agents

**Linux** (stdlib; install `python3-yara` for the full engine):

```bash
SENTINEL_API="http://<control-plane>:8080" AGENT_NAME="web-01" \
  python3 -m av_agent.agent
```

**Windows** — use the prebuilt `av_agent/dist/sentinel-av.exe`, or rebuild:

```powershell
powershell -ExecutionPolicy Bypass -File av_agent\build_windows.ps1
$env:SENTINEL_API="http://<control-plane>:8080"; .\sentinel-av.exe --once
```

Production install (systemd services `sentinel-api`, `sentinel-beacon`, `sentinel-av`),
scheduled-task setup, and the full two-VM walkthrough are in
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) and
[`docs/DEPLOYMENT_WINDOWS.md`](docs/DEPLOYMENT_WINDOWS.md).

---

## Detection content

The rule packs live as **blobs** (`av_content/rulepack.b64`, `behaviors.b64`) because
plaintext `.yar` files contain malware signature strings that trip endpoint AV. To
edit them:

```bash
python tools/rulepack.py unpack      # -> av_content/yara/*.yar + behaviors.json
# ...edit rules...
python tools/rulepack.py pack        # -> rebuild the blobs
```

The control plane decodes the blobs at load. Agents compile all signatures with a
standard set of YARA externals (`filename`, `filepath`, `extension`, …) and pass the
real per-file values at match time, so community rules that reference them work too.

Community sync is configured via env on the control plane (`SENTINEL_YARA_REPO_API`,
`..._MAX_FILES`, `..._MAX_RULES`, `..._INTERVAL_H`, optional `GITHUB_TOKEN`). Pulled
rules keep their upstream license; point the URL at any rule set you're licensed for.

---

## Endpoint isolation & remote updates

- **Isolate** — Fleet → endpoint → *Isolate Endpoint*. Drops all traffic except
  loopback, established connections, management (SSH/RDP/WinRM), and the control
  plane. Reversible from the same modal. Takes effect within ~60 s.
- **Update** — Fleet → endpoint → *Update Agent*. Deploy a new build to the control
  plane (`av_agent/agent.py` / rebuilt `sentinel-av.exe`); `GET /api/agent/manifest`
  reports the current version. The agent applies it on its next check-in, SHA-256
  verified and compile-checked, then restarts itself; the server clears the flag once
  it reports the new version.

---

## API (control plane)

| Endpoint | Purpose |
|----------|---------|
| `GET /` · `GET /healthz` | Dashboard · liveness |
| `GET /api/dashboard` | One call that populates the whole console (real data) |
| `POST /api/enroll` · `POST /api/agents/{id}/heartbeat` | Agent lifecycle |
| `GET /api/sync/policy` | IOCs + signatures + behaviors for an agent |
| `POST /api/detections` · `GET /api/detections` | Ingest / list v3 detection events |
| `POST /api/agents/{id}/isolate` · `/unisolate` | Network quarantine on/off |
| `POST /api/agents/{id}/update` · `/api/agents/update-all` | Push-to-update |
| `GET /api/agent/manifest` · `/api/agent/download/{platform}` | Build info + code |
| `GET/POST /api/iocs` · `/api/signatures` · `/api/behaviors` | Content management |
| `GET/POST /api/blocked` · `POST /api/blocked/{id}/unblock` | Manual IP blocklist |

Set `SENTINEL_API_TOKEN` to require `Authorization: Bearer <token>` on producer/agent
writes (open by default for dev).

---

## The Wazuh rule generator (original component)

`wazuh_rulegen/` still does its original job — mine a Wazuh **manager's** alert stream
and generate ready-to-use Wazuh XML detection rules + CDB IOC lists:

```bash
python run.py scan -c config.local.json     # bundled sample logs, no Wazuh needed
python -m unittest discover -s tests -v      # tests
```

It detects **brute force / scan floods**, **malicious IPs** (feed / high-severity /
volume), and **malicious artifacts** (known-bad hashes + suspicious command lines),
merges each IOC into a single rule (stable IDs ≥ 100000), validates the XML, and
writes it to a **staging** dir for analyst review before activation. Full details,
config reference, and systemd install are in
[`docs/`](docs/) and the package modules.

---

## Requirements

- **Control plane / beacon**: Python 3.10+, `fastapi`, `uvicorn`, `sqlalchemy`,
  `pydantic`, `psycopg` (PostgreSQL; SQLite needs no driver) — see
  [`controlplane/requirements.txt`](controlplane/requirements.txt).
- **Linux agent**: Python 3.8+ (stdlib). `python3-yara` for the real engine, `nftables`
  for isolation.
- **Windows agent**: the prebuilt exe (no Python needed), or Python + `pyinstaller` +
  `yara-python` to build.
- **Wazuh rule generator**: Python 3.8+, standard library only.

---

## Honest notes

- This is a **detect-and-contain** platform. There is no automatic per-detection
  blocking; response is manual isolation + the manual IP blocklist. Confidence scoring
  is in place to gate future guarded prevention.
- The built-in YARA rules are **expert-authored heuristics** informed by known TTPs,
  not a vendor feed — pair them with the scheduled community sync for breadth.
- Self-update compile-checks and SHA-256-verifies the new build, but a syntactically
  valid yet logically broken push can still disrupt an agent; test builds before a
  fleet-wide update.
