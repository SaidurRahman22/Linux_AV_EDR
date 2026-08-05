# Architecture

> **Documentation set:** v1.5.1 · **Last updated:** 2026-08-05 · **Status:** Current (living)
> **Applies to:** Control plane v1.5.0 · Agents — Linux `0.3.14`, Windows `0.3.19-win`

This document describes how Padakhep Sentinel is put together: its components, how data flows between
them, where the trust boundaries sit, and the threat model those boundaries are designed to withstand.

---

## 1. Component overview

```
                         ┌─────────────────────────────────────────────────────┐
                         │                  CONTROL PLANE (host)                 │
   Threat-intel feeds    │                                                       │
   (ThreatFox, ET, ...)  │   ┌───────────────┐        ┌──────────────────────┐  │
        │  ▲              │   │  Beacon        │  IOCs  │  FastAPI app         │  │
        ▼  │              │   │  (24/7 worker) ├───────▶│  controlplane/app    │  │
   ┌──────────────┐  pull │   │  beacon.py     │  rules │  - REST API          │  │
   │ FireHOL/abuse│◀──────┼───┤  feeds.py      │        │  - policy sync       │  │
   │ .ch/OISF/... │       │   └───────────────┘        │  - web console (/)   │  │
   └──────────────┘       │                            │  - self-update mfst  │  │
                          │   ┌───────────────┐        └──────────┬───────────┘  │
                          │   │ wazuh_rulegen │  rules            │              │
                          │   │ (intel→Wazuh) │─────▶ Wazuh       │ SQLAlchemy   │
                          │   └───────────────┘                   ▼              │
                          │                            ┌──────────────────────┐  │
                          │                            │ PostgreSQL (SQLite   │  │
                          │                            │ in dev)              │  │
                          │                            └──────────────────────┘  │
                          └───────────────────────────────────┬───────────────────┘
                                     HTTP(S) — enroll / heartbeat / policy / detections / download
                          ┌───────────────────────┬───────────┴───────────┬─────────────────────┐
                          ▼                        ▼                       ▼                     
                 ┌────────────────┐      ┌────────────────┐      ┌────────────────┐              
                 │ Linux agent    │      │ Linux agent    │      │ Windows agent  │              
                 │ agent.py 0.3.11│      │ agent.py 0.3.11│      │ sentinel-av.exe│              
                 │ + Suricata     │      │ + Suricata     │      │ 0.3.9-win      │              
                 │ + nftables     │      │ + nftables     │      │ + Defender FW  │              
                 └────────────────┘      └────────────────┘      └────────────────┘              
```

### 1.1 Control plane — `controlplane/app`
A FastAPI application (`main.py`, ~1200 LOC) that is the single source of truth. Responsibilities:
- **REST API** for the console and agents (see [API_REFERENCE.md](API_REFERENCE.md)).
- **Policy distribution** — computes each agent's blocklist, closed ports, allow-list, IOCs,
  signatures and Suricata ruleset.
- **Web console** — serves the single-file dashboard at `/`.
- **Self-update manifest** — advertises the current signed agent build per platform.
- **Security middleware** — one `/api/*` gate (auth when configured) that also stamps CSP and
  security headers on every response.

Persistence is SQLAlchemy 2.0 (`db.py`, `models.py`). Production uses PostgreSQL; development falls
back to SQLite (`SENTINEL_DB_URL`). Schema evolution for already-deployed DBs is handled by an
idempotent `ALTER`-based migration (`_ensure_columns` in `db.py`) alongside `create_all`.

### 1.2 Endpoint agents — `av_agent/`
Pure-**stdlib** Python (no pip dependencies), so a single file / single exe runs anywhere with a
Python 3 runtime (Linux) or as a PyInstaller one-file exe (Windows).

- `agent.py` (Linux, `VERSION 0.3.15`): file scanning (sha256 + lightweight YARA-ish string
  signatures + behaviour rules), realtime watch via **inotify** (ctypes), firewall enforcement via
  **nftables**, network isolation, Suricata IDS/IPS orchestration, log-based IDS, **rootkit/anomaly
  detection (rootcheck)**, and self-update.
- `agent_win.py` (Windows, `VERSION 0.3.16-win`, packaged as `sentinel-av.exe`): the same protocol
  with **ReadDirectoryChangesW** realtime, **Windows Defender Firewall** enforcement, rootcheck via
  process cross-view + catalog-aware driver trust, and real YARA when `yara-python` is bundled.

Both agents run as root/SYSTEM and follow the loop: **enroll → pull policy → baseline scan →
{realtime events, periodic heartbeat, periodic policy, periodic full scan, log-IDS scan, rootcheck}**.

**Rootkit / anomaly detection (rootcheck).** Each agent periodically runs local consistency/trust
checks (`rootcheck_scan`, `producer=rootcheck`) that need **no threat feed** — a rootkit reveals itself
through the discrepancies it creates while hiding. Linux: hidden-process/-port cross-views, `ld.so.preload`,
hidden/known kernel modules, promiscuous NIC, deleted-binary execution, SUID in world-writable dirs.
Windows: process cross-view (WMI vs `Get-Process`) and running-driver trust (catalog-aware
`Get-AuthenticodeSignature` + BYOVD name list). Both platforms also check a curated, policy-extensible
known-artifact list. This complements Wazuh's own `rootcheck`; see [DETECTIONS.md](DETECTIONS.md#host-rootkit--anomaly-detection-rootcheck).

**Log-based IDS (v1.1.0).** Each agent runs a general log **decoder + ruleset engine**: it tails
multiple sources (Linux `auth`/`syslog`/`web` files; Windows Security/System events rendered to
normalized lines), matches each decoded line against a control-plane-distributed ruleset
(`log_rules`), and emits `producer=log-ids` detections — single-shot or after N matches per entity
(e.g. source IP) within a window. Read offsets / event RecordIds are tracked so history is never
re-alerted and the first sighting establishes a baseline. This complements Wazuh (the aggregate SIEM)
with low-latency, endpoint-local detection; the seeded rules cover SSH brute force / user enumeration,
sudo abuse, account creation, web SQLi / path traversal, and Windows 4625/4720/1102/7045.

### 1.3 Threat-intel beacon — `controlplane/beacon`
A 24/7 worker (`beacon.py`) that fills the IOC database from feeds (`feeds.py`) and scrapes open
Suricata rulesets. Runs as a separate systemd unit (`sentinel-beacon`). Rate-limited and
interval-gated per source (e.g. AbuseIPDB is pulled a few times/day to stay within its free quota).
See [OPERATIONS.md](OPERATIONS.md#threat-intel-feeds).

### 1.4 Wazuh rule generator — `wazuh_rulegen`
Turns normalised intel into Wazuh detection rules (`engine.py`, `detectors.py`, `emit.py`).

### 1.4a Wazuh integration (detection forwarding, v1.5.0)
Separately from rule generation, the control plane **mirrors every detection/audit event** into Wazuh:
`_ingest_event` appends one JSON line (`{"padakhep": {...}}`) to
`/var/log/padakhep-sentinel/sentinel.json`, and a co-located Wazuh manager reads it
(`log_format json`) and classifies it via custom rules (`deploy/wazuh/padakhep_rules.xml`, ids
100200–100299). Result: AV/EDR, log-IDS, Suricata, and operator/response events appear in Wazuh
alerts and the Wazuh dashboard alongside everything else. Forwarding is best-effort and controlled by
`SENTINEL_WAZUH_FORWARD` / `SENTINEL_WAZUH_LOG`.

### 1.5 Web console — `webui/index.html`
One self-contained HTML/CSS/JS file (~4200 LOC), no external assets or CDNs. A `window.views[...]`
router renders each page; a live-data bootstrap fetches `/api/dashboard` and populates the views.
Operator actions (rename, isolate, block, allow-list, ports, feed sync, NIDS mode) call the API.

---

## 2. Data flows

### 2.1 Intel ingestion
`beacon` → fetch feeds → normalise/deduplicate → upsert `iocs` / `suricata_rules` → surfaced in the
console (Threat Intel, Feed Health) and folded into agent policy on the next sync.

### 2.2 Enrollment & policy (agent ↔ control plane)
1. **Enroll** (`POST /api/enroll`, `proto:2`): the agent presents a (possibly reused) `agent_id`; the
   server mints a **per-agent secret** on first contact and returns it once. Established identities
   require the secret to re-enroll (no hijack).
2. **Heartbeat** (`POST /api/agents/{id}/heartbeat`, `X-Agent-Secret`): telemetry up (CPU/mem/disk,
   observed ports, NIDS status, version); directives down (isolate, closed ports, blocklist, NIDS
   mode, update).
3. **Policy** (`GET /api/sync/policy`, `X-Agent-Secret`): IOCs, signatures, behaviours, the agent's
   blocklist (minus allow-listed IPs), and closed ports.
4. **Ruleset** (`GET /api/nids/ruleset`): the sanitised Suricata ruleset (community + custom).
5. **Detections** (`POST /api/detections`): the agent reports v3-schema events; the server stamps the
   authoritative device name and persists them.
6. **Self-update** (`GET /api/agent/manifest` + `/api/agent/download/{platform}`): the agent downloads
   the advertised build, verifies **sha256 + Ed25519 signature** against its pinned key, then re-execs.

### 2.3 Response actions (operator → endpoint)
Console → API writes intent (isolate flag, `blocked_ips`, `closed_ports`, `nids_mode`,
`update_requested`) → the agent applies it within ~1 heartbeat (~60 s) and reports the result, which
is recorded as an audit event in `detections`.

---

## 3. Data model (tables)

| Table | Purpose |
|---|---|
| `iocs` | Indicators (ip/hash/domain/url) with source, confidence, TTL, VirusTotal enrichment |
| `signatures` | YARA / regex signatures distributed to agents |
| `behaviors` | Behavioural detection rules |
| `agents` | Fleet inventory + telemetry + `agent_secret` (SEN-007) + NIDS mode/status + observed ports |
| `detections` | Detection **and** audit trail (isolation, block/unblock, rename, update, custom-rules) |
| `blocked_ips` | Manual/auto blocklist (global or per-agent), soft-active |
| `closed_ports` | Per-agent firewall port closures |
| `suricata_rules` | Scraped/curated Suricata rules (default `enabled=False` pending review) |
| `allowlist` | Operator allow-list: IP/CIDR + trusted binaries (SEN-005/allow-list) |
| `log_rules` | Log-based IDS ruleset (regex + source + threshold/window + MITRE), distributed to agents |
| `app_settings` | Small key/value store (e.g. operator custom Suricata rules) |
| `generated_rules` | Generated Wazuh rules |

---

## 4. Trust boundaries & threat model

| Boundary | Who's on each side | Primary controls |
|---|---|---|
| **Operator ↔ control plane** | Console/API caller vs. server | Operator token (when set), constant-time compare, CSP/security headers, input sanitisation |
| **Agent ↔ control plane** | Endpoint agent vs. server | Per-agent secret (SEN-007), lower-privilege agent token (SEN-001), TLS (SEN-006, opt-in) |
| **Control plane → agent code** | Server-advertised build vs. root/SYSTEM agent | Ed25519 signature verified against a **pinned key** (SEN-002); self-update refuses unsigned/tampered builds |
| **Untrusted intel → root engines** | Community rules/IOCs vs. root Suricata + nftables | Server-side rule sanitisation + `suricata -T` (SEN-005); IP/CIDR validation before nftables (SEN-009); scraped rules default disabled |
| **Endpoint response actions** | Operator intent vs. fleet availability | Blocklist/isolation guards: reject `/0`, over-broad CIDRs, control-plane-covering ranges (SEN-010 partial) |

**Design assumptions & residual risk.** The current live deployment runs **tokenless over HTTP** on a
trusted management network for continuity; token auth and TLS are implemented and backward-compatible
but not yet enforced fleet-wide. The strongest guarantee already in force everywhere is
**code-signing** — even a fully compromised control plane cannot push runnable code to the agents
without the offline private key. Remaining hardening (full mTLS, RBAC, append-only audit) is tracked
in [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md).

---

## 5. Deployment topology

- **Control-plane host** (Ubuntu 24.04): `sentinel-api` (FastAPI/uvicorn) + `sentinel-beacon` +
  PostgreSQL, plus (in the reference deployment) the Wazuh manager. The API binds `0.0.0.0:8080`
  by default — prefer a management interface and/or a TLS-terminating proxy in production.
- **Endpoints**: one agent per host (Linux service `sentinel-av`, or Windows `sentinel-av.exe`
  auto-started at logon). Agents reach the control plane over HTTP(S) on 8080.
- **Feeds**: outbound HTTPS from the beacon host to public feed providers.

See [DEPLOYMENT.md](DEPLOYMENT.md) and [OPERATIONS.md](OPERATIONS.md) for concrete procedures.

