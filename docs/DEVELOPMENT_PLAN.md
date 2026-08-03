# Padakhep Sentinel — Development Plan & Workflow

**Date:** 2026-08-03  ·  **Companion to:** `SRS_Padakhep_Sentinel_v3.md`
**Purpose:** answer *"can this be built, with what stack, which integrations (and their cost), and in what order so I can test + give feedback each step."*

---

## 1. Can it be built? (honest capability statement)

**Yes — the software layers can be built, incrementally.** But two truths shape *how*:

1. **Don't build an EDR from scratch.** A from-scratch AV/EDR (novel kernel agent, own scanning engine, own behavioral analytics) is a multi-year, large-team effort (CrowdStrike/SentinelOne scale). Instead we **orchestrate battle-tested open-source engines** and build the *glue*: integration, policy/allow-list engine, IOC lifecycle, safe-response controller, dynamic Wazuh rule generation, and the console. This is feasible and is what SRS v3 specifies.
2. **Division of labor.**

| I (Claude) can do | You / your Linux fleet must do |
|---|---|
| Write all code: Go agent, Python services, API, console, integrations, Wazuh rule-gen, installers, tests, docs | Compile & run on real Linux (eBPF/fanotify/nftables need a Linux kernel + root) |
| Design schemas, protocols, policies, threat model | Provide a **test fleet** (1–3 VMs) + your Wazuh manager |
| Wire third-party feed/API clients | Create the **free API keys/accounts** (they're tied to your identity) |
| Produce per-increment build + test steps | Deploy each increment, run the tests, and **give feedback** |
| Use **multi-agent workflows** to build faster (when you opt in) | Validate detection efficacy with real/benign samples (EICAR, Atomic Red Team) |

> Reality check: even done right, this is a **months-long, phased** program. The value is that every increment below is independently useful and testable — you're never waiting for a big-bang release.

---

## 2. Recommended Tech Stack

| Layer | Choice | Why |
|---|---|---|
| **Endpoint agent** | **Go** (not Rust, for speed of delivery) | Great syscall/eBPF ecosystem (`cilium/ebpf`), easy static cross-compile, systemd-friendly, memory-safe enough |
| On-access file scan | **fanotify** (`golang.org/x/sys/unix`) + **ClamAV** (`clamd`) + **YARA** | Proven; `FAN_OPEN_PERM` enables gated blocking later |
| Behavioral sensor | **Cilium Tetragon** or **Falco** (consume their eBPF events) | Don't hand-write/maintain kernel probes; safe degrade to `auditd` |
| Network response | **nftables** (`google/nftables` or exec) | Standard, scriptable, allow-list bypass chain |
| **Threat-Intel service** | **Python + FastAPI + httpx (async)**, `pymisp`, `taxii2-client` | Fastest way to build many feed clients + STIX/TAXII |
| **Control-plane API** | **Python FastAPI** (REST for console) + **gRPC** (agent comms over mTLS) | One language with intel service; quick iteration |
| **Console (web UI)** | Now: the delivered self-contained build. Grows into **React + Vite + TypeScript** when it needs real state | Keep what you can already see; evolve when justified |
| **Database** | **PostgreSQL** | State, policy, audit, IOC store |
| **Log search** | **OpenSearch** (or Postgres FTS for MVP) | Power-query + MITRE search at scale |
| **Message/telemetry bus** | Start **Redis** (or Postgres LISTEN/NOTIFY); **NATS/Kafka** at fleet scale | Backpressure, decoupling |
| **Trust plumbing** | **mTLS** via `step-ca`; artifact signing via **cosign/minisign**; secrets via **Vault** (or SOPS for MVP) | SRS §7 requirements |
| **SIEM** | **Wazuh** (you already run it) | Owns decode/correlate/active ruleset |
| **Packaging/deploy** | Agent: `.deb`/`.rpm` + systemd. Control plane: **Docker Compose** (Postgres+OpenSearch+API+intel) | Reproducible, easy for you to run |

Everything in this stack is **open-source / self-hostable at $0** except the optional external threat-intel APIs in §3.

---

## 3. Third-Party Integrations & Cost

The solution needs **threat-intel feeds**, some **enrichment APIs**, and **notification** channels. Breakdown by cost tier (verify current limits when you sign up — they change):

### 3.1 Core engines & infra — Free / Open-Source ($0, self-hosted)
ClamAV · YARA · Cilium Tetragon · Falco · Suricata · Wazuh · nftables · fanotify/eBPF (kernel) · PostgreSQL · OpenSearch · Redis/NATS · step-ca · cosign · MISP (self-hosted).
→ **~14 components, all $0.**

### 3.2 Threat-intel feeds — Free (account/API key may be required, but no fee)
| Source | Use | Note |
|---|---|---|
| abuse.ch **ThreatFox** | IP/hash/URL IOCs | Free; now needs a free Auth-Key |
| abuse.ch **URLhaus** | Malicious URLs | Free |
| abuse.ch **MalwareBazaar** | Malware hashes/samples | Free (auth-key) |
| abuse.ch **Feodo Tracker** | Botnet C2 IPs | Free |
| **AlienVault OTX** | Broad IOC pulses | Free API key |
| **Emerging Threats Open** | IDS/blocklist rules | Free |
| **FireHOL / blocklist-ipsets** | Aggregated IP blocklists | Free |
| **Spamhaus DROP/EDROP** | Hijacked netblocks | Free |
| **CISA KEV** | Known-exploited vulns | Free |
→ **~9 feeds, $0** (already integrated: ThreatFox, URLhaus, MalwareBazaar, Feodo, ET).

### 3.3 Enrichment/intel — Free tier but **rate/quota limited** (paid to scale)
| Source | Free tier (approx) | Paid |
|---|---|---|
| **VirusTotal** | ~4 req/min, 500/day, non-commercial | Enterprise (costly) |
| **AbuseIPDB** | ~1,000 checks/day | Paid tiers |
| **GreyNoise** | Community API (limited) | Paid |
| **URLScan.io** | Free tier + rate limits | Paid |
| **Shodan** | Very limited free / one-time credits | Mostly paid |
| **MaxMind GeoLite2** | Free (geo enrichment) | GeoIP2 paid |
| **IPinfo** | Free tier (limited) | Paid |
→ **~7 sources, free-but-limited.**

### 3.4 Premium — effectively Paid for production use
VirusTotal Enterprise · Recorded Future · Mandiant Advantage · CrowdStrike Falcon Intel · commercial MISP feeds · Shodan (real usage) · PagerDuty/Opsgenie at scale.
→ **~6+ paid** (all **optional** — the platform works without any of them).

### 3.5 Notifications / webhooks — Free
Slack incoming webhook · Discord webhook · Telegram bot · Microsoft Teams webhook · Email/SMTP · generic outbound webhook (for your own SOAR/ticketing).
→ **Free** (PagerDuty/Opsgenie have free-limited + paid tiers).

### 3.6 Summary count
- **Free / OSS (self-host):** ~14 components + ~9 feeds + free notifications.
- **Free-but-limited (free tier, capped):** ~7 enrichment APIs.
- **Paid (all optional):** ~6 premium intel/on-call services.

**Bottom line:** you can run the **entire platform on $0** using OSS + free feeds. Paid APIs only add enrichment depth/scale and are never required for core function.

---

## 4. Development Workflow (how we iterate)

For each increment:
1. **I build** the code (solo or via a multi-agent workflow when you opt in) → a branch/PR + a short *BUILD & TEST* runbook.
2. **You deploy** on the test VM(s) / Wazuh manager and run the listed test steps.
3. **You give feedback** (works / bug / change) → I fix & iterate.
4. **Gate:** an increment is "done" only when it meets its test criteria + (later phases) a security/perf check.

Git is the backbone (already initialized): each increment is a reviewable change; the control plane runs via Docker Compose; the agent installs via a script + systemd (like the delivered `wazuh_rulegen`).

---

## 5. Build Increments (segmented for test → feedback)

Aligned to SRS v3 §12 phases, but sliced small so you can see/test each. **Phase 1 is already delivered.**

| # | Increment | You can test by… | SRS phase |
|---|-----------|------------------|-----------|
| ✅ **1** | **Wazuh Rule Generator + IOC feeds + Console (mock)** — DELIVERED | Already running on XAMPP + Wazuh manager | 1 |
| **2** | **Control-plane skeleton**: FastAPI + Postgres + Docker Compose; **agent enrollment + mTLS**; console wired to real fleet/health API | A dummy agent registers → appears live in the console fleet page | 0 |
| **3** | **Threat-Intel service**: API-first feed clients → IOC store w/ confidence + aging + dedup → **signed** distribution; console IOC pages go live | Trigger a pull → new IOCs appear in console + delivered to a test agent | 1→2 |
| **4** | **Endpoint agent MVP (Go)**: enroll, heartbeat, telemetry; **on-demand + on-access (fanotify) scan** via ClamAV/YARA + hash DB; emit normalized JSON to Wazuh + control plane. **Detect-only** | Drop **EICAR** on the VM → detection shows in console + Wazuh alert | 2 |
| **5** | **Behavioral sensor**: integrate **Tetragon/Falco**; process/exec/network telemetry → MITRE mapping | Run **Atomic Red Team T1059** → behavioral detection appears | 2 |
| **6** | **Network IOC matching + Blocked-IP visibility** (nftables in **log-only** mode) | Curl a known-bad test IP → logged as would-block (no drop yet) | 2 |
| **7** | **Allow-list + Policy engine + RBAC/audit**: scope (global/device), **absolute precedence**, audit log | Whitelist a binary/IP → its detection is suppressed; action audited | 3 |
| **8** | **Safe Response engine (guarded prevention)**: enable nftables **drop** / **quarantine** / **kill** under §8 policy — confidence gate, TTL auto-expire, **canary**, **global kill-switch**, one-click undo | Block a test IOC → auto-expires; flip kill-switch → all prevention stops | 3 |
| **9** | **Hardening & scale**: HA/DR, signed **staged auto-updates + rollback**, observability (Prometheus), `.deb`/`.rpm` packaging, container/namespace awareness | Push a bad update → auto-rollback; kill a node → control plane survives | 3 |
| **10** | **Validation & docs**: MITRE coverage matrix, Atomic Red Team CI, FP/FN budgets, operator + install docs | CI detection suite green; runbooks complete | all |

**Suggested order of value:** 2 → 3 → 4 (you'll have a real detecting agent + live console after #4) → 5/6 → 7 → 8 → 9 → 10.

---

## 6. Prerequisites you'll set up (so builds are testable)
1. **1–3 Linux test VMs** (Ubuntu 22.04/24.04 or Rocky 9) with root + a recent kernel (≥5.10, BTF enabled) for eBPF.
2. Your **Wazuh manager** reachable from the VMs (already have it).
3. **Docker + Docker Compose** on a host for the control plane.
4. **Free API keys** as we reach each feed (ThreatFox/OTX/AbuseIPDB/VirusTotal…).
5. A git remote (you have `Linux_AV_EDR`/`Wazuh-Detection-Rule-Gen`) for PRs.

---

## 7. Decisions I need from you before Increment 2
- **Control-plane language:** FastAPI (recommended, one language w/ intel) or Node/TypeScript?
- **Console path:** keep the current self-contained build wired to the API for now, or start the React/Vite rebuild?
- **Where the control plane runs:** the Wazuh box, a separate VM, or a container host?
- **Scope of Increment 2** confirm (enrollment + fleet/health live) before I start.

---

## 8. Risks carried from SRS v3 (kept front-of-mind during build)
Auto-block self-DoS (→ detect-only + confidence gate + allow-list precedence), control-plane compromise (→ mTLS + signing + RBAC from Increment 2, not bolted on later), eBPF portability (→ use Tetragon/Falco + safe degrade), performance budgets (→ measured each agent increment). Full register in SRS §13.
