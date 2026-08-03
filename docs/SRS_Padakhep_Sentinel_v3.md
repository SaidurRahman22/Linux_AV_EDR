<!--
  Padakhep Sentinel — Software Requirements Specification v3.0
  Production-hardened revision authored 2026-08-03.
  Supersedes v2.0 ("Linux AV & Wazuh Integrator", see SRS_Linux_AV_Wazuh_Integrator.md).
  This revision folds in the cybersecurity-architecture review of v2 — the
  "Limitations & risks in production" — as concrete requirements, a platform
  threat model, a safe-response policy, NFRs, a delivery roadmap, and a risk register.
-->

# Padakhep Sentinel — Software Requirements Specification (SRS)

**Version:** 3.0 (Production-Hardened Revision)
**Date:** 2026-08-03
**Supersedes:** v2.0 — *Linux AV & Wazuh Integrator*
**Audience:** Senior software engineers, cybersecurity architects, SRE/SecOps, and AI coding agents.

---

## 0. Revision Summary (v2.0 → v3.0)

v2.0 described an excellent product *vision* but specified it like a finished commercial EDR while omitting the parts that make one safe, shippable, and operable. v3.0 keeps the vision and adds the missing 80%. Every change traces to a specific risk from the architecture review.

| # | Change in v3.0 | Addresses (risk from review) |
|---|----------------|------------------------------|
| R1 | **Safe Automated Response Policy** — detect-only by default; blocking/quarantine gated on high confidence + allow-list precedence + timeout + kill-switch | Auto-blocking from scraped IOCs = self-inflicted DoS / weaponizable EDR |
| R2 | **Security & Trust Architecture** (§7) — agent identity, mTLS, signed artifacts, RBAC, audit, tamper resistance, threat model | Root, kernel-hooked, fleet-controlled agent = high-value C2 target; no auth/signing in v2 |
| R3 | **Control-plane ownership boundary** with Wazuh (§2.3) | Two control planes managing the same endpoints → conflicts |
| R4 | **Detection feasibility constraints** for eBPF/HIPS (§3.4/3.5) — BPF-LSM/fanotify, prevention vs. tracing, kernel matrix | eBPF brittleness; "instant inline block" unrealistic/unsafe as stated |
| R5 | **Non-Functional Requirements** (§6) — perf budgets, scale, latency SLOs, HA/DR | v2 had no NFRs; "milliseconds at fleet scale" unrealistic |
| R6 | **Threat-intel via APIs, IOC lifecycle** (§4) — confidence, aging, dedup; no scraping | Scraping fragile/ToS-risky; bad IOCs cause outages |
| R7 | **Detection Engineering & Validation** (§9) — MITRE evals, Atomic Red Team, EICAR, FP/FN targets | No way to prove "detection" works |
| R8 | **Deployment/Updates/Operations** (§10) — signed staged rollout + rollback, observability, distro/kernel matrix, containers | No update strategy; single points of failure |
| R9 | **Data, Privacy & Compliance** (§11) | Quarantine/interception raise legal/privacy exposure |
| R10 | **Phased Delivery Roadmap** (§12) with `wazuh_rulegen` as the delivered Phase-1 core | v2 unbuildable as one release |
| R11 | **Re-scope to orchestrate proven OSS** (ClamAV/YARA, Falco/Tetragon, Suricata, Wazuh) rather than build a new kernel agent from scratch | Feasibility for a small team |
| R12 | **Risk Register** (§13) — living list, owner + mitigation per risk | — |

**Design principles adopted in v3.0**

1. **Safety over automation.** No destructive action (block, kill, quarantine) happens automatically except under an explicit, high-confidence, reversible, time-bounded policy with a global kill-switch. Human-in-the-loop is the default for anything that can break production.
2. **Least privilege & assume-breach of ourselves.** The security tool is itself a target; its control plane, update channel, and IOC feed are treated as attack surface and secured accordingly.
3. **Leverage, don't reinvent.** Compose hardened open-source engines; the product's value is integration, correlation, dynamic rule generation, threat-intel automation, and the console — not a novel kernel agent.
4. **Detect first, prevent later.** Ship visibility and alerting; enable prevention per-control, per-scope, after validation.
5. **Everything is versioned, signed, staged, and reversible.**

---

## 1. Project Overview

Padakhep Sentinel is an enterprise Linux **Antivirus + Endpoint Detection & Response (EDR)** platform that integrates natively with **Wazuh**. It provides signature/hash and behavioral threat detection, host-based prevention (HIPS) under a safe-response policy, **dynamic Wazuh rule generation**, centralized threat intelligence, and a central admin console for fleet monitoring, granular allow-listing, MITRE ATT&CK-correlated investigation, and controlled remote response.

The ecosystem consists of: a distributed **Linux endpoint agent**, a **Threat Intelligence service**, a **central management server + web console**, and integration with local/remote **Wazuh** manager(s).

**In scope (v3.0):** endpoint telemetry + detection, dynamic Wazuh ruleset generation, IOC management + safe fleet distribution, console (fleet, IOC/rules, blocked IPs, allow-list, log search, threat intel), safe response engine, the security/trust control plane.

**Out of scope (v3.0):** Windows/macOS agents; full disk forensic imaging; a bespoke ML detection model (behavioral analytics uses rules + established engines first); SOAR case management (integrate, don't build).

---

## 2. System Architecture

### 2.1 High-Level

Bi-directional, **mutually authenticated** data flow between the Central Console, the Threat-Intel service, distributed Linux endpoints, and Wazuh:

```
        +-------------------------------------------------------------+
        |   Central Management Server + Web Console (RBAC, Audit)      |
        |   REST/gRPC API · Policy engine · IOC store · Log search     |
        +-------------------------------------------------------------+
             ▲  telemetry (mTLS)            │  signed policies / IOCs (mTLS)
             │  clean logs, MITRE TTPs,     │  allow-lists, response cmds
             │  block events, agent health  ▼
        +-------------------------------------------------------------+
        |   LINUX ENDPOINT FLEET                                       |
        |   Sentinel Agent  (scanner, behavioral sensor, HIPS,        |
        |                    quarantine, local policy evaluator)      |
        |   Wazuh Agent     (log shipping + local ruleset)            |
        +-------------------------------------------------------------+
             ▲                                   │
             │ enriched IOCs (signed)            ▼ events → decoders/rules
        +------------------------+       +----------------------------+
        | Threat-Intel Service   |       | Wazuh Manager (SIEM +      |
        | (feed APIs, normalize, |       |  central ruleset storage)  |
        |  confidence, lifecycle)|       +----------------------------+
        +------------------------+
```

All agent↔server and server↔Wazuh channels are **mutually authenticated (mTLS)**; all pushed artifacts (IOCs, policies, rules, agent updates) are **cryptographically signed** and verified on the endpoint before use (see §7).

### 2.2 Components (revised — orchestrate proven engines)

* **Sentinel Endpoint Agent** (Go or Rust; runs least-privilege, drops caps where possible):
  * **File scanner** — on-access via **fanotify** (`FAN_OPEN_PERM` for gated modes) + on-demand; detection via **ClamAV** engine and **YARA** rules and a cryptographic hash database (MD5/SHA-1/SHA-256).
  * **Behavioral sensor** — **eBPF via an established framework (Cilium Tetragon or Falco)** or `auditd` fallback, observing `execve`, process lineage, privileged file/registry-equivalent changes, and suspicious network flows. Enforcement (kill/deny) only where **BPF-LSM** or fanotify permit it and only under the safe-response policy.
  * **Host IPS / network response** — `nftables` integration to drop malicious flows, always behind an evaluated allow-list bypass chain and a timeout.
  * **Quarantine manager** — see §3.5 for correctness requirements.
  * **Local policy evaluator** — applies global + device-scoped allow-lists *before* any isolation; memory-mapped for fast path.
  * **Wazuh integrator & dynamic rule engine** — emits normalized JSON to the local Wazuh agent and, on novel high-confidence detections, generates standard Wazuh XML rules to a **staging** path for review/promotion. *(This is the already-delivered `wazuh_rulegen` core — see §3.6 and §12 Phase 1.)*
* **Central Management Server + Console** — Fleet manager, Global IOC & Rule center, Allow-list controller (scope-aware), Log analytics + power query + MITRE mapping, Threat-intel orchestration, **RBAC + audit + policy signing service**.
* **Threat-Intel Service** — feed **API** clients (not scrapers), normalization, confidence scoring, IOC lifecycle, signed fleet distribution.

### 2.3 Control-Plane Ownership Boundary (with Wazuh)

To prevent two systems fighting over the same endpoints (**R3**):

* **Wazuh manager owns** decoding, correlation, alerting, and the *active* ruleset in `/var/ossec/etc/rules/`.
* **Sentinel owns** endpoint prevention/response, IOC lifecycle, and **generation** of candidate rules to a **staging** location. Sentinel never writes the active Wazuh ruleset directly; promotion is an explicit, validated, audited step (`wazuh-analysisd -t` gate + manager restart).
* Response actions (block/quarantine) are driven by **Sentinel policy**, not by Wazuh active-response, to keep a single decision authority; Wazuh active-response may be used only for clearly delineated, non-overlapping rule groups.

---

## 3. Functional Requirements

### 3.1 Web Console & Threat Inventory
| ID | Requirement | Notes |
|----|-------------|-------|
| FR-1.1 | Global Rules & IOC inventory: all active rules, malware hashes (MD5/SHA-1/SHA-256), malicious domains/URLs, blocked IPs — across the fleet or admin-pushed | Backed by PostgreSQL; distributed to agents over signed, mTLS channels |
| FR-1.2 | Blocked-IP visibility: every IP actively blocked by a Host-IPS, with host device, trigger count, first-block timestamp, and **expiry** | Blocks are time-bounded (see §8) |
| FR-1.3 | Fleet & instance manager: real-time status, health, uptime, OS/kernel version, agent version | Feeds the deployment/health SLOs (§6) |

### 3.2 Allow-List & Whitelisting Framework
| ID | Requirement | Notes |
|----|-------------|-------|
| FR-2.1 | Scope selector: apply allow-list **Globally** or to a **specific device/instance** | Policy payload `scope: "GLOBAL" \| "INSTANCE_UUID"` |
| FR-2.2 | IP/CIDR allow-list exempt from IPS blocking | High-priority `nftables` bypass chain evaluated **before** blocking chains |
| FR-2.3 | Process/binary allow-list by full path, parent lineage, or file hash | Evaluated by the sensor **before** any quarantine/kill |
| FR-2.4 | **Allow-list precedence is absolute** — an allow-list match always wins over any IOC/behavioral block, including auto-response | Prevents self-DoS on legitimate software (**R1**) |
| FR-2.5 | All allow-list changes are audited (who/when/scope/reason) | §7 audit |

### 3.3 Log Analytics, Power-Query Search & MITRE Mapping
| ID | Requirement | Notes |
|----|-------------|-------|
| FR-3.1 | Power-query search: free-text **and** field expressions (e.g., `ip:192.168.1.50 AND mitre.technique_id:T1059 AND severity:HIGH`) | OpenSearch/Elasticsearch or PostgreSQL FTS with Lucene-like parsing |
| FR-3.2 | Clean rendering: expandable JSON, ISO-8601 UTC (`YYYY-MM-DDTHH:mm:ss.sssZ`), origin host, action result (`BLOCKED/QUARANTINED/WHITELISTED/DETECTED`) | Normalized schema (§5) |
| FR-3.3 | Every event/alert enriched with MITRE ATT&CK tactic + technique IDs | Correlated pre-dispatch |

### 3.4 Detection Engine (feasibility-bounded — R4)
| ID | Requirement | Notes |
|----|-------------|-------|
| FR-4.1 | Signature/hash detection (ClamAV + YARA + hash DB), on-access (fanotify) and on-demand | On-access scanning MUST honor perf budgets (§6) with caching + exclusion lists |
| FR-4.2 | Behavioral detection via Tetragon/Falco (eBPF) or `auditd` fallback | Tracing is always available; **enforcement** requires BPF-LSM/fanotify and is optional per §8 |
| FR-4.3 | Detection content is versioned, signed, and validated before rollout | §9 |
| FR-4.4 | The agent MUST degrade safely: if the kernel lacks BTF/BPF-LSM, fall back to tracing + `auditd`, log the reduced capability, and never crash the host | Kernel matrix in §10 |

### 3.5 Response & Remediation (SAFE design)
| ID | Requirement | Notes |
|----|-------------|-------|
| FR-5.1 | **Detect-only by default.** Prevention (network drop, process kill, quarantine) is enabled per-control, per-scope, only after validation | §8 |
| FR-5.2 | Quarantine correctness: kill/deny the running instance, move+encrypt the artifact to `/opt/sentinel/quarantine`, strip exec perms, record hash + origin for chain-of-custody, support **restore/rollback** | Handle TOCTOU/races; never trust the malware to be at rest |
| FR-5.3 | Every response is reversible and time-bounded where applicable, with a per-action audit record | §8, §7 |
| FR-5.4 | **Global kill-switch** disables all prevention fleet-wide within one policy cycle | §8 |

### 3.6 Dynamic Wazuh Rule Generation (delivered Phase-1 core)
| ID | Requirement | Notes |
|----|-------------|-------|
| FR-6.1 | Mine the Wazuh alert stream + Sentinel detections for brute-force, malicious IPs, and malicious artifacts; generate valid Wazuh XML rules (IDs ≥ 100000) to a staging path | Implemented (`wazuh_rulegen`) |
| FR-6.2 | Merge indicators per IOC; MITRE mapping; evidence comments; atomic write; CDB IOC lists | Implemented |
| FR-6.3 | Self-updating threat-intel feeds + hot-reload; systemd daemon + timer | Implemented |
| FR-6.4 | `exclude_log_patterns` and IP allow-list to suppress known-benign traffic before detection | Implemented; addresses the observed legitimate-app false positive |

---

## 4. Threat Intelligence Service (revised — R6)

* **FR-TI.1 — API-first ingestion (no scraping).** Pull from official APIs/feeds: abuse.ch **ThreatFox / URLhaus / Feodo Tracker / MalwareBazaar**, **AbuseIPDB**, **AlienVault OTX**, **MISP/STIX-TAXII**, and (with a licensed key) **VirusTotal**. Web scraping is prohibited (fragility + ToS/legal).
* **FR-TI.2 — Normalization & classification** into IP, hash (SHA-256/1, MD5), domain/URL, and YARA/signature IOC types.
* **FR-TI.3 — IOC lifecycle:** every IOC carries `source`, `confidence` (0–100), `first_seen`, `last_seen`, `expires_at`, and dedup identity. IOCs **age out** and are re-validated; low-confidence IOCs never drive automatic prevention.
* **FR-TI.4 — Safe fleet distribution:** newly harvested IOCs are **signed** and pushed over mTLS; auto-*prevention* is applied only to IOCs above the confidence threshold and never overrides allow-lists (see §8). Distribution is **staged** (canary cohort → fleet).
* **FR-TI.5 — Licensing & attribution** for each feed is recorded; keys are stored in the secrets manager (§7).

---

## 5. Event & Log Schema (v3 — versioned, integrity-tagged)

The normalized event (Appendix A gives the full schema). Additions vs v2: `schema_version`, and an integrity/provenance block so events are attributable and tamper-evident.

```json
{
  "schema_version": "3.0",
  "timestamp": "2026-08-03T13:23:32.000Z",
  "instance": { "device_name": "prod-srv-db-01", "uuid": "a3b1c2d3-...", "ip_address": "10.0.4.15", "agent_version": "1.4.2", "kernel": "6.8.0-generic" },
  "event": {
    "type": "HIPS_NETWORK_BLOCK",
    "action_taken": "BLOCKED",
    "mode": "PREVENT",
    "severity": "HIGH",
    "confidence": 92,
    "details": { "source_ip": "198.51.100.42", "destination_port": 443, "process_path": "/usr/bin/curl", "process_id": 4821 }
  },
  "mitre_attack": { "tactic": "Command and Control", "tactic_id": "TA0011", "technique": "Application Layer Protocol", "technique_id": "T1071.001" },
  "policy": { "allowlisted": false, "matching_ioc_type": "MALICIOUS_IP", "ioc_confidence": 92, "policy_id": "pol-block-highconf-v4", "expires_at": "2026-08-03T13:33:32.000Z" },
  "integrity": { "agent_id": "ea11...", "signature": "base64...", "prev_hash": "sha256:..." }
}
```

---

## 6. Non-Functional Requirements (NEW — R5)

**Performance (per endpoint)**
| ID | Requirement |
|----|-------------|
| NFR-P1 | Steady-state agent CPU ≤ **3%** of one core (median), ≤ 15% burst during on-demand scan |
| NFR-P2 | Agent RSS ≤ **150 MB** steady state |
| NFR-P3 | On-access scan added latency ≤ **5 ms** p95 per `open()` on the hot path (with cache); cache hit ratio ≥ 95% |
| NFR-P4 | Behavioral event handling MUST NOT block syscalls beyond **1 ms** p99 in enforcement mode |

**Scale & availability**
| ID | Requirement |
|----|-------------|
| NFR-S1 | Support **10,000** endpoints per control-plane cluster; horizontal scale beyond via sharding |
| NFR-S2 | IOC/policy push propagation ≤ **60 s** p95 fleet-wide (not "milliseconds"); local `nftables` application ≤ 50 ms once received |
| NFR-S3 | Control plane target availability **99.9%**; **HA** (no single point of failure) for API, IOC store, and log store |
| NFR-S4 | Agent operates **offline**: buffers telemetry (bounded, disk-capped) and enforces last-known-good policy; reconciles on reconnect |
| NFR-S5 | Log ingestion sized for peak EPS with backpressure; no unbounded queues (avoids the "agent event queue flooded" class of failure) |

**Reliability / DR**
| ID | Requirement |
|----|-------------|
| NFR-R1 | RPO ≤ 15 min, RTO ≤ 1 h for the control plane; automated backups of PostgreSQL + IOC store + search index |
| NFR-R2 | A failed agent update auto-rolls-back to the previous signed version (§10) |

---

## 7. Security & Trust Architecture (NEW — R2)

The agent is root-capable, kernel-hooked, and fleet-controlled — i.e. an attacker who controls the control plane or the push channel controls every endpoint. This section is **mandatory before any prevention feature ships**.

**Threat model (headline threats)**
* **T1 — Weaponized EDR:** attacker poisons an IOC feed or hijacks the push channel to block legitimate infrastructure or quarantine legitimate binaries. → mitigations: FR-TI.4 confidence gating, FR-2.4 allow-list precedence, §8 canary + kill-switch, signed IOCs (SEC-3).
* **T2 — Control-plane compromise → fleet takeover.** → mitigations: SEC-1..6, network segmentation, break-glass.
* **T3 — Agent impersonation / rogue enrollment.** → SEC-1 enrollment identity.
* **T4 — Tampering with the agent or its telemetry.** → SEC-5 tamper resistance + integrity block (§5).

**Requirements**
| ID | Requirement |
|----|-------------|
| SEC-1 | **Agent enrollment & identity:** each agent obtains a unique key/cert via an enrollment protocol with an approval gate; no anonymous agents |
| SEC-2 | **mTLS everywhere:** agent↔server and server↔Wazuh; modern TLS, cert pinning, short-lived certs with rotation |
| SEC-3 | **Signed artifacts:** IOCs, policies, rules, and agent binaries/updates are signed by the control plane; the agent verifies signatures and refuses unsigned/instale payloads (anti-rollback via monotonic version) |
| SEC-4 | **RBAC + full audit:** least-privilege roles (viewer/analyst/responder/admin); every admin action (whitelist, block, push, promote, kill-switch) is audit-logged immutably (append-only, hash-chained) |
| SEC-5 | **Agent self-protection:** resist unprivileged tampering/stop; watchdog; optional secure-boot/attestation; the agent's own config/keys are protected |
| SEC-6 | **Secrets management:** feed API keys, signing keys, DB creds in a vault; never in code/repo/plain config |
| SEC-7 | **Supply-chain integrity:** reproducible builds where feasible, SBOM, dependency pinning + scanning, signed releases |
| SEC-8 | **Break-glass & separation of duties** for destructive fleet-wide actions (2-person rule for global block/kill-switch changes) |

---

## 8. Safe Automated Response Policy (NEW — R1)

The single most important control. Prevents the platform from harming the environment it protects.

| ID | Requirement |
|----|-------------|
| RESP-1 | **Detect-only is the default** for every control; prevention is opt-in per-control, per-scope |
| RESP-2 | Automatic prevention requires **confidence ≥ threshold** (default 90) **AND** a non-allow-listed target **AND** an enabled policy; behavioral/volume signals alone (low confidence) never auto-block |
| RESP-3 | **Allow-list precedence is absolute** (FR-2.4) |
| RESP-4 | **Staged rollout:** IOC/policy changes apply to a **canary cohort** first; auto-halt promotion if canary error/again-block metrics exceed a bound |
| RESP-5 | **Time-bounded actions:** network blocks and quarantines carry a default TTL and auto-expire unless renewed |
| RESP-6 | **Global kill-switch** disables all prevention fleet-wide within one policy cycle; reachable even during partial outage |
| RESP-7 | **Human-in-the-loop** required for high-impact actions (host isolation, fleet-wide block) unless an admin has pre-approved the specific automation with SEC-8 controls |
| RESP-8 | Every automated action is reversible, audited, and surfaced in the console with one-click undo |

> Rationale example: the observed legitimate mobile app (`Dart/…`) generating mass HTTP 401s would be flagged by volume heuristics — RESP-2 (low confidence, behavioral-only) + FR-2.4 (allow-list) ensure it is **never auto-blocked**.

---

## 9. Detection Engineering & Validation (NEW — R7)

| ID | Requirement |
|----|-------------|
| DET-1 | Maintain a MITRE ATT&CK coverage matrix; each detection maps to technique IDs |
| DET-2 | **Continuous validation** with **Atomic Red Team** and scenario tests in a lab fleet; regression-gate detection content in CI |
| DET-3 | **EICAR** and safe test IOCs validate the AV path end-to-end on every release |
| DET-4 | Track **false-positive / false-negative** budgets per detection; a detection exceeding its FP budget is auto-demoted to detect-only |
| DET-5 | Detection content lifecycle: authored → validated → canary → GA → deprecated, all versioned/signed (SEC-3) |

---

## 10. Deployment, Updates & Operations (NEW — R8)

| ID | Requirement |
|----|-------------|
| OPS-1 | **Supported matrix:** Ubuntu/Debian, RHEL/Rocky/Alma, Amazon Linux; kernel ≥ the min providing BTF/CO-RE for eBPF enforcement; documented degraded mode below that |
| OPS-2 | **Container/namespace awareness:** correctly attribute processes in containers (cgroup/namespace) or explicitly document exclusion |
| OPS-3 | **Signed, staged agent updates** with canary + automatic rollback on health failure (NFR-R2) |
| OPS-4 | **Observability of the platform itself:** agent + control-plane health, metrics (Prometheus), self-heartbeat, and alerting on sensor gaps |
| OPS-5 | **HA/DR:** clustered API, replicated PostgreSQL, replicated search index; backups + tested restore (NFR-R1) |
| OPS-6 | Packaging via `.deb`/`.rpm` + systemd units; the Phase-1 `wazuh_rulegen` already ships an installer + hardened service + feed-update timer |
| OPS-7 | Log/data **retention** policy configurable; storage sizing guidance per EPS |

---

## 11. Data Management, Privacy & Compliance (NEW — R9)

| ID | Requirement |
|----|-------------|
| DATA-1 | Retention windows for telemetry/quarantine/audit are configurable and enforced |
| DATA-2 | PII minimization; document what host/user data is collected and why; support redaction |
| DATA-3 | **Data residency** — deployable fully on-prem/air-gapped; no telemetry leaves the customer boundary without opt-in |
| DATA-4 | **Legal posture** for process interception, file quarantine/encryption, and (if applicable) employee-activity data — documented; admin acknowledgement on enabling prevention |
| DATA-5 | GDPR mapping retained (as v2), extended with lawful-basis + DPIA notes; feed **licensing** compliance (FR-TI.5) |

---

## 12. Phased Delivery Roadmap (NEW — R10)

Each phase is independently valuable, testable, and gated by validation (§9) and security (§7).

* **Phase 0 — Foundations & Trust (control plane MVP).** Enrollment + mTLS + signed artifacts + RBAC/audit (SEC-1..4), the console shell, and the normalized schema. *Nothing destructive yet.*
* **Phase 1 — Visibility & Dynamic Rules (DELIVERED CORE).** `wazuh_rulegen`: mine alerts → generate Wazuh rules to staging, self-updating signed IOC feeds, hot-reload, installer + service + timer, benign-traffic suppression. Console: fleet, IOC & rules, blocked-IP *visibility*, log search + MITRE, threat-intel status. **Detect-only.**
* **Phase 2 — Detection depth.** ClamAV/YARA on-access via fanotify (perf-budgeted), Tetragon/Falco behavioral tracing, MITRE coverage matrix + Atomic Red Team validation. Still detect-only.
* **Phase 3 — Guarded prevention.** Enable network drop / quarantine / kill **per §8** (confidence gating, allow-list precedence, canary, TTL, kill-switch, HITL). HA/DR hardening, container support, staged auto-updates.

**Per-phase Definition of Done:** meets its NFRs (§6), passes §9 validation, passes a security review against §7, ships docs + rollback.

---

## 13. Risk Register (NEW — R12)

| ID | Risk | Sev | Mitigation | Ref |
|----|------|-----|-----------|-----|
| RK-1 | Auto-block from low-quality/poisoned IOCs breaks production (self-DoS / weaponization) | Critical | Confidence gating, allow-list precedence, canary, TTL, kill-switch, HITL, signed IOCs | §8, FR-TI.4, SEC-3 |
| RK-2 | Control-plane / push-channel compromise → fleet takeover | Critical | mTLS, signed artifacts, RBAC+audit, agent self-protection, break-glass | §7 |
| RK-3 | Two control planes (Sentinel vs Wazuh) conflict on rules/blocking | High | Ownership boundary; staging + promotion; single response authority | §2.3 |
| RK-4 | eBPF brittleness across kernels; unsafe inline blocking | High | Use Tetragon/Falco + BPF-LSM/fanotify; safe degrade; kernel matrix | FR-4.2/4.4, OPS-1 |
| RK-5 | On-access scan performance regression on busy hosts | High | Perf budgets + caching + exclusions; benchmarks gate release | NFR-P1..4, DET |
| RK-6 | Quarantine races / malware resident in memory | Med | Kill-first, TOCTOU-safe move+encrypt, chain-of-custody, restore | FR-5.2 |
| RK-7 | Control-plane / data-store SPOF | High | HA + backups + tested DR | NFR-S3, OPS-5 |
| RK-8 | Bad update bricks fleet | High | Signed staged rollout + auto-rollback | OPS-3 |
| RK-9 | Feed scraping fragile / ToS / legal | Med | API-first ingestion + licensing record | FR-TI.1/5 |
| RK-10 | Unproven detection efficacy | High | MITRE evals, Atomic Red Team, EICAR, FP/FN budgets | §9 |
| RK-11 | Privacy/legal exposure from interception/quarantine | Med | Data governance + legal posture + admin acknowledgement | §11 |
| RK-12 | Alert fatigue / no SOC workflow | Med | Severity + confidence surfacing, dedup, integrate SOAR/ticketing | FR-3, §12 |

---

## 14. Technical Stack (revised — R11)

* **Endpoint agent:** Go or Rust (low footprint, memory safety); eBPF via **Cilium Tetragon** or **Falco**; **fanotify** for on-access; **ClamAV** + **YARA** for scanning; `nftables` for network response.
* **Threat-intel service:** Python (async) or Go worker with **STIX/TAXII** + feed API clients.
* **Control-plane backend:** Go or Node.js/TypeScript (or Python/FastAPI); **gRPC + mTLS** for agent comms; **REST** for the console.
* **Data & search:** **PostgreSQL** (state/policy/audit) + **OpenSearch/Elasticsearch** (log search); message bus (NATS/Kafka) for telemetry at scale.
* **SIEM:** **Wazuh** (manager/indexer/dashboard) — owns decoding/correlation/active ruleset.
* **Build vs. buy:** buy/adopt proven OSS engines; build the integration layer, policy engine, IOC lifecycle, dynamic rule generation, safe-response controller, and console.

---

## Appendix A — Full Event Schema (v3.0)

See §5 for the canonical object. Required top-level keys: `schema_version`, `timestamp` (ISO-8601 UTC), `instance`, `event` (with `mode` ∈ {DETECT, PREVENT} and `confidence`), `mitre_attack`, `policy` (with `ioc_confidence`, `policy_id`, `expires_at`), `integrity` (agent-signed, hash-chained). Consumers (console search, Wazuh decoders) MUST tolerate unknown additive fields (forward-compatible).

## Appendix B — Traceability

Every §13 risk maps to at least one requirement; every v3 addition (§0 table) traces to a review finding. Phase gates (§12) require NFR (§6), validation (§9), and security (§7) sign-off.
