# Changelog

All notable changes to Padakhep Sentinel are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

Version lines map platform releases to the **agent build versions** shipped with them, so an
operator can tell at a glance which signed agent builds correspond to a given control-plane state.

---

## [Unreleased]

_Planned:_ Log-based IDS — a general multi-source log decoder + ruleset engine on the agent (beyond
the current single SSH-brute-force rule), correlating with Wazuh where useful. Remaining audit items:
full mTLS, RBAC, append-only/hash-chained audit log, Windows ProgramData DACL hardening, NIDS
out-of-band provisioning, SSRF allow-list, dependency pinning.

---

## [1.0.0] — 2026-08-05

First consolidated, documented release. Agents: **Linux `0.3.11`**, **Windows `0.3.9-win`** (Ed25519-signed).

### Security — audit remediation (SEN-###, see [SECURITY.md](SECURITY.md))
- **SEN-001** RBAC-lite: separate agent vs. operator tokens; uniform `/api/*` gate; constant-time
  compare; `SENTINEL_REQUIRE_AUTH` fail-closed switch.
- **SEN-002** Agent code-signing: offline **Ed25519** signatures over each build; pinned public key
  embedded in the agents; self-update refuses any build without a valid signature.
- **SEN-003** CSP + security headers on every response; server-side sanitisation of agent-reported
  fields; dashboard output-escaping.
- **SEN-005** Suricata rule validation: server sanitises custom **and** community rules (deny
  `lua`/`dataset`/`filestore` etc., force `alert` unless promoted, size caps); agent validates with
  `suricata -T` and keeps the last-good ruleset on failure.
- **SEN-006** TLS support (opt-in): HTTPS via `controlplane.app.run`, agent cert verification/pinning
  (`SENTINEL_CA_CERT`), PostgreSQL `sslmode`.
- **SEN-007** Per-agent identity: a per-agent secret issued at enrolment and required on
  heartbeat/policy/re-enrol; re-enrolment can no longer hijack an identity.
- **SEN-008** Read-endpoint auth via the uniform gate; `/api/sync/policy` scoped to the authenticated
  agent; `/healthz` exempt.

### Added (features delivered on the road to 1.0.0)
- **Threat-intel beacon** across ThreatFox, Emerging Threats, MalwareBazaar, Feodo Tracker (aggressive
  list), **Cisco Talos** (via the FireHOL mirror), URLhaus, AlienVault OTX, AbuseIPDB (interval-gated),
  and VirusTotal (enrichment). On-demand "Pull now" / "Sync feeds".
- **Suricata rule ingestion** from ET Open + abuse.ch feeds (newest-SID slicing so fresh rules keep
  arriving); shown under Threat Intel → Suricata Rules.
- **IDS/IPS** orchestration of Suricata with a 3-way OFF/IDS/IPS console control.
- **Per-device open-port** inventory with open/close controls and on-demand scan.
- **Realtime detection** (inotify / ReadDirectoryChangesW) with low-overhead incremental scanning.
- **Allow-list** (IP/CIDR + trusted binaries), persisted and enforced (allow-listed IPs are subtracted
  from the distributed blocklist).
- **Device rename** — operator-assigned, authoritative names that survive agent re-enrolment and
  propagate to detection history.
- **Guarded network isolation** and a manual **blocklist** with fleet-stranding guards (reject `/0`,
  over-broad CIDRs, and any range covering the control plane).

### Changed
- Agent self-update hardened end-to-end (Windows updater made resilient; signed builds).
- Fleet OS column shows the Linux **distro** name (`/etc/os-release` PRETTY_NAME) instead of the raw
  kernel string; Windows unchanged.
- IOC & Rule Center shows **true DB totals** (not capped preview lengths).

### Notes
- The live fleet runs **tokenless by design** for continuity; token auth and TLS are backward-compatible
  and enforced only when configured. New installs are fail-closed via the installer.

---

## Agent build history (pre-1.0.0 milestones)

| Agent (Linux / Windows) | Milestone |
|---|---|
| `0.3.11` / `0.3.9-win` | SEN-005..008: per-agent secret, TLS client, `suricata -T` validation |
| `0.3.10` / `0.3.8-win` | Friendly Linux OS name; device-rename support |
| `0.3.9`  / `0.3.8-win` | SEN-001/002/003: Ed25519-signed self-update, RBAC-lite, CSP |
| `0.3.x`  / `0.3.x-win` | Suricata IDS/IPS, per-device ports, realtime detection, agent optimisation |
