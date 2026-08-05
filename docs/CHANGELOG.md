# Changelog

All notable changes to Padakhep Sentinel are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

Version lines map platform releases to the **agent build versions** shipped with them, so an
operator can tell at a glance which signed agent builds correspond to a given control-plane state.

---

## [Unreleased]

_Planned:_ remaining audit items — full mTLS, RBAC, append-only/hash-chained audit log, Windows
ProgramData DACL hardening, NIDS out-of-band provisioning, SSRF allow-list, dependency pinning.

---

## [1.3.0] — 2026-08-05

Detection content library + new telemetry sources. Agents: Linux `0.3.13`, Windows `0.3.12-win`.

### Added
- **ATT&CK-mapped detection library** (`controlplane/app/logrules_pack.py`) — the log-IDS ruleset grew
  from 22 to **~75 curated rules across 12 ATT&CK tactics**, mixing behavioural detections with
  known-threat / CVE / tooling signatures: Log4Shell, Spring4Shell, Shellshock, ProxyShell, OGNL RCE,
  PwnKit / Dirty Pipe, mimikatz / LSASS access (Sysmon EID 10), Kerberoasting (4769/RC4), BloodHound,
  Cobalt Strike named pipes, ransomware shadow-copy deletion, cryptominers, offensive tooling
  (linpeas/pspy/chisel/ligolo), web-shells, cloud-metadata SSRF, and more. Coverage matrix:
  [DETECTIONS.md](DETECTIONS.md).
- **New telemetry sources**: Linux **auditd** (`/var/log/audit/audit.log`) and Windows **Sysmon**
  (`Microsoft-Windows-Sysmon/Operational`). The Windows engine now renders the full Security+Sysmon
  field set (`Image`/`Cmd`/`Parent`/`Target`/`Dst`/`File`/`Reg`/`Query`/`Pipe`/…).
- **Enablement shipped**: `deploy/auditd/` (audit policy keyed to the detection rules + installer) and
  `deploy/sysmon/` (focused Sysmon config + guidance). Detection content is now separated from code as
  a maintained library, seeded idempotently by name.

### Notes
- Verified live: an auditd `/etc/shadow` modification produced an `IDENTITY_FILE_MODIFIED` detection
  that reached Wazuh (rule 100201). Audit policy tuned to **write-only** on identity files to cut noise.
- Coverage is telemetry-bound: rules needing auditd / Sysmon / Windows cmdline auditing stay quiet
  until that telemetry is enabled (no false negatives from our side).

---

## [1.2.0] — 2026-08-05

Wazuh integration, an expanded log-IDS ruleset, and console polish. Agents: Linux `0.3.12`,
Windows `0.3.11-win` (adds process/command-line fields for Windows 4688 rules).

### Added
- **Expanded log-IDS starter pack — 22 rules** (from 11): Linux reverse-shell, download-and-execute
  cradle, privileged-group add, repeated `su` failure, password change, cron edit / suspicious cron
  exec; Windows special-privilege assignment (4672) and 4688 process rules — LOLBin launch, encoded
  PowerShell, and LOLBin download (the Windows engine now surfaces `Process=`/`Cmd=`). Verified live:
  an injected download-cradle line produced a `DOWNLOAD_EXEC` detection that reached Wazuh as rule
  100201 (level 8).
- **Wazuh integration** — every Sentinel detection/audit event (file/YARA/behaviour, log-IDS,
  Suricata, and operator/response actions) is mirrored as a JSON line to
  `/var/log/padakhep-sentinel/sentinel.json`; a co-located **Wazuh** manager reads it
  (`log_format json`) and classifies it with custom rules (`deploy/wazuh/padakhep_rules.xml`,
  ids 100200–100299). AV/EDR events now appear in Wazuh alerts and the Wazuh dashboard — no separate
  pane of glass. One-shot installer: `deploy/wazuh/install_wazuh_integration.sh`. Toggle via
  `SENTINEL_WAZUH_FORWARD` / `SENTINEL_WAZUH_LOG`; forwarding is best-effort (never blocks ingestion).
- **Log-IDS rules console management** under *IDS / IPS* (list / add / enable-disable / delete;
  regex validated server-side).

### Changed
- The log-IDS rule enable/disable control is now an unambiguous **slider switch** (the old "On" button
  read as an action rather than a state).

### Notes
- Verified live: a `log-ids` `SSH_INVALID_USER` detection appeared in both `sentinel.json` and Wazuh
  `alerts.json` (rule id 100200, groups padakhep/sentinel/edr, JSON-decoded `padakhep.*` fields).

---

## [1.1.0] — 2026-08-05

Log-based IDS. Agents: **Linux `0.3.12`**, **Windows `0.3.10-win`** (Ed25519-signed).

### Added
- **General log-based IDS** — a multi-source log **decoder + ruleset engine** on the agent, replacing
  the single hard-coded SSH-brute-force check:
  - New `log_rules` table + `LogRule` model; **11 seeded starter rules** across Linux `auth`
    (SSH brute force, invalid-user enumeration, root login, sudo failures, user-created), `web`
    (SQLi, path traversal), and Windows `winsec`/`winsys` (4625 brute force, 4720 user created,
    1102 log cleared, 7045 service installed).
  - `GET/POST /api/log-rules`, `POST /api/log-rules/{id}/toggle`, `DELETE /api/log-rules/{id}`
    (regex validated server-side). Enabled rules are distributed via `/api/sync/policy` scoped to the
    agent platform, and shown in `/api/dashboard`.
  - Agent engine: Linux tails `auth`/`syslog`/`web` files; Windows renders Security/System events to
    normalized lines. Each rule's regex is compiled once; a correlation entity (e.g. source IP) is
    extracted; rules fire single-shot or on N-matches-in-window. Offsets/RecordIds are tracked so
    history is never re-alerted and the first sighting establishes a baseline.
  - Detections carry `producer=log-ids`; the console SRS Logs view gains a **LOG-IDS** filter chip.
  - **Console management** under *IDS / IPS* → "Log-based IDS Rules": list, add (regex-validated),
    enable/disable, and delete rules; changes are distributed on the next policy sync.

### Changed
- The agent's `scan_auth_log` (Linux) / `scan_security_log` (Windows) paths are superseded by the
  generic engine; SSH brute force is now simply one seeded log rule.

### Notes
- Verified live: six failed SSH logins on a Linux host produced a `log-ids` `SSH_INVALID_USER`
  detection (source `127.0.0.1`, count 5).
- Wazuh remains the aggregate SIEM; this feature adds low-latency, endpoint-local log detection that
  complements it (and can be correlated with Wazuh alerts).

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
