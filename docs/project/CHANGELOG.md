# Changelog

All notable changes to Padakhep Sentinel are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

Version lines map platform releases to the **agent build versions** shipped with them, so an
operator can tell at a glance which signed agent builds correspond to a given control-plane state.

---

## [Unreleased]

- **Detection Funnel Scanner (experimental / not released)** — under the console **Optional** menu.
  Scores every saved detection instance (log rules, YARA signatures, behaviours, Suricata) 0–100 for
  **precision vs. noise** — blending pattern specificity, the false-positive self-check, ATT&CK mapping,
  correlation, and *how often it actually fired* (from the detections table) — and classifies each
  golden / good / review / noisy. Surfaces your **golden rules** and the noisy ones that drown real
  events, with a pass/failed view and schedulable scan tasks (run-now + open-task count; the beacon
  runs due tasks). Read-only: it does **not** change what agents enforce. `controlplane/app/scanner.py`,
  `scan_tasks` / `scan_runs` tables, `/api/scanner/*`. Kept isolated + badged EXPERIMENTAL pending sign-off.

### Added
- **Host rootkit / anomaly detection (rootcheck)** — a new on-agent detector (`rootcheck_scan`),
  wired into the existing scan loop (default every 600 s, `SENTINEL_ROOTCHECK` / `SENTINEL_ROOTCHECK_INTERVAL`)
  and reported as `producer=rootcheck` → forwarded to Wazuh like every other detection. **Consistency/
  trust based, fully local — no threat feed, no internet.** Agents **Linux `0.3.15`, Windows `0.3.14-win`**.
  - *Linux* (`agent.py`): hidden-process cross-view (`/proc` brute-force vs readdir vs `ps`),
    hidden-port cross-view (`/proc/net/tcp` vs `ss`), `ld.so.preload` hijack, hidden kernel module
    (`/sys/module` live vs `/proc/modules`), known-rootkit LKM names, promiscuous NIC (suppressed while
    Suricata runs), fileless/deleted-binary execution from world-writable paths, SUID-root in
    world-writable dirs, and known-rootkit artifact paths. Event types `HIDDEN_PROCESS` / `HIDDEN_PORT` /
    `PRELOAD_HIJACK` / `HIDDEN_MODULE` / `KNOWN_ROOTKIT_MODULE` / `PROMISC_IFACE` /
    `DELETED_BINARY_RUNNING` / `SUSPICIOUS_SUID` / `KNOWN_ROOTKIT_ARTIFACT` (MITRE T1014/T1564/T1574.006/
    T1547.006/T1040/T1620/T1548.001).
  - *Windows* (`agent_win.py`): process cross-view (WMI `Win32_Process` vs `Get-Process`, double-snapshot
    to shed races), running-driver trust check (catalog-aware `Get-AuthenticodeSignature`) →
    `UNSIGNED_DRIVER`, known-abused/BYOVD driver names → `KNOWN_VULNERABLE_DRIVER` (T1068), and known
    artifact paths. Verified live on a Windows host: **0 false positives**, driver scan ~3.6 s.
  - Both lists are **policy-extensible** — the control plane may distribute extra `rootkit_artifacts`
    (and, Windows, `bad_drivers`) in `/api/sync/policy`; no schema change required, embedded defaults ship
    in the agent. Each sub-check is isolated (one failure can't sink the rest) and every finding is
    deduped for the process lifetime.

### Fixed
- **Windows detection reporting crash** — `report()` was invoked with `producer="log-ids"` but the
  Windows `report()` signature didn't accept it, raising `TypeError` on the log-IDS reporting path
  (startup + every aux cycle). `report()` now takes `producer` (default `av-agent-win`), matching the
  Linux agent. This bug predates this change (present in the committed tree).

_Planned:_ remaining audit items — full mTLS, RBAC, append-only/hash-chained audit log, Windows
ProgramData DACL hardening, NIDS out-of-band provisioning, SSRF allow-list, dependency pinning.

---

## [1.5.0] — 2026-08-05

Two more security-audit findings closed. Agents: Linux `0.3.14`, Windows `0.3.13-win`.

### Security — audit remediation (see [SECURITY.md](SECURITY.md))
- **SEN-013 (High) — remote-triggered root package install** — a control-plane NIDS-mode change no
  longer runs `apt/dnf/yum` as root on endpoints. Auto-install is **off by default**; Suricata is
  provisioned out of band (`av_agent/install_suricata.sh`) or opted in per-host with
  `SENTINEL_NIDS_AUTOINSTALL=1`. Otherwise the agent simply reports the engine missing.
- **SEN-011 (High) — Windows install-dir local privilege escalation** — `C:\ProgramData\PadakhepSentinel`
  is now created with a restrictive DACL (`icacls /inheritance:r`, write only for SYSTEM +
  Administrators), re-asserted on every start with a user-writable self-check, so a standard user can
  no longer pre-plant/race a malicious `sentinel-update.cmd` / exe that the SYSTEM agent would execute.
  The Defender exclusion is now scoped to the **signed exe**, not the whole directory (no malware
  safe-harbor). **The DACL is applied only when the agent runs elevated / as SYSTEM** — a non-elevated
  agent skips hardening so it can never lock itself out of its own dir/state/self-update (agent
  `0.3.14-win`); full protection therefore requires running the Windows agent as SYSTEM.

Remediation scorecard now **13 Fixed / 5 Partial / 1 Open** (only SEN-015 SSRF remains open).

### Notes
- Verified: the Windows install-dir ACL now lists only SYSTEM + Administrators. Full system test +
  feed-health check passed (7/8 feeds fresh; AbuseIPDB gated as designed).

---

## [1.4.0] — 2026-08-05

Sigma pipeline (upload + scrape + verify) and documentation reorganisation.

### Added
- **Sigma import** — convert community **Sigma** YAML rules into log-IDS rules
  (`controlplane/app/sigma.py`): manual upload in the console (*IDS/IPS → Import Sigma*) or
  `POST /api/log-rules/sigma`, plus a **24/7 beacon scraper** (`sync_sigma_rules`, default **off**,
  pulls from configured SigmaHQ dirs). Handles the common Sigma shapes (keywords, field
  contains/startswith/endswith/re, simple and/or/not conditions); unsupported shapes (aggregation /
  correlation) are skipped with a reason.
- **False-positive self-check + staging (SEN-hardening)** — every imported/converted rule runs through
  `verify_pattern()` (rejects over-broad patterns and anything matching a benign-log corpus). Rules
  that fail land **staged** (`verified=false`) and are **never distributed** until an operator reviews
  and promotes them (`POST /api/log-rules/{id}/verify`). Distribution is gated to
  **verified AND enabled** rules. New `LogRule.origin` / `LogRule.verified` columns + migration.
- Console shows rule **origin** (builtin/manual/sigma) and **status** (ok/staged) with a per-rule
  **Verify** action; the Sigma import modal reports converted / verified / staged / skipped.

### Changed
- **Documentation reorganised** — the versioned living documentation set now lives in **`docs/project/`**
  (README hub, ARCHITECTURE, API_REFERENCE, SECURITY, OPERATIONS, DETECTIONS, CHANGELOG). Point-in-time
  and standalone files (SECURITY_AUDIT.html, SRS_*, DEPLOYMENT*, IDS_IPS) remain in `docs/`.

### Notes
- Verified live: a precise Sigma rule imported as **verified & distributed**; a broad "any GET" rule was
  **caught by the self-check and staged**; the beacon converted 8 real SigmaHQ rules. Full system test
  passed (all endpoints, agents, feeds, Wazuh flow).

---

## [1.3.0] — 2026-08-05

Detection content library + new telemetry sources. Agents: Linux `0.3.14`, Windows `0.3.13-win`.

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
