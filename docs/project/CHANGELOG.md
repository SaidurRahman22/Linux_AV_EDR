# Changelog

All notable changes to Padakhep Sentinel are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

Version lines map platform releases to the **agent build versions** shipped with them, so an
operator can tell at a glance which signed agent builds correspond to a given control-plane state.

---

## [Unreleased]

### Automated Threat Hunter — scheduled Wazuh-sweep → auto-block (Optional menu)

Turned the manual SOC sweep into a self-contained, guard-railed, scheduled engine
(`controlplane/app/threathunter.py`): every **12 hours** (systemd `sentinel-threathunt.timer`)
and on demand (**Optional → Threat Hunter** in the console, or `POST /api/threathunt/run`, or
the CLI `python -m controlplane.app.threathunter --days N [--dry-run]`) it reads Wazuh alerts
over a **configurable window (default 30 days)**, aggregates attacker IPs + behaviour, enriches
via Sentinel IOCs + **AbuseIPDB** (cached), and **auto-blocks** confirmed-malicious foreign
sources globally (`source=auto`).

- **"Double bulletproof" safety:** never touches private / control-plane / monitored-agent /
  allow-listed / own-infra IPs (`118.179.149.162` pre-seeded); **Bangladesh IPs are never
  hard-blocked** — strong-signal ones are tagged `Bangladesh` for manual review, weak ones
  skipped; per-run block cap + over-broad-CIDR/control-plane guards; **/32-only** auto-blocks;
  a cross-process file lock; and a **Dry-run** mode that previews every verdict but blocks
  nothing. Validated by an adversarial multi-agent red-team pass before go-live.
- **Idempotent:** re-runs create no duplicate blocks (skips IPs already covered by any active
  block **including CIDRs**), cache reputation lookups (`threat_intel_cache`), and de-duplicate
  synthesised rules.
- **Rule synthesis:** distinctive malicious URL tokens (≥3 confirmed-malicious sources) become
  regex-escaped candidate `web` rules gated by the FP self-check (`origin=threathunt`).
- New tables `threat_hunt_runs` + `threat_intel_cache`; new view under Optional with KPIs +
  per-IP verdict table + Days field + Run-now/Dry-run.
- **Pre-go-live adversarial red-team (38 agents, 6 lenses → verify) found 23 confirmed issues incl.
  a CRITICAL self-inflicted-DoS I'd introduced** — the "bangladesh" action actually created an
  enforced global block instead of a review tag (would have firewall-cut the org's own BD users on
  every 12h run). All fixed before enabling: BD is now review-only (never enforced), fail-safe on
  unknown country, clear-attacks block regardless of score, allow-list additive, shared-FS run lock
  (PrivateTmp-safe), CIDR-aware dedup, errors never poison the reputation cache, synthesised rules
  always staged, malice-aware enrichment ranking, atomic run guard. Verified by decision unit-tests
  + dry-run (0 blocks). **First live run: 637k alerts scanned, 80 confirmed-malicious IPs auto-blocked,
  1 BD → review-only, 6 rules staged.**

### Web recon detections + threat sweep: 4 log-IDS rules (→ 92 total) + IOC-driven global blocks

Added four `web`-source rules to the detection library, driven by a Wazuh log sweep (597k
alerts / 31 days / 17k source IPs): **`web_secret_file_probe`** (HIGH, T1552.001/T1595.003 —
`.env`/`.git`/`.aws`/`wp-config`/`id_rsa` probing), **`web_fake_browser_ua`** (MEDIUM, T1595 —
`Mozlila`/`Bulid`/`Moblie` typo UAs), **`web_cms_admin_probe`** (MEDIUM, T1595.003 — wp-login/
phpMyAdmin/actuator/manager panels), and **`web_exploit_scan`** (HIGH, T1595.002/T1190 — boaform/
HNAP/GponForm/phpunit/ThinkPHP RCE probes). All validated against real attack lines with **zero**
false positives on benign traffic.

Threat sweep also blocked the confirmed-malicious sources globally in Sentinel (AbuseIPDB score
100 + Sentinel-IOC cross-checked): scanning/brute-force hosting ranges `185.177.72.0/24`,
`77.83.39.0/24`, `213.209.159.0/24`, `45.148.10.0/24` (DMZHOST/AS48090 bulletproof) + ~11
individual hosts. **Bangladesh-conservative:** BD ISP IPs (Amber IT / Dtech / HelloTech / Robi),
which are poorly-rated but weak (AbuseIPDB 0–32, generic 4xx), were **not** hard-blocked; the
higher-volume ones are tagged `Bangladesh` for manual review, and the org's own server
`118.179.149.162` (hosts `attendance/cs.padakhep.org`) was correctly left unblocked.

### Blocked processes + beacon feed knobs (agents Linux `0.4.4` / Windows `0.5.1-win`)

- **Blocked Processes** — a new active-response object mirroring the IP blocklist. Operators
  block a process by **name / image path / SHA-256** (console → **Blocked** → *Blocked
  Processes*, or `POST /api/blocked/processes`); the block rides the heartbeat and agents
  **terminate any matching running process** within ~60 s (Linux `SIGKILL`, Windows
  `TerminateProcess`), reporting a `PROCESS_BLOCKED` event. **Release** (`POST
  /api/blocked/processes/{id}/release`) deactivates it and logs an audit event, so agents
  stop killing it. `source` is `manual` today and `auto` once detection-driven auto-blocking
  is enabled — auto-blocked instances land in the same list and are released the same way.
  **Guardrails:** a protected-process set (OS-critical + the agent itself) is refused on both
  the API and the agent, so a bad block can't brick a host. Validated live: a blocked test
  process was killed on the fleet and released cleanly.
- The **Blocked IPs** console page is now **Blocked** (IPs + Processes side by side, each with
  Release). New `blocked_processes` table (auto-created), `blocked_processes` in the heartbeat
  response.
- **Fixed** the Detection Funnel Scanner promote (and the new pause) to act on the **full**
  rule set — they iterated the 50-capped display list, so with 64 golden only 50 were enabled.
- **Beacon feed knobs applied + fetch hardened:** community **YARA** pulls enabled
  (`SENTINEL_YARA_REPO=1` — was off; +148 rules on first sync), **Suricata cap raised**
  (`SENTINEL_SURICATA_RULES_MAX=20000`, was 6000), and `collect_suricata_rules` now **recovers
  partial reads** (keeps `IncompleteRead.partial` instead of dropping the whole file) + retries
  transient errors + uses a longer timeout — so the ~50k-rule ET Open bulk feed stops truncating.

### Windows behavioral telemetry (Sysmon + ETW) & enforcement status (Windows agent `0.5.0-win`)

Deepened the Windows endpoint's behavioral coverage and made its telemetry + enforcement
posture **visible to the admin per device** in the console — the Windows-side answer to the
Linux eBPF/Suricata layers (Windows has no NFQUEUE/eBPF, so it leans on Sysmon's kernel driver
+ ETW-backed event channels + Windows Firewall/WFP).

- **Fixed a latent gap:** `sysmon`-source rules were filtered out of the Windows agent's rule
  matcher and never actually fired. The agent now matches `sysmon` **and** `etw` sources, so the
  10 existing Sysmon rules are live for the first time.
- **New detections (+6 rules → 88 total):** Sysmon `PROCESS_TAMPERING` (EID 25 hollowing) and
  `PROCESS_INJECTION_LOLBIN` (EID 8 from a script host); ETW `POWERSHELL_OBFUSCATION` (4104
  script-block), `WMI_EVENT_SUBSCRIPTION` (persistence), `DEFENDER_MALWARE`, and
  `DEFENDER_DISABLED`. New `etw` source (PowerShell/Operational, WMI-Activity/Operational,
  Windows Defender/Operational — all read via the existing event reader; absent/disabled
  channels simply cost nothing).
- **Per-device status the admin can see** (fleet → device detail modal): a *Windows Telemetry &
  Enforcement* panel showing Sysmon (installed/running + events/hr), each ETW channel
  (+ PowerShell script-block logging), Windows Firewall (profiles on), and Sentinel enforcement
  (isolation / blocked IPs / closed ports). Reported on the heartbeat as `win_telemetry`
  (new `agents.win_telemetry` column), refreshed every `SENTINEL_WIN_TELEMETRY_INTERVAL` (300 s).
- **One-shot provisioning at install** (`SENTINEL_WIN_PROVISION`, on by default for SYSTEM
  installs): enables the Windows Firewall, enables the ETW channels + PowerShell script-block
  logging, and installs Sysmon with the Padakhep config (best-effort binary fetch; if absent it
  logs a clear "deploy Sysmon via GPO/SCCM" note and the panel shows it missing). Keeps the
  "run the installer once, everything's armed" model.
- Validated end-to-end on a live Win11 host: the agent reports accurate status (Sysmon absent,
  ETW channels on by default, all 3 firewall profiles on), it persists, and `/api/agents`
  surfaces it to the console panel.

### Real-time eBPF behavioral tracing (Linux agent `0.4.3`)

Added an in-kernel **syscall** detection engine so the agent catches threats that never reach a log and
that exec-and-exit between `/proc` polls — without weighing the agent down. The agent orchestrates
**bpftrace** (iovisor/bpftrace, provisioned out of band like Suricata) and is a thin consumer of its
compact event stream; hits emit `producer=ebpf` and forward to Wazuh. Seven `source=ebpf` rules ship in
`logrules_pack.py` (seeded on restart).

- **Light by design — two tiers.** Tracing every `execve` with an argv `join()` pinned a CPU on a busy
  host (and overran the 512-byte BPF stack when combined with an in-kernel filter), so it is **not** the
  default. **Base** (`SENTINEL_EBPF=1`) traces only rare, no-join syscalls — `ptrace(POKETEXT/POKEDATA)`
  injection and `init/finit_module` load — measured at **bpftrace ~0.4% CPU / agent ~1–2% CPU** with these
  syscalls firing **0×/20 s** at steady state. **Exec** (`SENTINEL_EBPF_EXEC=1`, opt-in) adds
  `execve`/`execveat` + `memfd_create` for lower-exec endpoints.
- **Safety rails:** in-kernel gating (ptrace to requests 4/5 only), a backpressure cap
  (`SENTINEL_EBPF_MAX_PER_SEC`, default 300, drops excess), 60 s `(rule,entity)` dedup, and auto-restart
  with backoff. Requires Linux + root + a BTF kernel; if anything is missing the agent logs why and runs on.
- **Provisioning:** `av_agent/install_ebpf.sh` (installs bpftrace, checks BTF, smoke-tests, writes a
  systemd drop-in, enables base or — with `SENTINEL_EBPF_EXEC=1` — exec mode).
- **Validated live on the fleet:** `modprobe dummy` → `KERNEL_MODULE_LOAD` (base); a simulated reverse
  shell → `REVERSE_SHELL_EXEC` (exec tier); bpftrace steady at 0.4% CPU, no crash-loop.
- **Coverage snapshot:** detection library now **83 rules** (76 log-based + 7 eBPF); **23,409 IOCs**
  (ip 15,194 · hash 3,005 · url 2,887 · driver 2,003 · domain 320).

### Rootcheck hidden-process detection — confidence-scored, system-process-safe (agents `0.3.18` / `0.4.6-win`)

Replaced the binary cross-view flag (which fired CRITICAL on transient races and protected system
processes) with a four-stage funnel — **existence anomaly → multi-method visibility validation → trust
evaluation → rootkit confidence score** — so it mostly avoids system processes and reserves high severity
for real threats.

- **Windows:** the reference "does this PID really exist" signal is now a **kernel `OpenProcess`
  confirmation** (a direct query, not a racy WMI/Get-Process/Toolhelp snapshot diff). A candidate must be
  kernel-confirmed, resolve a real image path, be absent from *every* enumeration API, **and persist across
  a settle-and-revalidate** — which eliminated the false-positive storm. (Fixed a nasty bug where a
  `GetLastError`/`ACCESS_DENIED` branch over-counted the kernel set and flagged hundreds of path-less PIDs.)
- **Linux:** keeps the thread-group-leader validation (Tgid==pid) and adds a **kernel-thread (PF_KTHREAD)
  exclusion**; a validated-hidden leader is inherently high-signal (nothing legit is hidden from `/proc`).
- **Trust + confidence (both):** score starts high for a *validated* hidden process, then **subtracts** for
  benign classes (known system process, signed binary under `C:\Windows`, kernel thread) and **adds** for
  suspicious ones (temp/user-writable image, system-name masquerade, deleted binary). Severity is scaled by
  the score; anything below `SENTINEL_ROOTKIT_MIN_CONFIDENCE` (default 70) is suppressed with a debug log.
  Validated live: **zero** FPs on clean hosts; a simulated hidden system process → suppressed (conf 15), a
  hidden temp-path binary → CRITICAL (conf 95).

### LOLDrivers now visible as IOCs + Detection Funnel Scanner: dedup & golden-promote

- **LOLDrivers BYOVD hashes are now first-class IOCs.** The beacon stores them as `driver`-type IOCs
  (`source=LOLDrivers`) instead of an opaque AppSetting blob, so the ~2003 hashes show on the **Feed Health**
  panel (a "LOLDrivers" card) and under **IOC & Rules → Bad Drivers** (new tab). `sync_policy` still serves
  them to Windows agents as `bad_driver_hashes` (filtered out of the general file-hash set; Linux gets none).
- **Detection Funnel Scanner — duplicate prevention.** `run_scan` now flags rules with identical normalized
  detection logic (a `Duplicates` KPI + list; the highest-scoring one is kept, the rest marked
  `duplicate_of`). Verified live: two identical log-rules → `duplicates=1`.
- **Detection Funnel Scanner — golden rules are now actionable.** The scanner stays read-only, but a new
  **Promote golden → fleet** action (`POST /api/scanner/promote`) enables every golden log-rule / YARA
  signature / behaviour (marking log-rules verified) so agents actually enforce them on the next policy
  sync. (Previously golden rules only displayed — they were never pushed.) Golden Suricata rules are
  reported but enabled from the NIDS view.

### Rootcheck advancement — cross-view, BYOVD hashes, persistence (agents `0.3.17` / `0.4.5-win`)

Deepened the host rootkit/anomaly engine toward the techniques renowned tools use, staying stdlib-only.

- **Deeper process cross-view.** Windows now reconciles **three** independent enumerators — WMI
  `Win32_Process`, `Get-Process`, and a native **Toolhelp32** snapshot (ctypes) — so a user-mode hook must
  spoof all three; known system pseudo-processes are excluded to stay low-FP. Linux adds a `kill(0)`
  syscall probe and, crucially, **now filters to thread-group leaders (`Tgid==pid`)** — fixing a
  long-standing false-positive storm where every multi-threaded process's threads (which have
  `/proc/<tid>/stat` and are `kill(0)`-reachable but aren't in `/proc` readdir) were flagged as hidden.
  Verified live: a fresh scan on a busy host now yields **zero** false positives.
- **BYOVD by content hash (LOLDrivers).** A new beacon collector pulls the [loldrivers.io](https://www.loldrivers.io)
  known-vulnerable/malicious driver set (**2003** hashes on first sync), stores it, and the control plane
  hands it to **Windows** agents as `bad_driver_hashes`; rootcheck flags any loaded driver whose SHA-256
  matches (`KNOWN_MALICIOUS_DRIVER`) — a renamed driver still matches, unlike the embedded name list.
  Default on (curated hash IOC list, nothing executed); `SENTINEL_LOLDRIVERS*`. Linux policies get none
  (BYOVD is Windows-only). SSRF-guarded fetch (SEN-015).
- **Persistence / ASEP enumeration.** Windows: **WMI permanent event-consumer** persistence
  (`WMI_PERSISTENCE`) and fileless/obfuscated or user-writable **Run/RunOnce** autoruns
  (`SUSPICIOUS_AUTORUN`). Linux: **cron + systemd** `ExecStart` running from `/tmp`,`/dev/shm`,`/var/tmp`
  or a fileless one-liner (`CRON_PERSISTENCE`, `SYSTEMD_PERSISTENCE`) — `CRON_PERSISTENCE` verified live.

### Windows agent — fleet installer redesign (agent `0.4.4-win`)

A ground-up rework so a **one-time install** yields an **always-on, fully-privileged** agent that is
**remotely updatable** from the control plane with no further machine access (the 5000-endpoint fleet
model). This **supersedes the earlier "per-user default" decision** below.

- **SYSTEM is now the default when the installer runs elevated.** A bare first-run (or `--install`) that
  is already elevated — the natural state under Intune / SCCM / GPO startup / RMM, which execute payloads
  as SYSTEM — registers a **boot-start SYSTEM scheduled task** (full EDR privilege, survives reboots, no
  interactive session needed). A plain **non-elevated double-click stays per-user with no surprise UAC**;
  `--install-user` forces the degraded per-user mode; `--install-system` forces SYSTEM (self-elevates once).
  Fixes a blocking bug where an elevated no-flag run dropped a per-user `.vbs` into the SYSTEM profile
  where it never ran.
- **Hardened task + resilience:** the SYSTEM task is registered from Task-Scheduler XML (BootTrigger,
  `RestartOnFailure`, `StartWhenAvailable`, unbounded run-time) with a plain-`schtasks` fallback, plus a
  companion **watchdog task** (`--ensure`, every 10 min, mutex-guarded) that restarts a hung/killed agent,
  and an **indefinite capped-backoff enroll loop** so an agent never permanently exits after a control-plane
  outage or mass reboot.
- **Fixed identity churn (would duplicate every agent on every restart/update).** The SEN-011 dir hardening
  used `icacls /inheritance:r /T`, which stripped child files' inherited ACEs and — because `(OI)(CI)`
  grants are invalid on a *file* — left the exe **and `state.json`** with an **empty DACL** unreadable even
  by SYSTEM. Result: the exe wouldn't launch (task `0x80070005`) and, once running, the agent re-enrolled
  with a **new id on every start** (duplicate records fleet-wide). Hardening now grants inheritable ACEs on
  the dir and makes children **re-inherit**, so the exe stays executable and `state.json` persists. Verified
  live: identity stable across install + restarts + a remote update.
- **Fixed Windows response enforcement — it never actually worked.** `netsh advfirewall firewall add/delete
  rule` has **no `group=` parameter**, so isolation, IP-blocklist, and port-close commands were rejected;
  the old code ignored the return code and recorded them as *applied* (the console showed blocks that did
  not exist). Now rules are added/deleted **by name** and the **return code is checked** — a failure is no
  longer recorded as success. Verified live: a pushed blocked IP now produces a real Windows Firewall rule.
- **SYSTEM detection coverage:** scan roots now enumerate every real user profile's Downloads/Desktop
  (running as SYSTEM, `expanduser('~')` is the empty systemprofile), so a SYSTEM agent still sees user
  malware drop zones. Cross-session **`Global\` single-instance mutex**. New **`--uninstall`** for clean
  decommission (stop/delete tasks, kill agent, remove autostart + install dir).
- **Self-update hardening:** reject a build whose version is **not strictly newer** (anti-rollback vs a
  replayed signed directive) and apply **rollout jitter** so a fleet-wide push doesn't stampede the
  download endpoint.
- **Control-plane update circuit breaker:** the pull-style update directive is re-sent every heartbeat
  until the agent reports the target version (durable across offline/mid-crash) but now **caps attempts**
  (`SENTINEL_UPDATE_MAX_ATTEMPTS`, default 8) so a deterministically-failing build can't re-download
  forever across the fleet; re-armed on a fresh push and on `update-all`.

- **Post-adversarial-review hardening (agent `0.4.4-win`).** A multi-agent review of the redesign
  surfaced defects that were then fixed: (1) **SSRF-guard bypass** — the Sigma-repo collector in
  `beacon.py` fetched the remote `download_url` with a raw opener; it now uses the SEN-015
  `_safe_urlopen`. (2) **`--install` gating** — an elevated `--install` now follows the SYSTEM default
  (matching its help) instead of forcing per-user; only `--install-user` forces per-user. (3)
  **anti-rollback** now *rejects* an unparseable target version instead of skipping the check. (4)
  **incident response before update** — `_apply_hb` applies isolate/blocklist/ports *before* a queued
  self-update (which exits the process), so quarantine isn't deferred a whole update cycle; the update
  jitter is capped under a heartbeat. (5) **`remove_isolation`** now checks the netsh return code (a
  failed un-isolate is no longer reported as success). (6) **cross-session mutex** — the `Global\`
  singleton is created with an Everyone-SYNCHRONIZE DACL and a non-elevated agent probes it via
  `OpenMutexW`, so a SYSTEM agent and a stray per-user agent can't both run. (7) **`--uninstall`** now
  excludes its own process tree from the agent kill. (8) **build** — no unpinned `pip --upgrade`; the
  pinned set installs with `--no-deps` (every transitive dep pinned in `build-requirements.txt`); venv
  + ACL steps are now failure-checked. (9) control-plane: `_update_attempts` is cleared on agent
  removal; installer `ALTER ROLE`s the DB password so a regenerated env can't desync from Postgres.
  Tracked residuals (defense-in-depth, documented in SECURITY.md): binding the version into the update
  signature (full anti-downgrade), DNS-rebinding on collectors (mitigate with `SENTINEL_FEED_HOST_ALLOW`),
  and separating writable state from read-only code under the systemd sandbox.

### Security — audit remediation (SEN-014..017)

- **SEN-014 (High) — supply-chain build hardening.** The Windows build now installs **exact, pinned**
  dependencies from a hash-lockable `av_agent/build-requirements.txt` (`--require-virtualenv`), resolves
  the interpreter by **absolute path** (not PATH), builds in a **fresh ACL-restricted randomized dir**
  that is removed afterward, **records the artifact SHA-256**, and has an optional **Authenticode signtool**
  hook (`SENTINEL_SIGN_PFX`/`SENTINEL_SIGN_AUTO`). Closes the Windows half of SEN-014 (dependency pinning
  + reproducible build); CI `--require-hashes` from an internal mirror remains the last step.
- **SEN-015 (Medium, was the sole Open) — SSRF in feed/rule collectors → Fixed.** Every server-side fetch
  in `controlplane/beacon/feeds.py` and `wazuh_rulegen/feedupdate.py` now goes through an SSRF guard: an
  **http/https-only scheme allow-list** (blocks `file://`/`ftp://`/`gopher://`), rejection of any host that
  resolves to a **private/loopback/link-local/reserved/multicast** address (blocks cloud-metadata
  `169.254.169.254`, `127.0.0.1`, RFC1918), **redirect re-validation on every hop**, and an optional host
  allow-list (`SENTINEL_FEED_HOST_ALLOW`). Verified live: all public feeds still collect.
- **SEN-016 (Medium) — remains Fixed** (installer generates random DB password + API token, env file
  `chmod 600`, `umask 077`).
- **SEN-017 (Medium) — services run as root/SYSTEM → Fixed (Linux).** `install.sh` now creates a dedicated
  unprivileged **`sentinel`** service account and the `sentinel-api` / `sentinel-beacon` units run as it
  with a full systemd **sandbox** (`ProtectSystem=strict` + scoped `ReadWritePaths`, empty
  `CapabilityBoundingSet`, `ProtectHome`, `PrivateTmp`, `ProtectKernel*`, `RestrictAddressFamilies`, …).
  Applied + verified live (API `healthz=200`, both services active as `sentinel`). On Windows the agent
  runs as SYSTEM **by necessity** (netsh firewall, Security/Sysmon log read, full process visibility have
  no least-privilege equivalent); the accepted containment is the signed-update-only chain (Ed25519 +
  optional Authenticode) + the SEN-011 install-dir DACL + an exe-scoped Defender exclusion.

### Fixed (misc)
- Silenced a benign `DeprecationWarning` (`invalid escape sequence`) emitted while normalising YARA rule
  strings via `unicode_escape` on the Windows agent.

---

- **Windows self-update reliability fix** (agent `0.3.19-win`). A pushed Windows update could get
  stuck in "UPDATE QUEUED": the new build downloaded and verified fine, but the swap step failed. Two
  causes, both fixed in the updater: (1) a prior interrupted `sentinel-update.cmd` could be left locked
  and block every later swap — the updater now cleans stale `*.cmd`/`.bak`/`.new` first and writes a
  **unique per-attempt** `.cmd`, and retries the exe `move` while the onefile bootstrap releases its
  lock; (2) the per-user relaunch used a bare `start`, which does not work from a console-less detached
  batch and left the host with no running agent — it now uses `powershell … Start-Process -WindowStyle
  Hidden` (SYSTEM installs still relaunch via the scheduled task). Rollback-to-known-good is preserved.
  (The "two agent processes" seen during diagnosis were the normal PyInstaller onefile parent+child, not
  a duplicate instance.)
- **Windows install modes split — per-user default, SYSTEM opt-in** (agent `0.3.16-win`). The Windows
  installer no longer auto-elevates on a plain `--install`: the default is now the proven **per-user
  logon launcher** (agent runs as the logged-in user; the SEN-011 dir hardening self-skips so it can
  never lock itself out). A SYSTEM scheduled task — reliable remote-update relaunch + SEN-011 hardening
  — is now a **deliberate opt-in**: `sentinel-av.exe --install-system` (or `SENTINEL_INSTALL_SYSTEM=1`),
  which self-elevates once via UAC and falls back to per-user if declined. This removes the surprise UAC
  prompt / silent-failure loop seen when SYSTEM-task creation was attempted on every install, and keeps
  the default path the one verified stable on the live fleet.
- **Remove / decommission agent** — `DELETE /api/agents/{id}` and a **Remove** button in the Fleet
  device modal, to prune stale or duplicate agent records (detection history is kept). Added after a
  duplicate `windows-endpoint-01` record appeared when the crash-looping agent re-enrolled without its
  (locked) state; the duplicate was removed and the underlying self-lock was fixed (see 1.5.0 notes).
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
  trust based, fully local — no threat feed, no internet.** Agents **Linux `0.3.18`, Windows `0.3.14-win`**.
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

Two more security-audit findings closed. Agents: Linux `0.3.18`, Windows `0.3.14-win`.

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

Detection content library + new telemetry sources. Agents: Linux `0.3.18`, Windows `0.3.13-win`.

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

