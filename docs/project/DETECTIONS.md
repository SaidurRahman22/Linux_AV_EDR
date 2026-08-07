# Detection Coverage (log-based IDS + real-time eBPF)

> **Documentation set:** v1.13.0 · **Last updated:** 2026-08-07 · **Status:** Current (living)
> **Applies to:** Control plane v1.13.0 · Agents — Linux `0.4.9`, Windows `0.5.2-win`

The detection library (`controlplane/app/logrules_pack.py`) is a curated, **MITRE ATT&CK-mapped** rule set — currently **92 rules**: **81 log-based** across **12 tactics** (matched against decoded log lines), **7 real-time eBPF** behavioural rules ([in-kernel syscalls](#real-time-ebpf-behavioral-tracing-linux), `producer=ebpf`), and **4 ETW-channel** rules ([Windows behavioral telemetry](#windows-behavioral-telemetry-sysmon--etw)). Rules are distributed to agents by platform and matched locally; every hit is also forwarded to Wazuh (see [../deploy/wazuh/README.md](../../deploy/wazuh/README.md)).

Rules by platform: **any** 9, **linux** 42, **windows** 37. By source: `any` 19, `auditd` 4, `auth` 10, `ebpf` 7, `etw` 4, `syslog` 3, `sysmon` 12, `web` 13, `winsec` 20, `winsys` 1.

## Telemetry sources & enablement

Coverage is **telemetry-bound** — a rule only fires if its events reach a log the agent reads:

| Source | Where | Enable |
|---|---|---|
| `auth` / `syslog` | Linux `/var/log/auth.log`, `syslog` | on by default |
| `web` | nginx/apache access logs | set `SENTINEL_WEB_LOGS` |
| `auditd` | Linux `/var/log/audit/audit.log` | `sudo bash deploy/auditd/install_auditd.sh` |
| `winsec` / `winsys` | Windows Security / System log | Advanced Audit Policy (4688 + cmdline for process rules) |
| `sysmon` | `Microsoft-Windows-Sysmon/Operational` | install Sysmon: [deploy/sysmon/README.md](../../deploy/sysmon/README.md) |

> Rules whose events need extra telemetry (auditd keys, Sysmon, or the Windows "include command line in 4688" policy) stay quiet until that telemetry is enabled — they produce no false negatives from our side, there is simply nothing to match.

## Coverage by ATT&CK tactic

### TA0001 — Initial Access (7)

| Rule | Platform | Source | Sev | MITRE | Detects |
|---|---|---|---|---|---|
| `web_confluence_ognl` | any | web | CRITICAL | T1190 | OGNL/EL injection RCE (e.g. Confluence CVE-2022-26134, Struts) |
| `web_log4shell` | any | web | CRITICAL | T1190 | Log4Shell (CVE-2021-44228) JNDI lookup |
| `web_proxyshell_logon` | any | web | CRITICAL | T1190 | Exchange ProxyShell/ProxyLogon exploitation pattern |
| `web_shellshock` | any | web | HIGH | T1190 | Shellshock (CVE-2014-6271) bash function injection |
| `web_spring4shell` | any | web | HIGH | T1190 | Spring4Shell (CVE-2022-22965) class-loader manipulation |
| `web_sql_injection` | any | web | HIGH | T1190 | SQL-injection signature in a web request |
| `sysmon_office_spawns_shell` | windows | sysmon | HIGH | T1566.001 | Office application spawned a shell/script host (Sysmon 1) |

### TA0002 — Execution (9)

| Rule | Platform | Source | Sev | MITRE | Detects |
|---|---|---|---|---|---|
| `download_pipe_to_shell` | linux | any | HIGH | T1105 | Download-and-execute cradle (curl/wget piped to a shell) |
| `linux_exec_suspicious_binary` | linux | auditd | HIGH | T1059 | Execution of nc/ncat/socat/nmap/etc. (auditd exec watch) |
| `perl_ruby_reverse_shell` | linux | any | CRITICAL | T1059 | Perl/Ruby reverse shell |
| `python_reverse_shell` | linux | any | CRITICAL | T1059.006 | Python one-liner reverse shell |
| `reverse_shell_command` | linux | any | CRITICAL | T1059.004 | Interactive reverse-shell one-liner in a log |
| `sysmon_encoded_powershell` | windows | sysmon | CRITICAL | T1059.001 | Encoded/obfuscated PowerShell (Sysmon 1) |
| `sysmon_server_spawns_shell` | windows | sysmon | HIGH | T1505.003 | Web/DB server process spawned a shell (webshell / RCE, Sysmon 1) |
| `win_encoded_powershell` | windows | winsec | CRITICAL | T1059.001 | Encoded/obfuscated PowerShell in a process command line (4688) |
| `win_wmic_process_call` | windows | winsec | HIGH | T1047 | Remote/lateral execution via wmic process call create (4688) |

### TA0003 — Persistence (14)

| Rule | Platform | Source | Sev | MITRE | Detects |
|---|---|---|---|---|---|
| `web_webshell_request` | any | web | HIGH | T1505.003 | Request to a known web-shell filename |
| `at_job_scheduled` | linux | syslog | LOW | T1053.002 | An at(1) job was scheduled |
| `cron_edited` | linux | syslog | MEDIUM | T1053.003 | A user's crontab was edited |
| `cron_suspicious_exec` | linux | syslog | HIGH | T1053.003 | A cron job ran from a temp dir or fetched/decoded a payload |
| `linux_persistence_file` | linux | auditd | HIGH | T1543.002, T1037, T1574.006 | Write to a persistence path (systemd/cron/rc.local/ld.so.preload/authorized_keys) — auditd |
| `password_changed` | linux | auth | MEDIUM | T1098 | An account password was changed |
| `user_account_created` | linux | auth | HIGH | T1136.001 | A local user account was created |
| `user_added_privileged_group` | linux | auth | HIGH | T1098 | A user was added to a privileged group |
| `sysmon_run_key_persistence` | windows | sysmon | HIGH | T1547.001 | Autorun registry Run-key set (Sysmon 12/13) |
| `sysmon_startup_persistence` | windows | sysmon | HIGH | T1547.001 | File dropped into a Startup folder (Sysmon 11) |
| `win_added_to_privileged_group` | windows | winsec | HIGH | T1098 | Member added to a security-enabled/admin group (4728/4732/4756) |
| `win_scheduled_task_created` | windows | winsec | HIGH | T1053.005 | A scheduled task was created (4698) |
| `win_service_installed` | windows | winsys | MEDIUM | T1543.003 | A new Windows service was installed (7045) |
| `win_user_created` | windows | winsec | HIGH | T1136.001 | A Windows user account was created (4720) |

### TA0004 — Privilege Escalation (5)

| Rule | Platform | Source | Sev | MITRE | Detects |
|---|---|---|---|---|---|
| `dirtypipe_dirtycow` | linux | any | CRITICAL | T1068 | Dirty Pipe / Dirty COW kernel LPE indicator |
| `pkexec_pwnkit` | linux | any | CRITICAL | T1068 | PwnKit / CVE-2021-4034 pkexec local privilege escalation |
| `setuid_shell` | linux | any | HIGH | T1548.001 | Setuid bit set on a shell/interpreter |
| `sudo_auth_failure` | linux | auth | MEDIUM | T1548.003 | Repeated sudo authentication failures |
| `win_special_privileges` | windows | winsec | MEDIUM | T1078 | Admin/special privileges assigned to a non-system logon (4672) |

### TA0005 — Defense Evasion (10)

| Rule | Platform | Source | Sev | MITRE | Detects |
|---|---|---|---|---|---|
| `base64_decode_exec` | linux | any | HIGH | T1027, T1140 | Base64-decoded payload piped to a shell |
| `defense_disable` | linux | any | HIGH | T1562.001 | Security control disabled (auditd/apparmor/selinux/firewall) |
| `history_tamper` | linux | any | MEDIUM | T1070.003 | Shell history cleared / disabled |
| `linux_defense_evasion_audit` | linux | auditd | HIGH | T1562.001 | Change to audit/security config (auditd defense watch) |
| `log_tamper` | linux | any | HIGH | T1070.002 | System log truncated / vacuumed / shredded |
| `sysmon_remote_thread` | windows | sysmon | HIGH | T1055 | CreateRemoteThread — process injection (Sysmon 8) |
| `win_audit_policy_changed` | windows | winsec | HIGH | T1562.002 | System audit policy was changed (4719) |
| `win_defender_tamper` | windows | winsec | HIGH | T1562.001 | Defender/firewall tampering via command line (4688) |
| `win_log_cleared` | windows | winsec | HIGH | T1070.001 | The Windows Security audit log was cleared (1102) |
| `win_lolbin_process` | windows | winsec | HIGH | T1218 | A living-off-the-land binary was launched (4688) |

### TA0006 — Credential Access (11)

| Rule | Platform | Source | Sev | MITRE | Detects |
|---|---|---|---|---|---|
| `linux_cred_dump_tool` | linux | any | HIGH | T1003 | Known Linux credential-dumping tool referenced |
| `linux_shadow_access` | linux | auditd | HIGH | T1003.008 | Access to /etc/shadow|passwd|sudoers (auditd identity watch) |
| `pam_auth_failure` | linux | auth | MEDIUM | T1110 | Repeated PAM auth failures from one host (any service) |
| `ssh_bruteforce` | linux | auth | HIGH | T1110 | 5+ failed SSH passwords from one source IP |
| `ssh_invalid_user` | linux | auth | MEDIUM | T1110 | Repeated logins for non-existent users (enumeration) |
| `su_failed` | linux | auth | MEDIUM | T1078 | Repeated failed su attempts by one user |
| `sysmon_lsass_access` | windows | sysmon | CRITICAL | T1003.001 | Process accessed LSASS memory (credential dumping, Sysmon 10) |
| `win_account_lockout` | windows | winsec | MEDIUM | T1110 | A Windows account was locked out (4740) |
| `win_failed_logon` | windows | winsec | HIGH | T1110 | 5+ failed Windows logons (4625) from one source |
| `win_kerberoast` | windows | winsec | HIGH | T1558.003 | Kerberos service ticket requested with RC4 (kerberoasting, 4769/0x17) |
| `win_lsass_dump_tool` | windows | winsec | CRITICAL | T1003.001 | LSASS credential-dumping tool/technique (4688 cmdline) |

### TA0007 — Discovery (5)

| Rule | Platform | Source | Sev | MITRE | Detects |
|---|---|---|---|---|---|
| `web_path_traversal` | any | web | HIGH | T1083 | Path-traversal / LFI attempt |
| `cloud_metadata_ssrf` | linux | any | HIGH | T1552.005 | Access to cloud instance metadata endpoint (SSRF / cred theft) |
| `sysmon_metadata_connection` | windows | sysmon | HIGH | T1552.005 | Network connection to cloud metadata endpoint (Sysmon 3) |
| `win_bloodhound` | windows | winsec | HIGH | T1087.002 | BloodHound / SharpHound AD enumeration (4688) |
| `win_domain_recon` | windows | winsec | MEDIUM | T1087 | Active-Directory reconnaissance commands (4688) |

### TA0008 — Lateral Movement (2)

| Rule | Platform | Source | Sev | MITRE | Detects |
|---|---|---|---|---|---|
| `win_psexec` | windows | any | HIGH | T1569.002, T1021.002 | PsExec service execution (lateral movement) |
| `win_rdp_logon` | windows | winsec | MEDIUM | T1021.001 | Interactive RDP logon (4624 type 10) |

### TA0011 — Command & Control (4)

| Rule | Platform | Source | Sev | MITRE | Detects |
|---|---|---|---|---|---|
| `linux_c2_tunnel_tool` | linux | any | HIGH | T1090, T1071 | Known tunnelling / C2 relay tool |
| `sysmon_cobaltstrike_pipe` | windows | sysmon | CRITICAL | T1055 | Cobalt Strike / Meterpreter default named pipe (Sysmon 17/18) |
| `sysmon_susp_dns` | windows | sysmon | MEDIUM | T1071.004 | DNS query to a high-abuse TLD / dynamic-DNS / tunnelling domain (Sysmon 22) |
| `win_lolbin_download` | windows | winsec | HIGH | T1105 | A LOLBin was used to download a payload (4688) |

### TA0040 — Impact (6)

| Rule | Platform | Source | Sev | MITRE | Detects |
|---|---|---|---|---|---|
| `cryptominer` | linux | any | HIGH | T1496 | Cryptocurrency miner indicator |
| `disk_wipe` | linux | any | CRITICAL | T1561.002 | Raw write / reformat of a physical disk |
| `mass_ransom_note` | linux | any | CRITICAL | T1486 | Ransomware note / encrypted-extension indicator |
| `user_account_deleted` | linux | auth | MEDIUM | T1531 | A local user account was deleted |
| `win_shadow_copy_delete` | windows | winsec | CRITICAL | T1490 | Shadow-copy / backup deletion (ransomware precursor, 4688) |
| `win_user_deleted` | windows | winsec | MEDIUM | T1531 | A Windows user account was deleted (4726) |

### TA0042 — Resource Development (1)

| Rule | Platform | Source | Sev | MITRE | Detects |
|---|---|---|---|---|---|
| `linux_offensive_tool` | linux | any | HIGH | T1588.002 | Known Linux privilege-escalation / enumeration tool |

### TA0043 — Reconnaissance (5)

| Rule | Platform | Source | Sev | MITRE | Detects |
|---|---|---|---|---|---|
| `web_scanner_ua` | any | web | MEDIUM | T1595.002 | Known web scanner / fuzzer user-agent or tool |
| `web_secret_file_probe` | any | web | HIGH | T1552.001, T1595.003 | Probe for exposed secrets/config (`.env`, `.git`, `.aws`, `wp-config`, `id_rsa`) — credential-harvesting scan |
| `web_fake_browser_ua` | any | web | MEDIUM | T1595, T1071.001 | Malformed/spoofed browser User-Agent (Mozlila/Bulid/Moblie typos) — scanner/botnet fingerprint |
| `web_cms_admin_probe` | any | web | MEDIUM | T1595.003 | CMS / admin-panel / mgmt-endpoint probing (wp-login, phpMyAdmin, actuator, Tomcat manager) |
| `web_exploit_scan` | any | web | HIGH | T1595.002, T1190 | Router/IoT/framework RCE exploit probe (boaform/HNAP/GponForm/phpunit/ThinkPHP) |

## Windows behavioral telemetry (Sysmon + ETW)

Windows has no NFQUEUE or eBPF, so its behavioral depth comes from **Sysmon's kernel driver** plus **ETW-backed event-log channels**. The agent reads these through the same Windows event reader that handles the Security/System logs — Sysmon (`Microsoft-Windows-Sysmon/Operational`, source `sysmon`) and three ETW channels (source `etw`): `PowerShell/Operational` (script-block logging), `WMI-Activity/Operational`, and `Windows Defender/Operational`. Channels that aren't enabled simply return nothing, so they cost nothing until provisioned. **ETW-TI** (the protected in-kernel injection provider) is *not* consumed — it requires a Microsoft-signed ELAM/PPL anti-malware process — so injection coverage comes from Sysmon EID 8/10/25 instead, which needs no special signing.

> **Fixed:** `sysmon`-source rules were previously filtered out of the Windows agent's matcher and never fired; the agent now matches `sysmon` and `etw` sources, so all Sysmon rules are live (agent `0.5.0-win`+).

| Rule | Source | Sev | MITRE | Detects |
|---|---|---|---|---|
| `sysmon_process_tampering` | sysmon | HIGH | T1055.012 | Process hollowing / image tampering / herpaderping (Sysmon 25) |
| `sysmon_injection_from_lolbin` | sysmon | HIGH | T1055.001 | CreateRemoteThread originating from a script host / LOLBin (Sysmon 8) |
| `etw_powershell_obfuscation` | etw | HIGH | T1059.001, T1027 | Obfuscated/encoded PowerShell caught by script-block logging (4104) |
| `etw_wmi_persistence` | etw | HIGH | T1546.003 | WMI permanent event consumer / subscription bound — persistence |
| `etw_defender_malware` | etw | HIGH | T1204 | Microsoft Defender detected/acted on malware |
| `etw_defender_tamper` | etw | HIGH | T1562.001 | Microsoft Defender real-time / scanning protection disabled |

(These join the 10 existing `sysmon` rules — LSASS access, encoded PowerShell, Office/webshell spawns, C2 named pipes, run-key/startup persistence, cloud-metadata, suspicious DNS.)

**Telemetry & enforcement status — visible per device.** Each Windows agent reports a `win_telemetry` snapshot on its heartbeat, shown in the console (Fleet → device → *Windows Telemetry & Enforcement* panel): Sysmon installed/running + events/hr, each ETW channel (and whether PowerShell script-block logging is on), Windows Firewall profiles enabled, and Sentinel enforcement (isolation / blocked IPs / closed ports). The installer provisions all of it in one shot (Sysmon config, ETW channels, script-block logging, firewall on) — see OPERATIONS → *Windows telemetry*.

## Real-time eBPF behavioral tracing (Linux)

The log-based rules above fire only when an event reaches a log, and the `/proc` cmdline scanner only sees processes that are still alive at poll time. The **eBPF engine** closes both gaps: the agent orchestrates **bpftrace** (iovisor/bpftrace) to trace a handful of **high-signal syscalls in-kernel**, in real time, catching threats that never touch a log or that exec-and-exit between poll cycles. The agent is a **thin consumer** — bpftrace filters in-kernel and prints compact `TYPE|pid|uid|comm|detail` lines, the agent regex-matches only `source=ebpf` rules and queues hits (`producer=ebpf`, forwarded to Wazuh). This mirrors the Suricata model: the engine is provisioned out-of-band and the agent just orchestrates it.

**Two tiers, light by default.** Tracing every `execve` with an argv `join()` is heavy on a busy host (it can pin a CPU) and blows the 512-byte BPF stack when combined with an in-kernel filter, so it is **not** the default:

| Tier | Env | Syscalls traced | Cost (measured) |
|---|---|---|---|
| **Base** (default when eBPF on) | `SENTINEL_EBPF=1` | `ptrace(POKETEXT/POKEDATA)`, `init_module`/`finit_module` — **rare, no argv join** | bpftrace **~0.4% CPU**, agent **~1–2% CPU / 35 MB**. These syscalls measured **0/20 s** at steady state → effectively nothing to false-positive on. |
| **Exec** (opt-in) | `SENTINEL_EBPF_EXEC=1` | adds `execve`/`execveat` (with argv) + `memfd_create` | heavier per-exec; for lower-exec **endpoints**, not busy servers. memfd rides here (it is bursty on desktops via PipeWire/browsers/snapd). |

A **backpressure cap** (`SENTINEL_EBPF_MAX_PER_SEC`, default 300) drops excess events so a syscall storm can never load the host, and identical `(rule, entity)` hits are deduped for 60 s. bpftrace holds a **constant ~100 MB RSS** (its BPF/runtime baseline — it does not grow). Requirements: Linux, agent running as **root**, a **BTF** kernel (`/sys/kernel/btf/vmlinux`), and bpftrace — all provisioned by `sudo bash av_agent/install_ebpf.sh` (see OPERATIONS). If any is missing the engine logs the reason and the agent runs normally without it.

| Rule | Tier | Sev | MITRE | Detects |
|---|---|---|---|---|
| `ebpf_ptrace_inject` | base | HIGH | T1055.008 | Process injection via `ptrace(PTRACE_POKETEXT/POKEDATA)` — writing another process's memory |
| `ebpf_kernel_module_load` | base | MEDIUM | T1547.006 | Runtime kernel-module load (`init_module`/`finit_module`) — rootkit / BYOVD |
| `ebpf_reverse_shell` | exec | CRITICAL | T1059.004 | Interactive reverse-shell exec (`bash -i`, `/dev/tcp`, `nc -e`, `socat …exec`) |
| `ebpf_script_reverse_shell` | exec | CRITICAL | T1059.006 | Python/Perl/Ruby/PHP inline reverse-shell exec |
| `ebpf_download_exec` | exec | HIGH | T1105 | Download-and-run cradle exec'd (curl/wget piped to a shell) |
| `ebpf_offensive_tool` | exec | MEDIUM | T1046 | Offensive/recon tool exec'd (nmap/masscan/ncat/socat…) |
| `ebpf_memfd_fileless` | exec | MEDIUM | T1620 | `memfd_create` — fileless / in-memory payload staging |

> The exec-tier reverse-shell / download rules overlap by design with the log-IDS (`reverse_shell_command`, `download_pipe_to_shell`, `python_reverse_shell`) and `/proc` scanner rules — eBPF adds the sub-poll-interval and no-log-produced cases. The **base tier is the unique, always-safe contribution**: kernel-level injection and module-load visibility that logs alone don't give you. Validated live on the fleet: a `modprobe` load produced `KERNEL_MODULE_LOAD`; a simulated reverse-shell exec produced `REVERSE_SHELL_EXEC` (exec tier) — with bpftrace at 0.4% CPU in base mode.

**Process-ancestry lineage (agent `0.4.8`).** The exec probe also emits the **parent PID** (`curtask->real_parent->tgid` — a scalar int, so no BPF-stack cost), letting the agent resolve `/proc/<ppid>/comm` and flag a **network-facing server/daemon spawning a shell or interpreter** (`SUSPICIOUS_LINEAGE`, HIGH, T1505.003 / T1059) — the Linux analog of the Windows `sysmon_server_spawns_shell`. It fires **regardless of the child's command line**, so it catches webshells whose payload looks benign to the argv-pattern rules. Conservative by design: a focused daemon set (nginx / apache / httpd / lighttpd / caddy / php-fpm / mysqld / mariadbd / postgres / redis / mongod / ftp / smbd / dovecot / named) × shell/interpreter children (sh/bash/python/perl/ruby/nc/socat/…), excluding the normal cases (sshd login → shell, cron → sh, php-fpm → php). Deduped per (parent, child) for 5 min; independent of the distributed rule set; active where the exec tier is enabled.

## Tuning & false positives

- Rules are managed in the console under **IDS / IPS → Log-based IDS Rules** (add / toggle / delete) or via `/api/log-rules`; disabling a rule removes it from the distributed policy.
- Threshold rules (e.g. brute force) correlate N matches per entity within a window, reducing single-event noise. Tune `threshold` / `window_sec` per environment.
- The command-line rules (Linux reverse-shell/download; Windows encoded-PowerShell/LOLBin) depend on command-line logging (Linux auditd/`execve`; Windows 4688 cmdline GPO or Sysmon).
- Content lives in `controlplane/app/logrules_pack.py` — a maintained library; new rules land there and seed on restart (idempotent by name).

## Alert calibration — the analyst-in-a-box (`controlplane/app/calibrate.py`)

A raw detector emits a fixed severity for a pattern; it has no idea whether *this* hit is a real threat or benign noise. Left uncalibrated, everything trends HIGH/CRITICAL and triage drowns. **After a detection triggers, the calibration engine does what a senior analyst does before acting** — it gathers context, weighs it, and renders a **verdict** plus a **re-tiered severity**. It runs **automatically at ingest** (invisible — every detection is calibrated as it is stored) and can be re-run on demand.

**Evidence it gathers** (DB-only, no network, so it is safe to run inline):

| Signal | Effect | Source |
|---|---|---|
| Indicator in the IOC store / flagged by VirusTotal / high AbuseIPDB | **raise** + floor at HIGH | threat-intel store (server-side) |
| Exact file-hash match | pinned — never downgraded below raw | the indicator the detection fired on |
| Operator-allowlisted / own-infrastructure | suppress → benign | allowlist table / `OWN_INFRA` (server-side) |
| File in a system/package path, `*.so`/`.dll` under a real system dir, signed binary | ease down (**capped**) | endpoint `details.*` (self-reported) |
| SSH / remote-exec transport tool (`ssh`, `plink`, `kubectl`, …) | ease down (**capped**) | endpoint `details.*` |
| File/exec in a user-writable or temp path, deleted image, multiple behaviours | raise | endpoint `details.*` |
| Host corroboration — many distinct alert types in 24 h | small raise | detections table |
| High prevalence — the same indicator firing constantly across the fleet | ease down | detections table |
| Bangladesh IP with weak reputation | cap at MEDIUM + flag for review | operator policy |

**Verdict taxonomy** (shown in the SRS Logs *Calibration* panel and the Severity column): `confirmed-threat` · `likely-threat` · `inconclusive` · `likely-noise` · `benign-noise`. The panel lists every contributing reason (▲ raised / ▼ eased / ● neutral), so the re-tiering is fully explainable, never a black box.

**Fail-safe by design — it never buries a real threat:**

- **Precise evidence wins.** An exact file-hash match, or an indicator already in the IOC store, is *never* downgraded below its triggered severity; a known-bad indicator is floored at HIGH.
- **Uncertainty keeps the raw severity.** When the evidence is thin or contradictory the verdict is `inconclusive` and the severity is left untouched — the analyst decides.
- **Anti-evasion.** `details.*` fields come from the endpoint agent, which on a compromised host is attacker-controlled. So: self-reported downgrades (signed / path / process-name) are **capped at a two-tier drop** and never applied to a precise detection; the allowlist only honours the **authoritative** artifact hash (not a decorative `details.sha256`); a `.so`/`.dll` in a writable/staging dir is **not** trusted; and **only hard reputation (intel/VT/AbuseIPDB) can lift an alert to CRITICAL** — host context alone caps at HIGH, so a busy host can't turn every alert critical. An allowlisted indicator that later matches high-confidence intel is surfaced for review, not silently suppressed.
- **Bulletproof.** `calibrate()` never raises — any internal error yields an `uncalibrated` result that preserves the raw severity, so a calibration bug can't drop or corrupt an ingest.

Logic (`evaluate`) is split from the DB reads (`gather_context`) and pinned by `controlplane/tests/test_calibrate.py` (20 cases incl. the anti-evasion rules). Re-run on demand: `POST /api/detections/{id}/recalibrate` (one alert) or `POST /api/detections/recalibrate?limit=N` (fold over the backlog — returns the before/after severity + verdict distribution). Live validation over 1 000 backlog detections re-tiered ~230 noise alerts down (HIGH 618→397, MEDIUM 67→294) while leaving the genuinely threat-shaped CRITICALs (Suricata IDS, Meterpreter/reverse-shell signatures) in place.

## Importing Sigma rules

Community **Sigma** rules can be imported and converted to log-IDS rules — via the console (*IDS / IPS → Import Sigma*, paste YAML), `POST /api/log-rules/sigma`, or the optional **24/7 beacon scraper** (`SENTINEL_SIGMA_REPO=1`, default off, pulls from SigmaHQ dirs). The converter (`controlplane/app/sigma.py`) handles the common Sigma shapes (keywords; field contains/startswith/endswith/re; simple and/or/not conditions); aggregation/correlation rules are skipped with a reason.

**False-positive gate.** Every imported rule runs a **self-check** (`verify_pattern`): it rejects over-broad patterns and anything matching a benign-log corpus. Rules that fail land **staged** (`verified=false`) and are **never distributed** until an operator reviews and promotes them (the *Verify* action / `POST /api/log-rules/{id}/verify`). Only **verified AND enabled** rules reach agents — so noisy Sigma content is triaged safely before it can fire in production.

## Host rootkit / anomaly detection (rootcheck)

Separate from the log-based IDS above, each agent runs a **rootcheck** pass (`rootcheck_scan`, default every 600 s — `SENTINEL_ROOTCHECK` / `SENTINEL_ROOTCHECK_INTERVAL`; `producer=rootcheck`, forwarded to Wazuh). Rootkit detection is **consistency/trust based, not IOC-feed based** — a rootkit betrays itself through the discrepancies it creates while hiding — so these checks run **entirely locally, with no threat feed and no internet**. A small curated known-artifacts / known-driver list supplements them and is **policy-extensible** (`rootkit_artifacts`, and on Windows `bad_drivers`, in `/api/sync/policy`). Windows drivers are additionally matched by **content hash** against the **LOLDrivers** known-vulnerable/malicious set (`bad_driver_hashes`, populated by the beacon from loldrivers.io — see OPERATIONS).

**Hidden-process detection is confidence-scored (not a binary flag)** following a four-stage funnel — *existence anomaly → multi-method visibility validation → trust evaluation → rootkit confidence score* — so it mostly avoids system processes and reserves CRITICAL for real threats. A candidate must be **kernel-confirmed** (Linux: a thread-group leader reachable via `kill(0)`; Windows: `OpenProcess` succeeds and resolves a real image) yet hidden from every enumeration source, and must **persist across a re-sample** (killing transient start/exit races). The trust stage then subtracts confidence for benign classes (a known system process, a signed binary under `C:\Windows`, a kernel thread) and adds it for suspicious ones (a temp/user-writable image, a system-name masquerade, a deleted binary). Only findings at or above `SENTINEL_ROOTKIT_MIN_CONFIDENCE` (default 70) are emitted, with severity scaled by the score (≥85 CRITICAL, ≥70 HIGH). Validated live: **zero** false positives on clean hosts; a simulated hidden system process is suppressed while a hidden temp-path binary scores CRITICAL.

| Check | Platform | How | Event type | MITRE |
|---|---|---|---|---|
| Hidden process (confidence-scored) | linux | existence anomaly (`/proc` readdir vs `/proc/<pid>/stat` vs `kill(0)` vs `ps`) → **thread-group-leader** validation (Tgid==pid; threads + kernel threads excluded) → trust (exe path / deleted / temp) → **confidence score**; severity scaled, kernel threads suppressed | `HIDDEN_PROCESS` | T1014, T1564 |
| Hidden process (confidence-scored) | windows | existence anomaly → **kernel confirmation via OpenProcess** (not a racy snapshot) + settle-and-revalidate → trust (Authenticode + known system name + `C:\Windows` path) → **confidence score**; a known system process / signed Windows binary is suppressed, an unsigned/temp/masquerading hidden process is flagged (CRITICAL) | `HIDDEN_PROCESS` | T1014, T1564 |
| Hidden listening port | linux | `/proc/net/tcp` vs `ss` | `HIDDEN_PORT` | T1014 |
| Preload hijack | linux | `/etc/ld.so.preload` entries | `PRELOAD_HIJACK` | T1574.006 |
| Hidden / known kernel module | linux | `/sys/module` live vs `/proc/modules`; known LKM names | `HIDDEN_MODULE`, `KNOWN_ROOTKIT_MODULE` | T1547.006, T1014 |
| BYOVD driver — **content hash** | windows | SHA-256 of each loaded driver vs the **LOLDrivers** set (`bad_driver_hashes`) — a renamed driver still matches | `KNOWN_MALICIOUS_DRIVER` | T1014, T1068, T1211 |
| Untrusted / abused driver | windows | catalog-aware `Get-AuthenticodeSignature`; BYOVD name list | `UNSIGNED_DRIVER`, `KNOWN_VULNERABLE_DRIVER` | T1014, T1068 |
| WMI persistence | windows | `root\subscription` Command-Line/Active-Script event consumers | `WMI_PERSISTENCE` | T1546.003 |
| Suspicious autorun | windows | Run/RunOnce with a fileless/obfuscated command (`-enc`, `DownloadString`, `mshta http…`) or a payload in a user-writable/temp path | `SUSPICIOUS_AUTORUN` | T1547.001, T1059 |
| cron / systemd persistence | linux | cron entries + unit `ExecStart` running from `/tmp`,`/dev/shm`,`/var/tmp` or a fileless one-liner (`curl\|sh`, `base64 -d`, `/dev/tcp`) | `CRON_PERSISTENCE`, `SYSTEMD_PERSISTENCE` | T1053.003, T1543.002 |
| XDG autostart (user + system) | linux | `~/.config/autostart/*.desktop` + `/etc/xdg/autostart` whose `Exec` runs from a temp path or is a fileless one-liner | `AUTOSTART_PERSISTENCE` | T1547.001 |
| `systemd --user` unit | linux | `~/.config/systemd/user/*.service` with a suspicious `ExecStart` (temp path / fileless) | `SYSTEMD_PERSISTENCE` | T1543.002 |
| Shell rc / profile init | linux | `~/.bashrc`/`.profile`/`.zshrc`/…, `/etc/profile.d/*` with a fetch-and-run, reverse shell, temp-path exec, or an `LD_PRELOAD`/`LD_AUDIT` hook from a **writable** path (tighter matcher — a `/usr/lib` shim, aliases, conditional sourcing don't trip it) | `SHELL_RC_PERSISTENCE` | T1546.004, T1574.006 |
| at(1) job | linux | `/var/spool/cron/atjobs`,`/var/spool/at` job running from a temp path or fileless | `AT_JOB_PERSISTENCE` | T1053.002 |
| Promiscuous NIC (sniffer) | linux | `/sys/class/net/*/flags` (suppressed while Suricata runs) | `PROMISC_IFACE` | T1040 |
| Fileless / deleted-binary exec | linux | `/proc/<pid>/exe` → `(deleted)` from a world-writable path | `DELETED_BINARY_RUNNING` | T1620, T1070.004 |
| SUID-root in world-writable dir | linux | scan `/tmp`,`/dev/shm`,`/var/tmp` | `SUSPICIOUS_SUID` | T1548.001 |
| Known rootkit artifact | any | curated + policy-supplied path present | `KNOWN_ROOTKIT_ARTIFACT` | T1014 |

Each sub-check is isolated (one failure can't sink the rest) and every finding is deduped for the process lifetime. This is host-level rootkit coverage that complements Wazuh's own `rootcheck`; both land in the same Wazuh alert stream.

