# Detection Coverage (log-based IDS)

> **Documentation set:** v1.5.1 · **Last updated:** 2026-08-05 · **Status:** Current (living)
> **Applies to:** Control plane v1.5.0 · Agents — Linux `0.3.17`, Windows `0.4.5-win`

The log-based IDS ships a curated, **MITRE ATT&CK-mapped detection library** (`controlplane/app/logrules_pack.py`) — currently **75 rules** across **12 tactics**, mixing behavioural detections with known-threat / CVE / tooling signatures. Rules are distributed to agents by platform and matched against decoded log lines locally; every hit is also forwarded to Wazuh (see [../deploy/wazuh/README.md](../../deploy/wazuh/README.md)).

Rules by platform: **any** 9, **linux** 34, **windows** 32. By source: `any` 19, `auditd` 4, `auth` 9, `syslog` 3, `sysmon` 10, `web` 9, `winsec` 20, `winsys` 1.

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

### TA0043 — Reconnaissance (1)

| Rule | Platform | Source | Sev | MITRE | Detects |
|---|---|---|---|---|---|
| `web_scanner_ua` | any | web | MEDIUM | T1595.002 | Known web scanner / fuzzer user-agent or tool |

## Tuning & false positives

- Rules are managed in the console under **IDS / IPS → Log-based IDS Rules** (add / toggle / delete) or via `/api/log-rules`; disabling a rule removes it from the distributed policy.
- Threshold rules (e.g. brute force) correlate N matches per entity within a window, reducing single-event noise. Tune `threshold` / `window_sec` per environment.
- The command-line rules (Linux reverse-shell/download; Windows encoded-PowerShell/LOLBin) depend on command-line logging (Linux auditd/`execve`; Windows 4688 cmdline GPO or Sysmon).
- Content lives in `controlplane/app/logrules_pack.py` — a maintained library; new rules land there and seed on restart (idempotent by name).

## Importing Sigma rules

Community **Sigma** rules can be imported and converted to log-IDS rules — via the console (*IDS / IPS → Import Sigma*, paste YAML), `POST /api/log-rules/sigma`, or the optional **24/7 beacon scraper** (`SENTINEL_SIGMA_REPO=1`, default off, pulls from SigmaHQ dirs). The converter (`controlplane/app/sigma.py`) handles the common Sigma shapes (keywords; field contains/startswith/endswith/re; simple and/or/not conditions); aggregation/correlation rules are skipped with a reason.

**False-positive gate.** Every imported rule runs a **self-check** (`verify_pattern`): it rejects over-broad patterns and anything matching a benign-log corpus. Rules that fail land **staged** (`verified=false`) and are **never distributed** until an operator reviews and promotes them (the *Verify* action / `POST /api/log-rules/{id}/verify`). Only **verified AND enabled** rules reach agents — so noisy Sigma content is triaged safely before it can fire in production.

## Host rootkit / anomaly detection (rootcheck)

Separate from the log-based IDS above, each agent runs a **rootcheck** pass (`rootcheck_scan`, default every 600 s — `SENTINEL_ROOTCHECK` / `SENTINEL_ROOTCHECK_INTERVAL`; `producer=rootcheck`, forwarded to Wazuh). Rootkit detection is **consistency/trust based, not IOC-feed based** — a rootkit betrays itself through the discrepancies it creates while hiding — so these checks run **entirely locally, with no threat feed and no internet**. A small curated known-artifacts / known-driver list supplements them and is **policy-extensible** (`rootkit_artifacts`, and on Windows `bad_drivers`, in `/api/sync/policy`). Windows drivers are additionally matched by **content hash** against the **LOLDrivers** known-vulnerable/malicious set (`bad_driver_hashes`, populated by the beacon from loldrivers.io — see OPERATIONS).

| Check | Platform | How | Event type | MITRE |
|---|---|---|---|---|
| Hidden process (multi-source cross-view) | linux | `/proc` readdir vs direct `/proc/<pid>/stat` vs `kill(0)` syscall vs `ps`, reconciled to **thread-group leaders** (Tgid==pid, so threads never false-positive) | `HIDDEN_PROCESS` | T1014, T1564 |
| Hidden process (3-way cross-view) | windows | WMI `Win32_Process` vs `Get-Process` vs native **Toolhelp32** (double-snapshot, pseudo-processes excluded) | `HIDDEN_PROCESS` | T1014, T1564 |
| Hidden listening port | linux | `/proc/net/tcp` vs `ss` | `HIDDEN_PORT` | T1014 |
| Preload hijack | linux | `/etc/ld.so.preload` entries | `PRELOAD_HIJACK` | T1574.006 |
| Hidden / known kernel module | linux | `/sys/module` live vs `/proc/modules`; known LKM names | `HIDDEN_MODULE`, `KNOWN_ROOTKIT_MODULE` | T1547.006, T1014 |
| BYOVD driver — **content hash** | windows | SHA-256 of each loaded driver vs the **LOLDrivers** set (`bad_driver_hashes`) — a renamed driver still matches | `KNOWN_MALICIOUS_DRIVER` | T1014, T1068, T1211 |
| Untrusted / abused driver | windows | catalog-aware `Get-AuthenticodeSignature`; BYOVD name list | `UNSIGNED_DRIVER`, `KNOWN_VULNERABLE_DRIVER` | T1014, T1068 |
| WMI persistence | windows | `root\subscription` Command-Line/Active-Script event consumers | `WMI_PERSISTENCE` | T1546.003 |
| Suspicious autorun | windows | Run/RunOnce with a fileless/obfuscated command (`-enc`, `DownloadString`, `mshta http…`) or a payload in a user-writable/temp path | `SUSPICIOUS_AUTORUN` | T1547.001, T1059 |
| cron / systemd persistence | linux | cron entries + unit `ExecStart` running from `/tmp`,`/dev/shm`,`/var/tmp` or a fileless one-liner (`curl\|sh`, `base64 -d`, `/dev/tcp`) | `CRON_PERSISTENCE`, `SYSTEMD_PERSISTENCE` | T1053.003, T1543.002 |
| Promiscuous NIC (sniffer) | linux | `/sys/class/net/*/flags` (suppressed while Suricata runs) | `PROMISC_IFACE` | T1040 |
| Fileless / deleted-binary exec | linux | `/proc/<pid>/exe` → `(deleted)` from a world-writable path | `DELETED_BINARY_RUNNING` | T1620, T1070.004 |
| SUID-root in world-writable dir | linux | scan `/tmp`,`/dev/shm`,`/var/tmp` | `SUSPICIOUS_SUID` | T1548.001 |
| Known rootkit artifact | any | curated + policy-supplied path present | `KNOWN_ROOTKIT_ARTIFACT` | T1014 |

Each sub-check is isolated (one failure can't sink the rest) and every finding is deduped for the process lifetime. This is host-level rootkit coverage that complements Wazuh's own `rootcheck`; both land in the same Wazuh alert stream.

