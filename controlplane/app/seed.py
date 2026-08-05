"""Seed default signatures + behavior rules (idempotent, on first boot)."""

from __future__ import annotations

from sqlalchemy import select

from . import models

DEFAULT_SIGNATURES = [
    {
        "name": "EICAR_Test_File",
        "kind": "yara",
        "severity": "HIGH",
        "mitre": ["T1204"],
        "content": (
            'rule EICAR_Test_File {\n'
            '  meta: description = "EICAR antivirus test string"\n'
            '  strings: $e = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"\n'
            '  condition: $e\n}'
        ),
    },
    {
        "name": "Linux_Reverse_Shell",
        "kind": "yara",
        "severity": "HIGH",
        "mitre": ["T1059.004"],
        "content": (
            'rule Linux_Reverse_Shell {\n'
            '  strings: $a = "/dev/tcp/" $b = "bash -i"\n'
            '  condition: all of them\n}'
        ),
    },
    {
        "name": "Linux_Webshell_PHP_Obfuscated",
        "kind": "yara",
        "severity": "HIGH",
        "mitre": ["T1505.003"],
        "content": (
            'rule Linux_Webshell_PHP_Obfuscated {\n'
            '  meta: description = "PHP web shell using base64-decoded eval"\n'
            '  strings: $a = "eval(base64_decode("\n'
            '  condition: $a\n}'
        ),
    },
    {
        "name": "Linux_Webshell_PHP_System",
        "kind": "yara",
        "severity": "HIGH",
        "mitre": ["T1505.003"],
        "content": (
            'rule Linux_Webshell_PHP_System {\n'
            '  meta: description = "PHP web shell piping request params to system()"\n'
            '  strings: $a = "system($_REQUEST"\n'
            '  condition: $a\n}'
        ),
    },
    {
        "name": "Linux_CryptoMiner_Stratum",
        "kind": "yara",
        "severity": "HIGH",
        "mitre": ["T1496"],
        "content": (
            'rule Linux_CryptoMiner_Stratum {\n'
            '  meta: description = "Cryptominer stratum pool protocol URL"\n'
            '  strings: $a = "stratum+tcp://"\n'
            '  condition: $a\n}'
        ),
    },
    {
        "name": "Linux_Python_Reverse_Shell",
        "kind": "yara",
        "severity": "CRITICAL",
        "mitre": ["T1059.006"],
        "content": (
            'rule Linux_Python_Reverse_Shell {\n'
            '  meta: description = "Python socket + subprocess reverse shell"\n'
            '  strings: $a = "socket.socket(socket.AF_INET" $b = "subprocess.call"\n'
            '  condition: all of them\n}'
        ),
    },
    {
        "name": "Linux_Perl_Reverse_Shell",
        "kind": "yara",
        "severity": "CRITICAL",
        "mitre": ["T1059.004"],
        "content": (
            'rule Linux_Perl_Reverse_Shell {\n'
            '  meta: description = "Perl IO::Socket reverse shell"\n'
            '  strings: $a = "IO::Socket::INET" $b = "STDIN->fdopen"\n'
            '  condition: all of them\n}'
        ),
    },
    {
        "name": "Linux_Netcat_Backpipe_Shell",
        "kind": "yara",
        "severity": "HIGH",
        "mitre": ["T1059.004"],
        "content": (
            'rule Linux_Netcat_Backpipe_Shell {\n'
            '  meta: description = "mkfifo/netcat backpipe reverse shell one-liner"\n'
            '  strings: $a = "mkfifo /tmp/f"\n'
            '  condition: $a\n}'
        ),
    },
    {
        "name": "Linux_LDPreload_Rootkit",
        "kind": "yara",
        "severity": "HIGH",
        "mitre": ["T1574.006"],
        "content": (
            'rule Linux_LDPreload_Rootkit {\n'
            '  meta: description = "userland rootkit persistence via ld.so.preload"\n'
            '  strings: $a = "/etc/ld.so.preload"\n'
            '  condition: $a\n}'
        ),
    },
    {
        "name": "Linux_Meterpreter_Payload",
        "kind": "yara",
        "severity": "CRITICAL",
        "mitre": ["T1059", "T1055"],
        "content": (
            'rule Linux_Meterpreter_Payload {\n'
            '  meta: description = "Metasploit meterpreter payload marker strings"\n'
            '  strings: $a = "meterpreter" $b = "stdapi_"\n'
            '  condition: all of them\n}'
        ),
    },
]

DEFAULT_BEHAVIORS = [
    {
        "name": "multiple_failed_logins",
        "description": "Several authentication failures from one source in a short window.",
        "rule": {"type": "threshold", "event": "auth_failure", "count": 5, "window_seconds": 120,
                 "group_by": "source_ip"},
        "severity": "HIGH", "mitre": ["T1110"],
    },
    {
        "name": "reverse_shell_command",
        "description": "Interactive reverse shell via /dev/tcp.",
        "rule": {"type": "regex", "field": "cmdline", "pattern": r"bash\s+-i.*/dev/tcp/"},
        "severity": "CRITICAL", "mitre": ["T1059.004"],
    },
    {
        "name": "download_and_execute_cradle",
        "description": "Download a payload and pipe straight to a shell/interpreter.",
        "rule": {"type": "regex", "field": "cmdline", "pattern": r"(curl|wget)\s+.+\|\s*((ba)?sh|python)"},
        "severity": "HIGH", "mitre": ["T1105"],
    },
    {
        "name": "shadow_copy_or_log_deletion",
        "description": "Anti-forensic deletion of logs/backups.",
        "rule": {"type": "regex", "field": "cmdline",
                 "pattern": r"(rm\s+-rf\s+/var/log|journalctl\s+--vacuum|shred\s+)"},
        "severity": "HIGH", "mitre": ["T1070"],
    },
    {
        "name": "suspicious_persistence_cron",
        "description": "Writing to cron/systemd for persistence.",
        "rule": {"type": "regex", "field": "path",
                 "pattern": r"/etc/cron|/etc/systemd/system/.*\.service|/etc/rc\.local"},
        "severity": "MEDIUM", "mitre": ["T1053", "T1543"],
    },
]


# Log-based IDS starter ruleset (v1). A general decoder+ruleset engine on the
# agent matches these regexes against decoded log lines; threshold>1 correlates
# N matches per entity within window_sec. IPv4 group is captured for correlation.
_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
DEFAULT_LOG_RULES = [
    # --- Linux: auth.log / secure ---
    {"name": "ssh_bruteforce", "platform": "linux", "source": "auth",
     "pattern": r"Failed password for (?:invalid user )?\S+ from " + _IP,
     "entity_group": 1, "threshold": 5, "window_sec": 300, "severity": "HIGH",
     "mitre": ["T1110"], "event_type": "BRUTE_FORCE_SOURCE",
     "description": "5+ failed SSH passwords from one source IP"},
    {"name": "ssh_invalid_user", "platform": "linux", "source": "auth",
     "pattern": r"Invalid user \S+ from " + _IP,
     "entity_group": 1, "threshold": 5, "window_sec": 300, "severity": "MEDIUM",
     "mitre": ["T1110"], "event_type": "SSH_INVALID_USER",
     "description": "Repeated logins for non-existent users (user enumeration)"},
    {"name": "ssh_root_login", "platform": "linux", "source": "auth",
     "pattern": r"Accepted (?:password|publickey) for root from " + _IP,
     "entity_group": 1, "threshold": 1, "severity": "MEDIUM",
     "mitre": ["T1078"], "event_type": "ROOT_LOGIN",
     "description": "Direct root SSH login"},
    {"name": "sudo_auth_failure", "platform": "linux", "source": "auth",
     "pattern": r"sudo:.*authentication failure",
     "entity_group": 0, "threshold": 3, "window_sec": 300, "severity": "MEDIUM",
     "mitre": ["T1548.003"], "event_type": "SUDO_AUTH_FAILURE",
     "description": "Repeated sudo authentication failures"},
    {"name": "user_account_created", "platform": "linux", "source": "auth",
     "pattern": r"new user: name=(\S+?)[,\s]",
     "entity_group": 1, "threshold": 1, "severity": "HIGH",
     "mitre": ["T1136.001"], "event_type": "USER_ACCOUNT_CREATED",
     "description": "A local user account was created"},
    # --- Web access logs (nginx/apache) ---
    {"name": "web_sql_injection", "platform": "any", "source": "web",
     "pattern": r"(?i)(union(?:\s|/\*.*?\*/)+select|\bor\s+1=1\b|sleep\(\d|information_schema)",
     "entity_group": 0, "threshold": 1, "severity": "HIGH",
     "mitre": ["T1190"], "event_type": "WEB_SQLI",
     "description": "SQL-injection signature in a web request"},
    {"name": "web_path_traversal", "platform": "any", "source": "web",
     "pattern": r"(?i)(\.\./\.\./|/etc/passwd|%2e%2e%2f|\.\.%5c)",
     "entity_group": 0, "threshold": 1, "severity": "HIGH",
     "mitre": ["T1083"], "event_type": "WEB_PATH_TRAVERSAL",
     "description": "Path-traversal / LFI attempt in a web request"},
    # --- Windows: Security / System event log (engine renders EventID=.. lines) ---
    {"name": "win_failed_logon", "platform": "windows", "source": "winsec",
     "pattern": r"EventID=4625\b.*Address=(\S+)",
     "entity_group": 1, "threshold": 5, "window_sec": 300, "severity": "HIGH",
     "mitre": ["T1110"], "event_type": "BRUTE_FORCE_SOURCE",
     "description": "5+ failed Windows logons (4625) from one source"},
    {"name": "win_user_created", "platform": "windows", "source": "winsec",
     "pattern": r"EventID=4720\b",
     "entity_group": 0, "threshold": 1, "severity": "HIGH",
     "mitre": ["T1136.001"], "event_type": "USER_ACCOUNT_CREATED",
     "description": "A Windows user account was created (4720)"},
    {"name": "win_log_cleared", "platform": "windows", "source": "winsec",
     "pattern": r"EventID=1102\b",
     "entity_group": 0, "threshold": 1, "severity": "HIGH",
     "mitre": ["T1070.001"], "event_type": "AUDIT_LOG_CLEARED",
     "description": "The Windows Security audit log was cleared (1102)"},
    {"name": "win_service_installed", "platform": "windows", "source": "winsys",
     "pattern": r"EventID=7045\b",
     "entity_group": 0, "threshold": 1, "severity": "MEDIUM",
     "mitre": ["T1543.003"], "event_type": "SERVICE_INSTALLED",
     "description": "A new Windows service was installed (7045)"},

    # --- second wave (v1.2.x): Linux syslog/auth + Windows 4688/4672 ---
    {"name": "reverse_shell_command", "platform": "linux", "source": "any",
     "pattern": r"(?:bash|sh)\s+-i\b.*(?:/dev/tcp/|0>&1)|nc(?:\.traditional)?\s+.*\s-e\s|mkfifo\s+\S+.*\|\s*(?:nc|/?bin/(?:ba)?sh)",
     "entity_group": 0, "threshold": 1, "severity": "CRITICAL",
     "mitre": ["T1059.004"], "event_type": "REVERSE_SHELL",
     "description": "Interactive reverse-shell one-liner seen in a log (needs execve/audit logging)"},
    {"name": "download_pipe_to_shell", "platform": "linux", "source": "any",
     "pattern": r"(?:curl|wget)\s+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",
     "entity_group": 0, "threshold": 1, "severity": "HIGH",
     "mitre": ["T1105"], "event_type": "DOWNLOAD_EXEC",
     "description": "Download-and-execute cradle (curl/wget piped to a shell)"},
    {"name": "user_added_privileged_group", "platform": "linux", "source": "auth",
     "pattern": r"add '(\S+)' to (?:shadow )?group '(?:sudo|admin|wheel|root|docker)'",
     "entity_group": 1, "threshold": 1, "severity": "HIGH",
     "mitre": ["T1098"], "event_type": "PRIVILEGED_GROUP_ADD",
     "description": "A user was added to a privileged group (sudo/wheel/admin/docker)"},
    {"name": "su_failed", "platform": "linux", "source": "auth",
     "pattern": r"su(?:\[\d+\])?:.*FAILED su for \S+ by (\S+)",
     "entity_group": 1, "threshold": 3, "window_sec": 300, "severity": "MEDIUM",
     "mitre": ["T1078"], "event_type": "SU_FAILED",
     "description": "Repeated failed su attempts by one user"},
    {"name": "password_changed", "platform": "linux", "source": "auth",
     "pattern": r"passwd\[\d+\]: password changed for (\S+)",
     "entity_group": 1, "threshold": 1, "severity": "MEDIUM",
     "mitre": ["T1098"], "event_type": "PASSWORD_CHANGED",
     "description": "An account password was changed"},
    {"name": "cron_edited", "platform": "linux", "source": "syslog",
     "pattern": r"crontab\[\d+\]: \((\S+)\) (?:REPLACE|BEGIN EDIT)",
     "entity_group": 1, "threshold": 1, "severity": "MEDIUM",
     "mitre": ["T1053.003"], "event_type": "CRON_EDITED",
     "description": "A user's crontab was edited (possible persistence)"},
    {"name": "cron_suspicious_exec", "platform": "linux", "source": "syslog",
     "pattern": r"CRON\[\d+\]:.*(?:/tmp/|/dev/shm/|curl\s|wget\s|base64\s|bash\s+-c)",
     "entity_group": 0, "threshold": 1, "severity": "HIGH",
     "mitre": ["T1053.003"], "event_type": "CRON_SUSPICIOUS_EXEC",
     "description": "A cron job ran from a temp dir or fetched/decoded a payload"},
    {"name": "win_special_privileges", "platform": "windows", "source": "winsec",
     "pattern": r"EventID=4672\b.*Subject=(?!SYSTEM|LOCAL SERVICE|NETWORK SERVICE|-)(\S+)",
     "entity_group": 1, "threshold": 1, "severity": "MEDIUM",
     "mitre": ["T1078"], "event_type": "SPECIAL_PRIVILEGES_ASSIGNED",
     "description": "Admin/special privileges assigned to a non-system logon (4672)"},
    {"name": "win_lolbin_process", "platform": "windows", "source": "winsec",
     "pattern": r"(?i)EventID=4688\b.*Process=.*\\(?:mshta|wscript|cscript|regsvr32|rundll32|certutil|bitsadmin|msbuild|installutil)\.exe",
     "entity_group": 0, "threshold": 1, "severity": "HIGH",
     "mitre": ["T1059"], "event_type": "LOLBIN_PROCESS",
     "description": "A living-off-the-land binary was launched (4688)"},
    {"name": "win_encoded_powershell", "platform": "windows", "source": "winsec",
     "pattern": r"(?i)EventID=4688\b.*Cmd=.*(?:-enc\b|-EncodedCommand|FromBase64String|IEX\b|Invoke-Expression|-nop\b.*-w\s*hidden)",
     "entity_group": 0, "threshold": 1, "severity": "CRITICAL",
     "mitre": ["T1059.001"], "event_type": "ENCODED_POWERSHELL",
     "description": "Encoded/obfuscated PowerShell in a process command line (4688; needs cmdline auditing)"},
    {"name": "win_lolbin_download", "platform": "windows", "source": "winsec",
     "pattern": r"(?i)EventID=4688\b.*Cmd=.*(?:certutil.*-urlcache|bitsadmin.*/transfer|Invoke-WebRequest|curl\s+.*http|wget\s+.*http)",
     "entity_group": 0, "threshold": 1, "severity": "HIGH",
     "mitre": ["T1105"], "event_type": "LOLBIN_DOWNLOAD",
     "description": "A LOLBin was used to download a payload (4688; needs cmdline auditing)"},
]


def seed(db) -> dict:
    """Idempotent per-name: inserts any default signature/behavior that is
    missing, so redeploying with new built-in rules picks them up on restart."""
    added = {"signatures": 0, "behaviors": 0, "log_rules": 0}
    have_sigs = set(db.execute(select(models.Signature.name)).scalars().all())
    for s in DEFAULT_SIGNATURES:
        if s["name"] not in have_sigs:
            db.add(models.Signature(**s))
            added["signatures"] += 1
    have_beh = set(db.execute(select(models.Behavior.name)).scalars().all())
    for b in DEFAULT_BEHAVIORS:
        if b["name"] not in have_beh:
            db.add(models.Behavior(**b))
            added["behaviors"] += 1
    have_lr = set(db.execute(select(models.LogRule.name)).scalars().all())
    for r in DEFAULT_LOG_RULES:
        if r["name"] not in have_lr:
            db.add(models.LogRule(**r))
            added["log_rules"] += 1
    db.commit()
    # load the large expert rule packs (YARA signatures + behavior patterns)
    try:
        from . import rulepacks
        packs = rulepacks.load_all(db)
        added["signatures"] += packs.get("yara", 0)
        added["behaviors"] += packs.get("behaviors", 0)
    except Exception:
        pass
    return added
