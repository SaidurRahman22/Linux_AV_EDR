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


def seed(db) -> dict:
    """Idempotent per-name: inserts any default signature/behavior that is
    missing, so redeploying with new built-in rules picks them up on restart."""
    added = {"signatures": 0, "behaviors": 0}
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
    db.commit()
    return added
