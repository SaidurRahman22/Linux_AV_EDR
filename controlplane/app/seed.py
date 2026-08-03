"""Seed default signatures + behavior rules (idempotent, on first boot)."""

from __future__ import annotations

from sqlalchemy import func, select

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
    added = {"signatures": 0, "behaviors": 0}
    if db.scalar(select(func.count()).select_from(models.Signature)) == 0:
        for s in DEFAULT_SIGNATURES:
            db.add(models.Signature(**s))
            added["signatures"] += 1
    if db.scalar(select(func.count()).select_from(models.Behavior)) == 0:
        for b in DEFAULT_BEHAVIORS:
            db.add(models.Behavior(**b))
            added["behaviors"] += 1
    db.commit()
    return added
