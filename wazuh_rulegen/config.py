"""Configuration: dataclasses with Linux-Wazuh defaults, JSON overrides, path resolution."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Any


# On the Wazuh manager these are the canonical locations. They are overridable so
# the tool also runs against an exported copy of the logs (e.g. ./logs/...).
DEFAULT_ALERTS_JSON = "/var/ossec/logs/alerts/alerts.json"
DEFAULT_ALERTS_LOG = "/var/ossec/logs/alerts/alerts.log"


@dataclass
class BruteForceConfig:
    enabled: bool = True
    # classic auth brute force: N auth failures from one source within the window
    min_auth_failures: int = 6
    # scan/flood brute force: N attack/web/recon alerts from one source within the window
    min_flood_events: int = 50
    timeframe_seconds: int = 300
    per_user_spray_users: int = 5   # distinct users -> password-spray flag
    level: int = 12


@dataclass
class MaliciousIPConfig:
    enabled: bool = True
    high_severity_level: int = 10       # an IP seen in an alert >= this level is suspect
    volume_threshold: int = 100         # total attack-ish alerts from one IP overall
    suspicious_groups: list[str] = field(default_factory=lambda: [
        "attack", "exploit", "web_scan", "recon", "sql_injection",
        "shellshock", "web_attack", "ids", "intrusion_detection",
    ])
    level: int = 12


@dataclass
class MaliciousArtifactConfig:
    enabled: bool = True
    level: int = 12
    # High-confidence IOC rules (hash-feed matches, command signatures) are always on.
    # Registry-persistence and suspicious-path detection are behavioral and noisy
    # (they overlap Wazuh's built-in FIM rules), so they are OPT-IN.
    detect_registry_persistence: bool = False
    detect_suspicious_paths: bool = False
    # file paths matching these (case-insensitive substrings) are suspicious drop sites
    suspicious_path_hints: list[str] = field(default_factory=lambda: [
        "\\temp\\", "\\appdata\\", "\\programdata\\", "\\public\\",
        "/tmp/", "/dev/shm/", "\\startup\\", "\\downloads\\",
    ])
    # command-line signatures (regex, case-insensitive) -> (label, mitre)
    command_signatures: list[dict] = field(default_factory=lambda: [
        {"pattern": r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", "label": "PowerShell encoded command", "mitre": "T1059.001"},
        {"pattern": r"frombase64string", "label": "PowerShell base64 decode", "mitre": "T1027"},
        {"pattern": r"(iex|invoke-expression)\b", "label": "PowerShell Invoke-Expression", "mitre": "T1059.001"},
        {"pattern": r"invoke-(mimikatz|webrequest|shellcode)", "label": "Offensive PowerShell cmdlet", "mitre": "T1059.001"},
        {"pattern": r"downloadstring|downloadfile|net\.webclient", "label": "In-memory download cradle", "mitre": "T1105"},
        {"pattern": r"certutil(\.exe)?\s+.*(urlcache|-decode|-encode)", "label": "certutil abuse", "mitre": "T1105"},
        {"pattern": r"bitsadmin(\.exe)?\s+/transfer", "label": "bitsadmin transfer", "mitre": "T1197"},
        {"pattern": r"\bmimikatz\b|sekurlsa|lsadump", "label": "Mimikatz credential dumping", "mitre": "T1003"},
        {"pattern": r"nc(\.exe)?\s+.*-e\s|/bin/(ba)?sh\s+-i|bash\s+-i\s+>&", "label": "Reverse shell", "mitre": "T1059"},
        {"pattern": r"whoami\s*/priv|reg\s+save\s+hklm\\sam", "label": "Credential/priv enumeration", "mitre": "T1003"},
        {"pattern": r"vssadmin.*delete\s+shadows|wbadmin\s+delete", "label": "Shadow-copy deletion", "mitre": "T1490"},
    ])
    # flag registry FIM changes to autorun / persistence locations (used only when
    # detect_registry_persistence is enabled). Deliberately narrow: the full
    # Services hive churns constantly and would drown the ruleset in noise.
    suspicious_registry_hints: list[str] = field(default_factory=lambda: [
        r"\\currentversion\\run\b", r"\\currentversion\\runonce\b",
        r"\\winlogon\\(shell|userinit)", r"\\image file execution options\\",
        r"\\currentversion\\explorer\\shell folders",
    ])


@dataclass
class DetectorsConfig:
    bruteforce: BruteForceConfig = field(default_factory=BruteForceConfig)
    malicious_ip: MaliciousIPConfig = field(default_factory=MaliciousIPConfig)
    malicious_artifact: MaliciousArtifactConfig = field(default_factory=MaliciousArtifactConfig)


@dataclass
class Config:
    # ---- inputs ----
    alerts_file: str = DEFAULT_ALERTS_JSON
    alerts_log_fallback: str = DEFAULT_ALERTS_LOG
    ip_feeds: list[str] = field(default_factory=list)      # files of malicious IPs / CIDRs
    hash_feeds: list[str] = field(default_factory=list)    # files of malicious hashes
    feed_sources: list = field(default_factory=list)       # override update-feeds URLs (empty=defaults)
    # never generate rules matching these (RFC1918 etc. + your own ranges)
    ip_allowlist: list[str] = field(default_factory=lambda: [
        "127.0.0.0/8", "::1/128",
    ])
    # events whose full_log matches ANY of these regexes are ignored entirely
    # (case-insensitive). Use to drop known-benign traffic, e.g. your own app's
    # user-agent, health checks, monitoring probes.  Example: ["Dart/\\d"].
    exclude_log_patterns: list[str] = field(default_factory=list)

    # ---- outputs ----
    output_dir: str = "output"
    rules_filename: str = "wazuh_rulegen_generated_rules.xml"
    cdb_ip_list: str = "generated_malicious_ip.list"
    cdb_hash_list: str = "generated_malicious_hash.list"
    report_filename: str = "wazuh_rulegen_report.json"
    id_base: int = 100000            # Wazuh custom rules must be >= 100000
    id_max: int = 120000
    write_cdb_lists: bool = True

    # ---- daemon ----
    state_file: str = "output/.wazuh_rulegen_state.json"
    poll_interval: float = 2.0       # seconds between reads while tailing
    window_seconds: int = 3600       # rolling window kept in memory for correlation
    flush_interval: float = 15.0     # seconds between rule-file rewrites in daemon mode

    detectors: DetectorsConfig = field(default_factory=DetectorsConfig)

    # ---- resolution helpers ----
    base_dir: str = "."              # everything relative resolves against this

    def resolve(self, path: str) -> str:
        path = os.path.expanduser(path)
        if os.path.isabs(path):
            return path
        return os.path.normpath(os.path.join(self.base_dir, path))

    @property
    def rules_path(self) -> str:
        return os.path.join(self.resolve(self.output_dir), self.rules_filename)

    @property
    def report_path(self) -> str:
        return os.path.join(self.resolve(self.output_dir), self.report_filename)

    @property
    def cdb_ip_path(self) -> str:
        return os.path.join(self.resolve(self.output_dir), self.cdb_ip_list)

    @property
    def cdb_hash_path(self) -> str:
        return os.path.join(self.resolve(self.output_dir), self.cdb_hash_list)

    # ---- (de)serialization ----
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Config":
        d = dict(d or {})
        det = d.pop("detectors", None)
        cfg = cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
        if det:
            cfg.detectors = DetectorsConfig(
                bruteforce=BruteForceConfig(**{**asdict(BruteForceConfig()), **det.get("bruteforce", {})}),
                malicious_ip=MaliciousIPConfig(**{**asdict(MaliciousIPConfig()), **det.get("malicious_ip", {})}),
                malicious_artifact=MaliciousArtifactConfig(
                    **{**asdict(MaliciousArtifactConfig()), **det.get("malicious_artifact", {})}),
            )
        return cfg

    @classmethod
    def load(cls, path: str | None) -> "Config":
        if not path:
            return cls()
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        cfg = cls.from_dict(data)
        # config-relative paths resolve against the config file's directory
        cfg.base_dir = os.path.dirname(os.path.abspath(path)) or "."
        return cfg

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
