"""Core data models: normalized Event, Indicator (IOC), and GeneratedRule."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Event:
    """A single Wazuh alert normalized to the fields the detectors care about."""

    timestamp: Optional[datetime]
    raw_timestamp: str = ""
    rule_id: Optional[str] = None
    level: int = 0
    description: str = ""
    groups: list[str] = field(default_factory=list)

    # network / identity
    srcip: Optional[str] = None          # port-stripped source IP
    srcport: Optional[str] = None
    dstuser: Optional[str] = None
    srcuser: Optional[str] = None

    # provenance
    program: Optional[str] = None        # decoder name / program_name
    agent_name: Optional[str] = None
    agent_id: Optional[str] = None
    location: Optional[str] = None

    # artifacts
    file_path: Optional[str] = None
    file_hash: Optional[str] = None      # sha256 preferred, else md5
    hash_type: Optional[str] = None
    command: Optional[str] = None        # command line (win eventdata / auditd)

    full_log: str = ""
    mitre: list[str] = field(default_factory=list)
    source_file: str = ""

    def is_auth_failure(self) -> bool:
        g = set(self.groups)
        if g & {"authentication_failures", "authentication_failed", "invalid_login",
                "win_authentication_failed"}:
            return True
        d = (self.description or "").lower()
        return any(k in d for k in (
            "authentication failure", "failed password", "invalid user",
            "login failed", "failed login", "authentication failed",
            "user login failed", "brute force",
        ))


@dataclass
class Indicator:
    """An aggregated observation about one IOC (an IP, hash, path, command...).

    Detectors emit these already aggregated over their rolling window; the rule
    generator then merges indicators that share the same (match_field, value)
    so a single IOC yields exactly one rule even if several detectors flag it.
    """

    itype: str                     # bruteforce | malicious_ip | malicious_artifact
    subtype: str                   # auth | scan_flood | threat_feed | high_severity |
                                   # file_hash | registry | suspicious_path | command
    value: str                     # the IOC value that will be matched in the rule
    match_field: str = "srcip"     # Wazuh rule field to match on (srcip, sha256_after, ...)
    reason: str = ""
    level: int = 10                # suggested Wazuh rule level
    count: int = 1

    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    users: set[str] = field(default_factory=set)
    sample_rule_ids: set[str] = field(default_factory=set)
    sample_logs: list[str] = field(default_factory=list)
    groups: set[str] = field(default_factory=set)
    mitre: set[str] = field(default_factory=set)
    agents: set[str] = field(default_factory=set)
    confidence: str = "medium"     # low | medium | high (human label)
    score: int = 60                # numeric confidence 0-100 (drives safe-response gating)
    source: str = ""               # threat-intel source that vouched for this IOC (if any)

    def key(self) -> tuple[str, str]:
        """Merge key: rules are one-per (field, value)."""
        return (self.match_field, self.value)

    def add_sample_log(self, log: str, limit: int = 3) -> None:
        log = (log or "").strip()
        if log and log not in self.sample_logs and len(self.sample_logs) < limit:
            self.sample_logs.append(log)

    def merge(self, other: "Indicator") -> None:
        """Fold another indicator for the same IOC into this one."""
        self.count += other.count
        self.level = max(self.level, other.level)
        self.reason = "; ".join(dict.fromkeys(
            p for p in (self.reason, other.reason) if p))
        if other.first_seen and (not self.first_seen or other.first_seen < self.first_seen):
            self.first_seen = other.first_seen
        if other.last_seen and (not self.last_seen or other.last_seen > self.last_seen):
            self.last_seen = other.last_seen
        self.users |= other.users
        self.sample_rule_ids |= other.sample_rule_ids
        self.groups |= other.groups
        self.mitre |= other.mitre
        self.agents |= other.agents
        for log in other.sample_logs:
            self.add_sample_log(log)
        # subtype becomes a "+"-joined set of contributing detectors' subtypes
        subs = dict.fromkeys(self.subtype.split("+") + other.subtype.split("+"))
        self.subtype = "+".join(s for s in subs if s)
        rank = {"low": 0, "medium": 1, "high": 2}
        if rank.get(other.confidence, 1) > rank.get(self.confidence, 1):
            self.confidence = other.confidence
        if other.score > self.score:      # keep the strongest evidence's score + source
            self.score = other.score
            self.source = other.source or self.source
        elif not self.source:
            self.source = other.source


@dataclass
class GeneratedRule:
    """A rendered Wazuh ``<rule>`` block ready to be written to disk."""

    rule_id: int
    level: int
    xml: str
    ioc_type: str
    ioc_value: str
    description: str
    match_field: str = "srcip"
