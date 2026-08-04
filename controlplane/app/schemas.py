"""Pydantic request/response models for the control-plane API."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class IocIn(BaseModel):
    type: str                       # ip | hash | domain | url
    value: str
    source: str = ""
    malware: str = ""
    confidence: int = 60
    ttl_days: Optional[int] = None


class IocBulkIn(BaseModel):
    iocs: list[IocIn]


class SignatureIn(BaseModel):
    name: str
    kind: str = "yara"
    content: str
    severity: str = "HIGH"
    mitre: list[str] = Field(default_factory=list)
    source: str = "manual"


class BehaviorIn(BaseModel):
    name: str
    description: str = ""
    rule: dict[str, Any] = Field(default_factory=dict)
    severity: str = "MEDIUM"
    mitre: list[str] = Field(default_factory=list)


class BlockIn(BaseModel):
    ip: str
    reason: str = ""
    scope: str = "global"           # global | agent
    agent_id: str = ""              # target agent when scope == "agent"


class EnrollIn(BaseModel):
    name: str
    ip: str = ""
    os: str = ""
    kernel: str = ""
    version: str = ""
    agent_id: Optional[str] = None   # re-enroll keeps the same id
    proto: int = 1                   # 1 = legacy; >=2 = supports the per-agent secret (SEN-007)


class HeartbeatIn(BaseModel):
    status: str = "online"
    policy_version: int = 0
    cpu: int = 0
    mem: int = 0
    disk: int = 0                    # % used across all fixed drives
    disk_total: int = 0              # total capacity, GB (all fixed drives)
    disk_free: int = 0               # free space, GB (all fixed drives)
    disk_drives: Optional[list[dict[str, Any]]] = None   # per-drive breakdown
    version: str = ""                # agent build version (lets the server confirm updates)
    ports: Optional[list[dict[str, Any]]] = None   # observed listening sockets (None = unchanged)
    nids_status: Optional[dict[str, Any]] = None   # Suricata engine status (None = unchanged)


class PortActionIn(BaseModel):
    port: int                        # 1-65535
    proto: str = "tcp"               # tcp | udp
    reason: str = ""


class NidsIn(BaseModel):
    mode: str                        # off | ids | ips


class CustomRulesIn(BaseModel):
    rules: str = ""                  # operator Suricata rules (raw .rules text)
    allow_drop: bool = False         # keep drop/reject actions (deliberate IPS use); else forced to alert (SEN-005)


class DetectionsIn(BaseModel):
    producer: str = ""
    agent_id: str = ""
    events: list[dict[str, Any]]     # v3-schema detection events (permissive)


class RenameIn(BaseModel):
    name: str


class LogRuleIn(BaseModel):
    name: str
    platform: str = "any"            # linux | windows | any
    source: str = "any"              # auth|syslog|journal|web|winsec|winsys|any
    pattern: str                     # regex over a decoded log line
    entity_group: int = 0            # capture group to key correlation on (0 = none)
    threshold: int = 1               # >1 = alert after N matches in window
    window_sec: int = 300
    severity: str = "MEDIUM"
    mitre: list[str] = Field(default_factory=list)
    event_type: str = "LOG_MATCH"
    description: str = ""
    enabled: bool = True


class LogRuleToggleIn(BaseModel):
    enabled: bool = True


class AllowlistIn(BaseModel):
    kind: str = "ip"                 # ip | binary
    value: str = ""                  # IP/CIDR (kind=ip) or binary path (kind=binary)
    sha256: str = ""                 # optional; binary only
    scope: str = "GLOBAL"
    note: str = ""
