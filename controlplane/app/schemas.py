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


class EnrollIn(BaseModel):
    name: str
    ip: str = ""
    os: str = ""
    kernel: str = ""
    version: str = ""
    agent_id: Optional[str] = None   # re-enroll keeps the same id


class HeartbeatIn(BaseModel):
    status: str = "online"
    policy_version: int = 0
    cpu: int = 0
    mem: int = 0


class DetectionsIn(BaseModel):
    producer: str = ""
    agent_id: str = ""
    events: list[dict[str, Any]]     # v3-schema detection events (permissive)
