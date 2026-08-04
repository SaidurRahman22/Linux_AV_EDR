"""ORM tables: IOCs, signatures, behaviors, agents, detections, generated rules."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Ioc(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("type", "value", name="uq_ioc_type_value"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(16), index=True)      # ip | hash | domain | url
    value: Mapped[str] = mapped_column(String(512), index=True)
    source: Mapped[str] = mapped_column(String(64), default="")
    malware: Mapped[str] = mapped_column(String(128), default="")
    confidence: Mapped[int] = mapped_column(Integer, default=60)   # 0-100
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    vt_checked: Mapped[bool] = mapped_column(Boolean, default=False)   # VirusTotal enrichment
    vt_malicious: Mapped[int] = mapped_column(Integer, default=0)      # engines flagging it
    vt_ratio: Mapped[str] = mapped_column(String(16), default="")      # e.g. "45/70"


class Signature(Base):
    __tablename__ = "signatures"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    kind: Mapped[str] = mapped_column(String(16), default="yara")  # yara | regex
    content: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default="HIGH")
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(64), default="builtin")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class Behavior(Base):
    __tablename__ = "behaviors"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    rule: Mapped[dict] = mapped_column(JSON, default=dict)         # engine-specific matcher
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # uuid
    name: Mapped[str] = mapped_column(String(128), index=True)
    ip: Mapped[str] = mapped_column(String(64), default="")
    os: Mapped[str] = mapped_column(String(128), default="")
    kernel: Mapped[str] = mapped_column(String(128), default="")
    version: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(16), default="online")
    policy_version: Mapped[int] = mapped_column(Integer, default=0)
    cpu: Mapped[int] = mapped_column(Integer, default=0)          # % busy
    mem: Mapped[int] = mapped_column(Integer, default=0)          # % used
    spark: Mapped[list] = mapped_column(JSON, default=list)       # recent cpu history
    isolated: Mapped[bool] = mapped_column(Boolean, default=False)  # network quarantine on/off
    update_requested: Mapped[bool] = mapped_column(Boolean, default=False)  # push-to-update flag
    enrolled_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class Detection(Base):
    __tablename__ = "detections"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    agent_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    device_name: Mapped[str] = mapped_column(String(128), default="")
    event_type: Mapped[str] = mapped_column(String(48), default="")
    ioc_value: Mapped[str] = mapped_column(String(512), default="", index=True)
    ioc_type: Mapped[str] = mapped_column(String(32), default="")
    severity: Mapped[str] = mapped_column(String(16), default="")
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    mode: Mapped[str] = mapped_column(String(16), default="DETECT")
    action_taken: Mapped[str] = mapped_column(String(24), default="DETECTED")
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    producer: Mapped[str] = mapped_column(String(48), default="")
    event: Mapped[dict] = mapped_column(JSON, default=dict)        # full v3 event


class BlockedIp(Base):
    __tablename__ = "blocked_ips"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[str] = mapped_column(String(256), default="")
    source: Mapped[str] = mapped_column(String(24), default="manual")   # manual | auto
    scope: Mapped[str] = mapped_column(String(16), default="global")    # global | agent
    agent_id: Mapped[str] = mapped_column(String(64), default="")       # target when scope=agent
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class GeneratedRule(Base):
    __tablename__ = "generated_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(Integer, index=True)
    level: Mapped[int] = mapped_column(Integer, default=0)
    ioc: Mapped[str] = mapped_column(String(512), default="")
    xml: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
