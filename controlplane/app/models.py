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


class DeviceGroup(Base):
    """A device group — a simple organizational label for the fleet (by department,
    site, role, …). Purely for organising devices in the console; a device belongs to
    at most one group (Agent.group_id). Not a security boundary."""
    __tablename__ = "device_groups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(96), unique=True, index=True)
    note: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # uuid
    name: Mapped[str] = mapped_column(String(128), index=True)
    group_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)  # DeviceGroup.id or NULL
    ip: Mapped[str] = mapped_column(String(64), default="")
    os: Mapped[str] = mapped_column(String(128), default="")
    kernel: Mapped[str] = mapped_column(String(128), default="")
    version: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(16), default="online")
    policy_version: Mapped[int] = mapped_column(Integer, default=0)
    cpu: Mapped[int] = mapped_column(Integer, default=0)          # % busy
    mem: Mapped[int] = mapped_column(Integer, default=0)          # % used (RAM)
    disk: Mapped[int] = mapped_column(Integer, default=0)         # % used (all fixed drives)
    disk_total: Mapped[int] = mapped_column(Integer, default=0)   # total capacity, GB (all drives)
    disk_free: Mapped[int] = mapped_column(Integer, default=0)    # free space, GB (all drives)
    disk_drives: Mapped[list] = mapped_column(JSON, default=list) # per-drive [{drive,total_gb,free_gb}]
    spark: Mapped[list] = mapped_column(JSON, default=list)       # recent cpu history
    isolated: Mapped[bool] = mapped_column(Boolean, default=False)  # network quarantine on/off
    update_requested: Mapped[bool] = mapped_column(Boolean, default=False)  # push-to-update flag
    nids_mode: Mapped[str] = mapped_column(String(8), default="off")   # off | ids | ips (Suricata)
    nids_status: Mapped[dict] = mapped_column(JSON, default=dict)      # agent-reported engine status
    win_telemetry: Mapped[dict] = mapped_column(JSON, default=dict)    # Windows Sysmon/ETW/Firewall status (agent-reported)
    # SEN-007: per-agent secret (sha256 hex of the token issued at enrollment).
    # Empty = legacy agent not yet migrated; once set, enroll-update + heartbeat
    # + policy-sync must present the matching token (trust-on-first-use bootstrap).
    agent_secret: Mapped[str] = mapped_column(String(64), default="")
    ports: Mapped[list] = mapped_column(JSON, default=list)        # last observed listening sockets
    ports_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # when ports last reported
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
    # Analyst-in-a-box calibration (see calibrate.py). Set automatically at ingest;
    # verdict is the triage call, calibrated_severity the re-tiered level, and
    # calibration the full rationale {score, delta, confidence, reasons[...]}.
    verdict: Mapped[str] = mapped_column(String(24), default="", index=True)
    calibrated_severity: Mapped[str] = mapped_column(String(16), default="")
    calibration: Mapped[dict] = mapped_column(JSON, default=dict)


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


class BlockedProcess(Base):
    """A process the operator (or, later, an automatic response rule) has blocked.

    Mirrors BlockedIp: the agent pulls the active set on its heartbeat and TERMINATES
    any running process whose name / image path / SHA-256 matches (`match`), then keeps
    killing it while the block is active. `source` records who created it (manual now;
    'auto' once automatic blocking is enabled). Releasing sets active=False, so the agent
    stops killing it on the next heartbeat (~60s). A small protected-process guard on both
    the API and the agent prevents blocking OS-critical processes / the agent itself.
    """
    __tablename__ = "blocked_processes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[str] = mapped_column(String(512), index=True)        # name / path / sha256 (per `match`)
    match: Mapped[str] = mapped_column(String(8), default="name")      # name | path | hash
    reason: Mapped[str] = mapped_column(String(256), default="")
    source: Mapped[str] = mapped_column(String(24), default="manual")  # manual | auto
    scope: Mapped[str] = mapped_column(String(16), default="global")   # global | agent
    agent_id: Mapped[str] = mapped_column(String(64), default="")      # target when scope=agent
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class ClosedPort(Base):
    """A host firewall port the operator has closed on a specific endpoint.

    Mirrors BlockedIp: the agent pulls the active set and drops inbound traffic
    to those ports via nftables (Linux) / Windows Firewall (Windows). Opening a
    port simply deactivates its row, so the agent stops dropping it on the next
    heartbeat (~60s).
    """
    __tablename__ = "closed_ports"
    __table_args__ = (UniqueConstraint("agent_id", "proto", "port", name="uq_closed_port"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    port: Mapped[int] = mapped_column(Integer)
    proto: Mapped[str] = mapped_column(String(8), default="tcp")     # tcp | udp
    reason: Mapped[str] = mapped_column(String(256), default="")
    source: Mapped[str] = mapped_column(String(24), default="manual")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class SuricataRule(Base):
    """A Suricata IDS/IPS rule scraped from a community/open source (or custom).

    The beacon fills this from open rule feeds; the control plane distributes the
    enabled rules (+ operator custom rules) to agents, which load them into the
    Suricata engine. Shown in the console under Threat Intel → Suricata Rules.
    """
    __tablename__ = "suricata_rules"
    __table_args__ = (UniqueConstraint("key", name="uq_suricata_key"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(96), index=True)   # dedupe: "<source>:<sid>"
    sid: Mapped[str] = mapped_column(String(24), default="", index=True)
    action: Mapped[str] = mapped_column(String(12), default="alert")   # alert|drop|reject|pass
    proto: Mapped[str] = mapped_column(String(12), default="")
    msg: Mapped[str] = mapped_column(String(400), default="")
    category: Mapped[str] = mapped_column(String(64), default="")      # classtype
    source: Mapped[str] = mapped_column(String(64), default="", index=True)
    raw: Mapped[str] = mapped_column(Text, default="")
    # Default DISABLED (SEN-014): scraped community rules require operator review
    # before they are distributed to (root) Suricata engines.
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class AppSetting(Base):
    """Small key/value store (e.g. operator custom Suricata rules)."""
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class AllowlistEntry(Base):
    """Operator allow-list: an IP/CIDR or a trusted binary (path + optional
    sha256) that must never be blocked or quarantined. Allow-listed IPs are
    subtracted from the blocklist the control plane distributes to agents (so an
    allow-listed IP is never enforced), and the full list is shown in the console."""
    __tablename__ = "allowlist"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(8), index=True, default="ip")   # ip | binary
    value: Mapped[str] = mapped_column(String(512), default="")   # CIDR/IP or binary path
    sha256: Mapped[str] = mapped_column(String(64), default="")   # binary only
    scope: Mapped[str] = mapped_column(String(32), default="GLOBAL")
    note: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class LogRule(Base):
    """A log-based IDS rule: a regex applied to decoded log lines from a given
    source, optionally correlated over a threshold/window (brute-force style).
    Distributed to agents, which decode their local logs and match locally —
    a general decoder+ruleset engine, not the old single hard-coded SSH rule."""
    __tablename__ = "log_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(96), unique=True)
    platform: Mapped[str] = mapped_column(String(8), default="any")    # linux | windows | any
    source: Mapped[str] = mapped_column(String(16), default="any")     # auth|syslog|journal|web|winsec|winsys|any
    pattern: Mapped[str] = mapped_column(String(512))                  # regex over a decoded log line
    entity_group: Mapped[int] = mapped_column(Integer, default=0)      # capture group to key correlation on (0 = none)
    threshold: Mapped[int] = mapped_column(Integer, default=1)         # >1 = alert only after N matches in window
    window_sec: Mapped[int] = mapped_column(Integer, default=300)
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    event_type: Mapped[str] = mapped_column(String(48), default="LOG_MATCH")
    description: Mapped[str] = mapped_column(String(256), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Provenance + verification: builtin/manual rules are trusted; sigma-imported
    # and unverified rules are NOT distributed until verified (FP self-check).
    origin: Mapped[str] = mapped_column(String(16), default="builtin")   # builtin | manual | sigma
    verified: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class ScanTask(Base):
    """A scheduled Detection Funnel Scanner task (optional/experimental feature)."""
    __tablename__ = "scan_tasks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(96), default="scan")
    targets: Mapped[list] = mapped_column(JSON, default=list)       # ["log_rule","signature",...]
    interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_run: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class ScanRun(Base):
    """The result summary of one funnel-scan (manual or scheduled)."""
    __tablename__ = "scan_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int | None] = mapped_column(Integer, nullable=True)   # None = manual run
    ran_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    total: Mapped[int] = mapped_column(Integer, default=0)
    passed: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    golden: Mapped[int] = mapped_column(Integer, default=0)
    report: Mapped[dict] = mapped_column(JSON, default=dict)        # trimmed report (golden+failed lists)


class GeneratedRule(Base):
    __tablename__ = "generated_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(Integer, index=True)
    level: Mapped[int] = mapped_column(Integer, default=0)
    ioc: Mapped[str] = mapped_column(String(512), default="")
    xml: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class ThreatHuntRun(Base):
    """One run of the automated threat hunter (scheduled 12h, or manual/CLI)."""
    __tablename__ = "threat_hunt_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ran_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    source: Mapped[str] = mapped_column(String(16), default="manual")   # manual | scheduled | cli | api
    days: Mapped[int] = mapped_column(Integer, default=30)              # lookback window
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    alerts_scanned: Mapped[int] = mapped_column(Integer, default=0)
    ips_evaluated: Mapped[int] = mapped_column(Integer, default=0)
    blocked: Mapped[int] = mapped_column(Integer, default=0)
    bangladesh_tagged: Mapped[int] = mapped_column(Integer, default=0)
    skipped: Mapped[int] = mapped_column(Integer, default=0)
    rules_created: Mapped[int] = mapped_column(Integer, default=0)
    duration_s: Mapped[float] = mapped_column(Float, default=0.0)
    report: Mapped[dict] = mapped_column(JSON, default=dict)            # {decisions:[...], rules:[...]}


class ThreatIntelCache(Base):
    """Cached external-reputation lookups (AbuseIPDB) so a repeated hunt doesn't re-query."""
    __tablename__ = "threat_intel_cache"
    ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    country: Mapped[str | None] = mapped_column(String(4), nullable=True)
    reports: Mapped[int | None] = mapped_column(Integer, nullable=True)
    isp: Mapped[str] = mapped_column(String(64), default="")
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
