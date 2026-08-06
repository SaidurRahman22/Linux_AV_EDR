"""Padakhep Sentinel control-plane API (FastAPI).

The hub the beacon writes to, the dashboard reads from, and (later increments)
the AV agents pull IOCs/policy from and report detections to.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from . import crud, models, scanner, schemas, sigma
from .config import settings
from .db import get_db, init_db
from .seed import seed

app = FastAPI(title="Padakhep Sentinel — Control Plane", version="0.1.0")
# CORS: only the explicitly-configured origins (none by default). The dashboard is
# served same-origin from this app, so it needs no cross-origin grant (SEN-018).
_cors = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=_cors, allow_credentials=False,
                   allow_methods=["*"], allow_headers=["*"])


def _bearer_in(authorization: str | None, tokens) -> bool:
    """Constant-time check that the bearer matches ANY of the given tokens (SEN-019)."""
    auth = authorization or ""
    return any(t and hmac.compare_digest(auth, f"Bearer {t}") for t in tokens)


def _token_ok(authorization: str | None) -> bool:
    return _bearer_in(authorization, [settings.API_TOKEN])


# Endpoints an AGENT legitimately calls — accept the (lower-privilege) agent token
# OR the operator token. Everything else under /api/* is operator-only, so a leaked
# agent token cannot isolate hosts, push updates, block IPs, etc. (SEN-001 RBAC-lite).
def _is_agent_path(path: str) -> bool:
    return (path == "/api/enroll" or path.endswith("/heartbeat")
            or path == "/api/detections" or path == "/api/sync/policy"
            or path == "/api/nids/ruleset" or path == "/api/agent/manifest"
            or path.startswith("/api/agent/download/"))


# Uniform gate: every /api/* route (GET and POST) requires a valid token when one is
# configured — so no route can be forgotten (SEN-001/SEN-008). Also stamps security
# headers (SEN-003) on every response. Backward-compatible: if API_TOKEN is unset the
# API stays open (dev), but startup warns / can fail closed.
_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'")


@app.middleware("http")
async def _security_middleware(request: Request, call_next):
    op = settings.API_TOKEN
    if op and request.url.path.startswith("/api/"):
        agent = settings.AGENT_TOKEN or op
        allowed = [op, agent] if _is_agent_path(request.url.path) else [op]
        if not _bearer_in(request.headers.get("authorization"), allowed):
            return JSONResponse({"detail": "invalid or missing token"}, status_code=401)
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = _CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


def require_token(authorization: str | None = Header(default=None)) -> None:
    """Per-route gate (kept for defence-in-depth; the middleware is the real gate)."""
    if not settings.API_TOKEN:
        return
    if not _token_ok(authorization):
        raise HTTPException(status_code=401, detail="invalid or missing token")


@app.on_event("startup")
def _startup() -> None:
    if settings.REQUIRE_AUTH and not settings.API_TOKEN:
        raise RuntimeError("SENTINEL_REQUIRE_AUTH=1 but SENTINEL_API_TOKEN is empty — "
                           "refusing to start (fail-closed).")
    if not settings.API_TOKEN:
        print("WARNING: control plane is running WITHOUT authentication "
              "(SENTINEL_API_TOKEN empty). Set a token before any non-lab use.", flush=True)
    if _WAZUH_FORWARD:                       # ensure the Wazuh-readable log dir exists
        try:
            os.makedirs(os.path.dirname(_WAZUH_LOG), exist_ok=True)
        except OSError:
            pass
    init_db()
    from .db import SessionLocal
    db = SessionLocal()
    try:
        seed(db)
    finally:
        db.close()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _clean(s, maxlen: int = 120) -> str:
    """Strip control chars + angle brackets and cap length (defence-in-depth for
    agent-reported strings rendered in the console)."""
    return re.sub(r"[\x00-\x1f\x7f<>]", "", str(s or ""))[:maxlen]


def _hash_secret(s: str) -> str:
    return hashlib.sha256((s or "").encode()).hexdigest()


def _agent_secret_ok(row: "models.Agent", provided: str | None) -> bool:
    """Constant-time check of a presented agent secret against the stored hash
    (SEN-007). False when the agent has no secret yet (caller must handle TOFU)."""
    return bool(row.agent_secret) and bool(provided) and \
        hmac.compare_digest(row.agent_secret, _hash_secret(provided))


def _ctrl_host() -> str:
    """Best-effort primary IP of this control-plane host (to protect it from blocks)."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return ""


# Agent ids the operator asked to re-scan ports on their next heartbeat (in-memory;
# a rescan is a transient hint, not durable state worth a DB column).
_ports_rescan: set[str] = set()

# Per-agent update-delivery attempt counter (in-memory, like _ports_rescan — resets on
# control-plane restart, which safely re-arms a stalled rollout). The heartbeat re-sends
# the update directive every beat until the agent reports the target version; this caps
# that so a deterministically-failing build (bad exe, Defender quarantine, version-string
# mismatch between source and built exe) can't re-download forever across the fleet.
_update_attempts: dict[str, int] = {}
_UPDATE_MAX_ATTEMPTS = int(os.environ.get("SENTINEL_UPDATE_MAX_ATTEMPTS", "8"))


# --------------------------------------------------------------------------- Wazuh forwarding
# Every Sentinel detection/audit event is appended as one JSON line to this file;
# a co-located Wazuh manager reads it (log_format json) so AV/EDR events show up
# in Wazuh alongside everything else. See deploy/wazuh/.
_WAZUH_LOG = os.environ.get("SENTINEL_WAZUH_LOG", "/var/log/padakhep-sentinel/sentinel.json")
_WAZUH_FORWARD = os.environ.get("SENTINEL_WAZUH_FORWARD", "1") not in ("0", "false", "")
_wazuh_lock = threading.Lock()


def _forward_wazuh(rec: dict) -> None:
    """Append one detection as a JSON line for Wazuh's logcollector. Best-effort:
    never let a logging failure break ingestion."""
    if not _WAZUH_FORWARD:
        return
    try:
        line = json.dumps({"padakhep": rec}, separators=(",", ":"), default=str)
        with _wazuh_lock, open(_WAZUH_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------- serialization
def _ioc_dict(r: models.Ioc) -> dict:
    return {"id": r.id, "type": r.type, "value": r.value, "source": r.source,
            "malware": r.malware, "confidence": r.confidence,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "active": r.active, "vt_ratio": r.vt_ratio or "", "vt_malicious": r.vt_malicious or 0}


def _sig_dict(r: models.Signature) -> dict:
    return {"id": r.id, "name": r.name, "kind": r.kind, "severity": r.severity,
            "mitre": r.mitre, "source": r.source, "active": r.active}


def _agent_dict(r: models.Agent) -> dict:
    return {"id": r.id, "name": r.name, "ip": r.ip, "os": r.os, "kernel": r.kernel,
            "version": r.version, "status": r.status, "policy_version": r.policy_version,
            "cpu": r.cpu or 0, "mem": r.mem or 0,
            "disk": getattr(r, "disk", 0) or 0, "disk_total": getattr(r, "disk_total", 0) or 0,
            "disk_free": getattr(r, "disk_free", 0) or 0, "disk_drives": getattr(r, "disk_drives", []) or [],
            "spark": r.spark or [],
            "isolated": bool(getattr(r, "isolated", False)),
            "update_requested": bool(getattr(r, "update_requested", False)),
            "nids_mode": getattr(r, "nids_mode", "off") or "off",
            "nids_status": getattr(r, "nids_status", {}) or {},
            "win_telemetry": getattr(r, "win_telemetry", {}) or {},
            "platform": _agent_platform(r),
            "group_id": getattr(r, "group_id", None),
            "ports": r.ports or [],
            "ports_at": r.ports_at.isoformat() if getattr(r, "ports_at", None) else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None}


def _groups_list(db: Session) -> list:
    """All device groups with a live device-count (for the console group UI)."""
    groups = db.execute(select(models.DeviceGroup).order_by(models.DeviceGroup.name)).scalars().all()
    counts: dict[int, int] = {}
    for (gid,) in db.execute(select(models.Agent.group_id).where(models.Agent.group_id.isnot(None))).all():
        counts[gid] = counts.get(gid, 0) + 1
    return [{"id": g.id, "name": g.name, "note": g.note, "device_count": counts.get(g.id, 0)}
            for g in groups]


def _port_dict(r: models.ClosedPort) -> dict:
    return {"id": r.id, "port": r.port, "proto": r.proto, "reason": r.reason,
            "source": r.source, "created_at": r.created_at.isoformat() if r.created_at else None}


def _closed_ports_for(db: Session, agent_id: str) -> list:
    """The active closed-port rules an agent must enforce, as [{proto, port}]."""
    rows = db.execute(select(models.ClosedPort).where(
        models.ClosedPort.agent_id == agent_id, models.ClosedPort.active.is_(True))).scalars().all()
    return [{"proto": r.proto, "port": r.port} for r in rows]


# --------------------------------------------------------------------------- agent code / self-update
_AGENT_FILES = {
    "linux": os.path.join(settings.repo_root, "av_agent", "agent.py"),
    "windows": os.path.join(settings.repo_root, "av_agent", "dist", "sentinel-av.exe"),
}
_AGENT_VERSION_SRC = {
    "linux": os.path.join(settings.repo_root, "av_agent", "agent.py"),
    "windows": os.path.join(settings.repo_root, "av_agent", "agent_win.py"),
}


def _agent_platform(r: models.Agent) -> str:
    return "windows" if "windows" in (r.os or "").lower() else "linux"


def _parse_version(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = re.match(r'\s*VERSION\s*=\s*["\']([^"\']+)["\']', line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return "unknown"


def _agent_manifest_one(platform: str) -> "dict | None":
    fpath = _AGENT_FILES.get(platform)
    if not fpath or not os.path.isfile(fpath):
        return None
    with open(fpath, "rb") as f:
        data = f.read()
    sig = ""                                    # SEN-002: offline Ed25519 signature of this build
    try:
        with open(fpath + ".sig", encoding="utf-8") as sf:
            sig = sf.read().strip()
    except OSError:
        pass
    return {"platform": platform, "version": _parse_version(_AGENT_VERSION_SRC[platform]),
            "signature": sig,
            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
            "url": f"/api/agent/download/{platform}"}


def _agent_manifest() -> dict:
    out = {}
    for p in ("linux", "windows"):
        m = _agent_manifest_one(p)
        if m:
            out[p] = m
    return out


def _det_dict(r: models.Detection) -> dict:
    return {"id": r.id, "ts": r.ts.isoformat() if r.ts else None, "agent_id": r.agent_id,
            "device_name": r.device_name, "event_type": r.event_type, "ioc_value": r.ioc_value,
            "ioc_type": r.ioc_type, "severity": r.severity, "confidence": r.confidence,
            "mode": r.mode, "action_taken": r.action_taken, "mitre": r.mitre,
            "producer": r.producer, "event": r.event}


# --------------------------------------------------------------------------- health
@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "sentinel-control-plane", "version": app.version}


# --------------------------------------------------------------------------- IOCs
@app.get("/api/iocs")
def list_iocs(type: str | None = None, active_only: bool = True, limit: int = 500,
              db: Session = Depends(get_db)) -> dict:
    q = select(models.Ioc)
    if type:
        q = q.where(models.Ioc.type == type)
    if active_only:
        q = q.where(models.Ioc.active.is_(True))
    q = q.order_by(models.Ioc.last_seen.desc()).limit(min(limit, 5000))
    rows = db.execute(q).scalars().all()
    return {"count": len(rows), "iocs": [_ioc_dict(r) for r in rows]}


@app.post("/api/iocs", dependencies=[Depends(require_token)])
def add_iocs(body: schemas.IocBulkIn, db: Session = Depends(get_db)) -> dict:
    n = 0
    for i in body.iocs:
        if crud.upsert_ioc(db, i.type, i.value, i.source, i.malware, i.confidence,
                           i.ttl_days if i.ttl_days is not None else settings.IOC_TTL_DAYS):
            n += 1
    db.commit()
    return {"upserted": n}


# --------------------------------------------------------------------------- signatures / behaviors
@app.get("/api/signatures")
def list_signatures(db: Session = Depends(get_db)) -> dict:
    rows = db.execute(select(models.Signature)).scalars().all()
    return {"count": len(rows), "signatures": [_sig_dict(r) for r in rows]}


@app.post("/api/signatures", dependencies=[Depends(require_token)])
def add_signature(body: schemas.SignatureIn, db: Session = Depends(get_db)) -> dict:
    row = db.execute(select(models.Signature).where(models.Signature.name == body.name)).scalar_one_or_none()
    if row:
        row.content, row.kind, row.severity, row.mitre = body.content, body.kind, body.severity, body.mitre
    else:
        db.add(models.Signature(**body.model_dump()))
    db.commit()
    return {"ok": True, "name": body.name}


@app.get("/api/behaviors")
def list_behaviors(db: Session = Depends(get_db)) -> dict:
    rows = db.execute(select(models.Behavior)).scalars().all()
    return {"count": len(rows),
            "behaviors": [{"id": r.id, "name": r.name, "description": r.description,
                           "rule": r.rule, "severity": r.severity, "mitre": r.mitre,
                           "active": r.active} for r in rows]}


# --------------------------------------------------------------------------- agents
@app.post("/api/enroll")
def enroll(body: schemas.EnrollIn,
           x_agent_secret: str | None = Header(default=None, alias="X-Agent-Secret"),
           db: Session = Depends(get_db)) -> dict:
    aid = re.sub(r"[^0-9a-fA-F-]", "", (body.agent_id or ""))[:64] or uuid.uuid4().hex
    row = db.get(models.Agent, aid)
    issued = None
    # Only mint a secret for agents that advertise support (proto>=2). A legacy
    # (proto 1) agent is never issued one, so it can never be locked out of its
    # own heartbeat — it simply stays unauthenticated until upgraded (SEN-007).
    can_secret = int(getattr(body, "proto", 1) or 1) >= 2
    if row is not None and row.agent_secret:
        # An established identity may only be re-enrolled by the holder of its
        # secret — otherwise a caller could hijack a record's name/ip/os.
        if not _agent_secret_ok(row, x_agent_secret):
            raise HTTPException(status_code=403, detail="agent secret required to re-enroll this identity")
    if row is None:
        row = models.Agent(id=aid, name=_clean(body.name))   # first enrollment: adopt install-time name
        db.add(row)
    if can_secret and not row.agent_secret:
        issued = secrets.token_hex(32)                        # mint (new agent) or migrate (TOFU) a secret
        row.agent_secret = _hash_secret(issued)
    # Sanitize agent-reported strings (SEN-003): strip control chars + angle brackets
    # and cap length, so a rogue agent can't store XSS/garbage in the console.
    # NOTE: name is NOT refreshed on re-enroll — once set, the console name is
    # operator-authoritative, so a rename survives an agent restart/re-enroll.
    row.ip, row.os = _clean(body.ip, 64), _clean(body.os)
    row.kernel, row.version = _clean(body.kernel), _clean(body.version, 40)
    row.status, row.last_seen = "online", _now()
    db.commit()
    resp = {"agent_id": aid, "policy_version": row.policy_version}
    if issued:
        resp["agent_secret"] = issued          # returned once; the agent stores it
    return resp


@app.post("/api/agents/{agent_id}/heartbeat")
def heartbeat(agent_id: str, body: schemas.HeartbeatIn,
              x_agent_secret: str | None = Header(default=None, alias="X-Agent-Secret"),
              db: Session = Depends(get_db)) -> dict:
    row = db.get(models.Agent, agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    # SEN-007: bind the heartbeat to the agent's own identity. Legacy agents with
    # no secret yet are allowed (they migrate on their next enroll); once a secret
    # exists it is mandatory, so a guessed agent_id can't read/forge this agent.
    if row.agent_secret and not _agent_secret_ok(row, x_agent_secret):
        raise HTTPException(status_code=403, detail="invalid agent secret")
    row.status, row.last_seen, row.policy_version = body.status, _now(), body.policy_version
    row.cpu, row.mem = int(body.cpu or 0), int(body.mem or 0)
    if body.disk_total:              # capacity known -> refresh the whole storage snapshot
        row.disk = int(body.disk or 0)
        row.disk_total = int(body.disk_total or 0)
        row.disk_free = int(body.disk_free or 0)
        if body.disk_drives is not None:
            row.disk_drives = body.disk_drives
    if body.version:
        row.version = body.version
    if body.ports is not None:                # observed listening sockets snapshot
        row.ports = body.ports
        row.ports_at = _now()
    if body.nids_status is not None:          # Suricata engine status snapshot
        row.nids_status = body.nids_status
    if body.win_telemetry is not None:        # Windows Sysmon/ETW/Firewall status snapshot
        row.win_telemetry = body.win_telemetry
    hist = list(row.spark or [])[-15:]
    hist.append(int(body.cpu or 0))
    row.spark = hist          # reassign so SQLAlchemy tracks the JSON change
    resp = {"ok": True, "isolate": bool(getattr(row, "isolated", False)),
            "closed_ports": _closed_ports_for(db, agent_id),
            "nids_mode": getattr(row, "nids_mode", "off") or "off"}
    if agent_id in _ports_rescan:                 # operator asked for an on-demand port scan
        resp["rescan_ports"] = True
        _ports_rescan.discard(agent_id)
    # IPs this agent must drop (global + agent-scoped) — enforced within ~1 heartbeat.
    blk = db.execute(select(models.BlockedIp).where(models.BlockedIp.active.is_(True))).scalars().all()
    resp["blocked"] = sorted({b.ip for b in blk
                              if getattr(b, "scope", "global") != "agent"
                              or getattr(b, "agent_id", "") == agent_id})
    # push-to-update: hand the agent a download directive; re-send every beat until
    # the agent reports the target version (durable across offline/mid-crash), but cap
    # attempts so a deterministically-failing build can't re-download forever.
    if getattr(row, "update_requested", False):
        man = _agent_manifest_one(_agent_platform(row))
        if man and body.version and body.version == man["version"]:
            row.update_requested = False                     # confirmed applied
            _update_attempts.pop(agent_id, None)
        elif man:
            n = _update_attempts.get(agent_id, 0)
            if n >= _UPDATE_MAX_ATTEMPTS:                    # circuit breaker
                row.update_requested = False
                _update_attempts.pop(agent_id, None)
                _ingest_event(db, "control-plane", _update_giveup_event(row, man["version"], n))
            else:
                _update_attempts[agent_id] = n + 1
                resp["update"] = man
    db.commit()
    return resp


@app.get("/api/agents")
def list_agents(db: Session = Depends(get_db)) -> dict:
    rows = db.execute(select(models.Agent).order_by(models.Agent.last_seen.desc())).scalars().all()
    return {"count": len(rows), "agents": [_agent_dict(r) for r in rows],
            "agent_versions": _agent_manifest(), "groups": _groups_list(db)}


@app.get("/api/agent/manifest")
def agent_manifest() -> dict:
    """Current agent build per platform (version + sha256)."""
    return _agent_manifest()


@app.get("/api/agent/download/{platform}")
def agent_download(platform: str):
    fpath = _AGENT_FILES.get(platform)
    if not fpath or not os.path.isfile(fpath):
        raise HTTPException(status_code=404, detail="no agent build for platform")
    media = "text/x-python" if platform == "linux" else "application/octet-stream"
    fname = "agent.py" if platform == "linux" else "sentinel-av.exe"
    return FileResponse(fpath, media_type=media, filename=fname)


def _update_event(row: models.Agent, version: str) -> dict:
    return {"schema_version": "3.0", "timestamp": _now().isoformat(),
            "instance": {"device_name": row.name, "uuid": row.id, "ip_address": row.ip},
            "ioc": {"value": row.name, "type": "host"},
            "event": {"type": "AGENT_UPDATE_REQUESTED", "action_taken": "DETECTED", "mode": "MANAGE",
                      "severity": "INFO", "confidence": 100,
                      "details": {"agent": row.name, "target_version": version,
                                  "from_version": row.version or "?",
                                  "note": "operator pushed an agent update from the console"}}}


def _update_giveup_event(row: models.Agent, version: str, attempts: int) -> dict:
    return {"schema_version": "3.0", "timestamp": _now().isoformat(),
            "instance": {"device_name": row.name, "uuid": row.id, "ip_address": row.ip},
            "ioc": {"value": row.name, "type": "host"},
            "event": {"type": "AGENT_UPDATE_ABANDONED", "action_taken": "DETECTED", "mode": "MANAGE",
                      "severity": "MEDIUM", "confidence": 100,
                      "details": {"agent": row.name, "target_version": version,
                                  "from_version": row.version or "?", "attempts": attempts,
                                  "note": f"update not confirmed after {attempts} deliveries — "
                                          "circuit breaker tripped; re-push to retry"}},
            "integrity": {"producer": "control-plane"}}


@app.post("/api/agents/{agent_id}/update", dependencies=[Depends(require_token)])
def request_update(agent_id: str, db: Session = Depends(get_db)) -> dict:
    row = db.get(models.Agent, agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    man = _agent_manifest_one(_agent_platform(row))
    if not man:
        raise HTTPException(status_code=409, detail="no agent build available for this platform")
    row.update_requested = True
    _update_attempts.pop(agent_id, None)                 # fresh push -> re-arm the retry budget
    _ingest_event(db, "control-plane", _update_event(row, man["version"]))
    db.commit()
    return {"ok": True, "agent_id": agent_id, "target_version": man["version"]}


@app.post("/api/agents/{agent_id}/rename", dependencies=[Depends(require_token)])
def rename_agent(agent_id: str, body: schemas.RenameIn, db: Session = Depends(get_db)) -> dict:
    """Set the operator-assigned device name. Authoritative: it survives agent
    re-enrollment (see enroll) and is propagated to detection history so the
    name changes everywhere it is shown."""
    row = db.get(models.Agent, agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    new = _clean(body.name, 128)
    if not new:
        raise HTTPException(status_code=400, detail="name required")
    old = row.name
    if new == old:
        return {"ok": True, "agent_id": agent_id, "name": new, "note": "unchanged"}
    row.name = new
    # Propagate to the denormalized device_name on every past detection so the
    # fleet, logs, and alerts all show the new name.
    db.execute(update(models.Detection).where(models.Detection.agent_id == agent_id)
               .values(device_name=new))
    ev = {"schema_version": "3.0", "timestamp": _now().isoformat(),
          "instance": {"device_name": new, "uuid": row.id, "ip_address": row.ip},
          "ioc": {"value": new, "type": "host"},
          "event": {"type": "AGENT_RENAMED", "action_taken": "MANAGE", "mode": "MANAGE",
                    "severity": "INFO", "confidence": 100,
                    "details": {"from": old, "to": new,
                                "note": "operator renamed the device from the console"}},
          "integrity": {"producer": "control-plane"}}
    _ingest_event(db, "control-plane", ev, agent_id=agent_id)
    db.commit()
    return {"ok": True, "agent_id": agent_id, "name": new, "was": old}


# --------------------------------------------------------------------------- device groups (organizational)
@app.get("/api/groups")
def list_groups(db: Session = Depends(get_db)) -> dict:
    return {"groups": _groups_list(db)}


@app.post("/api/groups", dependencies=[Depends(require_token)])
def create_group(body: schemas.GroupIn, db: Session = Depends(get_db)) -> dict:
    name = _clean(body.name, 96)
    if not name:
        raise HTTPException(status_code=400, detail="group name required")
    if db.execute(select(models.DeviceGroup).where(models.DeviceGroup.name == name)).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="a group with that name already exists")
    g = models.DeviceGroup(name=name, note=_clean(body.note, 256))
    db.add(g)
    db.commit()
    return {"ok": True, "id": g.id, "name": g.name, "note": g.note, "device_count": 0}


@app.post("/api/groups/{group_id}/rename", dependencies=[Depends(require_token)])
def rename_group(group_id: int, body: schemas.GroupIn, db: Session = Depends(get_db)) -> dict:
    g = db.get(models.DeviceGroup, group_id)
    if g is None:
        raise HTTPException(status_code=404, detail="unknown group")
    name = _clean(body.name, 96)
    if not name:
        raise HTTPException(status_code=400, detail="group name required")
    clash = db.execute(select(models.DeviceGroup).where(
        models.DeviceGroup.name == name, models.DeviceGroup.id != group_id)).scalar_one_or_none()
    if clash:
        raise HTTPException(status_code=409, detail="a group with that name already exists")
    g.name = name
    g.note = _clean(body.note, 256)
    db.commit()
    return {"ok": True, "id": g.id, "name": g.name, "note": g.note}


@app.delete("/api/groups/{group_id}", dependencies=[Depends(require_token)])
def delete_group(group_id: int, db: Session = Depends(get_db)) -> dict:
    g = db.get(models.DeviceGroup, group_id)
    if g is None:
        raise HTTPException(status_code=404, detail="unknown group")
    # un-assign members (organizational only — devices are never deleted with a group)
    freed = db.execute(update(models.Agent).where(models.Agent.group_id == group_id)
                       .values(group_id=None)).rowcount
    db.delete(g)
    db.commit()
    return {"ok": True, "removed": group_id, "unassigned": freed or 0}


@app.post("/api/agents/{agent_id}/group", dependencies=[Depends(require_token)])
def set_agent_group(agent_id: str, body: schemas.GroupAssignIn, db: Session = Depends(get_db)) -> dict:
    row = db.get(models.Agent, agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    gid = body.group_id or None
    if gid is not None and db.get(models.DeviceGroup, gid) is None:
        raise HTTPException(status_code=404, detail="unknown group")
    row.group_id = gid
    db.commit()
    return {"ok": True, "agent_id": agent_id, "group_id": gid}


@app.post("/api/groups/{group_id}/members", dependencies=[Depends(require_token)])
def set_group_members(group_id: int, body: schemas.GroupMembersIn, db: Session = Depends(get_db)) -> dict:
    """Bulk-assign several devices to a group in one call (organize N devices at once)."""
    if db.get(models.DeviceGroup, group_id) is None:
        raise HTTPException(status_code=404, detail="unknown group")
    ids = [i for i in (body.agent_ids or []) if i]
    n = 0
    if ids:
        n = db.execute(update(models.Agent).where(models.Agent.id.in_(ids))
                       .values(group_id=group_id)).rowcount or 0
    db.commit()
    return {"ok": True, "group_id": group_id, "assigned": n}


@app.delete("/api/agents/{agent_id}", dependencies=[Depends(require_token)])
def remove_agent(agent_id: str, db: Session = Depends(get_db)) -> dict:
    """Remove an agent record (decommission / prune a stale or duplicate host).
    Also clears that agent's blocklist + closed-port rows. Detection history is
    kept for audit. If the agent is still running it will re-enroll on its next
    start; a live host should be uninstalled/isolated first."""
    row = db.get(models.Agent, agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    name = row.name
    db.execute(models.BlockedIp.__table__.delete().where(models.BlockedIp.agent_id == agent_id))
    db.execute(models.ClosedPort.__table__.delete().where(models.ClosedPort.agent_id == agent_id))
    _ports_rescan.discard(agent_id)
    _update_attempts.pop(agent_id, None)             # don't leak the update counter on decommission
    ev = {"schema_version": "3.0", "timestamp": _now().isoformat(),
          "instance": {"device_name": name, "uuid": agent_id, "ip_address": row.ip},
          "ioc": {"value": name, "type": "host"},
          "event": {"type": "AGENT_REMOVED", "action_taken": "MANAGE", "mode": "MANAGE",
                    "severity": "INFO", "confidence": 100,
                    "details": {"agent": name, "note": "operator removed the agent record from the console"}},
          "integrity": {"producer": "control-plane"}}
    _ingest_event(db, "control-plane", ev, agent_id="control-plane")
    db.delete(row)
    db.commit()
    return {"ok": True, "removed": agent_id, "name": name}


@app.post("/api/agents/{agent_id}/update/cancel", dependencies=[Depends(require_token)])
def cancel_update(agent_id: str, db: Session = Depends(get_db)) -> dict:
    """Clear a stuck update flag (e.g. an agent that went offline mid-update)."""
    row = db.get(models.Agent, agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    row.update_requested = False
    _update_attempts.pop(agent_id, None)
    db.commit()
    return {"ok": True, "agent_id": agent_id, "update_requested": False}


@app.post("/api/agents/update-all", dependencies=[Depends(require_token)])
def request_update_all(db: Session = Depends(get_db)) -> dict:
    rows = db.execute(select(models.Agent)).scalars().all()
    n = 0
    for row in rows:
        if _agent_manifest_one(_agent_platform(row)):
            row.update_requested = True
            _update_attempts.pop(row.id, None)           # re-arm the retry budget per agent
            n += 1
    db.commit()
    return {"ok": True, "queued": n}


def _isolation_event(row: models.Agent, isolate: bool) -> dict:
    action = "ISOLATED" if isolate else "UNISOLATED"
    return {"schema_version": "3.0", "timestamp": _now().isoformat(),
            "instance": {"device_name": row.name, "uuid": row.id, "ip_address": row.ip},
            "ioc": {"value": row.ip or row.name, "type": "host"},
            "event": {"type": f"ENDPOINT_{action}", "action_taken": action, "mode": "PREVENT",
                      "severity": "CRITICAL" if isolate else "HIGH", "confidence": 100,
                      "details": {"agent": row.name,
                                  "note": ("network quarantine engaged (allow lo/established/ssh/control-plane)"
                                           if isolate else "network quarantine lifted")}}}


@app.post("/api/agents/{agent_id}/isolate", dependencies=[Depends(require_token)])
def isolate_agent(agent_id: str, db: Session = Depends(get_db)) -> dict:
    row = db.get(models.Agent, agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    row.isolated = True
    _ingest_event(db, "control-plane", _isolation_event(row, True))
    db.commit()
    return {"ok": True, "agent_id": agent_id, "isolated": True}


@app.post("/api/agents/{agent_id}/unisolate", dependencies=[Depends(require_token)])
def unisolate_agent(agent_id: str, db: Session = Depends(get_db)) -> dict:
    row = db.get(models.Agent, agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    row.isolated = False
    _ingest_event(db, "control-plane", _isolation_event(row, False))
    db.commit()
    return {"ok": True, "agent_id": agent_id, "isolated": False}


# --------------------------------------------------------------------------- detections
def _ingest_event(db: Session, producer: str, ev: dict, agent_id: str = "") -> None:
    """Map one v3 event dict to a Detection row (no commit — caller commits)."""
    e = ev.get("event", {}) if isinstance(ev, dict) else {}
    ioc = ev.get("ioc", {}) if isinstance(ev, dict) else {}
    inst = ev.get("instance", {}) if isinstance(ev, dict) else {}
    mitre = (ev.get("mitre_attack", {}) or {}).get("technique_ids", [])
    aid = agent_id or inst.get("uuid", "")
    device_name = inst.get("device_name", "")
    # The console name is authoritative: if we know the agent, use its current
    # name so a rename reflects everywhere (incl. the event JSON we persist).
    if aid:
        known = db.get(models.Agent, aid)
        if known and known.name:
            device_name = known.name
            if isinstance(inst, dict):
                inst["device_name"] = device_name
    prod = producer or ev.get("integrity", {}).get("producer", "")
    db.add(models.Detection(
        agent_id=aid,
        device_name=device_name,
        event_type=e.get("type", ""),
        ioc_value=ioc.get("value", ""), ioc_type=ioc.get("type", ""),
        severity=e.get("severity", ""), confidence=int(e.get("confidence", 0) or 0),
        mode=e.get("mode", "DETECT"), action_taken=e.get("action_taken", "DETECTED"),
        mitre=mitre, producer=prod,
        event=ev,
    ))
    # Mirror every event into the Wazuh-readable JSON log so AV/EDR detections
    # appear in Wazuh (fields are namespaced under "padakhep.*").
    det = e.get("details", {}) if isinstance(e.get("details"), dict) else {}
    _forward_wazuh({
        "producer": prod, "event_type": e.get("type", ""), "device": device_name,
        "agent_id": aid, "severity": e.get("severity", ""),
        "confidence": int(e.get("confidence", 0) or 0),
        "action": e.get("action_taken", "DETECTED"), "mode": e.get("mode", "DETECT"),
        "ioc": ioc.get("value", ""), "ioc_type": ioc.get("type", ""),
        "mitre": mitre, "rule": det.get("rule", ""), "source": det.get("source", ""),
        "timestamp": ev.get("timestamp") or _now().isoformat(),
    })


@app.post("/api/detections", dependencies=[Depends(require_token)])
def ingest_detections(body: schemas.DetectionsIn, db: Session = Depends(get_db)) -> dict:
    n = 0
    for ev in body.events:
        _ingest_event(db, body.producer, ev if isinstance(ev, dict) else {}, agent_id=body.agent_id)
        n += 1
    db.commit()
    return {"ingested": n}


@app.get("/api/detections")
def list_detections(limit: int = 200, db: Session = Depends(get_db)) -> dict:
    rows = db.execute(select(models.Detection).order_by(models.Detection.ts.desc())
                      .limit(min(limit, 2000))).scalars().all()
    return {"count": len(rows), "detections": [_det_dict(r) for r in rows]}


# --------------------------------------------------------------------------- sync (pulldown for AV)
@app.get("/api/sync/policy")
def sync_policy(agent_id: str | None = None,
                x_agent_secret: str | None = Header(default=None, alias="X-Agent-Secret"),
                db: Session = Depends(get_db)) -> dict:
    # SEN-008: don't hand an arbitrary agent's blocklist/firewall policy to any
    # caller. If the named agent has a secret, the caller must present it.
    if agent_id:
        who = db.get(models.Agent, agent_id)
        if who is not None and who.agent_secret and not _agent_secret_ok(who, x_agent_secret):
            raise HTTPException(status_code=403, detail="invalid agent secret")
    iocs = db.execute(select(models.Ioc).where(models.Ioc.active.is_(True))).scalars().all()
    sigs = db.execute(select(models.Signature).where(models.Signature.active.is_(True))).scalars().all()
    behs = db.execute(select(models.Behavior).where(models.Behavior.active.is_(True))).scalars().all()
    # IPs this agent must enforce: every global block + blocks targeting this agent.
    blk = db.execute(select(models.BlockedIp).where(models.BlockedIp.active.is_(True))).scalars().all()
    blocked = sorted({r.ip for r in blk
                      if getattr(r, "scope", "global") != "agent" or getattr(r, "agent_id", "") == agent_id})
    # Allow-list wins over the blocklist: never distribute an IP the operator has
    # allow-listed (matches host IPs or any allow-listed CIDR).
    allow = db.execute(select(models.AllowlistEntry).where(models.AllowlistEntry.active.is_(True))).scalars().all()
    allow_nets = []
    for a in allow:
        if a.kind != "ip":
            continue
        try:
            allow_nets.append(ipaddress.ip_network(a.value, strict=False))
        except ValueError:
            continue

    def _allowed(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in allow_nets)

    blocked = [ip for ip in blocked if not _allowed(ip)]
    allow_hashes = sorted({a.sha256 for a in allow if a.kind == "binary" and a.sha256})
    allow_ips = sorted({a.value for a in allow if a.kind == "ip"})
    version = int(_now().timestamp())
    return {
        "policy_version": version,
        # driver-hash IOCs are served separately as bad_driver_hashes (below), not in
        # the general file-hash set the on-disk scanner matches.
        "iocs": [{"type": r.type, "value": r.value, "confidence": r.confidence,
                  "source": r.source} for r in iocs if r.type != "driver"],
        "signatures": [{"name": r.name, "kind": r.kind, "content": r.content,
                        "severity": r.severity, "mitre": r.mitre} for r in sigs],
        "behaviors": [{"name": r.name, "rule": r.rule, "severity": r.severity,
                       "mitre": r.mitre} for r in behs],
        "blocked_ips": blocked,
        "allowlist_ips": allow_ips,
        "allowlist_hashes": allow_hashes,
        "log_rules": _log_rules_for(db, _agent_platform(who) if agent_id and who else None),
        "closed_ports": _closed_ports_for(db, agent_id or ""),
        # BYOVD: known-bad kernel-driver hashes (Windows agents match loaded drivers by content).
        "bad_driver_hashes": (sorted(r.value for r in iocs if r.type == "driver")
                              if agent_id and who and _agent_platform(who) == "windows" else []),
    }


# --------------------------------------------------------------------------- blocked IPs (manual)
@app.get("/api/blocked")
def list_blocked(db: Session = Depends(get_db)) -> dict:
    rows = db.execute(select(models.BlockedIp).where(models.BlockedIp.active.is_(True))
                      .order_by(models.BlockedIp.created_at.desc())).scalars().all()
    names = {a.id: a.name for a in db.execute(select(models.Agent)).scalars().all()}
    return {"count": len(rows), "blocked": [
        {"id": r.id, "ip": r.ip, "reason": r.reason, "source": r.source,
         "scope": getattr(r, "scope", "global"), "agent_id": getattr(r, "agent_id", ""),
         "target": names.get(getattr(r, "agent_id", ""), "") if getattr(r, "scope", "global") == "agent" else "All endpoints",
         "created_at": r.created_at.isoformat() if r.created_at else None} for r in rows]}


# --------------------------------------------------------------------------- allow-list
def _allow_dict(r: "models.AllowlistEntry") -> dict:
    return {"id": r.id, "kind": r.kind, "value": r.value, "sha256": r.sha256,
            "scope": r.scope, "note": r.note,
            "added": r.created_at.isoformat() if r.created_at else None}


def _allowlist(db: Session) -> dict:
    rows = db.execute(select(models.AllowlistEntry).where(models.AllowlistEntry.active.is_(True))
                      .order_by(models.AllowlistEntry.created_at.desc())).scalars().all()
    return {
        "scope": "GLOBAL",
        "ips": [_allow_dict(r) for r in rows if r.kind == "ip"],
        "binaries": [_allow_dict(r) for r in rows if r.kind == "binary"],
    }


@app.get("/api/allowlist")
def list_allowlist(db: Session = Depends(get_db)) -> dict:
    return _allowlist(db)


@app.post("/api/allowlist", dependencies=[Depends(require_token)])
def add_allowlist(body: schemas.AllowlistIn, db: Session = Depends(get_db)) -> dict:
    kind = "binary" if (body.kind or "ip").lower() == "binary" else "ip"
    value = _clean(body.value or "", 512)
    sha = re.sub(r"[^0-9a-fA-F]", "", (body.sha256 or ""))[:64].lower()
    if kind == "ip":
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid IP or CIDR")
    else:
        if not value:
            raise HTTPException(status_code=400, detail="binary path required")
        if sha and len(sha) != 64:
            raise HTTPException(status_code=400, detail="sha256 must be 64 hex chars")
    match = value if kind == "ip" else value
    exists = db.execute(select(models.AllowlistEntry).where(
        models.AllowlistEntry.kind == kind, models.AllowlistEntry.value == match,
        models.AllowlistEntry.active.is_(True))).scalar_one_or_none()
    if exists:
        return {"ok": True, "id": exists.id, "note": "already allow-listed"}
    row = models.AllowlistEntry(kind=kind, value=value, sha256=sha,
                                scope=_clean(body.scope or "GLOBAL", 32) or "GLOBAL",
                                note=_clean(body.note or "", 256))
    db.add(row)
    db.commit()
    return {"ok": True, "id": row.id, "entry": _allow_dict(row)}


@app.delete("/api/allowlist/{entry_id}", dependencies=[Depends(require_token)])
def remove_allowlist(entry_id: int, db: Session = Depends(get_db)) -> dict:
    row = db.get(models.AllowlistEntry, entry_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown allow-list entry")
    db.delete(row)
    db.commit()
    return {"ok": True}


@app.post("/api/blocked", dependencies=[Depends(require_token)])
def add_blocked(body: schemas.BlockIn, db: Session = Depends(get_db)) -> dict:
    ip = (body.ip or "").strip()
    try:
        net = ipaddress.ip_network(ip, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP or CIDR")
    # Reject fleet-stranding blocks (SEN-010): no default route / absurdly broad CIDR,
    # and nothing that would cover the control-plane's own address.
    if net.prefixlen == 0 or net.num_addresses > 65536:
        raise HTTPException(status_code=400,
                            detail="refusing an over-broad block (>/16 or 0.0.0.0/0)")
    try:
        cp = ipaddress.ip_address((_ctrl_host() or "").strip())
        if cp in net:
            raise HTTPException(status_code=400, detail="that CIDR contains the control plane")
    except ValueError:
        pass
    scope = "agent" if (body.scope == "agent" and body.agent_id) else "global"
    aid = body.agent_id if scope == "agent" else ""
    if scope == "agent" and db.get(models.Agent, aid) is None:
        raise HTTPException(status_code=404, detail="unknown target agent")
    exists = db.execute(select(models.BlockedIp).where(
        models.BlockedIp.ip == ip, models.BlockedIp.agent_id == aid,
        models.BlockedIp.active.is_(True))).scalar_one_or_none()
    if exists:
        return {"ok": True, "id": exists.id, "note": "already blocked"}
    row = models.BlockedIp(ip=ip, reason=body.reason or "", source="manual", scope=scope, agent_id=aid)
    db.add(row)
    db.commit()
    return {"ok": True, "id": row.id, "scope": scope}


@app.post("/api/blocked/{block_id}/unblock", dependencies=[Depends(require_token)])
def unblock_ip(block_id: int, db: Session = Depends(get_db)) -> dict:
    row = db.get(models.BlockedIp, block_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown block")
    ip, reason = row.ip, row.reason
    db.delete(row)
    # releasing a blocked IP is a CRITICAL, audit-worthy event -> log it
    ev = {"schema_version": "3.0", "timestamp": _now().isoformat(),
          "instance": {"device_name": "control-plane"},
          "ioc": {"value": ip, "type": "ip"},
          "event": {"type": "BLOCKED_IP_RELEASED", "action_taken": "UNBLOCKED", "mode": "DETECT",
                    "severity": "CRITICAL", "confidence": 100,
                    "details": {"ip": ip, "reason": reason, "note": "a blocked IP was released from the blocklist"}},
          "mitre_attack": {"technique_ids": [], "technique_id": None},
          "policy": {"allowlisted": False, "matching_ioc_type": "MALICIOUS_IP"},
          "integrity": {"producer": "console"}}
    db.add(models.Detection(event_type="BLOCKED_IP_RELEASED", ioc_value=ip, ioc_type="ip",
                            severity="CRITICAL", confidence=100, mode="DETECT",
                            action_taken="UNBLOCKED", producer="console",
                            device_name="control-plane", mitre=[], event=ev))
    db.commit()
    return {"ok": True, "released": ip, "log": "CRITICAL"}


# --------------------------------------------------------------------------- open ports / host firewall
_COMMON_PORTS = [
    {"port": 22, "proto": "tcp", "name": "SSH"},
    {"port": 3389, "proto": "tcp", "name": "RDP"},
    {"port": 445, "proto": "tcp", "name": "SMB"},
    {"port": 139, "proto": "tcp", "name": "NetBIOS"},
    {"port": 21, "proto": "tcp", "name": "FTP"},
    {"port": 23, "proto": "tcp", "name": "Telnet"},
    {"port": 25, "proto": "tcp", "name": "SMTP"},
    {"port": 53, "proto": "udp", "name": "DNS"},
    {"port": 80, "proto": "tcp", "name": "HTTP"},
    {"port": 443, "proto": "tcp", "name": "HTTPS"},
    {"port": 3306, "proto": "tcp", "name": "MySQL"},
    {"port": 5432, "proto": "tcp", "name": "PostgreSQL"},
    {"port": 6379, "proto": "tcp", "name": "Redis"},
    {"port": 27017, "proto": "tcp", "name": "MongoDB"},
    {"port": 8080, "proto": "tcp", "name": "HTTP-alt"},
    {"port": 5900, "proto": "tcp", "name": "VNC"},
]


def _port_event(row: models.Agent, port: int, proto: str, action: str, reason: str) -> dict:
    closing = action == "CLOSED"
    return {"schema_version": "3.0", "timestamp": _now().isoformat(),
            "instance": {"device_name": row.name, "uuid": row.id, "ip_address": row.ip},
            "ioc": {"value": f"{proto}/{port}", "type": "port"},
            "event": {"type": f"PORT_{action}", "action_taken": action, "mode": "PREVENT",
                      "severity": "HIGH" if closing else "MEDIUM", "confidence": 100,
                      "details": {"agent": row.name, "port": port, "proto": proto, "reason": reason,
                                  "note": (f"host firewall closing {proto}/{port}" if closing
                                           else f"host firewall re-opening {proto}/{port}")}}}


@app.get("/api/ports")
def list_ports(db: Session = Depends(get_db)) -> dict:
    """Per-device observed listening ports + the operator's closed-port rules."""
    agents = db.execute(select(models.Agent).order_by(models.Agent.last_seen.desc())).scalars().all()
    closed = db.execute(select(models.ClosedPort).where(models.ClosedPort.active.is_(True))).scalars().all()
    by_agent: dict[str, list] = {}
    for c in closed:
        by_agent.setdefault(c.agent_id, []).append(_port_dict(c))
    return {"common_ports": _COMMON_PORTS, "count": len(agents), "devices": [
        {"agent_id": a.id, "name": a.name, "ip": a.ip, "os": a.os, "status": a.status,
         "platform": _agent_platform(a),
         "ports_at": a.ports_at.isoformat() if getattr(a, "ports_at", None) else None,
         "observed": a.ports or [], "closed": by_agent.get(a.id, [])} for a in agents]}


@app.get("/api/agents/{agent_id}/ports")
def agent_ports(agent_id: str, db: Session = Depends(get_db)) -> dict:
    row = db.get(models.Agent, agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    closed = db.execute(select(models.ClosedPort).where(
        models.ClosedPort.agent_id == agent_id, models.ClosedPort.active.is_(True))).scalars().all()
    return {"agent_id": agent_id, "name": row.name, "platform": _agent_platform(row),
            "ports_at": row.ports_at.isoformat() if getattr(row, "ports_at", None) else None,
            "observed": row.ports or [], "closed": [_port_dict(c) for c in closed],
            "common_ports": _COMMON_PORTS}


@app.post("/api/agents/{agent_id}/ports/close", dependencies=[Depends(require_token)])
def close_port(agent_id: str, body: schemas.PortActionIn, db: Session = Depends(get_db)) -> dict:
    row = db.get(models.Agent, agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    port, proto = int(body.port), (body.proto or "tcp").lower()
    if not (1 <= port <= 65535) or proto not in ("tcp", "udp"):
        raise HTTPException(status_code=400, detail="invalid port or protocol")
    existing = db.execute(select(models.ClosedPort).where(
        models.ClosedPort.agent_id == agent_id, models.ClosedPort.proto == proto,
        models.ClosedPort.port == port)).scalar_one_or_none()
    if existing:
        existing.active, existing.reason = True, body.reason or existing.reason
    else:
        db.add(models.ClosedPort(agent_id=agent_id, port=port, proto=proto, reason=body.reason or ""))
    _ingest_event(db, "console", _port_event(row, port, proto, "CLOSED", body.reason or ""))
    db.commit()
    return {"ok": True, "agent_id": agent_id, "port": port, "proto": proto, "state": "closed"}


@app.post("/api/agents/{agent_id}/ports/scan", dependencies=[Depends(require_token)])
def scan_ports(agent_id: str, db: Session = Depends(get_db)) -> dict:
    """Ask an agent to re-observe its listening ports on its next heartbeat (~<=INTERVAL)."""
    row = db.get(models.Agent, agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    _ports_rescan.add(agent_id)
    return {"ok": True, "agent_id": agent_id, "queued": True,
            "ports_at": row.ports_at.isoformat() if getattr(row, "ports_at", None) else None}


@app.post("/api/agents/{agent_id}/ports/open", dependencies=[Depends(require_token)])
def open_port(agent_id: str, body: schemas.PortActionIn, db: Session = Depends(get_db)) -> dict:
    row = db.get(models.Agent, agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    port, proto = int(body.port), (body.proto or "tcp").lower()
    existing = db.execute(select(models.ClosedPort).where(
        models.ClosedPort.agent_id == agent_id, models.ClosedPort.proto == proto,
        models.ClosedPort.port == port, models.ClosedPort.active.is_(True))).scalar_one_or_none()
    if existing:
        existing.active = False
        _ingest_event(db, "console", _port_event(row, port, proto, "OPENED", body.reason or ""))
    db.commit()
    return {"ok": True, "agent_id": agent_id, "port": port, "proto": proto, "state": "open"}


# --------------------------------------------------------------------------- IDS / IPS (Suricata)
_NIDS_MODES = ("off", "ids", "ips")


def _nids_event(row: models.Agent, mode: str) -> dict:
    label = {"off": "NIDS_DISABLED", "ids": "NIDS_ENABLED_IDS", "ips": "NIDS_ENABLED_IPS"}[mode]
    sev = {"off": "MEDIUM", "ids": "MEDIUM", "ips": "HIGH"}[mode]
    note = {"off": "Suricata IDS/IPS disabled",
            "ids": "Suricata enabled in IDS (detect-only) mode",
            "ips": "Suricata enabled in IPS (inline, can drop) mode"}[mode]
    return {"schema_version": "3.0", "timestamp": _now().isoformat(),
            "instance": {"device_name": row.name, "uuid": row.id, "ip_address": row.ip},
            "ioc": {"value": row.name, "type": "host"},
            "event": {"type": label, "action_taken": "MANAGE", "mode": "PREVENT" if mode == "ips" else "DETECT",
                      "severity": sev, "confidence": 100,
                      "details": {"agent": row.name, "nids_mode": mode, "note": note}}}


@app.post("/api/agents/{agent_id}/nids", dependencies=[Depends(require_token)])
def set_nids_mode(agent_id: str, body: schemas.NidsIn, db: Session = Depends(get_db)) -> dict:
    """Set a device's Suricata mode: off | ids | ips (applied within ~1 heartbeat)."""
    row = db.get(models.Agent, agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    mode = (body.mode or "").lower()
    if mode not in _NIDS_MODES:
        raise HTTPException(status_code=400, detail="mode must be one of off|ids|ips")
    if _agent_platform(row) == "windows" and mode != "off":
        raise HTTPException(status_code=409,
                            detail="Suricata IDS/IPS runs on Linux endpoints; not supported on Windows")
    row.nids_mode = mode
    _ingest_event(db, "console", _nids_event(row, mode))
    db.commit()
    return {"ok": True, "agent_id": agent_id, "nids_mode": mode}


@app.get("/api/nids")
def list_nids(db: Session = Depends(get_db)) -> dict:
    """Per-device IDS/IPS state + engine status, plus recent Suricata alerts."""
    agents = db.execute(select(models.Agent).order_by(models.Agent.last_seen.desc())).scalars().all()
    alerts = db.execute(
        select(models.Detection).where(models.Detection.event_type.in_(("IDS_ALERT", "IPS_DROP")))
        .order_by(models.Detection.ts.desc()).limit(200)).scalars().all()
    return {
        "devices": [{"agent_id": a.id, "name": a.name, "ip": a.ip, "platform": _agent_platform(a),
                     "status": a.status, "nids_mode": getattr(a, "nids_mode", "off") or "off",
                     "nids_status": getattr(a, "nids_status", {}) or {}} for a in agents],
        "alerts": [_det_dict(r) for r in alerts],
    }


# --------------------------------------------------------------------------- Suricata rules (community + custom)
_CUSTOM_RULES_KEY = "suricata_custom_rules"


def _suri_dict(r: models.SuricataRule) -> dict:
    return {"sid": r.sid, "action": r.action, "proto": r.proto, "msg": r.msg,
            "category": r.category, "source": r.source, "enabled": r.enabled}


def _custom_rules(db: Session) -> str:
    row = db.get(models.AppSetting, _CUSTOM_RULES_KEY)
    return row.value if row else ""


# SEN-005: Suricata rules are loaded by a root engine on every endpoint, so both
# operator-custom and scraped community rules are untrusted code. Sanitize before
# storage and distribution: drop rules using dangerous/stateful keywords, force
# the action to `alert` (no fleet-wide traffic drop) unless explicitly promoted,
# drop malformed lines, and cap total size.
_SURI_HEADER = re.compile(r"^\s*(alert|drop|reject|rejectsrc|rejectdst|rejectboth|pass)\s+(\S+)\s", re.I)
# Keywords that let a rule reach code/file-write or heavy state in the root engine.
_SURI_DENY = re.compile(r"\b(lua|luajit|luaxform|dataset|datarep|filestore)\b", re.I)
_SURI_MAX_LINES = 20000
_SURI_MAX_BYTES = 8_000_000
_SURI_MAX_LINE = 8000


def sanitize_suricata_rules(text: str, allow_drop: bool = False) -> "tuple[str, dict]":
    """Return (clean_text, stats). Keeps comments; drops dangerous/malformed rules;
    rewrites drop/reject -> alert unless allow_drop; enforces size caps."""
    out, kept, dropped, downgraded = [], 0, 0, 0
    total = 0
    for raw in (text or "").splitlines():
        ln = raw.rstrip("\r\n")
        s = ln.strip()
        if not s or s.startswith("#"):
            out.append(ln[:_SURI_MAX_LINE]); continue
        if len(ln) > _SURI_MAX_LINE:
            dropped += 1; continue                      # pathological single line (e.g. giant PCRE)
        m = _SURI_HEADER.match(s)
        if not m or not re.search(r"\bsid\s*:", s, re.I):
            dropped += 1; continue                      # not a well-formed rule (needs action+proto+sid)
        if _SURI_DENY.search(s):
            dropped += 1; continue                      # lua/dataset/filestore etc.
        action = m.group(1).lower()
        if action != "alert" and action != "pass" and not allow_drop:
            s = re.sub(r"^\s*(drop|reject|rejectsrc|rejectdst|rejectboth)\b", "alert", s, count=1, flags=re.I)
            downgraded += 1
        if total + len(s) + 1 > _SURI_MAX_BYTES or kept >= _SURI_MAX_LINES:
            dropped += 1; continue                      # hard cap reached
        out.append(s); kept += 1; total += len(s) + 1
    return "\n".join(out), {"kept": kept, "dropped": dropped, "downgraded": downgraded}


def _suricata_ruleset(db: Session) -> str:
    """The full ruleset distributed to agents: enabled community rules + custom.
    Community rules are untrusted -> always alert-only; custom rules were already
    sanitized on store (see set_custom_rules)."""
    rows = db.execute(select(models.SuricataRule.raw)
                      .where(models.SuricataRule.enabled.is_(True)).limit(8000)).scalars().all()
    community, _ = sanitize_suricata_rules("\n".join(r for r in rows if r), allow_drop=False)
    text = "# Padakhep Sentinel distributed Suricata ruleset\n" + community
    custom = _custom_rules(db)
    if custom.strip():
        text += "\n# --- operator custom rules ---\n" + custom.strip() + "\n"
    return text


@app.get("/api/suricata-rules")
def list_suricata_rules(limit: int = 500, source: str | None = None,
                        db: Session = Depends(get_db)) -> dict:
    q = select(models.SuricataRule)
    if source:
        q = q.where(models.SuricataRule.source == source)
    rows = db.execute(q.order_by(models.SuricataRule.updated_at.desc())
                      .limit(min(limit, 5000))).scalars().all()
    total = int(db.scalar(select(func.count()).select_from(models.SuricataRule)) or 0)
    return {"count": total, "rules": [_suri_dict(r) for r in rows]}


@app.get("/api/nids/custom")
def get_custom_rules(db: Session = Depends(get_db)) -> dict:
    rules = _custom_rules(db)
    n = sum(1 for ln in rules.splitlines() if ln.strip() and not ln.strip().startswith("#"))
    return {"rules": rules, "count": n}


@app.post("/api/nids/custom", dependencies=[Depends(require_token)])
def set_custom_rules(body: schemas.CustomRulesIn, db: Session = Depends(get_db)) -> dict:
    # SEN-005: sanitize before storing. allow_drop lets an authenticated operator
    # keep drop/reject actions (for deliberate IPS use); default is alert-only.
    clean, stats = sanitize_suricata_rules(body.rules or "", allow_drop=bool(getattr(body, "allow_drop", False)))
    row = db.get(models.AppSetting, _CUSTOM_RULES_KEY)
    if row:
        row.value, row.updated_at = clean, _now()
    else:
        db.add(models.AppSetting(key=_CUSTOM_RULES_KEY, value=clean))
    ev = {"schema_version": "3.0", "timestamp": _now().isoformat(),
          "instance": {"device_name": "control-plane"}, "ioc": {"value": "suricata-custom", "type": "ruleset"},
          "event": {"type": "SURICATA_CUSTOM_RULES_UPDATED", "action_taken": "MANAGE", "mode": "DETECT",
                    "severity": "MEDIUM", "confidence": 100,
                    "details": {"rules": stats["kept"], "dropped": stats["dropped"],
                                "downgraded": stats["downgraded"],
                                "note": "operator updated custom Suricata rules (sanitized)"}},
          "integrity": {"producer": "suricata"}}
    _ingest_event(db, "suricata", ev)
    db.commit()
    return {"ok": True, "count": stats["kept"], "dropped": stats["dropped"],
            "downgraded": stats["downgraded"]}


@app.get("/api/nids/ruleset")
def nids_ruleset(agent_id: str | None = None, db: Session = Depends(get_db)) -> dict:
    """The Suricata ruleset an agent should load (community enabled + custom)."""
    text = _suricata_ruleset(db)
    return {"version": hashlib.sha256(text.encode()).hexdigest()[:16],
            "count": text.count("\n"), "ruleset": text}


# --------------------------------------------------------------------------- log-based IDS rules
def _log_rule_dict(r: "models.LogRule") -> dict:
    return {"id": r.id, "name": r.name, "platform": r.platform, "source": r.source,
            "pattern": r.pattern, "entity_group": r.entity_group, "threshold": r.threshold,
            "window_sec": r.window_sec, "severity": r.severity, "mitre": r.mitre,
            "event_type": r.event_type, "description": r.description, "enabled": r.enabled,
            "origin": getattr(r, "origin", "builtin") or "builtin",
            "verified": bool(getattr(r, "verified", True))}


def _log_rules_for(db: Session, platform: str | None) -> list:
    """Rules distributed to agents: enabled AND verified only (unverified/staged
    Sigma imports never reach production until an operator verifies them)."""
    rows = db.execute(select(models.LogRule).where(
        models.LogRule.enabled.is_(True), models.LogRule.verified.is_(True))).scalars().all()
    out = []
    for r in rows:
        if platform and r.platform not in ("any", platform):
            continue
        out.append({"name": r.name, "source": r.source, "pattern": r.pattern,
                    "entity_group": r.entity_group, "threshold": r.threshold,
                    "window_sec": r.window_sec, "severity": r.severity, "mitre": r.mitre,
                    "event_type": r.event_type})
    return out


@app.get("/api/log-rules")
def list_log_rules(db: Session = Depends(get_db)) -> dict:
    rows = db.execute(select(models.LogRule).order_by(models.LogRule.name)).scalars().all()
    return {"count": len(rows), "rules": [_log_rule_dict(r) for r in rows]}


@app.post("/api/log-rules", dependencies=[Depends(require_token)])
def add_log_rule(body: schemas.LogRuleIn, db: Session = Depends(get_db)) -> dict:
    name = _clean(body.name, 96)
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    try:
        re.compile(body.pattern)                       # reject an invalid regex up front
    except re.error as exc:
        raise HTTPException(status_code=400, detail=f"invalid regex: {exc}")
    row = db.execute(select(models.LogRule).where(models.LogRule.name == name)).scalar_one_or_none()
    fields = dict(platform=body.platform, source=body.source, pattern=body.pattern,
                  entity_group=int(body.entity_group), threshold=int(body.threshold),
                  window_sec=int(body.window_sec), severity=body.severity, mitre=body.mitre,
                  event_type=_clean(body.event_type, 48) or "LOG_MATCH",
                  description=_clean(body.description, 256), enabled=bool(body.enabled),
                  origin="manual", verified=True)          # operator-authored = trusted
    if row:
        for k, v in fields.items():
            setattr(row, k, v)
    else:
        db.add(models.LogRule(name=name, **fields))
    db.commit()
    return {"ok": True, "name": name}


@app.post("/api/log-rules/sigma", dependencies=[Depends(require_token)])
def import_sigma_rules(body: schemas.SigmaImportIn, db: Session = Depends(get_db)) -> dict:
    """Convert one or more Sigma YAML rules into log-IDS rules. Converted rules
    are stored origin=sigma; they only distribute after passing the FP self-check
    (verified) AND being enabled. Returns a per-rule summary."""
    converted, skipped = sigma.convert_yaml(body.yaml or "")
    have = {n for (n,) in db.execute(select(models.LogRule.name)).all()}
    added, results = 0, []
    for r in converted:
        note = r.pop("verify_note", "")
        verified = bool(r.pop("verified", False))
        origin = r.pop("origin", "sigma")
        name = r["name"]
        if name in have:
            results.append({"name": name, "status": "duplicate"}); continue
        if not verified:
            r["description"] = (r["description"] + " — STAGED: " + note)[:256]
        # imported rules start disabled; verified ones may be auto-enabled on request
        enabled = bool(verified and body.enable)
        db.add(models.LogRule(origin=origin, verified=verified, enabled=enabled, **r))
        have.add(name); added += 1
        results.append({"name": name, "status": "verified" if verified else "staged",
                        "note": note, "enabled": enabled})
    db.commit()
    return {"ok": True, "converted": len(converted), "added": added,
            "verified": sum(1 for x in results if x.get("status") == "verified"),
            "staged": sum(1 for x in results if x.get("status") == "staged"),
            "skipped": [{"title": t, "reason": why} for (t, why) in skipped],
            "results": results}


@app.post("/api/log-rules/{rule_id}/verify", dependencies=[Depends(require_token)])
def verify_log_rule(rule_id: int, db: Session = Depends(get_db)) -> dict:
    """Operator promotes a reviewed staged rule to verified (it can then be enabled
    and distributed). The automated self-check result is returned as advisory so
    the operator sees the false-positive risk they are accepting."""
    row = db.get(models.LogRule, rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown log rule")
    ok, reason = sigma.verify_pattern(row.pattern, row.source)   # advisory
    row.verified = True
    db.commit()
    return {"ok": True, "id": rule_id, "verified": True,
            "self_check": ok, "advisory": reason}


@app.post("/api/log-rules/{rule_id}/toggle", dependencies=[Depends(require_token)])
def toggle_log_rule(rule_id: int, body: schemas.LogRuleToggleIn, db: Session = Depends(get_db)) -> dict:
    row = db.get(models.LogRule, rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown log rule")
    row.enabled = bool(body.enabled)
    db.commit()
    return {"ok": True, "id": rule_id, "enabled": row.enabled}


@app.delete("/api/log-rules/{rule_id}", dependencies=[Depends(require_token)])
def delete_log_rule(rule_id: int, db: Session = Depends(get_db)) -> dict:
    row = db.get(models.LogRule, rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown log rule")
    db.delete(row)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- Detection Funnel Scanner (optional)
def _store_scan_run(db: Session, report: dict, task_id: int | None) -> models.ScanRun:
    su = report.get("summary", {})
    trimmed = {"summary": su, "golden": report.get("golden", []), "failed": report.get("failed", [])}
    row = models.ScanRun(task_id=task_id, total=su.get("total", 0), passed=su.get("passed", 0),
                         failed=su.get("failed", 0), golden=su.get("golden", 0), report=trimmed)
    db.add(row)
    return row


@app.post("/api/scanner/run", dependencies=[Depends(require_token)])
def scanner_run(body: schemas.ScanRunIn, db: Session = Depends(get_db)) -> dict:
    report = scanner.run_scan(db, targets=body.targets)
    row = _store_scan_run(db, report, None)
    db.commit()
    return {"ok": True, "run_id": row.id, "summary": report["summary"],
            "golden": report["golden"], "failed": report["failed"],
            "duplicates": report.get("duplicates", [])}


@app.post("/api/scanner/promote", dependencies=[Depends(require_token)])
def scanner_promote(body: schemas.ScanRunIn, db: Session = Depends(get_db)) -> dict:
    """Promote the scan's GOLDEN rules into production. By default the funnel scanner is
    read-only — golden rules are only *shown*. This action **enables** (and marks verified)
    any golden log-rule / signature / behaviour that isn't already live, so they reach
    agents on the next policy sync. Suricata golden rules are reported but not auto-promoted
    (the scanner's name is a truncated msg, not a stable key — enable those from the NIDS view)."""
    report = scanner.run_scan(db, targets=body.targets)
    promoted = {"log_rule": 0, "signature": 0, "behavior": 0}
    suricata_golden = 0
    for g in report["golden"]:
        kind, name = g["kind"], g["name"]
        if kind == "log_rule":
            r = db.execute(select(models.LogRule).where(models.LogRule.name == name)).scalar_one_or_none()
            if r and (not r.enabled or not r.verified):
                r.enabled = True; r.verified = True; promoted["log_rule"] += 1
        elif kind == "signature":
            r = db.execute(select(models.Signature).where(models.Signature.name == name)).scalar_one_or_none()
            if r and not r.active:
                r.active = True; promoted["signature"] += 1
        elif kind == "behavior":
            r = db.execute(select(models.Behavior).where(models.Behavior.name == name)).scalar_one_or_none()
            if r and not r.active:
                r.active = True; promoted["behavior"] += 1
        elif kind == "suricata":
            suricata_golden += 1
    db.commit()
    return {"ok": True, "promoted": promoted, "promoted_total": sum(promoted.values()),
            "golden": len(report["golden"]), "suricata_golden_not_auto": suricata_golden}


@app.get("/api/scanner/runs")
def scanner_runs(limit: int = 20, db: Session = Depends(get_db)) -> dict:
    rows = db.execute(select(models.ScanRun).order_by(models.ScanRun.ran_at.desc())
                      .limit(min(limit, 100))).scalars().all()
    return {"runs": [{"id": r.id, "task_id": r.task_id,
                      "ran_at": r.ran_at.isoformat() if r.ran_at else None,
                      "total": r.total, "passed": r.passed, "failed": r.failed,
                      "golden": r.golden} for r in rows],
            "latest": (lambda r: {"summary": r.report.get("summary", {}),
                                  "golden": r.report.get("golden", []),
                                  "failed": r.report.get("failed", [])} if r else None)(
                          rows[0] if rows else None)}


def _task_dict(t: models.ScanTask) -> dict:
    return {"id": t.id, "name": t.name, "targets": t.targets, "interval_hours": t.interval_hours,
            "enabled": t.enabled, "last_run": t.last_run.isoformat() if t.last_run else None,
            "next_run": t.next_run.isoformat() if t.next_run else None}


@app.get("/api/scanner/tasks")
def scanner_tasks(db: Session = Depends(get_db)) -> dict:
    rows = db.execute(select(models.ScanTask).order_by(models.ScanTask.created_at.desc())).scalars().all()
    return {"tasks": [_task_dict(t) for t in rows],
            "open": sum(1 for t in rows if t.enabled)}


@app.post("/api/scanner/tasks", dependencies=[Depends(require_token)])
def scanner_task_create(body: schemas.ScanTaskIn, db: Session = Depends(get_db)) -> dict:
    t = models.ScanTask(name=_clean(body.name, 96) or "scan", targets=body.targets or ["log_rule"],
                        interval_hours=max(1, int(body.interval_hours)), enabled=bool(body.enabled),
                        next_run=_now())
    db.add(t)
    db.commit()
    return {"ok": True, "task": _task_dict(t)}


@app.post("/api/scanner/tasks/{task_id}/run", dependencies=[Depends(require_token)])
def scanner_task_run(task_id: int, db: Session = Depends(get_db)) -> dict:
    t = db.get(models.ScanTask, task_id)
    if t is None:
        raise HTTPException(status_code=404, detail="unknown scan task")
    report = scanner.run_scan(db, targets=t.targets or ["log_rule"])
    row = _store_scan_run(db, report, t.id)
    t.last_run = _now()
    t.next_run = _now() + timedelta(hours=max(1, t.interval_hours))
    db.commit()
    return {"ok": True, "run_id": row.id, "summary": report["summary"]}


@app.delete("/api/scanner/tasks/{task_id}", dependencies=[Depends(require_token)])
def scanner_task_delete(task_id: int, db: Session = Depends(get_db)) -> dict:
    t = db.get(models.ScanTask, task_id)
    if t is None:
        raise HTTPException(status_code=404, detail="unknown scan task")
    db.delete(t)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- dashboard aggregate
@app.get("/api/stats")
def stats(db: Session = Depends(get_db)) -> dict:
    def c(model, *where):
        q = select(func.count()).select_from(model)
        for w in where:
            q = q.where(w)
        return int(db.scalar(q) or 0)
    total_agents = c(models.Agent)
    online = c(models.Agent, models.Agent.status == "online")
    day_ago = _now() - timedelta(hours=24)
    return {
        "endpointsOnline": online, "endpointsTotal": total_agents,
        "threatsToday": c(models.Detection, models.Detection.ts >= day_ago),
        "ipsBlocked": c(models.BlockedIp, models.BlockedIp.active.is_(True)),
        "iocsTracked": c(models.Ioc, models.Ioc.active.is_(True)),
        "rulesGenerated": c(models.GeneratedRule),
        "quarantined": 0,
        "filesScanned": 0,
        "signatures": c(models.Signature),
        "behaviors": c(models.Behavior),
        "detections": c(models.Detection),
        "suricataRules": c(models.SuricataRule),
    }


@app.get("/api/dashboard")
def dashboard_data(db: Session = Depends(get_db)) -> dict:
    """One call the web dashboard can use to populate all live views."""
    # Fetch per type so a large single feed (e.g. 2000 AbuseIPDB IPs) can't crowd
    # the other types out of a global limit and make hashes/domains show as zero.
    grouped: dict[str, list] = {"ips": [], "hashes": [], "domains": [], "urls": [], "drivers": []}
    keymap = {"ip": "ips", "hash": "hashes", "domain": "domains", "url": "urls", "driver": "drivers"}
    for ioc_type, key in keymap.items():
        rows = db.execute(
            select(models.Ioc)
            .where(models.Ioc.active.is_(True), models.Ioc.type == ioc_type)
            .order_by(models.Ioc.last_seen.desc()).limit(1500)
        ).scalars().all()
        grouped[key] = [_ioc_dict(r) for r in rows]
    sigs = db.execute(select(models.Signature)).scalars().all()
    agents = db.execute(select(models.Agent).order_by(models.Agent.last_seen.desc())).scalars().all()
    dets = db.execute(select(models.Detection).order_by(models.Detection.ts.desc()).limit(200)).scalars().all()
    suri = db.execute(select(models.SuricataRule).order_by(models.SuricataRule.updated_at.desc())
                      .limit(500)).scalars().all()
    # True totals (uncapped) so the IOC & Rule Center shows real counts, not the
    # per-type page caps above — otherwise its tab badges freeze at the cap and
    # disagree with Feed Health's per-source totals.
    type_counts = dict(db.execute(
        select(models.Ioc.type, func.count())
        .where(models.Ioc.active.is_(True)).group_by(models.Ioc.type)).all())
    counts = {
        "ips": int(type_counts.get("ip", 0)),
        "hashes": int(type_counts.get("hash", 0)),
        "domains": int(type_counts.get("domain", 0)),
        "urls": int(type_counts.get("url", 0)),
        "drivers": int(type_counts.get("driver", 0)),   # LOLDrivers BYOVD hashes
        "yara": int(db.scalar(select(func.count()).select_from(models.Signature)) or 0),
        "suricata": int(db.scalar(select(func.count()).select_from(models.SuricataRule)) or 0),
        "rules": int(db.scalar(select(func.count()).select_from(models.GeneratedRule)) or 0),
    }
    return {
        "stats": stats(db),
        "iocs": grouped,
        "counts": counts,
        "suricata_rules": [_suri_dict(r) for r in suri],
        "signatures": [_sig_dict(r) for r in sigs],
        "agents": [_agent_dict(r) for r in agents],
        "groups": _groups_list(db),
        "detections": [_det_dict(r) for r in dets],
        "feeds": _feeds(db),
        "allowlist": _allowlist(db),
        "log_rules": [_log_rule_dict(r) for r in
                      db.execute(select(models.LogRule).order_by(models.LogRule.name)).scalars().all()],
        "agent_versions": _agent_manifest(),
    }


def _feeds(db: Session) -> list:
    rows = db.execute(select(models.Ioc.source, func.count()).where(models.Ioc.active.is_(True))
                      .group_by(models.Ioc.source)).all()
    by_src = {(s or "unknown"): int(n) for s, n in rows}
    last = db.scalar(select(func.max(models.Ioc.last_seen)))
    last_iso = last.isoformat() if last else None
    out = []
    # open feeds (key=None) + keyed feeds (key=the configured key, "" if unset)
    for name, key in [("ThreatFox", None), ("Emerging Threats", None), ("MalwareBazaar", None),
                      ("Feodo Tracker", None), ("Cisco Talos", None), ("LOLDrivers", None),
                      ("AlienVault OTX", settings.OTX_API_KEY),
                      ("AbuseIPDB", settings.ABUSEIPDB_API_KEY)]:
        n = by_src.get(name, 0)
        if n:
            st, note = "healthy", None
        elif key is not None and not key:      # keyed feed with no key configured
            st, note = "disabled", "API key required"
        else:
            st, note = "idle", None
        out.append({"name": name, "status": st, "ioc_count": n,
                    "last_pull": last_iso if n else None, "note": note, "trend": []})
    # VirusTotal is enrichment (rate-limited), not a bulk source
    vt_verified = int(db.scalar(select(func.count()).select_from(models.Ioc)
                                .where(models.Ioc.vt_ratio != "")) or 0)
    out.append({"name": "VirusTotal", "status": "healthy" if settings.VT_API_KEY else "disabled",
                "ioc_count": vt_verified, "last_pull": last_iso if vt_verified else None,
                "note": "enrichment - 4/min, 500/day", "trend": []})
    return out


# --------------------------------------------------------------------------- feed sync (on-demand beacon run)
# The beacon service pulls feeds on a schedule; this lets the console trigger a
# collection now. It runs in a background thread so the request returns at once,
# and the UI polls GET /api/feeds/sync for completion.
_feed_sync: dict = {"running": False, "started_at": None, "finished_at": None,
                    "iocs_upserted": 0, "error": None}
_feed_sync_lock = threading.Lock()


def _run_feed_sync() -> None:
    try:
        from ..beacon import beacon
        n = beacon.run_once()
        _feed_sync["iocs_upserted"] = int(n or 0)
        _feed_sync["error"] = None
    except Exception as exc:                # never let a feed error crash the thread
        _feed_sync["error"] = repr(exc)
    finally:
        _feed_sync["running"] = False
        _feed_sync["finished_at"] = _now().isoformat()


@app.post("/api/feeds/sync", dependencies=[Depends(require_token)])
def sync_feeds() -> dict:
    """Kick off a threat-intel feed collection now (non-blocking)."""
    with _feed_sync_lock:
        if _feed_sync["running"]:
            return {"ok": True, "already_running": True, "started_at": _feed_sync["started_at"]}
        _feed_sync.update(running=True, started_at=_now().isoformat(), finished_at=None, error=None)
    threading.Thread(target=_run_feed_sync, daemon=True).start()
    return {"ok": True, "started": True, "started_at": _feed_sync["started_at"]}


@app.get("/api/feeds/sync")
def sync_feeds_status() -> dict:
    return dict(_feed_sync)


# --------------------------------------------------------------------------- dashboard (static)
@app.get("/")
def dashboard_root():
    index = os.path.join(settings.WEBUI_DIR, "index.html")
    if os.path.exists(index):
        return FileResponse(index)
    return JSONResponse({"detail": "dashboard not found; set SENTINEL_WEBUI", "api": "/api"},
                        status_code=200)
