"""Padakhep Sentinel control-plane API (FastAPI).

The hub the beacon writes to, the dashboard reads from, and (later increments)
the AV agents pull IOCs/policy from and report detections to.
"""

from __future__ import annotations

import ipaddress
import os
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import crud, models, schemas
from .config import settings
from .db import get_db, init_db
from .seed import seed

app = FastAPI(title="Padakhep Sentinel — Control Plane", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def _startup() -> None:
    init_db()
    from .db import SessionLocal
    db = SessionLocal()
    try:
        seed(db)
    finally:
        db.close()


def require_token(authorization: str | None = Header(default=None)) -> None:
    """Optional shared-secret gate (mTLS arrives later). Open if API_TOKEN unset."""
    if not settings.API_TOKEN:
        return
    if authorization != f"Bearer {settings.API_TOKEN}":
        raise HTTPException(status_code=401, detail="invalid or missing token")


def _now() -> datetime:
    return datetime.now(timezone.utc)


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
            "cpu": r.cpu or 0, "mem": r.mem or 0, "spark": r.spark or [],
            "last_seen": r.last_seen.isoformat() if r.last_seen else None}


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
def enroll(body: schemas.EnrollIn, db: Session = Depends(get_db)) -> dict:
    aid = body.agent_id or uuid.uuid4().hex
    row = db.get(models.Agent, aid)
    if row is None:
        row = models.Agent(id=aid, name=body.name)
        db.add(row)
    row.name, row.ip, row.os = body.name, body.ip, body.os
    row.kernel, row.version, row.status, row.last_seen = body.kernel, body.version, "online", _now()
    db.commit()
    return {"agent_id": aid, "policy_version": row.policy_version}


@app.post("/api/agents/{agent_id}/heartbeat")
def heartbeat(agent_id: str, body: schemas.HeartbeatIn, db: Session = Depends(get_db)) -> dict:
    row = db.get(models.Agent, agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    row.status, row.last_seen, row.policy_version = body.status, _now(), body.policy_version
    row.cpu, row.mem = int(body.cpu or 0), int(body.mem or 0)
    hist = list(row.spark or [])[-15:]
    hist.append(int(body.cpu or 0))
    row.spark = hist          # reassign so SQLAlchemy tracks the JSON change
    db.commit()
    return {"ok": True}


@app.get("/api/agents")
def list_agents(db: Session = Depends(get_db)) -> dict:
    rows = db.execute(select(models.Agent).order_by(models.Agent.last_seen.desc())).scalars().all()
    return {"count": len(rows), "agents": [_agent_dict(r) for r in rows]}


# --------------------------------------------------------------------------- detections
@app.post("/api/detections", dependencies=[Depends(require_token)])
def ingest_detections(body: schemas.DetectionsIn, db: Session = Depends(get_db)) -> dict:
    n = 0
    for ev in body.events:
        e = ev.get("event", {}) if isinstance(ev, dict) else {}
        ioc = ev.get("ioc", {}) if isinstance(ev, dict) else {}
        inst = ev.get("instance", {}) if isinstance(ev, dict) else {}
        mitre = (ev.get("mitre_attack", {}) or {}).get("technique_ids", [])
        db.add(models.Detection(
            agent_id=body.agent_id or inst.get("uuid", ""),
            device_name=inst.get("device_name", ""),
            event_type=e.get("type", ""),
            ioc_value=ioc.get("value", ""), ioc_type=ioc.get("type", ""),
            severity=e.get("severity", ""), confidence=int(e.get("confidence", 0) or 0),
            mode=e.get("mode", "DETECT"), action_taken=e.get("action_taken", "DETECTED"),
            mitre=mitre, producer=body.producer or ev.get("integrity", {}).get("producer", ""),
            event=ev,
        ))
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
def sync_policy(agent_id: str | None = None, db: Session = Depends(get_db)) -> dict:
    iocs = db.execute(select(models.Ioc).where(models.Ioc.active.is_(True))).scalars().all()
    sigs = db.execute(select(models.Signature).where(models.Signature.active.is_(True))).scalars().all()
    behs = db.execute(select(models.Behavior).where(models.Behavior.active.is_(True))).scalars().all()
    version = int(_now().timestamp())
    return {
        "policy_version": version,
        "iocs": [{"type": r.type, "value": r.value, "confidence": r.confidence,
                  "source": r.source} for r in iocs],
        "signatures": [{"name": r.name, "kind": r.kind, "content": r.content,
                        "severity": r.severity, "mitre": r.mitre} for r in sigs],
        "behaviors": [{"name": r.name, "rule": r.rule, "severity": r.severity,
                       "mitre": r.mitre} for r in behs],
    }


# --------------------------------------------------------------------------- blocked IPs (manual)
@app.get("/api/blocked")
def list_blocked(db: Session = Depends(get_db)) -> dict:
    rows = db.execute(select(models.BlockedIp).where(models.BlockedIp.active.is_(True))
                      .order_by(models.BlockedIp.created_at.desc())).scalars().all()
    return {"count": len(rows), "blocked": [
        {"id": r.id, "ip": r.ip, "reason": r.reason, "source": r.source,
         "created_at": r.created_at.isoformat() if r.created_at else None} for r in rows]}


@app.post("/api/blocked", dependencies=[Depends(require_token)])
def add_blocked(body: schemas.BlockIn, db: Session = Depends(get_db)) -> dict:
    ip = (body.ip or "").strip()
    try:
        ipaddress.ip_network(ip, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP or CIDR")
    exists = db.execute(select(models.BlockedIp).where(
        models.BlockedIp.ip == ip, models.BlockedIp.active.is_(True))).scalar_one_or_none()
    if exists:
        return {"ok": True, "id": exists.id, "note": "already blocked"}
    row = models.BlockedIp(ip=ip, reason=body.reason or "", source="manual")
    db.add(row)
    db.commit()
    return {"ok": True, "id": row.id}


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
    }


@app.get("/api/dashboard")
def dashboard_data(db: Session = Depends(get_db)) -> dict:
    """One call the web dashboard can use to populate all live views."""
    iocs = db.execute(select(models.Ioc).where(models.Ioc.active.is_(True))
                      .order_by(models.Ioc.last_seen.desc()).limit(2000)).scalars().all()
    grouped: dict[str, list] = {"ips": [], "hashes": [], "domains": [], "urls": []}
    keymap = {"ip": "ips", "hash": "hashes", "domain": "domains", "url": "urls"}
    for r in iocs:
        grouped.get(keymap.get(r.type, "ips"), grouped["ips"]).append(_ioc_dict(r))
    sigs = db.execute(select(models.Signature)).scalars().all()
    agents = db.execute(select(models.Agent).order_by(models.Agent.last_seen.desc())).scalars().all()
    dets = db.execute(select(models.Detection).order_by(models.Detection.ts.desc()).limit(200)).scalars().all()
    return {
        "stats": stats(db),
        "iocs": grouped,
        "signatures": [_sig_dict(r) for r in sigs],
        "agents": [_agent_dict(r) for r in agents],
        "detections": [_det_dict(r) for r in dets],
        "feeds": _feeds(db),
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
                      ("Feodo Tracker", None), ("AlienVault OTX", settings.OTX_API_KEY),
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


# --------------------------------------------------------------------------- dashboard (static)
@app.get("/")
def dashboard_root():
    index = os.path.join(settings.WEBUI_DIR, "index.html")
    if os.path.exists(index):
        return FileResponse(index)
    return JSONResponse({"detail": "dashboard not found; set SENTINEL_WEBUI", "api": "/api"},
                        status_code=200)
