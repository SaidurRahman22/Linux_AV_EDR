"""Shared DB helpers used by both the API and the beacon."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from . import models


def upsert_ioc(db, ioc_type: str, value: str, source: str = "", malware: str = "",
               confidence: int = 60, ttl_days: int | None = 30) -> "models.Ioc | None":
    value = (value or "").strip()
    if not value:
        return None
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=ttl_days) if ttl_days else None
    row = db.execute(
        select(models.Ioc).where(models.Ioc.type == ioc_type, models.Ioc.value == value)
    ).scalar_one_or_none()
    if row:
        row.last_seen = now
        row.source = source or row.source
        row.malware = malware or row.malware
        row.confidence = max(row.confidence or 0, confidence)
        row.expires_at = expires
        row.active = True
    else:
        row = models.Ioc(type=ioc_type, value=value, source=source, malware=malware,
                         confidence=confidence, first_seen=now, last_seen=now,
                         expires_at=expires, active=True)
        db.add(row)
    return row
