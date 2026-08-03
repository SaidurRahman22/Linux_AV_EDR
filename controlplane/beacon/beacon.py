"""Threat-Intel Beacon — 24/7 worker that fills the central IOC database.

Run once:   python -m controlplane.beacon.beacon --once
Run daemon: python -m controlplane.beacon.beacon        (loops every BEACON_INTERVAL)
"""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import date, datetime, timezone

from sqlalchemy import select

from ..app import crud, models
from ..app.config import settings
from ..app.db import SessionLocal, init_db
from . import feeds
from .feeds import collect_all


def _log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).astimezone().isoformat()}] beacon: {msg}", flush=True)


def run_once() -> int:
    init_db()
    rows = collect_all(settings, log=lambda m: print(m, flush=True))
    # de-duplicate within this run (same IOC can come from multiple feeds) — otherwise
    # two pending inserts of the same (type, value) violate the unique constraint at commit.
    uniq: dict = {}
    for typ, value, source, conf, malware in rows:
        key = (typ, (value or "").strip().lower())
        prev = uniq.get(key)
        if prev is None or conf > prev[3]:
            uniq[key] = (typ, value, source, conf, malware)
    db = SessionLocal()
    n = 0
    try:
        for typ, value, source, conf, malware in uniq.values():
            if crud.upsert_ioc(db, typ, value, source=source, malware=malware,
                               confidence=conf, ttl_days=settings.IOC_TTL_DAYS):
                n += 1
        db.commit()
    finally:
        db.close()
    _log(f"upserted {n} IOCs into the database")
    enrich_vt()
    return n


def _vt_usage_path() -> str:
    return os.path.join(settings.repo_root, "vt_usage.json")


def _load_vt_usage() -> dict:
    try:
        with open(_vt_usage_path(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"date": "", "count": 0}


def _save_vt_usage(u: dict) -> None:
    try:
        with open(_vt_usage_path(), "w", encoding="utf-8") as f:
            json.dump(u, f)
    except OSError:
        pass


def enrich_vt() -> int:
    """Enrich a few unverified hash IOCs via VirusTotal, honoring 4/min + daily cap."""
    key = settings.VT_API_KEY
    if not key:
        print("  - VirusTotal: skipped (set VT_API_KEY to enable)", flush=True)
        return 0
    today = date.today().isoformat()
    usage = _load_vt_usage()
    if usage.get("date") != today:
        usage = {"date": today, "count": 0}
    budget = min(int(settings.VT_PER_RUN), int(settings.VT_DAILY_CAP) - usage["count"])
    if budget <= 0:
        print(f"  - VirusTotal: daily quota reached ({usage['count']}/{settings.VT_DAILY_CAP})", flush=True)
        return 0
    db = SessionLocal()
    n = 0
    try:
        rows = db.execute(select(models.Ioc).where(
            models.Ioc.type == "hash", models.Ioc.vt_checked.is_(False)).limit(budget)).scalars().all()
        for i, row in enumerate(rows):
            if i > 0:
                time.sleep(float(settings.VT_MIN_INTERVAL))   # <= 4 lookups / min
            try:
                res = feeds.vt_lookup_hash(key, row.value)
            except Exception as exc:
                print(f"  ! VT {row.value[:12]}: {exc}", flush=True)
                continue
            row.vt_checked = True
            usage["count"] += 1
            if res.get("found"):
                row.vt_malicious = int(res.get("malicious", 0))
                row.vt_ratio = res.get("ratio", "")
                if res.get("malicious", 0) >= 3:
                    row.confidence = max(row.confidence or 0, min(98, 70 + int(res["malicious"])))
                    if res.get("label"):
                        row.malware = res["label"][:120]
            n += 1
        db.commit()
    finally:
        db.close()
    _save_vt_usage(usage)
    print(f"  + VirusTotal: enriched {n} hashes ({usage['count']}/{settings.VT_DAILY_CAP} today)", flush=True)
    return n


def main() -> None:
    ap = argparse.ArgumentParser(prog="sentinel-beacon")
    ap.add_argument("--once", action="store_true", help="collect once then exit")
    ap.add_argument("--interval", type=int, default=settings.BEACON_INTERVAL,
                    help="seconds between collections (daemon mode)")
    args = ap.parse_args()
    _log(f"started (interval={args.interval}s, db={settings.DATABASE_URL.split('@')[-1]})")
    while True:
        try:
            run_once()
        except Exception as exc:            # never let one failure kill the daemon
            _log(f"ERROR: {exc!r}")
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
