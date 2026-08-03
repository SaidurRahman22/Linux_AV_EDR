"""Threat-Intel Beacon — 24/7 worker that fills the central IOC database.

Run once:   python -m controlplane.beacon.beacon --once
Run daemon: python -m controlplane.beacon.beacon        (loops every BEACON_INTERVAL)
"""

from __future__ import annotations

import argparse
import time
from datetime import datetime, timezone

from ..app import crud
from ..app.config import settings
from ..app.db import SessionLocal, init_db
from .feeds import collect_all


def _log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).astimezone().isoformat()}] beacon: {msg}", flush=True)


def run_once() -> int:
    init_db()
    rows = collect_all(settings, log=lambda m: print(m, flush=True))
    db = SessionLocal()
    n = 0
    try:
        for typ, value, source, conf, malware in rows:
            if crud.upsert_ioc(db, typ, value, source=source, malware=malware,
                               confidence=conf, ttl_days=settings.IOC_TTL_DAYS):
                n += 1
        db.commit()
    finally:
        db.close()
    _log(f"upserted {n} IOCs into the database")
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
