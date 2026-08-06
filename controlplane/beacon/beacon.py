"""Threat-Intel Beacon — 24/7 worker that fills the central IOC database.

Run once:   python -m controlplane.beacon.beacon --once
Run daemon: python -m controlplane.beacon.beacon        (loops every BEACON_INTERVAL)
"""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select

from ..app import crud, models
from ..app.config import settings
from ..app.db import SessionLocal, init_db
from . import feeds
from .feeds import collect_all


def _log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).astimezone().isoformat()}] beacon: {msg}", flush=True)


def _abuse_state_path() -> str:
    return os.path.join(settings.repo_root, "abuseipdb_state.json")


def _abuse_due() -> bool:
    """AbuseIPDB free tier 429s if the blacklist is pulled hourly. Gate it to
    settings.ABUSEIPDB_INTERVAL_H so we stay within quota."""
    try:
        with open(_abuse_state_path(), encoding="utf-8") as f:
            last = datetime.fromisoformat(json.load(f).get("last_pull"))
    except Exception:
        return True
    hours = (datetime.now(timezone.utc) - last).total_seconds() / 3600.0
    return hours >= float(getattr(settings, "ABUSEIPDB_INTERVAL_H", 12))


def _abuse_mark() -> None:
    try:
        with open(_abuse_state_path(), "w", encoding="utf-8") as f:
            json.dump({"last_pull": datetime.now(timezone.utc).isoformat()}, f)
    except OSError:
        pass


def run_once() -> int:
    init_db()
    do_abuse = _abuse_due()
    if do_abuse:
        _abuse_mark()          # mark on attempt: caps calls at ~2/day even if the pull 429s
    rows = collect_all(settings, log=lambda m: print(m, flush=True), include_abuseipdb=do_abuse)
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
    try:
        sync_yara_repo()                    # interval-gated; no-op until due
    except Exception as exc:
        _log(f"YARA repo sync error: {exc!r}")
    try:
        sync_suricata_rules()               # scrape community/open Suricata rules
    except Exception as exc:
        _log(f"Suricata rules sync error: {exc!r}")
    try:
        sync_sigma_rules()                  # scrape community Sigma -> staged log rules
    except Exception as exc:
        _log(f"Sigma rules sync error: {exc!r}")
    try:
        sync_loldrivers()                   # LOLDrivers BYOVD hash set -> Windows agents
    except Exception as exc:
        _log(f"LOLDrivers sync error: {exc!r}")
    try:
        run_due_scans()                     # Detection Funnel Scanner scheduled tasks
    except Exception as exc:
        _log(f"scan task error: {exc!r}")
    return n


def run_due_scans() -> int:
    """Run any Detection Funnel Scanner task whose next_run is due (optional feature)."""
    from ..app import scanner
    now = datetime.now(timezone.utc)
    db = SessionLocal()
    ran = 0
    try:
        tasks = db.execute(select(models.ScanTask).where(models.ScanTask.enabled.is_(True))).scalars().all()
        for t in tasks:
            nr = t.next_run
            if nr is not None and nr.tzinfo is None:
                nr = nr.replace(tzinfo=timezone.utc)
            if nr is not None and nr > now:
                continue
            report = scanner.run_scan(db, targets=t.targets or ["log_rule"])
            su = report.get("summary", {})
            db.add(models.ScanRun(task_id=t.id, total=su.get("total", 0), passed=su.get("passed", 0),
                                  failed=su.get("failed", 0), golden=su.get("golden", 0),
                                  report={"summary": su, "golden": report.get("golden", []),
                                          "failed": report.get("failed", [])}))
            t.last_run = now
            t.next_run = now + timedelta(hours=max(1, t.interval_hours))
            ran += 1
        db.commit()
    finally:
        db.close()
    if ran:
        _log(f"funnel scanner: ran {ran} scheduled scan(s)")
    return ran


def _sigma_state_path() -> str:
    return os.path.join(settings.repo_root, "sigma_repo_state.json")


def _sigma_due() -> bool:
    try:
        with open(_sigma_state_path(), encoding="utf-8") as f:
            last = datetime.fromisoformat(json.load(f).get("last_sync"))
    except Exception:
        return True
    return (datetime.now(timezone.utc) - last).total_seconds() / 3600.0 >= float(settings.SIGMA_REPO_INTERVAL_H)


def _sigma_mark() -> None:
    try:
        with open(_sigma_state_path(), "w", encoding="utf-8") as f:
            json.dump({"last_sync": datetime.now(timezone.utc).isoformat()}, f)
    except OSError:
        pass


def sync_sigma_rules(force: bool = False) -> int:
    """Scrape community Sigma rules from configured GitHub dirs, convert them to
    log-IDS rules, and store them STAGED (verified per the FP self-check, always
    disabled). Nothing reaches agents until an operator verifies + enables it.
    Default OFF; interval-gated."""
    if not getattr(settings, "SIGMA_REPO_ENABLED", False):
        return 0
    if not force and not _sigma_due():
        return 0
    import urllib.request
    from ..app import sigma
    from .feeds import _safe_urlopen           # SEN-015: SSRF guard (scheme/IP allow-list + redirect re-validation)
    ua = {"User-Agent": "padakhep-sentinel-beacon/1.0", "Accept": "application/vnd.github+json"}
    if settings.GITHUB_TOKEN:
        ua["Authorization"] = "Bearer " + settings.GITHUB_TOKEN
    added, fetched, staged = 0, 0, 0
    db = SessionLocal()
    try:
        have = {n for (n,) in db.execute(select(models.LogRule.name)).all()}
        for api in [u.strip() for u in settings.SIGMA_REPO_API.split(",") if u.strip()]:
            if fetched >= settings.SIGMA_REPO_MAX_FILES:
                break
            try:
                listing = json.load(_safe_urlopen(urllib.request.Request(api, headers=ua), timeout=30))
            except Exception as exc:
                _log(f"  ! Sigma listing failed: {api} ({exc})"); continue
            if not isinstance(listing, list):
                continue
            for item in listing:
                if fetched >= settings.SIGMA_REPO_MAX_FILES:
                    break
                nm = item.get("name", "")
                if item.get("type") != "file" or not nm.endswith((".yml", ".yaml")):
                    continue
                url = item.get("download_url")
                if not url:
                    continue
                try:
                    text = _safe_urlopen(
                        urllib.request.Request(url, headers={"User-Agent": ua["User-Agent"]}),
                        timeout=30).read().decode("utf-8", "replace")
                except Exception:
                    continue
                fetched += 1
                rules, _ = sigma.convert_yaml(text)
                for r in rules:
                    note = r.pop("verify_note", ""); ok = bool(r.pop("verified", False)); origin = r.pop("origin", "sigma")
                    if r["name"] in have:
                        continue
                    if not ok:
                        r["description"] = (r["description"] + " — STAGED: " + note)[:256]; staged += 1
                    db.add(models.LogRule(origin=origin, verified=ok, enabled=False, **r))
                    have.add(r["name"]); added += 1
        db.commit()
    finally:
        db.close()
    _sigma_mark()
    _log(f"Sigma rules: {added} imported from {fetched} file(s) ({staged} staged for review)")
    return added


def sync_suricata_rules() -> int:
    """Scrape community/open-source Suricata rules into the DB (for display +
    distribution to agents). Runs every beacon cycle; upserts are idempotent."""
    if os.environ.get("SENTINEL_SURICATA_RULES", "1") in ("0", "false", ""):
        return 0
    urls = os.environ.get("SENTINEL_SURICATA_RULE_URLS", "")
    maxr = int(os.environ.get("SENTINEL_SURICATA_RULES_MAX", "6000"))
    rules = feeds.collect_suricata_rules(urls, max_rules=maxr, log=lambda m: print(m, flush=True))
    db = SessionLocal()
    added, seen = 0, set()
    try:
        for r in rules:
            if r["key"] in seen:            # intra-run dedup (avoid unique-constraint clash)
                continue
            seen.add(r["key"])
            if crud.upsert_suricata_rule(db, r):
                added += 1
        db.commit()
    finally:
        db.close()
    _log(f"Suricata rules: {len(seen)} scraped ({added} new)")
    return added


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


# YARA externals commonly referenced by community rules — define them so more
# rules compile (agents pass the real values at match time).
_YARA_EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "",
                   "owner": "", "md5": ""}


def _yara_repo_state_path() -> str:
    return os.path.join(settings.repo_root, "yara_repo_state.json")


def _yara_repo_due() -> bool:
    try:
        with open(_yara_repo_state_path(), encoding="utf-8") as f:
            last = datetime.fromisoformat(json.load(f).get("last_sync"))
    except Exception:
        return True
    hours = (datetime.now(timezone.utc) - last).total_seconds() / 3600.0
    return hours >= float(settings.YARA_REPO_INTERVAL_H)


def _yara_repo_mark() -> None:
    try:
        with open(_yara_repo_state_path(), "w", encoding="utf-8") as f:
            json.dump({"last_sync": datetime.now(timezone.utc).isoformat()}, f)
    except OSError:
        pass


def sync_yara_repo(force: bool = False) -> int:
    """Scheduled pull of community YARA rules into the signatures table."""
    if not getattr(settings, "YARA_REPO_ENABLED", False):
        return 0
    if not force and not _yara_repo_due():
        return 0
    try:
        import yara  # validate rules before storing (Linux control plane, no AV)
    except Exception:
        yara = None
    from ..app import rulepacks
    files = feeds.collect_yara_repo(settings.YARA_REPO_API,
                                    max_files=int(settings.YARA_REPO_MAX_FILES),
                                    token=settings.GITHUB_TOKEN,
                                    log=lambda m: print(m, flush=True))
    cap = int(settings.YARA_REPO_MAX_RULES)
    db = SessionLocal()
    added = 0
    try:
        have = set(db.execute(select(models.Signature.name)).scalars().all())
        for fname, text in files:
            if added >= cap:
                break
            for name, source, sev, mitre in rulepacks.split_yara(text):
                if added >= cap or name in have:
                    continue
                if yara is not None:
                    try:
                        yara.compile(source=source, externals=_YARA_EXTERNALS)
                    except Exception:
                        continue                       # skip rules needing modules/externals we lack
                have.add(name)
                db.add(models.Signature(name=name, kind="yara", content=source,
                                        severity=sev or "HIGH", mitre=mitre,
                                        source="repo:" + fname[:40]))
                added += 1
        db.commit()
    finally:
        db.close()
    _yara_repo_mark()
    _log(f"YARA repo sync: added {added} new rules ({'validated' if yara else 'unvalidated'})")
    return added


def sync_loldrivers(force: bool = False) -> int:
    """Pull the LOLDrivers known-bad kernel-driver hash set (BYOVD) and store each hash
    as an IOC (type='driver', source='LOLDrivers') so it shows in Feed Health and the
    IOC view. sync_policy serves these to Windows agents as bad_driver_hashes. Interval-
    gated via the newest LOLDrivers IOC's last_seen (no expiry — refreshed each sync)."""
    if not getattr(settings, "LOLDRIVERS_ENABLED", True):
        return 0
    from sqlalchemy import func
    db = SessionLocal()
    try:
        if not force:
            last = db.scalar(select(func.max(models.Ioc.last_seen)).where(models.Ioc.source == "LOLDrivers"))
            if last:
                t = last.replace(tzinfo=timezone.utc) if last.tzinfo is None else last
                if (datetime.now(timezone.utc) - t).total_seconds() / 3600.0 < float(settings.LOLDRIVERS_INTERVAL_H):
                    return 0
        hashes = feeds.collect_loldrivers(settings.LOLDRIVERS_API,
                                          max_hashes=int(settings.LOLDRIVERS_MAX),
                                          log=lambda m: print(m, flush=True))
        if not hashes:
            return 0
        n = 0
        for h in hashes:
            if crud.upsert_ioc(db, "driver", h, source="LOLDrivers", malware="vulnerable-driver",
                               confidence=90, ttl_days=None):   # no expiry; refreshed each sync
                n += 1
        db.commit()
        _log(f"LOLDrivers sync: {n} driver-hash IOCs (source=LOLDrivers)")
        return n
    finally:
        db.close()


def main() -> None:
    ap = argparse.ArgumentParser(prog="sentinel-beacon")
    ap.add_argument("--once", action="store_true", help="collect once then exit")
    ap.add_argument("--interval", type=int, default=settings.BEACON_INTERVAL,
                    help="seconds between collections (daemon mode)")
    ap.add_argument("--yara-repo", action="store_true",
                    help="force a YARA-rule-repo sync now, then exit")
    args = ap.parse_args()
    if args.yara_repo:
        init_db()
        sync_yara_repo(force=True)
        return
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
