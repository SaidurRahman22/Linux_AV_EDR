"""Automated threat hunter — scheduled Wazuh-alert sweep -> enrich -> auto-block.

Replicates the manual SOC workflow as a self-contained, idempotent, guard-railed job:

  1. Read Wazuh alerts over a lookback window (default 30 days; operator-overridable).
  2. Aggregate external source IPs + their attack behaviour (secret-file probing, exploit
     scans, SSH/auth brute-force, admin-panel recon, SQLi, traversal) and their country.
  3. Cross-check each candidate against the Sentinel Threat-Intel IOCs + AbuseIPDB (cached).
  4. DECIDE per IP with a conservative, "double bulletproof" policy:
        - never touch allow-listed / own-infra / control-plane / private / already-blocked IPs
        - foreign + confirmed-malicious (IOC hit OR AbuseIPDB>=90 OR clear attack)  -> BLOCK
        - Bangladesh IPs are NEVER hard-blocked; strong-signal ones are tagged "Bangladesh"
          for manual review, weak ones are skipped (they are poorly-rated but usually legit)
        - a hard cap on auto-blocks per run stops any runaway
  5. Auto-block the confirmed set globally (source="auto"); tag the BD-review set.
  6. Synthesise candidate detection rules from the confirmed-malicious traffic, gated by the
     false-positive self-check (staged if it can't be proven safe) and de-duplicated.
  7. Record the run (ThreatHuntRun) for the console.

Idempotency ("avoid duplication"): re-running over an overlapping window creates NO duplicate
blocks or rules — already-active blocks are skipped, reputation lookups are cached, and
synthesised rules are de-duplicated by normalized pattern. Safe to run on a 12-hour timer.

Run manually:   python -m controlplane.app.threathunter --days 30 [--dry-run]
"""
from __future__ import annotations

import argparse
import collections
import glob
import gzip
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

try:
    import fcntl                                          # POSIX advisory lock (control plane is Linux)
except ImportError:                                       # pragma: no cover (Windows dev box)
    fcntl = None

from sqlalchemy import select, func

from .db import SessionLocal
from .config import settings
from . import models

# ------------------------------------------------------------------ tunables (env-overridable)
DEFAULT_DAYS = int(os.environ.get("SENTINEL_THREATHUNT_DAYS", "30"))
ALERTS_DIR = os.environ.get("SENTINEL_WAZUH_ALERTS_DIR", "/var/ossec/logs/alerts")
ABUSE_BLOCK_MIN = int(os.environ.get("SENTINEL_THREATHUNT_ABUSE_MIN", "90"))   # AbuseIPDB score => malicious
ABUSE_CACHE_DAYS = int(os.environ.get("SENTINEL_THREATHUNT_CACHE_DAYS", "7"))  # don't re-query within
MIN_ALERTS = int(os.environ.get("SENTINEL_THREATHUNT_MIN_ALERTS", "8"))       # ignore trivial noise
BD_REVIEW_MIN = int(os.environ.get("SENTINEL_THREATHUNT_BD_MIN", "500"))       # BD tag-for-review threshold
MAX_BLOCKS = int(os.environ.get("SENTINEL_THREATHUNT_MAX_BLOCKS", "80"))       # runaway backstop / run
MAX_RULES = int(os.environ.get("SENTINEL_THREATHUNT_MAX_RULES", "6"))          # rule-synthesis cap / run
# Own public infrastructure that must NEVER be blocked even if it dominates the logs (e.g. a
# reverse proxy whose IP appears as the source for all traffic). Extend via env (comma list).
# The org's own server 118.179.149.162 is ALWAYS allow-listed; the env is ADDITIVE (does not replace it).
OWN_INFRA = {"118.179.149.162"} | {ip.strip() for ip in os.environ.get(
    "SENTINEL_THREATHUNT_ALLOWLIST", "").split(",") if ip.strip()}

_PRIV = re.compile(r'^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|0\.0\.0\.0)')
_IPRE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

# Behaviour signatures matched against the request URL of a web alert.
_BEHAV = {
    "secret_file_probe": re.compile(r'/\.env|/\.git/|/\.aws/|/\.ssh/|wp-config|/\.htpasswd|id_rsa|credentials\.json|/\.svn/'),
    "exploit_scan":      re.compile(r'/boaform|/HNAP1|/GponForm|/cgi-bin/(?:mainfunction|luci|kerbynet)|/vendor/phpunit|\?s=/index/think', re.I),
    "sqli":              re.compile(r'union(?:\s|%20|\+)+select|\bor(?:\s|%20|\+)+1=1\b|information_schema|sleep\(', re.I),
    "traversal":         re.compile(r'\.\./|/etc/passwd|%2e%2e', re.I),
    "admin_probe":       re.compile(r'/wp-login|/wp-admin|/phpmyadmin|/administrator|/manager/html|/actuator/', re.I),
    "shell_probe":       re.compile(r'\.php\b|/shell|eval\(|base64_decode', re.I),
}
_STRONG = ("secret_file_probe", "exploit_scan", "sqli", "traversal")   # unambiguous attack


def _log(msg):
    print(f"[{datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')}] threathunt: {msg}", flush=True)


# ------------------------------------------------------------------ 1) read + aggregate alerts
def _mtime(f):
    try:
        return os.path.getmtime(f)                         # a file rotated away mid-scan must not crash us
    except OSError:
        return 0


def _alert_files(days):
    files = [os.path.join(ALERTS_DIR, "alerts.json")]
    cutoff = time.time() - days * 86400 - 86400            # +1 day slack for rotation timing
    rot = [f for f in glob.glob(os.path.join(ALERTS_DIR, "*/*/ossec-alerts-*.json*"))
           if not f.endswith(".sum")]
    files += [f for f in rot if _mtime(f) >= cutoff]
    return [f for f in files if os.path.exists(f)]


def _open(f):
    return gzip.open(f, "rt", errors="replace") if f.endswith(".gz") else open(f, "r", errors="replace")


def aggregate(days):
    """Aggregate external source IPs from Wazuh alerts within the window."""
    since_date = (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()
    ips = collections.defaultdict(lambda: {"count": 0, "maxlevel": 0, "cats": collections.Counter(),
                                           "rules": collections.Counter(), "urls": set(),
                                           "country": "", "agents": set()})
    scanned = 0
    for f in _alert_files(days):
        try:
            with _open(f) as fh:
                for line in fh:
                    if not line.startswith("{"):
                        continue
                    try:
                        a = json.loads(line)
                    except Exception:
                        continue
                    scanned += 1
                    ts = a.get("timestamp", "")
                    if ts and ts[:10] < since_date:        # date-level filter (tz-safe; files pre-filtered by mtime)
                        continue
                    d = a.get("data", {}) or {}
                    srcip = (d.get("srcip") or "").split(":")[0].strip()
                    if not _IPRE.match(srcip) or _PRIV.match(srcip):
                        continue
                    rule = a.get("rule", {}) or {}
                    groups = set(rule.get("groups", []) or [])
                    lvl = int(rule.get("level", 0) or 0)
                    if not (groups & {"attack", "web", "authentication_failed", "authentication_failures",
                                      "recon", "intrusion_detection", "sshd", "brute_force",
                                      "sql_injection", "invalid_login"} or lvl >= 6):
                        continue
                    r = ips[srcip]
                    r["count"] += 1
                    r["maxlevel"] = max(r["maxlevel"], lvl)
                    r["rules"][rule.get("description", "")[:60]] += 1
                    if groups & {"sshd", "authentication_failed", "authentication_failures", "brute_force"}:
                        r["cats"]["sshd_bruteforce"] += 1
                    url = d.get("url", "")
                    if url:
                        if len(r["urls"]) < 8:
                            r["urls"].add(url[:100])
                        for cat, rx in _BEHAV.items():
                            if rx.search(url):
                                r["cats"][cat] += 1
                    geo = (a.get("GeoLocation", {}) or {}).get("country_name", "")
                    if geo:
                        r["country"] = geo
                    ag = (a.get("agent", {}) or {}).get("name", "")
                    if ag:
                        r["agents"].add(ag)
        except OSError as exc:
            _log(f"cannot read {f}: {exc!r}")
    return ips, scanned


# ------------------------------------------------------------------ 2) allow-list (never block these)
def build_allowlist(db):
    allow = set(OWN_INFRA)
    nets = []
    # control-plane host
    for h in (getattr(settings, "CONTROL_PLANE_IP", "") or "", os.environ.get("SENTINEL_HOST", "")):
        h = (h or "").strip()
        if _IPRE.match(h):
            allow.add(h)
    # every monitored agent's own IP — never firewall your own fleet
    try:
        for a in db.execute(select(models.Agent)).scalars().all():
            if a.ip and _IPRE.match(a.ip.split(":")[0]):
                allow.add(a.ip.split(":")[0])
    except Exception:
        pass
    # operator allow-list entries (ips / CIDRs)
    try:
        for e in db.execute(select(models.AllowlistEntry).where(models.AllowlistEntry.active.is_(True))).scalars().all():
            if getattr(e, "kind", "") == "ip" and e.value:
                try:
                    nets.append(ipaddress.ip_network(e.value, strict=False))
                except ValueError:
                    pass
    except Exception:
        pass
    return allow, nets


def _allowlisted(ip, allow, nets):
    if ip in allow:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True                                        # unpar. -> refuse to act on it
    return any(addr in n for n in nets)


# ------------------------------------------------------------------ 3) enrichment (IOC + AbuseIPDB, cached)
def ioc_match(db, ip):
    r = db.execute(select(models.Ioc).where(models.Ioc.type == "ip", models.Ioc.value == ip)
                   .limit(1)).scalars().first()                # value isn't unique alone -> filter type + first()
    return (f"{r.source}:{r.confidence}", int(r.confidence or 0)) if r else ("", 0)


def _abuse_key():
    for attr in ("ABUSEIPDB_API_KEY", "ABUSE_IPDB_API_KEY"):
        k = getattr(settings, attr, "") or ""
        if k:
            return k
    for line in _readenv():
        m = re.search(r'ABUSEIPDB_API_KEY=["\']?([^"\'\s]+)', line)
        if m:
            return m.group(1)
    return ""


def _readenv():
    for p in ("/etc/padakhep-sentinel.env",):
        try:
            with open(p) as fh:
                return fh.readlines()
        except OSError:
            pass
    return []


_abuse_stop = {"halt": False}   # set on HTTP 429 -> stop further AbuseIPDB calls for the rest of the run


def abuse_check(db, ip, key):
    """AbuseIPDB confidence/country/reports, cached in threat_intel_cache (TTL ABUSE_CACHE_DAYS).
    Only a SUCCESSFUL lookup is cached — an error/timeout/429/no-key returns (None,...) WITHOUT
    poisoning the cache, so the IP is retried next run rather than hidden for a week."""
    now = datetime.now(timezone.utc)
    row = db.execute(select(models.ThreatIntelCache).where(models.ThreatIntelCache.ip == ip)).scalar_one_or_none()
    if row and row.checked_at and (now - _aware(row.checked_at)).days < ABUSE_CACHE_DAYS:
        return row.score, row.country, row.reports, row.isp
    if not key or _abuse_stop["halt"]:
        return None, None, None, ""                        # no key / halted -> don't cache, retry next run
    try:
        req = urllib.request.Request(
            "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90}),
            headers={"Key": key, "Accept": "application/json"})
        d = json.load(urllib.request.urlopen(req, timeout=15))["data"]
        score, country, reports, isp = d.get("abuseConfidenceScore"), d.get("countryCode"), d.get("totalReports"), (d.get("isp") or "")[:60]
        if row:
            row.score, row.country, row.reports, row.isp, row.checked_at = score, country, reports, isp, now
        else:
            db.add(models.ThreatIntelCache(ip=ip, score=score, country=country, reports=reports, isp=isp, checked_at=now))
        return score, country, reports, isp
    except urllib.error.HTTPError as e:
        if e.code == 429:
            _abuse_stop["halt"] = True
            _log("abuseipdb 429 rate-limited — halting further lookups this run")
        else:
            _log(f"abuseipdb {ip}: HTTP {e.code}")
        return None, None, None, ""
    except Exception as exc:
        _log(f"abuseipdb {ip}: {exc!r}")
        return None, None, None, ""
    finally:
        time.sleep(1.3)                                    # pace on EVERY attempt (success or error)


def _aware(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ------------------------------------------------------------------ 4) decision engine (bulletproof)
def decide(agg, iocstr, iocconf, score, country):
    """Return (action, reason). action in {block, bangladesh, skip}. Conservative + fail-SAFE.
    'bangladesh' is a REVIEW-ONLY verdict (the caller never enforces it)."""
    cats = agg["cats"]
    strong = any(cats.get(c, 0) for c in _STRONG)           # secret/exploit/sqli/traversal = unambiguous
    brute = cats.get("sshd_bruteforce", 0) >= 20
    clear_attack = strong or brute                          # behaviour that is malicious on its own
    admin_heavy = cats.get("admin_probe", 0) >= 30          # recon; needs external confirmation (can be FP)
    behav = ",".join(k for k, v in cats.most_common(4)) or "generic-4xx"
    geo = (agg.get("country") or "").lower()
    is_bd = (country == "BD") or ("bangladesh" in geo)
    unknown_country = (not country) and (not geo)           # neither AbuseIPDB nor Wazuh resolved a country
    ioc = bool(iocstr)
    scored = score is not None
    hi_score = scored and score >= ABUSE_BLOCK_MIN

    if is_bd:
        # Bangladesh is NEVER hard-blocked — surface strong-signal ones for manual review, skip weak ones.
        if clear_attack or hi_score:
            return "bangladesh", f"Bangladesh - {behav}; REVIEW manually (score={score}, n={agg['count']})"
        return "skip", f"BD weak/likely-legit ({behav}, score={score})"

    if unknown_country:
        # Cannot rule out Bangladesh -> require POSITIVE external confirmation, never behaviour alone.
        if ioc or hi_score:
            return "block", f"{behav} | AbuseIPDB {score} | IOC {iocstr} [auto-threat-hunt]"
        return "skip", f"unknown-country, behaviour-only -> not auto-blocking ({behav})"

    # Known foreign: block on confirmed attack (behaviour), IOC, or high score. Admin-panel recon
    # alone is not enough — require a corroborating reputation score (avoids FP on lone recon).
    if ioc or hi_score or clear_attack or (admin_heavy and scored and score >= 25):
        bits = [behav]
        if scored:
            bits.append(f"AbuseIPDB {score}")
        if iocstr:
            bits.append(f"IOC {iocstr}")
        return "block", " | ".join(bits) + " [auto-threat-hunt]"
    return "skip", f"insufficient signal ({behav}, score={score})"


# ------------------------------------------------------------------ 5) apply blocks (idempotent)
def _already_blocked(db, ip):
    """True if the IP is already covered by ANY active block — exact match OR inside a
    blocked CIDR (so the hunter never adds a redundant /32 for an IP a /24 already covers)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True                                        # unparseable -> refuse to act
    for b in db.execute(select(models.BlockedIp.ip).where(models.BlockedIp.active.is_(True))).scalars().all():
        if b == ip:
            return True
        if "/" in (b or ""):
            try:
                if addr in ipaddress.ip_network(b, strict=False):
                    return True
            except ValueError:
                pass
    return False


def _control_plane_covered(ip):
    cp = (getattr(settings, "CONTROL_PLANE_IP", "") or os.environ.get("SENTINEL_HOST", "") or "").strip()
    try:
        return _IPRE.match(cp) and ipaddress.ip_address(cp) in ipaddress.ip_network(ip, strict=False)
    except ValueError:
        return False


def apply_block(db, ip, reason, dry_run):
    if _already_blocked(db, ip):
        return "dup"
    if _control_plane_covered(ip):
        return "refused-cp"
    if dry_run:
        return "would-block"
    db.add(models.BlockedIp(ip=ip, reason=reason[:256], source="auto", scope="global", agent_id=""))
    return "blocked"


# ------------------------------------------------------------------ 6) synthesise detection rules (gated + deduped)
def _verify(pattern, source):
    try:
        from .scanner import verify_pattern
        return verify_pattern(pattern, source)
    except Exception:
        try:
            from .sigma import verify_pattern
            return verify_pattern(pattern, source)
        except Exception:
            return True, "self-check unavailable"


def _norm(p):
    return re.sub(r"\s+", "", (p or "").lower())


def synthesize_rules(db, confirmed, dry_run):
    """Very conservative: only propose rules for distinctive malicious URL tokens seen across
    MULTIPLE confirmed-malicious IPs and not already covered. New rules go through the FP
    self-check (staged if they can't be proven safe) so they can never silently mis-fire."""
    from . import logrules_pack
    web_rx = []
    for r in logrules_pack.RULES:
        if r.get("source") == "web":
            try:
                web_rx.append(re.compile(r["pattern"]))
            except re.error:
                pass

    def covered(tok):                                      # already caught by an existing web rule?
        sample = f'"GET {tok}/x HTTP/1.1"'
        return any(rx.search(sample) or rx.search(tok) for rx in web_rx)

    token_ips = collections.defaultdict(set)
    for ip, agg in confirmed:
        for url in agg["urls"]:
            for tok in re.findall(r'/[A-Za-z0-9._\-]{4,40}', url):
                low = tok.lower()
                if any(s in low for s in (".php", ".env", ".git", "boaform", "hnap", "gponform",
                                          "phpunit", "wp-login", "phpmyadmin", "cgi-bin", "actuator",
                                          ".aws", ".ssh", "eval-stdin")):
                    token_ips[tok].add(ip)
    existing = {_norm(r.get("pattern")) for r in logrules_pack.RULES}
    try:
        for r in db.execute(select(models.LogRule)).scalars().all():
            existing.add(_norm(r.pattern))
    except Exception:
        pass
    created, names_seen = [], set()
    for tok, ipset in sorted(token_ips.items(), key=lambda kv: -len(kv[1])):
        if len(created) >= MAX_RULES or len(ipset) < 3:    # need >=3 distinct malicious sources
            continue
        if covered(tok):                                   # don't duplicate existing coverage
            continue
        pat = "(?i)" + re.escape(tok)                      # literal token, regex-escaped (no injection)
        if _norm(pat) in existing:
            continue
        name = "web_auto_" + re.sub(r"[^a-z0-9]+", "_", tok.lower()).strip("_")[:40]
        if name in names_seen:                             # two tokens can normalize to the same name
            continue
        names_seen.add(name)
        ok, _why = _verify(pat, "web")                     # recorded, but rules are ALWAYS staged (see below)
        if dry_run:
            created.append({"name": name, "pattern": pat, "sources": len(ipset), "self_check": ok, "staged": True})
            existing.add(_norm(pat))
            continue
        if db.execute(select(models.LogRule).where(models.LogRule.name == name)).scalar_one_or_none():
            continue
        # STAGED by design (enabled=False, verified=False): an auto-generated regex NEVER auto-distributes
        # to the fleet. It appears under IDS/IPS -> Log-based IDS Rules for an operator to review + promote.
        db.add(models.LogRule(name=name, platform="any", source="web", pattern=pat,
                              event_type="WEB_AUTO_PROBE", severity="MEDIUM",
                              mitre=["T1595"], entity_group=0, threshold=1, window_sec=300,
                              description=f"[TA0043] Auto-hunted probe path '{tok}' seen from {len(ipset)} malicious IPs (staged; review before enabling)",
                              enabled=False, verified=False, origin="threathunt"))
        created.append({"name": name, "pattern": pat, "sources": len(ipset), "self_check": ok, "staged": True})
        existing.add(_norm(pat))
    return created


# ------------------------------------------------------------------ single-run lock (cross-process)
# On a SHARED path (NOT /tmp) so the API service's PrivateTmp namespace can't defeat the lock
# vs. the timer service — both must contend on the same file.
_LOCK_PATH = os.environ.get("SENTINEL_THREATHUNT_LOCK",
                            os.path.join(settings.repo_root, ".threathunt.lock"))


def _acquire_lock():
    if fcntl is None:
        return open(os.devnull, "w")                      # no-op on non-POSIX
    try:
        f = open(_LOCK_PATH, "a")                         # create-if-missing, no truncate
        try:
            os.chmod(_LOCK_PATH, 0o666)                   # so root- and sentinel-run both can lock it
        except OSError:
            pass
    except OSError as exc:
        # A lock-FILE permission glitch must NOT block the security hunt (actions are already
        # idempotent + fail-safe). Fail-open on the lock, logged, rather than false "busy".
        _log(f"lock file unavailable ({exc!r}); proceeding without the cross-process lock")
        return open(os.devnull, "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return f
    except OSError:
        f.close()
        return None                                       # genuinely held -> another hunt running


# ------------------------------------------------------------------ orchestrate
def run_threat_hunt(db, days=DEFAULT_DAYS, dry_run=False, source="manual"):
    lock = _acquire_lock()
    if lock is None:
        _log("another threat hunt is already running — skipping")
        return {"ok": False, "note": "a threat hunt is already running", "running": True}
    try:
        return _run(db, days, dry_run, source)
    finally:
        try:
            lock.close()
        except Exception:
            pass


def _run(db, days=DEFAULT_DAYS, dry_run=False, source="manual"):
    t0 = time.time()
    days = max(1, min(int(days or DEFAULT_DAYS), 365))
    _log(f"start (days={days}, dry_run={dry_run}, source={source})")
    _abuse_stop["halt"] = False                            # reset the per-run 429 circuit-breaker
    ips, scanned = aggregate(days)
    allow, nets = build_allowlist(db)
    key = _abuse_key()

    def _strong_sig(agg):                                  # unambiguous attack, cheap to compute pre-enrichment
        return any(agg["cats"].get(c, 0) for c in _STRONG) or agg["cats"].get("sshd_bruteforce", 0) >= 20

    # Candidate set: meaningful volume OR a strong attack signal OR high Wazuh severity — so a
    # low-volume clear attacker isn't dropped by the volume floor. Rank malice-aware (strong
    # signal, then severity, then volume) so the best candidates are enriched within the cap.
    cands = [(ip, agg) for ip, agg in ips.items()
             if (agg["count"] >= MIN_ALERTS or _strong_sig(agg) or agg["maxlevel"] >= 10)
             and not _allowlisted(ip, allow, nets)]
    cands.sort(key=lambda kv: (-(2 if _strong_sig(kv[1]) else 0), -kv[1]["maxlevel"], -kv[1]["count"]))
    cands = cands[:int(os.environ.get("SENTINEL_THREATHUNT_MAX_ENRICH", "120"))]

    decisions, confirmed = [], []
    n_block = n_bd = n_skip = 0
    for ip, agg in cands:
        iocstr, iocconf = ioc_match(db, ip)
        score, country, reports, isp = abuse_check(db, ip, key)
        action, reason = decide(agg, iocstr, iocconf, score, country)
        rec = {"ip": ip, "count": agg["count"], "maxlevel": agg["maxlevel"],
               "country": country or agg["country"], "score": score, "reports": reports, "isp": isp,
               "behavior": [k for k, _ in agg["cats"].most_common(5)], "ioc": iocstr,
               "urls": list(agg["urls"])[:4], "action": action, "reason": reason, "applied": ""}
        if action == "block":
            if n_block >= MAX_BLOCKS:
                rec["applied"] = "capped"
            else:
                rec["applied"] = apply_block(db, ip, reason, dry_run)
                if rec["applied"] in ("blocked", "would-block"):
                    n_block += 1
                    confirmed.append((ip, agg))
        elif action == "bangladesh":
            # REVIEW-ONLY: never enforced. Surfaced in the run report for the operator to review;
            # they can manually block from the console if warranted. (A BD user is never auto-cut-off.)
            rec["applied"] = "review-only"
            n_bd += 1
        else:
            n_skip += 1
        decisions.append(rec)

    rules = synthesize_rules(db, confirmed, dry_run)
    dur = round(time.time() - t0, 1)
    report = {"decisions": sorted(decisions, key=lambda d: (d["action"] != "block", -d["count"])),
              "rules": rules}
    run = models.ThreatHuntRun(
        ran_at=datetime.now(timezone.utc), source=source, days=days, dry_run=bool(dry_run),
        alerts_scanned=scanned, ips_evaluated=len(cands), blocked=n_block,
        bangladesh_tagged=n_bd, skipped=n_skip, rules_created=len(rules),
        duration_s=dur, report=report)
    db.add(run)                                          # always record (dry-run rows are marked + block nothing)
    db.commit()
    _log(f"done in {dur}s: scanned={scanned} evaluated={len(cands)} blocked={n_block} "
         f"bangladesh={n_bd} skipped={n_skip} rules={len(rules)}")
    return {"ok": True, "days": days, "dry_run": bool(dry_run), "alerts_scanned": scanned,
            "ips_evaluated": len(cands), "blocked": n_block, "bangladesh_tagged": n_bd,
            "skipped": n_skip, "rules_created": len(rules),
            "report": report if dry_run else None, "run_id": getattr(run, "id", None)}


def main():
    ap = argparse.ArgumentParser(prog="threathunter", description="Sentinel automated threat hunter")
    ap.add_argument("--days", type=int, default=DEFAULT_DAYS, help=f"lookback window in days (default {DEFAULT_DAYS})")
    ap.add_argument("--dry-run", action="store_true", help="analyse + report but block nothing / create no rules")
    args = ap.parse_args()
    db = SessionLocal()
    try:
        res = run_threat_hunt(db, days=args.days, dry_run=args.dry_run, source="cli")
        print(json.dumps({k: v for k, v in res.items() if k != "report"}, indent=1))
    finally:
        db.close()


if __name__ == "__main__":
    main()
