"""Feed collectors for the beacon.

Open feeds are collected now (reusing the validated parsers from the rule engine).
Paid/keyed feeds (VirusTotal, AbuseIPDB, AlienVault OTX) are PLACEHOLDERS — they
activate once their API key is provided via env; until then they log and skip.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "padakhep-sentinel-beacon/1.0"

# Make the sibling top-level `wazuh_rulegen` package importable when the beacon
# runs from the repo root.
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from wazuh_rulegen import feedupdate                     # noqa: E402
from wazuh_rulegen.intel import source_confidence        # noqa: E402


def _malware_of(note: str) -> str:
    note = note or ""
    return note.split("(")[0].strip() if "(" in note else ""


def collect_free_feeds(max_per_source: int = 500, timeout: float = 30.0, log=print) -> list:
    """Return [(type, value, source, confidence, malware), ...] from open feeds."""
    out: list = []
    for src in feedupdate.DEFAULT_SOURCES:
        url, parser = src.get("url"), src.get("parser")
        fn = feedupdate.PARSERS.get(parser)
        if not (url and fn):
            continue
        try:
            text = feedupdate.fetch(url, timeout=timeout)
        except Exception as exc:            # a dead source must not stop the others
            log(f"  ! feed failed: {url} ({exc})")
            continue
        ips, hashes = fn(text)
        for value, note in list(ips.items())[:max_per_source]:
            conf, source = source_confidence(note)
            out.append(("ip", value, source, conf, _malware_of(note)))
        for value, note in list(hashes.items())[:max_per_source]:
            conf, source = source_confidence(note)
            out.append(("hash", value, source, conf, _malware_of(note)))
        log(f"  + {parser}: {len(ips)} ips, {len(hashes)} hashes")
    return out


def collect_urlhaus(max_urls: int = 1000, timeout: float = 30.0, log=print) -> list:
    """abuse.ch URLhaus — open feed of live malicious URLs. Each URL yields a
    `url` IOC and its host yields a `domain` IOC (deduped). No API key required."""
    url = "https://urlhaus.abuse.ch/downloads/text_online/"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            text = r.read().decode("utf-8", "replace")
    except Exception as exc:
        log(f"  ! URLhaus: {exc}")
        return []
    out: list = []
    seen_dom: set = set()
    n_url = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if n_url >= max_urls:
            break
        out.append(("url", line[:512], "URLhaus", 75, "malicious URL"))
        n_url += 1
        host = urllib.parse.urlsplit(line).hostname or ""
        # skip bare IPs (they belong in the IP feed) and dedupe hosts
        if host and not host.replace(".", "").isdigit() and host not in seen_dom:
            seen_dom.add(host)
            out.append(("domain", host[:512], "URLhaus", 72, "malware distribution"))
    log(f"  + URLhaus: {n_url} urls, {len(seen_dom)} domains")
    return out


# --- paid / keyed feeds: PLACEHOLDERS (activate when API key is supplied) ---
def collect_virustotal(api_key: str, log=print) -> list:
    if not api_key:
        log("  - VirusTotal: skipped (set VT_API_KEY to enable)")
        return []
    log("  - VirusTotal: API key present — integration TODO (placeholder)")
    return []


def collect_abuseipdb(api_key: str, log=print, limit: int = 2000, min_conf: int = 90,
                      timeout: float = 30.0) -> list:
    """AbuseIPDB free tier: pull the blacklist (bulk, up to 10k IPs) — one call,
    not per-IP checks (which would burn the 1000/day quota)."""
    if not api_key:
        log("  - AbuseIPDB: skipped (set ABUSEIPDB_API_KEY to enable)")
        return []
    url = f"https://api.abuseipdb.com/api/v2/blacklist?limit={limit}&confidenceMinimum={min_conf}"
    req = urllib.request.Request(url, headers={"Key": api_key, "Accept": "application/json", "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as exc:
        log(f"  ! AbuseIPDB: {exc}")
        return []
    out = []
    for row in data.get("data", []):
        ip = (row.get("ipAddress") or "").strip()
        if not ip:
            continue
        conf = int(row.get("abuseConfidenceScore", min_conf))
        out.append(("ip", ip, "AbuseIPDB", conf, "abusive host"))
    log(f"  + AbuseIPDB: {len(out)} IPs (blacklist)")
    return out


_OTX_TYPES = {"IPv4": "ip", "FileHash-SHA256": "hash", "FileHash-SHA1": "hash",
              "FileHash-MD5": "hash", "domain": "domain", "hostname": "domain", "URL": "url"}


def _otx_get(url: str, api_key: str, timeout: float, retries: int, log) -> "dict | None":
    """GET one OTX page with retries (OTX is intermittently slow)."""
    req = urllib.request.Request(url, headers={"X-OTX-API-KEY": api_key, "User-Agent": UA})
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except Exception as exc:
            if attempt >= retries:
                log(f"  ! OTX: {exc} (OTX intermittent; will retry next run)")
                return None
            time.sleep(3)
    return None


def collect_otx(api_key: str, log=print, max_pages: int = 8, max_iocs: int = 1000,
                timeout: float = 40.0, retries: int = 2) -> list:
    """AlienVault OTX is a real feed: pull indicators from subscribed pulses.
    OTX can be slow/flaky, so we use a generous timeout + retries + pagination."""
    if not api_key:
        log("  - AlienVault OTX: skipped (set OTX_API_KEY to enable)")
        return []
    out, seen = [], set()
    for page in range(1, max_pages + 1):
        url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20&page={page}"
        data = _otx_get(url, api_key, timeout, retries, log)
        if not data:
            break
        results = data.get("results", [])
        if not results:
            break
        for pulse in results:
            fam = (pulse.get("name") or "")[:80]
            for ind in pulse.get("indicators", []):
                typ = _OTX_TYPES.get(ind.get("type"))
                val = (ind.get("indicator") or "").strip()
                if not typ or not val:
                    continue
                if typ == "hash":
                    val = val.lower()
                key = (typ, val.lower())
                if key in seen:
                    continue
                seen.add(key)
                out.append((typ, val, "AlienVault OTX", 66, fam))
                if len(out) >= max_iocs:
                    log(f"  + AlienVault OTX: {len(out)} IOCs")
                    return out
    log(f"  + AlienVault OTX: {len(out)} IOCs")
    return out


def vt_lookup_hash(api_key: str, sha: str, timeout: float = 20.0) -> dict:
    """Single VirusTotal file lookup (enrichment). Caller MUST respect rate limits."""
    url = "https://www.virustotal.com/api/v3/files/" + sha
    req = urllib.request.Request(url, headers={"x-apikey": api_key, "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found": False}
        raise
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    mal = int(stats.get("malicious", 0))
    total = sum(int(v) for v in stats.values()) or 0
    label = (attrs.get("popular_threat_classification", {}) or {}).get("suggested_threat_label", "") \
        or attrs.get("meaningful_name", "")
    return {"found": True, "malicious": mal, "total": total, "ratio": f"{mal}/{total}", "label": label}


def collect_yara_repo(api_urls: str, max_files: int = 80, timeout: float = 30.0,
                      token: str = "", log=print) -> list:
    """Pull .yar files from GitHub directory listings (contents API).

    Returns [(filename, text), ...]. Raw file fetches hit raw.githubusercontent.com
    (not rate-limited); only the directory listing uses the API (60/hr unauth,
    5000/hr with a token)."""
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    out, fetched = [], 0
    for api in [u.strip() for u in api_urls.split(",") if u.strip()]:
        if fetched >= max_files:
            break
        try:
            req = urllib.request.Request(api, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                listing = json.loads(r.read().decode("utf-8", "replace"))
        except Exception as exc:
            log(f"  ! YARA repo listing failed: {api} ({exc})")
            continue
        if not isinstance(listing, list):
            continue
        for item in listing:
            if fetched >= max_files:
                break
            if item.get("type") != "file":
                continue
            name = item.get("name", "")
            if not (name.endswith(".yar") or name.endswith(".yara")):
                continue
            url = item.get("download_url")
            if not url:
                continue
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}),
                                            timeout=timeout) as r:
                    text = r.read().decode("utf-8", "replace")
            except Exception as exc:
                log(f"  ! YARA repo fetch failed: {name} ({exc})")
                continue
            out.append((name, text))
            fetched += 1
    log(f"  + YARA repo: fetched {fetched} rule file(s)")
    return out


# --------------------------------------------------------------------------- Suricata community rules
_SURI_HEAD = re.compile(r"^\s*(alert|drop|reject|rejectsrc|rejectdst|rejectboth|pass)\s+(\S+)\s", re.I)
_SURI_SID = re.compile(r"\bsid\s*:\s*(\d+)")
_SURI_MSG = re.compile(r'\bmsg\s*:\s*"([^"]*)"')
_SURI_CLASS = re.compile(r"\bclasstype\s*:\s*([^;]+)")

# Default open/community Suricata rule sources (raw .rules). Override with
# SENTINEL_SURICATA_RULE_URLS (comma-separated).
SURICATA_DEFAULT_URLS = ",".join([
    "https://raw.githubusercontent.com/travisbgreen/hunting-rules/master/hunting.rules",
    "https://raw.githubusercontent.com/OISF/suricata/master/rules/http-events.rules",
])


def _suri_source_label(url: str) -> str:
    if "emergingthreats" in url:
        return "et-open"
    if "travisbgreen" in url:
        return "hunting-rules"
    base = url.rstrip("/").split("/")[-1]
    return (base[:-6] if base.endswith(".rules") else base)[:48] or "community"


def parse_suricata_rules(text: str, source: str, max_rules: int) -> list:
    """Parse a .rules file into rule dicts (handles backslash line continuations)."""
    lines, buf = [], ""
    for ln in text.splitlines():
        if ln.rstrip().endswith("\\"):
            buf += ln.rstrip()[:-1] + " "
            continue
        lines.append(buf + ln)
        buf = ""
    if buf:
        lines.append(buf)
    out = []
    for ln in lines:
        if len(out) >= max_rules:
            break
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        h = _SURI_HEAD.match(s)
        sid = _SURI_SID.search(s)
        if not h or not sid:
            continue
        msg = _SURI_MSG.search(s)
        cls = _SURI_CLASS.search(s)
        out.append({"key": f"{source}:{sid.group(1)}", "sid": sid.group(1),
                    "action": h.group(1).lower(), "proto": h.group(2)[:12],
                    "msg": (msg.group(1) if msg else "")[:390],
                    "category": (cls.group(1).strip() if cls else "")[:60],
                    "source": source, "raw": s[:4000]})
    return out


def collect_suricata_rules(urls: str = "", max_rules: int = 4000,
                           timeout: float = 40.0, log=print) -> list:
    """Scrape community/open-source Suricata rules from the configured URLs."""
    srcs = [u.strip() for u in (urls or SURICATA_DEFAULT_URLS).split(",") if u.strip()]
    per = max(1, max_rules // max(1, len(srcs)))
    out = []
    for url in srcs:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 (trusted feeds)
                text = r.read().decode("utf-8", "replace")
        except Exception as exc:                # a dead source must not stop the others
            log(f"  ! suricata rules failed: {url} ({exc})")
            continue
        src = _suri_source_label(url)
        rules = parse_suricata_rules(text, src, per)
        out += rules
        log(f"  + suricata rules: {len(rules)} from {src}")
    return out[:max_rules]


def collect_all(settings, log=print) -> list:
    rows = collect_free_feeds(settings.BEACON_MAX_PER_SOURCE, log=log)
    rows += collect_urlhaus(max_urls=int(getattr(settings, "URLHAUS_MAX", 1000)), log=log)
    rows += collect_otx(settings.OTX_API_KEY, log=log, max_iocs=int(getattr(settings, "OTX_MAX", 400)))
    rows += collect_abuseipdb(settings.ABUSEIPDB_API_KEY, log,
                              limit=int(getattr(settings, "ABUSEIPDB_MAX", 2000)),
                              min_conf=int(getattr(settings, "ABUSEIPDB_MIN_CONF", 90)))
    # VirusTotal is enrichment (rate-limited), handled separately in beacon.enrich_vt()
    return rows
