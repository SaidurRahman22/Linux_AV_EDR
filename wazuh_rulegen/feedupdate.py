"""Self-updating threat-intel feeds.

Fetches public IOC feeds directly (stdlib urllib) and merges them into the local
feed files. Content ABOVE the auto marker (your header + hand-curated / manually
added IOCs) is preserved; only the section below the marker is refreshed, so the
file stays bounded across repeated runs.

Runs on the Wazuh box itself (systemd timer or cron) so IOCs stay fresh without
involving your dev machine. The daemon hot-reloads the files within ~30s.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import os
import re
import urllib.request
from datetime import datetime, timezone

from .rulegen import atomic_write

MARKER = "# === AUTO-UPDATED IOCs (managed by 'update-feeds'; content below is overwritten) ==="

# Public, open feeds (no API key required).
DEFAULT_SOURCES = [
    {"url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv", "parser": "feodo_csv"},
    {"url": "https://threatfox.abuse.ch/export/csv/recent/", "parser": "threatfox_csv"},
    {"url": "https://bazaar.abuse.ch/export/csv/recent/", "parser": "malwarebazaar_csv"},
    {"url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "parser": "plain_ip"},
]

USER_AGENT = "wazuh_rulegen-feedupdate/1.0 (+https://wazuh.com)"


# --------------------------------------------------------------------------- #
# fetch
# --------------------------------------------------------------------------- #
def fetch(url: str, timeout: float = 30.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (trusted feeds)
        return resp.read().decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #
def _valid_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and not (a.is_private or a.is_loopback or a.is_reserved
                                   or a.is_multicast or a.is_unspecified)


def _valid_hash(h: str) -> bool:
    h = h.lower()
    return bool(re.fullmatch(r"[0-9a-f]+", h)) and len(h) in (32, 40, 64)


def _csv_rows(text: str):
    lines = [ln for ln in text.splitlines() if ln and not ln.lstrip().startswith("#")]
    return csv.reader(io.StringIO("\n".join(lines)), skipinitialspace=True)


# --------------------------------------------------------------------------- #
# parsers -> ({ip: note}, {hash: note})
# --------------------------------------------------------------------------- #
def parse_plain_ip(text: str):
    ips = {}
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        tok = ln.split()[0]
        if _valid_ip(tok):
            ips.setdefault(tok, "compromised host (Emerging Threats)")
    return ips, {}


def parse_feodo_csv(text: str):
    ips = {}
    for row in _csv_rows(text):
        if len(row) < 6:
            continue
        ip, malware = row[1].strip(), row[5].strip() or "botnet"
        if _valid_ip(ip):
            ips.setdefault(ip, f"{malware} C2 (Feodo Tracker)")
    return ips, {}


def parse_threatfox_csv(text: str):
    ips, hashes = {}, {}
    for row in _csv_rows(text):
        if len(row) < 7:
            continue
        value, itype = row[2].strip(), row[3].strip()
        malware = (row[6] or row[5] or "malware").strip()
        if itype == "ip:port":
            ip = value.split(":")[0]
            if _valid_ip(ip):
                ips.setdefault(ip, f"{malware} (ThreatFox)")
        elif itype in ("sha256_hash", "md5_hash", "sha1_hash"):
            if _valid_hash(value):
                hashes.setdefault(value.lower(), f"{malware} (ThreatFox)")
    return ips, hashes


def parse_malwarebazaar_csv(text: str):
    hashes = {}
    for row in _csv_rows(text):
        if len(row) < 9:
            continue
        sha256, sig = row[1].strip(), row[8].strip()
        sig = "sample" if not sig or sig.lower() == "n/a" else sig
        if _valid_hash(sha256):
            hashes.setdefault(sha256.lower(), f"{sig} (MalwareBazaar)")
    return {}, hashes


PARSERS = {
    "plain_ip": parse_plain_ip,
    "feodo_csv": parse_feodo_csv,
    "threatfox_csv": parse_threatfox_csv,
    "malwarebazaar_csv": parse_malwarebazaar_csv,
}


# --------------------------------------------------------------------------- #
# merge helpers
# --------------------------------------------------------------------------- #
def _split_preamble(path: str) -> tuple[str, set[str]]:
    """Return (preamble_text_including_marker, tokens_seen_in_preamble)."""
    existing = ""
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            existing = fh.read()
    if MARKER in existing:
        preamble = existing.split(MARKER)[0] + MARKER + "\n"
    else:
        base = existing.rstrip("\n")
        preamble = (base + "\n\n" if base else "") + MARKER + "\n"
    # collect tokens already present so the auto section never duplicates them
    seen = set()
    for ln in preamble.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        seen.add(ln.split()[0].lower())
    return preamble, seen


def _write_feed(path: str, preamble: str, entries: dict, ip_sort: bool) -> int:
    if ip_sort:
        keys = sorted(entries, key=lambda x: tuple(int(o) for o in x.split(".")) if _valid_ip(x) else (9999,))
        body = "".join(f"{k:<18}{entries[k]}\n" for k in keys)
    else:
        body = "".join(f"{k}  {entries[k]}\n" for k in sorted(entries))
    stamp = f"# updated {datetime.now(timezone.utc).astimezone().isoformat()} - {len(entries)} entries\n"
    atomic_write(path, preamble + stamp + body)
    return len(entries)


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #
def update_feeds(cfg, timeout: float = 30.0, max_per_source: int = 400,
                 dry_run: bool = False, log=print) -> dict:
    sources = cfg.feed_sources or DEFAULT_SOURCES
    all_ips: dict[str, str] = {}
    all_hashes: dict[str, str] = {}
    errors: list[str] = []

    for src in sources:
        url, parser = src.get("url"), src.get("parser")
        fn = PARSERS.get(parser)
        if not (url and fn):
            continue
        try:
            text = fetch(url, timeout=timeout)
        except Exception as exc:  # a dead source must not abort the others
            errors.append(f"{url}: {exc!r}")
            log(f"  ! fetch failed: {url} ({exc})")
            continue
        ips, hashes = fn(text)
        for k, v in list(ips.items())[:max_per_source]:
            all_ips.setdefault(k, v)
        for k, v in list(hashes.items())[:max_per_source]:
            all_hashes.setdefault(k, v)
        log(f"  + {parser}: {len(ips)} ips, {len(hashes)} hashes")

    ip_path = cfg.resolve(cfg.ip_feeds[0]) if cfg.ip_feeds else None
    hash_path = cfg.resolve(cfg.hash_feeds[0]) if cfg.hash_feeds else None

    result = {"ips_fetched": len(all_ips), "hashes_fetched": len(all_hashes),
              "errors": errors, "ip_written": 0, "hash_written": 0}

    if ip_path and all_ips:
        preamble, seen = _split_preamble(ip_path)
        fresh = {k: v for k, v in all_ips.items() if k.lower() not in seen}
        if dry_run:
            log(f"  (dry-run) would write {len(fresh)} new IPs below marker in {ip_path}")
        else:
            result["ip_written"] = _write_feed(ip_path, preamble, fresh, ip_sort=True)

    if hash_path and all_hashes:
        preamble, seen = _split_preamble(hash_path)
        fresh = {k: v for k, v in all_hashes.items() if k.lower() not in seen}
        if dry_run:
            log(f"  (dry-run) would write {len(fresh)} new hashes below marker in {hash_path}")
        else:
            result["hash_written"] = _write_feed(hash_path, preamble, fresh, ip_sort=False)

    return result
