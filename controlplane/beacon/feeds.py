"""Feed collectors for the beacon.

Open feeds are collected now (reusing the validated parsers from the rule engine).
Paid/keyed feeds (VirusTotal, AbuseIPDB, AlienVault OTX) are PLACEHOLDERS — they
activate once their API key is provided via env; until then they log and skip.
"""

from __future__ import annotations

import os
import sys

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


# --- paid / keyed feeds: PLACEHOLDERS (activate when API key is supplied) ---
def collect_virustotal(api_key: str, log=print) -> list:
    if not api_key:
        log("  - VirusTotal: skipped (set VT_API_KEY to enable)")
        return []
    log("  - VirusTotal: API key present — integration TODO (placeholder)")
    return []


def collect_abuseipdb(api_key: str, log=print) -> list:
    if not api_key:
        log("  - AbuseIPDB: skipped (set ABUSEIPDB_API_KEY to enable)")
        return []
    log("  - AbuseIPDB: API key present — integration TODO (placeholder)")
    return []


def collect_otx(api_key: str, log=print) -> list:
    if not api_key:
        log("  - AlienVault OTX: skipped (set OTX_API_KEY to enable)")
        return []
    log("  - AlienVault OTX: API key present — integration TODO (placeholder)")
    return []


def collect_all(settings, log=print) -> list:
    rows = collect_free_feeds(settings.BEACON_MAX_PER_SOURCE, log=log)
    rows += collect_virustotal(settings.VT_API_KEY, log)
    rows += collect_abuseipdb(settings.ABUSEIPDB_API_KEY, log)
    rows += collect_otx(settings.OTX_API_KEY, log)
    return rows
