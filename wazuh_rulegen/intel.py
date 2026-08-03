"""Threat-intel feed loading and matching (IPs/CIDRs and file hashes)."""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Optional

# Per-source default confidence (0-100) used to score feed-matched IOCs.
# The source is parsed from the trailing "(Source)" tag a feed note carries.
_SOURCE_CONFIDENCE = {
    "feodo tracker": 90, "threatfox": 85, "malwarebazaar": 80, "urlhaus": 80,
    "cisa": 85, "spamhaus": 78, "abuseipdb": 72, "alienvault otx": 66, "otx": 66,
    "emerging threats": 60, "firehol": 60,
}


def source_confidence(note: str) -> "tuple[int, str]":
    """Derive (confidence 0-100, source_label) from a feed note.

    A note like "Emotet C2 (Feodo Tracker)" -> (90, "Feodo Tracker").
    A curated note with no "(Source)" tag is treated as manually-vetted (95).
    """
    note = (note or "").strip()
    m = re.search(r"\(([^)]+)\)\s*$", note)
    if m:
        label = m.group(1).strip()
        low = label.lower()
        for key, conf in _SOURCE_CONFIDENCE.items():
            if key in low:
                return conf, label
        return 60, label
    if note:
        return 95, "curated"
    return 60, "feed"


def _iter_feed_lines(paths: list[str]) -> "list[tuple[str, str]]":
    """Yield (token, note) from feed files.

    Line formats accepted (``#`` starts a comment):
        1.2.3.4
        1.2.3.0/24        Emerging Threats - scanners
        deadbeef...       known-malware.example
    Everything after the first whitespace/comma is treated as a free-text note.
    """
    out: list[tuple[str, str]] = []
    for path in paths or []:
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "#" in line:
                    line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.replace(",", " ").split(None, 1)
                token = parts[0].strip()
                note = parts[1].strip() if len(parts) > 1 else ""
                out.append((token, note))
    return out


class IPMatcher:
    """Match an IP against exact addresses and CIDR networks from feeds."""

    def __init__(self) -> None:
        self._exact: dict[str, str] = {}
        self._nets: list[tuple[ipaddress._BaseNetwork, str]] = []

    def add(self, token: str, note: str = "") -> None:
        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                self._nets.append((net, note))
            else:
                ip = ipaddress.ip_address(token)
                self._exact[str(ip)] = note
        except ValueError:
            return

    def match(self, ip: str) -> Optional[str]:
        """Return the feed note (possibly empty string) if ``ip`` is listed, else None."""
        if ip in self._exact:
            return self._exact[ip] or "listed in threat-intel feed"
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, note in self._nets:
            if addr.version == net.version and addr in net:
                return note or f"within blocklisted range {net}"
        return None

    def __len__(self) -> int:
        return len(self._exact) + len(self._nets)


def load_ip_feeds(paths: list[str]) -> IPMatcher:
    m = IPMatcher()
    for token, note in _iter_feed_lines(paths):
        m.add(token, note)
    return m


def load_allowlist(entries: list[str]) -> IPMatcher:
    m = IPMatcher()
    for token in entries or []:
        m.add(token, "allowlisted")
    return m


def load_hash_feeds(paths: list[str]) -> dict[str, str]:
    feed: dict[str, str] = {}
    for token, note in _iter_feed_lines(paths):
        h = token.lower()
        if all(c in "0123456789abcdef" for c in h) and len(h) in (32, 40, 64):
            feed[h] = note or "listed in malicious-hash feed"
    return feed
