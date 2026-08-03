"""Turn a raw Wazuh alert dict into a normalized :class:`Event`."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

from .models import Event

# "185.177.72.5:1366" -> "185.177.72.5" ; bare IPv4 kept as-is
_IPV4_PORT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?$")
# "[2001:db8::1]:443" -> "2001:db8::1"
_IPV6_BRACKET = re.compile(r"^\[([0-9A-Fa-f:]+)\](?::(\d+))?$")


def normalize_ip(value: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Return (ip, port). Strips a trailing :port that Wazuh sometimes appends."""
    if not value:
        return None, None
    value = value.strip()
    m = _IPV4_PORT.match(value)
    if m:
        return m.group(1), m.group(2)
    m = _IPV6_BRACKET.match(value)
    if m:
        return m.group(1), m.group(2)
    return value, None


def parse_timestamp(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        pass
    # Wazuh writes offsets like "+0600" (no colon); normalize then retry.
    m = re.match(r"^(.*[+-]\d{2})(\d{2})$", ts)
    if m:
        try:
            return datetime.fromisoformat(f"{m.group(1)}:{m.group(2)}")
        except ValueError:
            pass
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _first(d: dict, *keys: str) -> Optional[Any]:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", []):
            return v
    return None


def _dig(d: Any, *path: str) -> Optional[Any]:
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def normalize_alert(alert: dict[str, Any], source_file: str = "") -> Event:
    rule = alert.get("rule", {}) if isinstance(alert.get("rule"), dict) else {}
    data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
    agent = alert.get("agent", {}) if isinstance(alert.get("agent"), dict) else {}
    syscheck = alert.get("syscheck", {}) if isinstance(alert.get("syscheck"), dict) else {}

    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0

    # source IP can live in a few places depending on decoder
    raw_ip = _first(data, "srcip", "src_ip") or alert.get("srcip") \
        or _dig(data, "win", "eventdata", "ipAddress")
    srcip, srcport = normalize_ip(raw_ip)
    if not srcport:
        srcport = _first(data, "srcport") or _dig(data, "win", "eventdata", "ipPort")

    dstuser = _first(data, "dstuser", "dstuser") or _dig(data, "win", "eventdata", "targetUserName")
    srcuser = _first(data, "srcuser", "user", "srcUser") or _dig(data, "win", "eventdata", "subjectUserName")

    # artifact: file path + hash (FIM) or process image (Windows/Sysmon)
    file_path = _first(syscheck, "path") or _dig(data, "win", "eventdata", "image") \
        or _dig(data, "win", "eventdata", "targetFilename") or _first(data, "file")
    file_hash = _first(syscheck, "sha256_after", "sha1_after", "md5_after") \
        or _dig(data, "win", "eventdata", "hashes") or _first(data, "sha256", "md5", "hash")
    hash_type = None
    if file_hash:
        if syscheck.get("sha256_after") or (isinstance(file_hash, str) and len(file_hash) == 64):
            hash_type = "sha256"
        elif syscheck.get("sha1_after") or (isinstance(file_hash, str) and len(file_hash) == 40):
            hash_type = "sha1"
        elif syscheck.get("md5_after") or (isinstance(file_hash, str) and len(file_hash) == 32):
            hash_type = "md5"

    command = _dig(data, "win", "eventdata", "commandLine") or _first(data, "command", "cmdline")

    mitre = _dig(rule, "mitre", "id") or []
    if isinstance(mitre, str):
        mitre = [mitre]

    groups = rule.get("groups", []) or []
    if isinstance(groups, str):
        groups = [groups]

    return Event(
        timestamp=parse_timestamp(alert.get("timestamp", "")),
        raw_timestamp=alert.get("timestamp", ""),
        rule_id=str(rule.get("id")) if rule.get("id") is not None else None,
        level=level,
        description=rule.get("description", "") or "",
        groups=list(groups),
        srcip=srcip,
        srcport=str(srcport) if srcport else None,
        dstuser=str(dstuser) if dstuser else None,
        srcuser=str(srcuser) if srcuser else None,
        program=_dig(alert, "decoder", "name") or _first(data, "program_name"),
        agent_name=agent.get("name"),
        agent_id=agent.get("id"),
        location=alert.get("location"),
        file_path=str(file_path) if file_path else None,
        file_hash=str(file_hash) if file_hash else None,
        hash_type=hash_type,
        command=str(command) if command else None,
        full_log=alert.get("full_log", "") or "",
        mitre=list(mitre),
        source_file=source_file,
    )
