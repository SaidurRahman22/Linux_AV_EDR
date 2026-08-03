"""Platform integration (Increment 1.5).

Turns indicators into the normalized **v3 detection event** (matching the SRS
schema), writes them as JSON-lines, optionally POSTs them to the central
control-plane API, and writes a heartbeat + Prometheus-text metrics for
observability. Stdlib only.
"""

from __future__ import annotations

import json
import os
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from .models import Indicator
from .rulegen import FIM_HASH_FIELDS, atomic_write

SCHEMA_VERSION = "3.0"
PRODUCER = "wazuh_rulegen"


def _severity(level: int) -> str:
    return "HIGH" if level >= 12 else ("MEDIUM" if level >= 8 else "LOW")


def _event_type(ind: Indicator) -> tuple[str, str]:
    """Return (event.type, policy.matching_ioc_type)."""
    if ind.itype == "bruteforce":
        return "BRUTE_FORCE_SOURCE", "MALICIOUS_IP"
    if ind.itype == "malicious_ip":
        return "MALICIOUS_IP", "MALICIOUS_IP"
    # malicious_artifact
    if ind.match_field in FIM_HASH_FIELDS:
        return "MALICIOUS_FILE_HASH", "MALICIOUS_HASH"
    if ind.match_field == "full_log_regex":
        return "SUSPICIOUS_COMMAND", "SUSPICIOUS_COMMAND"
    return "SUSPICIOUS_FILE_CHANGE", "SUSPICIOUS_PATH"


def indicator_to_event(ind: Indicator, generated_at: str,
                       producer: str = PRODUCER, manager: str = "") -> dict:
    """Render one merged indicator as a v3-schema detection event."""
    etype, ioc_type = _event_type(ind)
    mitre = sorted(ind.mitre)
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": generated_at,
        "instance": {
            "device_name": manager or producer,
            "role": "wazuh-manager",
            "affected_agents": sorted(ind.agents),
        },
        "ioc": {
            "value": ind.value,
            "type": ioc_type,
            "match_field": ind.match_field,
            "source": ind.source or "",
            "confidence": ind.score,
        },
        "event": {
            "type": etype,
            "action_taken": "DETECTED",
            "mode": "DETECT",                     # generator never prevents; safe by design
            "severity": _severity(ind.level),
            "confidence": ind.score,
            "details": {
                "reason": ind.reason,
                "observations": ind.count,
                "first_seen": ind.first_seen.isoformat() if ind.first_seen else None,
                "last_seen": ind.last_seen.isoformat() if ind.last_seen else None,
                "source_rule_ids": sorted(ind.sample_rule_ids),
                "groups": sorted(ind.groups),
                "sample": (ind.sample_logs[0] if ind.sample_logs else None),
            },
        },
        "mitre_attack": {"technique_ids": mitre, "technique_id": (mitre[0] if mitre else None)},
        "policy": {
            "allowlisted": False,
            "matching_ioc_type": ioc_type,
            "ioc_confidence": ind.score,
            "source": ind.source or "",
            "policy_id": "detect-only",
            "mode": "DETECT",
            "expires_at": None,
        },
        "integrity": {"producer": producer, "schema": SCHEMA_VERSION, "signature": None},
    }


def build_events(indicators: list[Indicator], generated_at: str, manager: str = "") -> list[dict]:
    return [indicator_to_event(i, generated_at, manager=manager) for i in indicators]


def write_detections_jsonl(path: str, events: list[dict], append: bool = False) -> int:
    """Write events as JSON-lines. append=False rewrites a full snapshot (scan);
    append=True streams new detections (daemon)."""
    if not events and not append:
        atomic_write(path, "")
        return 0
    lines = "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events)
    if append:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(lines)
    else:
        atomic_write(path, lines)
    return len(events)


def post_detections(api_url: str, api_token: str, events: list[dict],
                    timeout: float = 15.0) -> tuple[bool, str]:
    """POST events to the control-plane ingest API. Non-fatal; returns (ok, message)."""
    if not api_url or not events:
        return False, "disabled"
    body = json.dumps({"producer": PRODUCER, "events": events}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_token:
        headers["Authorization"] = "Bearer " + api_token
    req = urllib.request.Request(api_url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return True, "HTTP " + str(resp.status)
    except Exception as exc:  # never let telemetry delivery break detection
        return False, repr(exc)


def write_heartbeat(path: str, status: str, stats: Optional[dict] = None) -> None:
    payload = {
        "producer": PRODUCER,
        "status": status,
        "updated": datetime.now(timezone.utc).astimezone().isoformat(),
        "pid": os.getpid(),
        "stats": stats or {},
    }
    atomic_write(path, json.dumps(payload, indent=2))


def write_metrics(path: str, stats: dict) -> None:
    """Minimal Prometheus text-format metrics."""
    now = int(datetime.now(timezone.utc).timestamp())
    lines = [
        "# HELP wazuh_rulegen_alerts_processed Alerts read from the Wazuh alert stream.",
        "# TYPE wazuh_rulegen_alerts_processed counter",
        "wazuh_rulegen_alerts_processed " + str(int(stats.get("alerts_processed", 0))),
        "# HELP wazuh_rulegen_indicators Current distinct IOC indicators.",
        "# TYPE wazuh_rulegen_indicators gauge",
        "wazuh_rulegen_indicators " + str(int(stats.get("indicators", 0))),
        "# HELP wazuh_rulegen_detections Detection events emitted in the last cycle.",
        "# TYPE wazuh_rulegen_detections gauge",
        "wazuh_rulegen_detections " + str(int(stats.get("detections", 0))),
        "# HELP wazuh_rulegen_last_run_timestamp Unix time of the last run/flush.",
        "# TYPE wazuh_rulegen_last_run_timestamp gauge",
        "wazuh_rulegen_last_run_timestamp " + str(now),
    ]
    atomic_write(path, "\n".join(lines) + "\n")
