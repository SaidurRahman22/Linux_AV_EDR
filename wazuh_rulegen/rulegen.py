"""Render indicators into Wazuh XML detection rules and CDB IOC lists.

Design choices worth knowing:

* Custom Wazuh rule IDs must be >= 100000. :class:`IdAllocator` hands out stable
  IDs and persists the IOC->ID mapping so re-runs (and the long-running daemon)
  never renumber an existing rule.
* Indicators are merged by (match_field, value) so one IOC becomes exactly one
  rule even when several detectors flag it.
* Output is validated (parsed under a synthetic root) before it is written, and
  written atomically (temp file + ``os.replace``) so a crashed run never leaves
  the manager with a half-written, un-loadable rule file.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Iterable, Optional
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

from .models import GeneratedRule, Indicator

FIM_HASH_FIELDS = {"sha256_after", "sha1_after", "md5_after"}


class IdAllocator:
    """Assigns and remembers Wazuh rule IDs (>= base) per IOC key."""

    def __init__(self, base: int, max_id: int, existing: Optional[dict] = None):
        self.base = base
        self.max_id = max_id
        self.map: dict[str, int] = {str(k): int(v) for k, v in (existing or {}).items()}
        self.next = (max(self.map.values()) + 1) if self.map else base

    @staticmethod
    def key(ind: Indicator) -> str:
        return f"{ind.match_field}\x1f{ind.value}"

    def id_for(self, ind: Indicator) -> int:
        k = self.key(ind)
        if k not in self.map:
            if self.next > self.max_id:
                raise RuntimeError(
                    f"Rule ID space exhausted (base={self.base}, max={self.max_id}). "
                    "Raise id_max in config.")
            self.map[k] = self.next
            self.next += 1
        return self.map[k]

    def to_dict(self) -> dict:
        return dict(self.map)


def merge_indicators(indicators: Iterable[Indicator]) -> list[Indicator]:
    """Collapse indicators that target the same (match_field, value)."""
    merged: dict[tuple, Indicator] = {}
    for ind in indicators:
        k = ind.key()
        if k in merged:
            merged[k].merge(ind)
        else:
            # shallow copy so we never mutate the caller's objects
            merged[k] = Indicator(
                itype=ind.itype, subtype=ind.subtype, value=ind.value,
                match_field=ind.match_field, reason=ind.reason, level=ind.level,
                count=ind.count, first_seen=ind.first_seen, last_seen=ind.last_seen,
                users=set(ind.users), sample_rule_ids=set(ind.sample_rule_ids),
                sample_logs=list(ind.sample_logs), groups=set(ind.groups),
                mitre=set(ind.mitre), agents=set(ind.agents), confidence=ind.confidence,
            )
    return list(merged.values())


def _sanitize_comment(text: str) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    text = text.replace("--", "- -")          # '--' is illegal inside XML comments
    return text[:400]


def _fmt_ts(ts: Optional[datetime]) -> str:
    return ts.isoformat() if ts else "n/a"


def _groups_for(ind: Indicator) -> str:
    base = "generated,wazuh_rulegen,"
    if ind.match_field == "srcip":
        if ind.itype == "malicious_ip" or "threat_feed" in ind.subtype or "volume" in ind.subtype:
            return "attack,blacklist," + base
        return "authentication_failures,attack," + base
    if ind.match_field in FIM_HASH_FIELDS:
        return "malware,syscheck," + base
    if ind.match_field == "full_log_regex":
        return "attack,malware," + base
    if ind.match_field in ("path", "file"):
        return "ossec,syscheck," + base
    return "attack," + base


def _match_element(ind: Indicator) -> str:
    """The rule's matching condition XML (indented 4 spaces)."""
    v = ind.value
    if ind.match_field == "srcip":
        return f"    <srcip>{escape(v)}</srcip>"
    if ind.match_field in FIM_HASH_FIELDS:
        return (f"    <if_group>syscheck</if_group>\n"
                f'    <field name="{ind.match_field}" type="pcre2">(?i)^{escape(v)}$</field>')
    if ind.match_field == "full_log_regex":
        # value is already a PCRE2 pattern; match case-insensitively on the raw log
        return f'    <match type="pcre2">(?i){escape(v)}</match>'
    if ind.match_field in ("path", "file"):
        return (f"    <if_group>syscheck</if_group>\n"
                f'    <field name="{ind.match_field}" type="pcre2">{escape(re.escape(v))}</field>')
    return f'    <field name="{escape(ind.match_field)}">{escape(v)}</field>'


def _description(ind: Indicator) -> str:
    label = {
        "bruteforce": "Brute-force / abusive source",
        "malicious_ip": "Malicious source IP",
        "malicious_artifact": "Malicious artifact",
    }.get(ind.itype, "Suspicious indicator")
    if ind.match_field in FIM_HASH_FIELDS:
        label = "Known-malicious file hash"
    elif ind.match_field == "full_log_regex":
        label = "Suspicious command execution"
    elif ind.match_field in ("path", "file"):
        label = "Suspicious file/registry change"
    short = ind.value if len(ind.value) <= 60 else ind.value[:57] + "..."
    return f"{label} detected [auto-generated]: {short}"


def render_rule(ind: Indicator, rule_id: int) -> GeneratedRule:
    reason = _sanitize_comment(ind.reason)
    rules = ", ".join(sorted(ind.sample_rule_ids)[:8]) or "n/a"
    agents = ", ".join(sorted(ind.agents)[:5]) or "n/a"
    evidence = (f"IOC={ind.value} | type={ind.itype}/{ind.subtype} | confidence={ind.confidence} "
                f"| observations={ind.count} | window={_fmt_ts(ind.first_seen)} -> "
                f"{_fmt_ts(ind.last_seen)} | source_rules=[{rules}] | agents=[{agents}]")
    sample = _sanitize_comment(ind.sample_logs[0]) if ind.sample_logs else ""

    lines = [f"  <!-- {_sanitize_comment(reason)} -->",
             f"  <!-- evidence: {_sanitize_comment(evidence)} -->"]
    if sample:
        lines.append(f"  <!-- sample: {sample} -->")
    lines.append(f'  <rule id="{rule_id}" level="{ind.level}">')
    lines.append(_match_element(ind))
    lines.append(f"    <description>{escape(_description(ind))}</description>")
    for tech in sorted(ind.mitre):
        lines.append("    <mitre>")
        lines.append(f"      <id>{escape(tech)}</id>")
        lines.append("    </mitre>")
    lines.append(f"    <group>{_groups_for(ind)}</group>")
    lines.append("  </rule>")
    xml = "\n".join(lines)
    return GeneratedRule(rule_id=rule_id, level=ind.level, xml=xml,
                         ioc_type=ind.itype, ioc_value=ind.value,
                         description=_description(ind), match_field=ind.match_field)


def build_rules_document(indicators: list[Indicator], allocator: IdAllocator,
                         generated_at: str) -> tuple[str, list[GeneratedRule]]:
    merged = merge_indicators(indicators)
    # deterministic ordering for stable diffs
    merged.sort(key=lambda i: (i.match_field, i.itype, i.value))
    rendered = [render_rule(ind, allocator.id_for(ind)) for ind in merged]

    header = (
        "<!--\n"
        "  Wazuh detection rules auto-generated by wazuh_rulegen.\n"
        f"  Generated: {generated_at}\n"
        f"  Rules: {len(rendered)} | ID range: {allocator.base}-{allocator.max_id}\n"
        "  REVIEW before enabling in production. Copy into a manager ruleset file\n"
        "  (e.g. /var/ossec/etc/rules/local_rules.xml) and restart wazuh-manager.\n"
        "-->\n"
    )
    body = "\n\n".join(r.xml for r in rendered)
    doc = f'{header}<group name="local,generated,wazuh_rulegen,">\n{body}\n</group>\n'
    return doc, rendered


def validate_document(doc: str) -> None:
    """Raise ET.ParseError if the rules file is not well-formed XML."""
    ET.fromstring(f"<_root_>{doc}</_root_>")


def atomic_write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    os.replace(tmp, path)


def write_cdb_lists(indicators: list[Indicator], ip_path: str, hash_path: str) -> dict[str, int]:
    """Write Wazuh CDB lists (key:value per line). Returns counts written."""
    ips: dict[str, str] = {}
    hashes: dict[str, str] = {}
    for ind in merge_indicators(indicators):
        note = _sanitize_comment(ind.reason).replace(":", " ")[:120] or ind.itype
        if ind.match_field == "srcip":
            ips[ind.value] = note
        elif ind.match_field in FIM_HASH_FIELDS:
            hashes[ind.value] = note
    counts = {"ip": 0, "hash": 0}
    if ips:
        atomic_write(ip_path, "".join(f"{k}:{v}\n" for k, v in sorted(ips.items())))
        counts["ip"] = len(ips)
    if hashes:
        atomic_write(hash_path, "".join(f"{k}:{v}\n" for k, v in sorted(hashes.items())))
        counts["hash"] = len(hashes)
    return counts
