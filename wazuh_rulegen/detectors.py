"""Detectors: brute force, malicious IP, and malicious artifact.

Each detector aggregates events keyed by IOC and can operate in two ways:

* streaming (real-time) - ``feed(event)`` returns any indicator that *crosses*
  its threshold on this event, for immediate rule generation;
* batch - ``finalize()`` returns indicators for every IOC that qualifies, with
  full aggregate counts.

Rate-based detectors keep a rolling time window (``collections.deque`` of
timestamps) and remember the *peak* window occupancy so a burst is still
detected when the whole log is replayed in one pass.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from .config import (BruteForceConfig, MaliciousArtifactConfig, MaliciousIPConfig)
from .intel import (IPMatcher, load_allowlist, load_ip_feeds, load_hash_feeds,
                    source_confidence)
from .models import Event, Indicator


def _clone(ind: Indicator) -> Indicator:
    """A defensive copy so streaming emissions don't mutate under later feeds."""
    return Indicator(
        itype=ind.itype, subtype=ind.subtype, value=ind.value, match_field=ind.match_field,
        reason=ind.reason, level=ind.level, count=ind.count,
        first_seen=ind.first_seen, last_seen=ind.last_seen,
        users=set(ind.users), sample_rule_ids=set(ind.sample_rule_ids),
        sample_logs=list(ind.sample_logs), groups=set(ind.groups),
        mitre=set(ind.mitre), agents=set(ind.agents), confidence=ind.confidence,
        score=ind.score, source=ind.source,
    )


# --------------------------------------------------------------------------- #
# Brute force
# --------------------------------------------------------------------------- #
@dataclass
class _IPState:
    total: int = 0
    auth_win: deque = field(default_factory=deque)
    flood_win: deque = field(default_factory=deque)
    auth_peak: int = 0
    flood_peak: int = 0
    users: set = field(default_factory=set)
    rule_ids: set = field(default_factory=set)
    groups: set = field(default_factory=set)
    agents: set = field(default_factory=set)
    samples: list = field(default_factory=list)
    first: Optional[datetime] = None
    last: Optional[datetime] = None
    emitted: bool = False


_FLOOD_GROUPS = {"attack", "web_scan", "recon", "web", "web_attack",
                 "sql_injection", "exploit", "ids"}


class BruteForceDetector:
    itype = "bruteforce"

    def __init__(self, cfg: BruteForceConfig):
        self.cfg = cfg
        self._ips: dict[str, _IPState] = {}
        self._tf = timedelta(seconds=cfg.timeframe_seconds)

    def _prune(self, win: deque, now: Optional[datetime]) -> None:
        if now is None:
            return
        while win and win[0] < now - self._tf:
            win.popleft()

    def feed(self, e: Event) -> list[Indicator]:
        if not self.cfg.enabled or not e.srcip:
            return []
        is_auth = e.is_auth_failure()
        is_flood = bool(set(e.groups) & _FLOOD_GROUPS)
        if not (is_auth or is_flood):
            return []

        st = self._ips.setdefault(e.srcip, _IPState())
        st.total += 1
        if e.rule_id:
            st.rule_ids.add(e.rule_id)
        st.groups |= set(e.groups)
        if e.agent_name:
            st.agents.add(e.agent_name)
        if e.dstuser:
            st.users.add(e.dstuser)
        if e.full_log and len(st.samples) < 3 and e.full_log not in st.samples:
            st.samples.append(e.full_log)
        if e.timestamp:
            st.first = e.timestamp if not st.first else min(st.first, e.timestamp)
            st.last = e.timestamp if not st.last else max(st.last, e.timestamp)

        crossed = None
        if is_auth:
            st.auth_win.append(e.timestamp or datetime.min)
            self._prune(st.auth_win, e.timestamp)
            st.auth_peak = max(st.auth_peak, len(st.auth_win))
            if len(st.auth_win) >= self.cfg.min_auth_failures and not st.emitted:
                crossed = self._build(e.srcip, st)
        if crossed is None and is_flood:
            st.flood_win.append(e.timestamp or datetime.min)
            self._prune(st.flood_win, e.timestamp)
            st.flood_peak = max(st.flood_peak, len(st.flood_win))
            if len(st.flood_win) >= self.cfg.min_flood_events and not st.emitted:
                crossed = self._build(e.srcip, st)

        if crossed is not None:
            st.emitted = True
            return [crossed]
        return []

    def _build(self, ip: str, st: _IPState) -> Indicator:
        spray = len(st.users) >= self.cfg.per_user_spray_users
        if st.auth_peak >= self.cfg.min_auth_failures:
            sub = "password_spray" if spray else "auth"
            reason = (f"{st.auth_peak} authentication failures within "
                      f"{self.cfg.timeframe_seconds}s from {ip}")
            if spray:
                reason += f" against {len(st.users)} distinct users (password spraying)"
            mitre = {"T1110.003"} if spray else {"T1110"}
            conf, score = "high", 78
        else:
            sub = "scan_flood"
            reason = (f"{st.flood_peak} attack/scan alerts within "
                      f"{self.cfg.timeframe_seconds}s from {ip} (automated abuse)")
            mitre = {"T1595"}
            # behavioral volume signal is FP-prone (e.g. a chatty legit client) ->
            # deliberately LOW score so it never drives automatic prevention.
            conf, score = "low", 55
        ind = Indicator(
            itype=self.itype, subtype=sub, value=ip, match_field="srcip",
            reason=reason, level=self.cfg.level, count=st.total,
            first_seen=st.first, last_seen=st.last,
            users=set(st.users), sample_rule_ids=set(st.rule_ids),
            sample_logs=list(st.samples), groups=set(st.groups),
            mitre=mitre, agents=set(st.agents), confidence=conf, score=score,
            source="behavioral",
        )
        return ind

    def finalize(self) -> list[Indicator]:
        out = []
        for ip, st in self._ips.items():
            if st.auth_peak >= self.cfg.min_auth_failures or st.flood_peak >= self.cfg.min_flood_events:
                out.append(self._build(ip, st))
        return out


# --------------------------------------------------------------------------- #
# Malicious IP
# --------------------------------------------------------------------------- #
@dataclass
class _MalIPState:
    attack_count: int = 0
    max_level: int = 0
    feed_note: Optional[str] = None
    rule_ids: set = field(default_factory=set)
    groups: set = field(default_factory=set)
    agents: set = field(default_factory=set)
    samples: list = field(default_factory=list)
    first: Optional[datetime] = None
    last: Optional[datetime] = None
    emitted: bool = False


class MaliciousIPDetector:
    itype = "malicious_ip"

    def __init__(self, cfg: MaliciousIPConfig, ip_feed: IPMatcher, allowlist: IPMatcher):
        self.cfg = cfg
        self.ip_feed = ip_feed
        self.allow = allowlist
        self._ips: dict[str, _MalIPState] = {}
        self._groups = set(cfg.suspicious_groups)

    def feed(self, e: Event) -> list[Indicator]:
        if not self.cfg.enabled or not e.srcip:
            return []
        if self.allow.match(e.srcip):
            return []
        note = self.ip_feed.match(e.srcip)
        suspicious = bool(set(e.groups) & self._groups)
        high = e.level >= self.cfg.high_severity_level
        if not (note or suspicious or high):
            return []

        st = self._ips.setdefault(e.srcip, _MalIPState())
        if suspicious or high:
            st.attack_count += 1
        st.max_level = max(st.max_level, e.level)
        if note and not st.feed_note:
            st.feed_note = note
        if e.rule_id:
            st.rule_ids.add(e.rule_id)
        st.groups |= set(e.groups)
        if e.agent_name:
            st.agents.add(e.agent_name)
        if e.full_log and len(st.samples) < 3 and e.full_log not in st.samples:
            st.samples.append(e.full_log)
        if e.timestamp:
            st.first = e.timestamp if not st.first else min(st.first, e.timestamp)
            st.last = e.timestamp if not st.last else max(st.last, e.timestamp)

        qualifies = bool(st.feed_note) or st.max_level >= self.cfg.high_severity_level \
            or st.attack_count >= self.cfg.volume_threshold
        if qualifies and not st.emitted:
            st.emitted = True
            return [self._build(e.srcip, st)]
        return []

    def _build(self, ip: str, st: _MalIPState) -> Indicator:
        reasons = []
        level = self.cfg.level
        subtype = []
        score = 0
        source = ""
        if st.feed_note:
            reasons.append(f"threat-intel match: {st.feed_note}")
            subtype.append("threat_feed")
            fconf, fsrc = source_confidence(st.feed_note)
            score = max(score, fconf); source = fsrc
        if st.max_level >= self.cfg.high_severity_level:
            reasons.append(f"seen in high-severity alert (level {st.max_level})")
            subtype.append("high_severity")
            score = max(score, min(60 + max(0, st.max_level - 10) * 4, 82))
        if st.attack_count >= self.cfg.volume_threshold:
            reasons.append(f"{st.attack_count} attack/scan alerts total")
            subtype.append("volume")
            score = max(score, min(58 + st.attack_count // 200, 72))
            source = source or "behavioral"
        if not subtype:
            subtype.append("suspicious"); score = max(score, 55)
        conf = "high" if score >= 80 else ("medium" if score >= 65 else "low")
        return Indicator(
            itype=self.itype, subtype="+".join(subtype), value=ip, match_field="srcip",
            reason="; ".join(reasons), level=level, count=max(st.attack_count, 1),
            first_seen=st.first, last_seen=st.last,
            sample_rule_ids=set(st.rule_ids), sample_logs=list(st.samples),
            groups=set(st.groups), mitre={"T1595", "T1071"}, agents=set(st.agents),
            confidence=conf, score=score, source=source,
        )

    def finalize(self) -> list[Indicator]:
        out = []
        for ip, st in self._ips.items():
            if st.feed_note or st.max_level >= self.cfg.high_severity_level \
                    or st.attack_count >= self.cfg.volume_threshold:
                out.append(self._build(ip, st))
        return out


# --------------------------------------------------------------------------- #
# Malicious artifact
# --------------------------------------------------------------------------- #
@dataclass
class _ArtState:
    ind: Indicator
    emitted: bool = False


class MaliciousArtifactDetector:
    itype = "malicious_artifact"

    def __init__(self, cfg: MaliciousArtifactConfig, hash_feed: dict[str, str]):
        self.cfg = cfg
        self.hash_feed = hash_feed
        self._by_key: dict[tuple, _ArtState] = {}
        self._sigs = [(re.compile(s["pattern"], re.I), s["label"], s.get("mitre", ""), s["pattern"])
                      for s in cfg.command_signatures]
        self._path_hints = [h.lower() for h in cfg.suspicious_path_hints]
        self._reg_hints = [re.compile(h, re.I) for h in cfg.suspicious_registry_hints]

    def _touch(self, key, factory) -> tuple[_ArtState, bool]:
        st = self._by_key.get(key)
        new = False
        if st is None:
            st = _ArtState(ind=factory())
            self._by_key[key] = st
            new = True
        return st, new

    def _update_common(self, ind: Indicator, e: Event) -> None:
        ind.count += 1
        if e.rule_id:
            ind.sample_rule_ids.add(e.rule_id)
        ind.groups |= set(e.groups)
        if e.agent_name:
            ind.agents.add(e.agent_name)
        ind.add_sample_log(e.full_log)
        if e.timestamp:
            ind.first_seen = e.timestamp if not ind.first_seen else min(ind.first_seen, e.timestamp)
            ind.last_seen = e.timestamp if not ind.last_seen else max(ind.last_seen, e.timestamp)

    def feed(self, e: Event) -> list[Indicator]:
        if not self.cfg.enabled:
            return []
        emitted: list[Indicator] = []

        # 1) known-malicious file hash (FIM / Sysmon)
        if e.file_hash:
            h = e.file_hash.lower()
            note = self.hash_feed.get(h)
            if note:
                field_name = {"sha256": "sha256_after", "sha1": "sha1_after",
                              "md5": "md5_after"}.get(e.hash_type or "sha256", "sha256_after")
                key = ("hash", h)
                st, new = self._touch(key, lambda: Indicator(
                    itype=self.itype, subtype="file_hash", value=h, match_field=field_name,
                    reason=f"known-malicious file hash ({note})", level=self.cfg.level,
                    count=0, mitre={"T1204", "T1105"}, confidence="high",
                    score=max(source_confidence(note)[0], 90), source=source_confidence(note)[1]))
                self._update_common(st.ind, e)
                if e.file_path:
                    st.ind.reason = f"known-malicious file hash ({note}) e.g. {e.file_path}"
                if not st.emitted:
                    st.emitted = True
                    emitted.append(_clone(st.ind))

        # 2) command-line / full_log attack signatures
        hay = " ".join(x for x in (e.command, e.full_log) if x)
        if hay:
            for rx, label, mitre, pattern in self._sigs:
                if rx.search(hay):
                    key = ("cmd", label)
                    st, new = self._touch(key, lambda lbl=label, pat=pattern, mit=mitre: Indicator(
                        itype=self.itype, subtype="command", value=pat, match_field="full_log_regex",
                        reason=f"suspicious command pattern: {lbl}", level=self.cfg.level,
                        count=0, mitre={mit} if mit else set(), confidence="medium",
                        score=65, source="signature"))
                    self._update_common(st.ind, e)
                    if not st.emitted:
                        st.emitted = True
                        emitted.append(_clone(st.ind))

        # 3) suspicious registry persistence change (FIM registry) - opt-in
        if self.cfg.detect_registry_persistence and e.file_path and \
                ("syscheck_registry" in e.groups or e.file_path.upper().startswith("HKEY")):
            if any(rx.search(e.file_path) for rx in self._reg_hints):
                key = ("reg", e.file_path)
                st, new = self._touch(key, lambda p=e.file_path: Indicator(
                    itype=self.itype, subtype="registry", value=p, match_field="path",
                    reason=f"FIM change to persistence registry key: {p}", level=self.cfg.level,
                    count=0, mitre={"T1547.001"}, confidence="medium", score=55, source="behavioral"))
                self._update_common(st.ind, e)
                if not st.emitted:
                    st.emitted = True
                    emitted.append(_clone(st.ind))

        # 4) file dropped into a suspicious location (FIM file added) - opt-in
        elif self.cfg.detect_suspicious_paths and e.file_path and "syscheck" in e.groups \
                and not e.file_path.upper().startswith("HKEY"):
            low = e.file_path.lower()
            if any(hint in low for hint in self._path_hints):
                key = ("path", e.file_path)
                st, new = self._touch(key, lambda p=e.file_path: Indicator(
                    itype=self.itype, subtype="suspicious_path", value=p, match_field="file",
                    reason=f"file change in suspicious location: {p}", level=self.cfg.level - 2,
                    count=0, mitre={"T1105"}, confidence="low", score=45, source="behavioral"))
                self._update_common(st.ind, e)
                if not st.emitted:
                    st.emitted = True
                    emitted.append(_clone(st.ind))

        return emitted

    def finalize(self) -> list[Indicator]:
        return [_clone(st.ind) for st in self._by_key.values()]


# --------------------------------------------------------------------------- #
# Bundle
# --------------------------------------------------------------------------- #
class DetectorBundle:
    """Runs all enabled detectors and offers a single feed()/finalize() surface."""

    def __init__(self, cfg, ip_feed: IPMatcher, allowlist: IPMatcher, hash_feed: dict[str, str]):
        self.bruteforce = BruteForceDetector(cfg.detectors.bruteforce)
        self.malicious_ip = MaliciousIPDetector(cfg.detectors.malicious_ip, ip_feed, allowlist)
        self.malicious_artifact = MaliciousArtifactDetector(cfg.detectors.malicious_artifact, hash_feed)
        self._all = [self.bruteforce, self.malicious_ip, self.malicious_artifact]

    def feed(self, e: Event) -> list[Indicator]:
        out: list[Indicator] = []
        for d in self._all:
            out.extend(d.feed(e))
        return out

    def finalize(self) -> list[Indicator]:
        out: list[Indicator] = []
        for d in self._all:
            out.extend(d.finalize())
        return out

    def reload_feeds(self, cfg) -> None:
        """Swap in freshly-loaded threat-intel feeds without losing detector state."""
        self.malicious_ip.ip_feed = load_ip_feeds([cfg.resolve(p) for p in cfg.ip_feeds])
        self.malicious_ip.allow = load_allowlist(cfg.ip_allowlist)
        self.malicious_artifact.hash_feed = load_hash_feeds([cfg.resolve(p) for p in cfg.hash_feeds])


def build_bundle(cfg) -> DetectorBundle:
    ip_feed = load_ip_feeds([cfg.resolve(p) for p in cfg.ip_feeds])
    allowlist = load_allowlist(cfg.ip_allowlist)
    hash_feed = load_hash_feeds([cfg.resolve(p) for p in cfg.hash_feeds])
    return DetectorBundle(cfg, ip_feed, allowlist, hash_feed)
