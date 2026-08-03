"""Orchestration: batch ``scan`` and real-time ``run`` (daemon) modes.

State (tailer offset/inode, the IOC->rule-ID map, and accumulated indicators) is
persisted to a JSON file so the daemon resumes cleanly across restarts and log
rotation without renumbering rules or reprocessing old alerts.
"""

from __future__ import annotations

import json
import os
import re
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Optional

from .config import Config
from .detectors import build_bundle
from .emit import (build_events, post_detections, write_detections_jsonl,
                   write_heartbeat, write_metrics)
from .models import Indicator
from .normalize import normalize_alert
from .rulegen import (IdAllocator, atomic_write, build_rules_document,
                      merge_indicators, validate_document, write_cdb_lists)
from .sources import Tailer, discover_archived_alerts, iter_alerts, parse_line


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


# --------------------------------------------------------------------------- #
# Indicator (de)serialization for the state file
# --------------------------------------------------------------------------- #
def _ind_to_json(ind: Indicator) -> dict:
    return {
        "itype": ind.itype, "subtype": ind.subtype, "value": ind.value,
        "match_field": ind.match_field, "reason": ind.reason, "level": ind.level,
        "count": ind.count,
        "first_seen": ind.first_seen.isoformat() if ind.first_seen else None,
        "last_seen": ind.last_seen.isoformat() if ind.last_seen else None,
        "users": sorted(ind.users), "sample_rule_ids": sorted(ind.sample_rule_ids),
        "sample_logs": ind.sample_logs, "groups": sorted(ind.groups),
        "mitre": sorted(ind.mitre), "agents": sorted(ind.agents),
        "confidence": ind.confidence, "score": ind.score, "source": ind.source,
    }


def _ind_from_json(d: dict) -> Indicator:
    def _dt(v):
        try:
            return datetime.fromisoformat(v) if v else None
        except (ValueError, TypeError):
            return None
    return Indicator(
        itype=d["itype"], subtype=d.get("subtype", ""), value=d["value"],
        match_field=d.get("match_field", "srcip"), reason=d.get("reason", ""),
        level=d.get("level", 10), count=d.get("count", 1),
        first_seen=_dt(d.get("first_seen")), last_seen=_dt(d.get("last_seen")),
        users=set(d.get("users", [])), sample_rule_ids=set(d.get("sample_rule_ids", [])),
        sample_logs=list(d.get("sample_logs", [])), groups=set(d.get("groups", [])),
        mitre=set(d.get("mitre", [])), agents=set(d.get("agents", [])),
        confidence=d.get("confidence", "medium"),
        score=d.get("score", 60), source=d.get("source", ""),
    )


class Engine:
    def __init__(self, cfg: Config, verbose: bool = False):
        self.cfg = cfg
        self.verbose = verbose
        self.bundle = build_bundle(cfg)
        self._excludes = [re.compile(p, re.I) for p in (cfg.exclude_log_patterns or [])]
        self._stop = False
        self._processed = 0
        state = self._load_state()
        self.allocator = IdAllocator(cfg.id_base, cfg.id_max, state.get("allocator"))
        # live merged indicators (run mode), keyed by (field, value)
        self.indicators: dict[tuple, Indicator] = {}
        for d in state.get("indicators", []):
            ind = _ind_from_json(d)
            self.indicators[ind.key()] = ind
        self._state_tailer = state.get("tailer") or {}

    # ---- logging ----
    def _log(self, msg: str) -> None:
        print(f"[{_now_iso()}] {msg}", flush=True)

    def _vlog(self, msg: str) -> None:
        if self.verbose:
            self._log(msg)

    def _excluded(self, e) -> bool:
        """True if this event's full_log matches a configured benign/exclude pattern."""
        if not self._excludes:
            return False
        hay = e.full_log or ""
        return any(rx.search(hay) for rx in self._excludes)

    # ---- state ----
    @property
    def _state_path(self) -> str:
        return self.cfg.resolve(self.cfg.state_file)

    def _load_state(self) -> dict:
        try:
            with open(self._state_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_state(self, tailer: Optional[Tailer] = None) -> None:
        state = {
            "version": 1,
            "updated": _now_iso(),
            "allocator": self.allocator.to_dict(),
            "indicators": [_ind_to_json(i) for i in self.indicators.values()],
        }
        if tailer is not None:
            state["tailer"] = tailer.state
        elif self._state_tailer:
            state["tailer"] = self._state_tailer
        atomic_write(self._state_path, json.dumps(state, indent=2))

    # ---- writing rules ----
    def _write_outputs(self, indicators: list[Indicator]) -> tuple[str, list]:
        doc, rendered = build_rules_document(indicators, self.allocator, _now_iso())
        validate_document(doc)  # raises on malformed XML -> we never write junk
        atomic_write(self.cfg.rules_path, doc)
        cdb = {"ip": 0, "hash": 0}
        if self.cfg.write_cdb_lists:
            cdb = write_cdb_lists(indicators, self.cfg.cdb_ip_path, self.cfg.cdb_hash_path)
        return doc, rendered, cdb  # type: ignore[return-value]

    def _emit_detections(self, indicators: list[Indicator], stats: dict) -> None:
        """Write normalized v3 detection events (JSONL), optionally POST to the
        control-plane API, and refresh heartbeat + metrics. Never fatal."""
        if not self.cfg.emit_detections:
            return
        merged = merge_indicators(indicators)
        events = build_events(merged, _now_iso(), manager=self.cfg.manager_name)
        try:
            n = write_detections_jsonl(self.cfg.detections_path, events, append=False)
        except OSError as exc:
            self._log(f"ERROR writing detections: {exc!r}")
            return
        posted = ""
        if self.cfg.api_url:
            ok, msg = post_detections(self.cfg.api_url, self.cfg.api_token, events)
            posted = f" | control-plane POST: {'ok' if ok else 'FAILED'} ({msg})"
        s = dict(stats)
        s["detections"] = n
        s.setdefault("alerts_processed", self._processed)
        s.setdefault("indicators", len(merged))
        try:
            write_heartbeat(self.cfg.heartbeat_path, "ok", s)
            write_metrics(self.cfg.metrics_path, s)
        except OSError:
            pass
        self._log(f"Emitted {n} detection(s) -> {self.cfg.detections_path}{posted}")

    # ------------------------------------------------------------------ #
    # Batch scan
    # ------------------------------------------------------------------ #
    def scan(self, include_archives: bool = False, print_only: bool = False) -> dict:
        paths = [self.cfg.resolve(self.cfg.alerts_file)]
        if include_archives:
            adir = os.path.dirname(paths[0])
            paths += [p for p in discover_archived_alerts(adir) if p not in paths]

        total = 0
        excluded = 0
        t0 = time.time()
        for path in paths:
            if not os.path.exists(path):
                self._log(f"WARNING: alerts file not found: {path}")
                continue
            self._log(f"Scanning {path}")
            for alert in iter_alerts(path):
                total += 1
                ev = normalize_alert(alert, source_file=path)
                if self._excluded(ev):
                    excluded += 1
                    continue
                self.bundle.feed(ev)
        if excluded:
            self._log(f"Ignored {excluded} events matching exclude_log_patterns")

        indicators = self.bundle.finalize()
        stats = self._summarize(indicators, total, time.time() - t0)

        if not indicators:
            self._log("No suspicious indicators found - nothing to generate.")
            return stats
        if print_only:
            doc, _ = build_rules_document(indicators, self.allocator, _now_iso())
            validate_document(doc)
            sys.stdout.write(doc)
            return stats

        _doc, rendered, cdb = self._write_outputs(indicators)
        self.indicators = {i.key(): i for i in merge_indicators(indicators)}
        self._save_state()
        self._write_report(indicators, rendered, stats, cdb)
        self._log(f"Wrote {len(rendered)} rules -> {self.cfg.rules_path}")
        if cdb["ip"] or cdb["hash"]:
            self._log(f"Wrote CDB lists: {cdb['ip']} IPs, {cdb['hash']} hashes")
        self._log(f"Wrote report -> {self.cfg.report_path}")
        self._processed = total
        self._emit_detections(indicators, stats)
        return stats

    # ------------------------------------------------------------------ #
    # Real-time daemon
    # ------------------------------------------------------------------ #
    def run(self, once: bool = False) -> None:
        self._install_signals()
        path = self.cfg.resolve(self.cfg.alerts_file)
        st = self._state_tailer
        tailer = Tailer(
            path,
            from_start=False,
            start_offset=st.get("offset"),
            start_inode=tuple(st["inode"]) if st.get("inode") else None,
        )
        self._log(f"wazuh_rulegen daemon started; following {path}")
        self._log(f"Output rules: {self.cfg.rules_path}")
        if self.indicators:
            self._log(f"Resumed with {len(self.indicators)} known IOC(s) from state")

        last_flush = 0.0
        last_feed_check = 0.0
        self._feed_mtime = self._feeds_mtime()
        write_heartbeat(self.cfg.heartbeat_path, "running", {"indicators": len(self.indicators)})
        dirty = False
        while not self._stop:
            new_lines = tailer.poll()

            # hot-reload threat-intel feeds if the files changed on disk (checked ~every 30s)
            now0 = time.time()
            if now0 - last_feed_check >= 30:
                last_feed_check = now0
                m = self._feeds_mtime()
                if m != self._feed_mtime:
                    self._feed_mtime = m
                    self.bundle.reload_feeds(self.cfg)
                    self._log("Reloaded threat-intel feeds (files changed on disk)")
            for line in new_lines:
                alert = parse_line(line)
                if not alert:
                    continue
                ev = normalize_alert(alert, source_file=path)
                if self._excluded(ev):
                    continue
                self._processed += 1
                emitted = self.bundle.feed(ev)
                for ind in emitted:
                    k = ind.key()
                    if k in self.indicators:
                        self.indicators[k].merge(ind)
                    else:
                        self.indicators[k] = ind
                        self._log(f"NEW IOC [{ind.itype}/{ind.subtype}] {ind.value} - {ind.reason}")
                    dirty = True

            now = time.time()
            if dirty and (now - last_flush) >= self.cfg.flush_interval:
                self._flush(tailer)
                dirty = False
                last_flush = now
            elif new_lines:
                # persist tailer position frequently even without new IOCs
                self._state_tailer = tailer.state
                self._save_state(tailer)

            if once and not new_lines:
                break
            if not new_lines:
                time.sleep(self.cfg.poll_interval)

        # clean shutdown
        if dirty:
            self._flush(tailer)
        else:
            self._save_state(tailer)
        tailer.close()
        self._log("wazuh_rulegen daemon stopped; state saved.")

    def _flush(self, tailer: Tailer) -> None:
        indicators = list(self.indicators.values())
        try:
            _doc, rendered, cdb = self._write_outputs(indicators)
        except Exception as exc:  # never let a bad write kill the daemon
            self._log(f"ERROR writing rules: {exc!r}")
            return
        self._state_tailer = tailer.state
        self._save_state(tailer)
        self._log(f"Flushed {len(rendered)} rules -> {self.cfg.rules_path} "
                  f"(CDB: {cdb['ip']} IPs, {cdb['hash']} hashes)")
        self._emit_detections(indicators, {"indicators": len(indicators)})

    def _feeds_mtime(self) -> float:
        """Newest mtime across all configured feed files (0 if none exist)."""
        latest = 0.0
        for p in list(self.cfg.ip_feeds) + list(self.cfg.hash_feeds):
            try:
                latest = max(latest, os.path.getmtime(self.cfg.resolve(p)))
            except OSError:
                continue
        return latest

    # ---- signals ----
    def _install_signals(self) -> None:
        def handler(signum, _frame):
            self._log(f"Received signal {signum}; shutting down...")
            self._stop = True
        for name in ("SIGTERM", "SIGINT", "SIGHUP"):
            sig = getattr(signal, name, None)
            if sig is not None:
                try:
                    signal.signal(sig, handler)
                except (ValueError, OSError):
                    pass

    # ---- reporting ----
    def _summarize(self, indicators: list[Indicator], alerts: int, secs: float) -> dict:
        merged = merge_indicators(indicators)
        by_type: dict[str, int] = {}
        for i in merged:
            by_type[i.itype] = by_type.get(i.itype, 0) + 1
        return {
            "alerts_processed": alerts,
            "indicators": len(merged),
            "by_type": by_type,
            "elapsed_seconds": round(secs, 3),
        }

    def _write_report(self, indicators, rendered, stats, cdb) -> None:
        merged = merge_indicators(indicators)
        report = {
            "generated_at": _now_iso(),
            "stats": stats,
            "cdb_lists": cdb,
            "rules_file": self.cfg.rules_path,
            "indicators": [
                {**_ind_to_json(i), "rule_id": self.allocator.map.get(IdAllocator.key(i))}
                for i in merged
            ],
        }
        atomic_write(self.cfg.report_path, json.dumps(report, indent=2))
