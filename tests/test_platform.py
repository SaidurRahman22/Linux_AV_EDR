"""Tests for Increment 1.5 (platform integration): numeric confidence, v3 emit,
IOC source confidence, and the lifecycle sidecar. Run: python -m unittest."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wazuh_rulegen import feedupdate
from wazuh_rulegen.config import Config, MaliciousIPConfig
from wazuh_rulegen.detectors import MaliciousIPDetector
from wazuh_rulegen.emit import build_events, indicator_to_event
from wazuh_rulegen.intel import IPMatcher, source_confidence
from wazuh_rulegen.models import Indicator
from wazuh_rulegen.normalize import normalize_alert


def _alert(srcip, rule_id="31151", level=10, desc="Multiple 400s", groups=("web", "attack")):
    return {"timestamp": "2026-08-03T10:00:00.000+0600",
            "rule": {"id": rule_id, "level": level, "description": desc, "groups": list(groups)},
            "agent": {"name": "A"}, "data": {"srcip": srcip}}


class TestSourceConfidence(unittest.TestCase):
    def test_known_sources(self):
        self.assertEqual(source_confidence("Emotet C2 (Feodo Tracker)")[0], 90)
        self.assertEqual(source_confidence("Cobalt Strike (ThreatFox)")[0], 85)
        self.assertEqual(source_confidence("x (MalwareBazaar)")[0], 80)

    def test_curated_vs_empty(self):
        self.assertEqual(source_confidence("hand-written note")[0], 95)   # curated
        self.assertEqual(source_confidence("")[0], 60)                     # bare feed


class TestNumericScore(unittest.TestCase):
    def test_feed_match_high_score(self):
        m = IPMatcher(); m.add("9.9.9.9", "Cobalt Strike (ThreatFox)")
        det = MaliciousIPDetector(MaliciousIPConfig(), m, IPMatcher())
        inds = det.feed(normalize_alert(_alert("9.9.9.9")))
        self.assertTrue(inds, "feed match should emit")
        self.assertGreaterEqual(inds[0].score, 85)
        self.assertIn("threat_feed", inds[0].subtype)
        self.assertEqual(inds[0].source, "ThreatFox")

    def test_behavioral_volume_low_score(self):
        cfg = MaliciousIPConfig(); cfg.volume_threshold = 3
        det = MaliciousIPDetector(cfg, IPMatcher(), IPMatcher())
        inds = []
        for _ in range(4):
            inds = det.feed(normalize_alert(_alert("7.7.7.7", level=5))) or inds
        self.assertTrue(inds)
        # volume-only (no feed, low severity) must stay a low score so it never auto-blocks
        self.assertLess(inds[0].score, 80)


class TestEmitSchema(unittest.TestCase):
    def test_v3_event(self):
        ind = Indicator(itype="malicious_ip", subtype="threat_feed", value="1.2.3.4",
                        match_field="srcip", reason="threat-intel match",
                        level=12, score=90, source="ThreatFox", mitre={"T1071"})
        ev = indicator_to_event(ind, "2026-08-03T10:00:00+06:00", manager="wazuh-mgr")
        self.assertEqual(ev["schema_version"], "3.0")
        self.assertEqual(ev["event"]["mode"], "DETECT")
        self.assertEqual(ev["event"]["confidence"], 90)
        self.assertEqual(ev["ioc"]["confidence"], 90)
        self.assertEqual(ev["mitre_attack"]["technique_id"], "T1071")
        self.assertFalse(ev["policy"]["allowlisted"])
        # must be JSON-serializable
        json.dumps(ev)

    def test_build_events(self):
        inds = [Indicator(itype="bruteforce", subtype="auth", value="5.5.5.5", score=78)]
        evs = build_events(inds, "2026-08-03T10:00:00+06:00")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["event"]["type"], "BRUTE_FORCE_SOURCE")


class TestMergePreservesScore(unittest.TestCase):
    def test_merge_keeps_highest_score_and_source(self):
        from wazuh_rulegen.rulegen import merge_indicators
        a = Indicator(itype="bruteforce", subtype="scan_flood", value="1.1.1.1",
                      score=55, source="behavioral")
        b = Indicator(itype="malicious_ip", subtype="threat_feed", value="1.1.1.1",
                      score=95, source="curated")
        merged = merge_indicators([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].score, 95)      # regression: score survived the copy
        self.assertEqual(merged[0].source, "curated")


class TestLifecycle(unittest.TestCase):
    def test_sidecar_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(); cfg.output_dir = tmp; cfg.base_dir = tmp; cfg.ioc_ttl_days = 30
            res = feedupdate._update_lifecycle(
                cfg, {"1.2.3.4": "x (ThreatFox)"}, {"a" * 64: "mal (MalwareBazaar)"})
            self.assertEqual(res["tracked"], 2)
            store = json.load(open(os.path.join(tmp, "ioc_lifecycle.json"), encoding="utf-8"))
            rec = store["1.2.3.4"]
            self.assertEqual(rec["confidence"], 85)
            self.assertEqual(rec["source"], "ThreatFox")
            self.assertIn("first_seen", rec)
            self.assertIn("expires_at", rec)
            self.assertFalse(rec["expired"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
