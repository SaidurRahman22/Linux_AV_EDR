"""Self-contained tests: run with `python -m unittest` or `python tests/test_rulegen.py`."""

import os
import sys
import unittest
from xml.etree import ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wazuh_rulegen.config import Config
from wazuh_rulegen.detectors import build_bundle
from wazuh_rulegen.intel import IPMatcher, load_hash_feeds
from wazuh_rulegen.normalize import normalize_alert, normalize_ip, parse_timestamp
from wazuh_rulegen.rulegen import (IdAllocator, build_rules_document,
                                   merge_indicators, validate_document)


def alert(rule_id, level, desc, groups, srcip=None, **data):
    a = {"timestamp": "2026-08-02T10:00:00.000+0600",
         "rule": {"id": str(rule_id), "level": level, "description": desc, "groups": groups},
         "agent": {"name": "TestAgent"}}
    if srcip:
        data["srcip"] = srcip
    if data:
        a["data"] = data
    return a


class TestNormalize(unittest.TestCase):
    def test_ip_port_strip(self):
        self.assertEqual(normalize_ip("185.177.72.5:1366"), ("185.177.72.5", "1366"))
        self.assertEqual(normalize_ip("8.8.8.8"), ("8.8.8.8", None))
        self.assertEqual(normalize_ip("[2001:db8::1]:443"), ("2001:db8::1", "443"))

    def test_timestamp_offset(self):
        ts = parse_timestamp("2026-08-02T10:00:00.000+0600")
        self.assertIsNotNone(ts)
        self.assertEqual(ts.utcoffset().total_seconds(), 6 * 3600)

    def test_event_fields(self):
        e = normalize_alert(alert(31101, 5, "Web 400", ["web", "attack"], srcip="1.2.3.4:99"))
        self.assertEqual(e.srcip, "1.2.3.4")
        self.assertEqual(e.rule_id, "31101")
        self.assertEqual(e.level, 5)


class TestIntel(unittest.TestCase):
    def test_ip_and_cidr_match(self):
        m = IPMatcher()
        m.add("45.148.10.238", "bad host")
        m.add("185.220.101.0/24", "tor")
        self.assertEqual(m.match("45.148.10.238"), "bad host")
        self.assertIn("tor", m.match("185.220.101.55"))
        self.assertIsNone(m.match("8.8.8.8"))


class TestDetectors(unittest.TestCase):
    def _cfg(self):
        c = Config()
        c.detectors.bruteforce.min_flood_events = 3
        c.detectors.bruteforce.timeframe_seconds = 3600
        c.detectors.malicious_ip.volume_threshold = 3
        return c

    def test_scan_flood_bruteforce(self):
        cfg = self._cfg()
        bundle = build_bundle(cfg)
        for i in range(5):
            a = alert(31101, 5, "Web server 400 error code.", ["web", "attack", "web_scan"], srcip="9.9.9.9:500")
            a["timestamp"] = f"2026-08-02T10:0{i}:00.000+0600"
            bundle.feed(normalize_alert(a))
        inds = bundle.finalize()
        bf = [i for i in inds if i.itype == "bruteforce" and i.value == "9.9.9.9"]
        self.assertTrue(bf, "expected a brute-force/scan indicator for 9.9.9.9")

    def test_malicious_ip_high_severity(self):
        cfg = self._cfg()
        bundle = build_bundle(cfg)
        bundle.feed(normalize_alert(alert(31151, 10, "Multiple 400s", ["web", "attack"], srcip="7.7.7.7")))
        inds = bundle.finalize()
        self.assertTrue(any(i.itype == "malicious_ip" and i.value == "7.7.7.7" for i in inds))

    def test_malicious_artifact_hash(self):
        cfg = Config()
        cfg.hash_feeds = []
        bundle = build_bundle(cfg)
        # inject a known hash directly into the detector's feed
        bundle.malicious_artifact.hash_feed["abc123" + "0" * 58] = "test-malware"
        a = {"timestamp": "2026-08-02T10:00:00.000+0600",
             "rule": {"id": "554", "level": 7, "description": "File added", "groups": ["syscheck"]},
             "agent": {"name": "A"},
             "syscheck": {"path": "/tmp/evil", "sha256_after": "abc123" + "0" * 58}}
        bundle.feed(normalize_alert(a))
        inds = bundle.finalize()
        self.assertTrue(any(i.itype == "malicious_artifact" and i.subtype == "file_hash" for i in inds))


class TestRuleGen(unittest.TestCase):
    def _ind_from(self, cfg_events):
        cfg = Config()
        cfg.detectors.bruteforce.min_flood_events = 2
        bundle = build_bundle(cfg)
        for a in cfg_events:
            bundle.feed(normalize_alert(a))
        return bundle.finalize()

    def test_valid_xml_and_ids(self):
        events = []
        for i in range(3):
            a = alert(31101, 5, "Web 400", ["web", "attack", "web_scan"], srcip="5.5.5.5")
            a["timestamp"] = f"2026-08-02T10:0{i}:00.000+0600"
            events.append(a)
        inds = self._ind_from(events)
        alloc = IdAllocator(100000, 120000)
        doc, rendered = build_rules_document(inds, alloc, "2026-08-02T10:00:00+06:00")
        validate_document(doc)  # must not raise
        root = ET.fromstring(f"<r>{doc}</r>")
        rules = root.findall(".//rule")
        self.assertTrue(rules)
        for r in rules:
            self.assertGreaterEqual(int(r.get("id")), 100000)
            self.assertTrue(r.findall("description"))

    def test_merge_dedup_and_id_stability(self):
        from wazuh_rulegen.models import Indicator
        i1 = Indicator(itype="bruteforce", subtype="scan_flood", value="1.1.1.1", reason="scan")
        i2 = Indicator(itype="malicious_ip", subtype="threat_feed", value="1.1.1.1", reason="feed")
        merged = merge_indicators([i1, i2])
        self.assertEqual(len(merged), 1)
        self.assertIn("scan", merged[0].reason)
        self.assertIn("feed", merged[0].reason)
        alloc = IdAllocator(100000, 120000)
        first = alloc.id_for(merged[0])
        again = alloc.id_for(merged[0])
        self.assertEqual(first, again)  # stable id


if __name__ == "__main__":
    unittest.main(verbosity=2)
