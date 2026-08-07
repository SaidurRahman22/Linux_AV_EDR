"""Bulletproof tests for the alert-calibration engine (analyst-in-a-box).

Drives the PURE verdict logic (calibrate.evaluate) with synthetic evidence — no DB,
no clock — so every senior-analyst rule is pinned down and can't silently regress.

Run:  cd controlplane && python -m unittest tests.test_calibrate -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.calibrate import _rank, evaluate  # noqa: E402


def det(severity="MEDIUM", event_type="SUSPICIOUS_PROCESS", ioc_type="", confidence=50):
    return {"severity": severity, "event_type": event_type, "ioc_type": ioc_type,
            "confidence": confidence}


def ctx(**kw):
    base = {"ioc_conf": None, "vt_malicious": 0, "allowlisted": False, "own_infra": False,
            "corroboration": 0, "related_types": 0, "prevalence": 0, "abuse_score": None,
            "path": "", "sha": "", "ioc_type": "", "details": {}, "event_type": ""}
    base.update(kw)
    # keep det ioc_type and ctx ioc_type in sync unless caller overrides
    return base


class TestKnownBad(unittest.TestCase):
    def test_ioc_hash_stays_critical_confirmed(self):
        r = evaluate(det("CRITICAL", "MALICIOUS_FILE_HASH", "hash", 90),
                     ctx(ioc_conf=95, vt_malicious=5, ioc_type="hash"))
        self.assertEqual(r["verdict"], "confirmed-threat")
        self.assertEqual(r["severity"], "CRITICAL")

    def test_known_ioc_never_below_high(self):
        # a known-bad IP that triggered only MEDIUM is FLOORED up to HIGH
        r = evaluate(det("MEDIUM", "MALICIOUS_IP", "ip", 60),
                     ctx(ioc_conf=85, ioc_type="ip"))
        self.assertGreaterEqual(_rank(r["severity"]), _rank("HIGH"))
        self.assertIn(r["verdict"], ("confirmed-threat", "likely-threat"))


class TestBenignSuppression(unittest.TestCase):
    def test_allowlisted_is_benign_noise(self):
        r = evaluate(det("HIGH", "SIGNATURE_MATCH", "hash", 96),
                     ctx(allowlisted=True, sha="abc", ioc_type="hash"))
        self.assertEqual(r["verdict"], "benign-noise")
        self.assertEqual(r["severity"], "INFO")

    def test_own_infra_is_benign(self):
        r = evaluate(det("HIGH", "MALICIOUS_IP", "ip", 70),
                     ctx(own_infra=True, ioc_type="ip"))
        self.assertEqual(r["verdict"], "benign-noise")


class TestFuzzyFalsePositives(unittest.TestCase):
    def test_yara_on_system_lib_downgraded(self):
        # the exact libc/initramfs false positive that started this work
        r = evaluate(det("CRITICAL", "SIGNATURE_MATCH", "", 96),
                     ctx(path="/var/tmp/mkinitramfs_9C8/usr/lib/x86_64-linux-gnu/libc.so.6"))
        self.assertEqual(r["verdict"], "likely-noise")
        self.assertLessEqual(_rank(r["severity"]), _rank("MEDIUM"))

    def test_transport_tool_process_downgraded(self):
        # plink.exe carrying a remote command — the 4x-alert spam source
        r = evaluate(det("CRITICAL", "SUSPICIOUS_PROCESS", "process", 90),
                     ctx(path="C:\\tools\\plink.exe", ioc_type="process",
                         details={"name": "plink.exe", "all_behaviors": ["curl_pipe_shell"]}))
        self.assertEqual(r["verdict"], "likely-noise")
        self.assertLessEqual(_rank(r["severity"]), _rank("MEDIUM"))

    def test_signed_windows_binary_eased(self):
        r = evaluate(det("HIGH", "SUSPICIOUS_PROCESS", "process", 70),
                     ctx(path="C:\\Program Files\\App\\app.exe", ioc_type="process",
                         details={"name": "app.exe", "signed": True}))
        self.assertLessEqual(_rank(r["severity"]), _rank("HIGH"))
        self.assertNotEqual(r["verdict"], "confirmed-threat")


class TestRealThreatsPreserved(unittest.TestCase):
    def test_dropper_in_tmp_corroborated_stays_high(self):
        # writable-path + corroboration keep this a threat, but WITHOUT reputation the
        # CRITICAL cap holds it at HIGH (only hard intel can manufacture CRITICAL — A8)
        r = evaluate(det("HIGH", "SUSPICIOUS_PROCESS", "process", 70),
                     ctx(path="/tmp/xmrig", ioc_type="process", related_types=4, corroboration=6))
        self.assertIn(r["verdict"], ("likely-threat", "inconclusive", "confirmed-threat"))
        self.assertGreaterEqual(_rank(r["severity"]), _rank("HIGH"))

    def test_context_cannot_manufacture_critical(self):
        # a MEDIUM heuristic with lots of host context must not become CRITICAL
        r = evaluate(det("MEDIUM", "SUSPICIOUS_PROCESS", "process", 70),
                     ctx(path="/tmp/x", ioc_type="process", related_types=6,
                         details={"all_behaviors": ["a", "b", "c"]}))
        self.assertLess(_rank(r["severity"]), _rank("CRITICAL"))

    def test_reputation_can_reach_critical(self):
        # known-bad intel is allowed to escalate all the way
        r = evaluate(det("HIGH", "MALICIOUS_IP", "ip", 70),
                     ctx(ioc_conf=95, vt_malicious=8, ioc_type="ip", related_types=4))
        self.assertEqual(r["verdict"], "confirmed-threat")

    def test_exact_hash_on_system_path_not_downgraded(self):
        # FAIL-SAFE: a precise hash match is never suppressed by a "trusted path"
        r = evaluate(det("HIGH", "SIGNATURE_MATCH", "hash", 90),
                     ctx(path="/usr/lib/x86_64-linux-gnu/evil.so", sha="deadbeef", ioc_type="hash"))
        self.assertGreaterEqual(_rank(r["severity"]), _rank("HIGH"))
        self.assertIn(r["verdict"], ("likely-threat", "confirmed-threat"))

    def test_writable_path_raises(self):
        r = evaluate(det("MEDIUM", "SUSPICIOUS_PROCESS", "process", 70),
                     ctx(path="/dev/shm/.x", ioc_type="process",
                         details={"all_behaviors": ["reverse_shell", "curl_pipe_shell"]}))
        self.assertGreaterEqual(_rank(r["severity"]), _rank("MEDIUM"))
        self.assertNotEqual(r["verdict"], "likely-noise")


class TestFailSafeAndNoise(unittest.TestCase):
    def test_thin_evidence_is_inconclusive_keeps_raw(self):
        r = evaluate(det("MEDIUM", "SUSPICIOUS_PROCESS", "process", 50),
                     ctx(path="/opt/app/bin/tool", ioc_type="process", prevalence=2))
        self.assertEqual(r["verdict"], "inconclusive")
        self.assertEqual(r["severity"], "MEDIUM")   # unchanged — human decides

    def test_high_prevalence_is_noise(self):
        r = evaluate(det("HIGH", "SUSPICIOUS_PROCESS", "process", 55),
                     ctx(path="/opt/app/x", ioc_type="process", prevalence=40))
        self.assertEqual(r["verdict"], "likely-noise")
        self.assertLess(_rank(r["severity"]), _rank("HIGH"))

    def test_bd_ip_capped_and_flagged_for_review(self):
        r = evaluate(det("HIGH", "MALICIOUS_IP", "ip", 60),
                     ctx(ioc_type="ip", vt_malicious=1, details={"country": "BD"}))
        self.assertLessEqual(_rank(r["severity"]), _rank("MEDIUM"))  # capped
        self.assertTrue(r["review"])                                  # flagged for a human
        self.assertEqual(r["verdict"], "inconclusive")               # not auto-buried

    def test_reasons_always_present(self):
        r = evaluate(det("LOW", "SOME_EVENT", "", 10), ctx())
        self.assertTrue(r["reasons"])
        self.assertIn("version", r)


class TestAntiEvasion(unittest.TestCase):
    """A compromised endpoint controls details.* — these lock down the downgrades."""

    def test_soft_negatives_capped_cannot_bury_critical(self):
        # attacker stacks signed + system-path + transport-tool on a real reverse shell
        r = evaluate(det("CRITICAL", "SUSPICIOUS_PROCESS", "process", 90),
                     ctx(path="/usr/bin/ssh", ioc_type="process",
                         details={"name": "ssh", "signed": True}))
        # capped at a 2-tier drop → MEDIUM, never INFO/LOW
        self.assertEqual(r["severity"], "MEDIUM")
        self.assertTrue(any(x["signal"] == "soft-neg-cap" for x in r["reasons"]))

    def test_so_in_devshm_is_not_trusted(self):
        # ".so" extension no longer confers trust inside a writable/staging dir
        r = evaluate(det("CRITICAL", "SIGNATURE_MATCH", "", 95),
                     ctx(path="/dev/shm/.x.so"))
        self.assertGreaterEqual(_rank(r["severity"]), _rank("HIGH"))
        self.assertNotIn(r["verdict"], ("likely-noise", "benign-noise"))

    def test_transport_downgrade_not_applied_to_known_bad(self):
        # confirmed-bad process with a spoofed name="ssh" must stay a threat
        r = evaluate(det("CRITICAL", "SUSPICIOUS_PROCESS", "process", 90),
                     ctx(ioc_conf=90, ioc_type="process",
                         details={"name": "ssh", "signed": True}))
        self.assertEqual(r["severity"], "CRITICAL")
        self.assertEqual(r["verdict"], "confirmed-threat")
        self.assertFalse(any(x["signal"] == "transport-tool" for x in r["reasons"]))

    def test_allowlist_conflict_is_surfaced_not_suppressed(self):
        # allowlisted indicator that is ALSO high-confidence threat intel → review, not benign
        r = evaluate(det("HIGH", "MALICIOUS_IP", "ip", 70),
                     ctx(allowlisted=True, ioc_conf=100, vt_malicious=60, ioc_type="ip"))
        self.assertNotEqual(r["verdict"], "benign-noise")
        self.assertTrue(r["review"])
        self.assertGreaterEqual(_rank(r["severity"]), _rank("HIGH"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
