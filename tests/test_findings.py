"""Tests for findings digest and Markdown report generation."""
import os
import shutil
import tempfile
import unittest
from unittest import mock

from locaudit import findings, paths, store


class FindingsTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="locaudit-findings-")
        self.addCleanup(shutil.rmtree, self.home)
        patcher = mock.patch.dict(os.environ, {"LOCAUDIT_HOME": self.home})
        patcher.start()
        self.addCleanup(patcher.stop)
        paths.ensure()
        self.rid = store.start_run("0.1.0", rid="2026-01-01T000000Z")
        self.add_app("com.example.closed", background=True, says_collects="yes",
                     says_shares="yes", purposes="App functionality", ad_id=True,
                     sdks=[("braze", "Braze")])
        self.add_app("com.example.open", background=False, says_collects="yes",
                     says_shares="no", bg_logged=True)
        self.add_app("com.example.refused", background=False, refused=True,
                     says_collects="yes", says_shares="no")

    def add_app(self, pkg, background=False, refused=False, says_collects=None,
                says_shares=None, purposes=None, ad_id=False, bg_logged=False,
                bg_rejected=False, delivered=0, sdks=None):
        def mutate(doc):
            store.add_fact(doc, "perm:ACCESS_BACKGROUND_LOCATION",
                           "granted" if background else "no", tier="T0",
                           source="dumpsys package")
            store.add_fact(doc, "perm:ACCESS_FINE_LOCATION",
                           "denied" if refused else "granted",
                           tier="T0", source="dumpsys package")
            store.add_fact(doc, "install:from", "com.android.vending", tier="T0",
                           source="dumpsys package")
            store.add_fact(doc, "sig:signed-by", "Maker Ltd", tier="T0", source="apksigner")
            if ad_id:
                store.add_fact(doc, "perm:AD_ID", "granted", tier="T0", source="dumpsys package")
            if bg_logged:
                store.add_fact(doc, "access:location", 2, tier="T1", source="dumpsys appops",
                               background=True, last="2026-10-18 10:00:00")
            if bg_rejected:
                store.add_fact(doc, "reject:location", 1, tier="T1", source="dumpsys appops",
                               background=True, last="2026-10-18 09:00:00")
            if delivered:
                store.add_fact(doc, "delivered:location", delivered, tier="T1",
                               source="dumpsys location counters")
            for slug, label in (sdks or []):
                store.add_fact(doc, f"sdk:{slug}", label, tier="T0", source="dumpsys package")
            if says_collects:
                store.add_fact(doc, "datasafety:collected:location", says_collects, tier="T2",
                               source="Play page")
            if says_shares:
                store.add_fact(doc, "datasafety:shared:location", says_shares, tier="T2",
                               source="Play page")
            if purposes:
                store.add_fact(doc, "datasafety:purposes:location", purposes, tier="T2",
                               source="Play page")
        store.update_app(pkg, mutate, self.rid)

    def test_the_counts_and_the_lists_agree(self):
        doc = findings.build(self.rid)
        counts, reads = doc["counts"], doc["by_reads"]
        self.assertEqual(counts["apps"], 3)
        self.assertEqual(len(reads["while closed"]), 1)
        self.assertEqual(len(reads["only while open"]), 1)
        self.assertEqual(len(reads["refused"]), 1)
        self.assertEqual(counts["says_collects"], 3)
        self.assertEqual(counts["says_shares"], 1)
        self.assertEqual(counts["location_with_ad_id"], 1)
        self.assertEqual(counts["location_with_sdks"], 1)
        self.assertEqual(counts["background_anomalies"], 1)
        self.assertEqual(counts["undisclosed_location"], 0)
        self.assertEqual(sum(len(reads[name]) for name in findings.READS), counts["apps"])

    def test_background_anomaly_detected(self):
        doc = findings.build(self.rid)
        anomalies = [a["pkg"] for a in doc["background_anomalies"]]
        self.assertEqual(anomalies, ["com.example.open"])

    def test_blocked_background_attempt_triggers_anomaly(self):
        self.add_app("com.example.blocked", background=False, bg_rejected=True)
        doc = findings.build(self.rid)
        anomalies = [a["pkg"] for a in doc["background_anomalies"]]
        self.assertIn("com.example.blocked", anomalies)

    def test_undisclosed_location_detected(self):
        self.add_app("com.example.secretive", background=False, bg_logged=True,
                     says_collects="no")
        doc = findings.build(self.rid)
        undisclosed = [a["pkg"] for a in doc["undisclosed_location"]]
        self.assertIn("com.example.secretive", undisclosed)

    def test_an_app_that_claims_location_without_the_permission_is_listed(self):
        doc = findings.build(self.rid)
        listed = {app["pkg"] for app in doc["claims_without_permission"]}
        self.assertEqual(listed, {"com.example.refused"})

    def test_the_markdown_says_what_the_digest_says(self):
        text = findings.markdown(findings.build(self.rid))
        self.assertIn("com.example.closed", text)
        self.assertIn("3 apps read from the phone", text)
        self.assertIn("Braze", text)


    def test_deep_dive_inspection_rendering(self):
        def mutate(doc):
            store.add_fact(doc, "code:primary-engine", "React Native (Hermes bytecode)",
                           tier="T3", source="zip central directory")
            store.add_fact(doc, "code:decompilation-confidence", "partial (React Native bundle)",
                           tier="T3", source="zip central directory")
            store.add_fact(doc, "code:binary-structure", "1 DEX (0.01 MB), 8 .so libs",
                           tier="T3", source="zip central directory")
            store.add_fact(doc, "code:location-classes", "com.example.closed.LocMgr",
                           tier="T3", source="jadx", count=1)
        store.update_app("com.example.closed", mutate, self.rid)
        doc = findings.build(self.rid)
        text = findings.markdown(doc)
        self.assertIn("React Native (Hermes bytecode)", text)
        self.assertIn("1 DEX (0.01 MB), 8 .so libs", text)
        self.assertIn("com.example.closed.LocMgr", text)


if __name__ == "__main__":
    unittest.main()
