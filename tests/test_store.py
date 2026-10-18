"""Store, gate and diff behaviour. Run: python3 -m unittest discover -s tests"""
import json
import os
import tempfile
import unittest

from locaudit import paths, store


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="locaudit-")
        os.environ["LOCAUDIT_HOME"] = self.home
        self.rid = store.start_run("test", note="unit")

    def tearDown(self):
        os.environ.pop("LOCAUDIT_HOME", None)

    def test_run_created_and_latest(self):
        self.assertTrue(os.path.exists(paths.run_file(self.rid)))
        self.assertEqual(store.latest(), self.rid)

    def test_fact_requires_tier_and_namespaced_subject(self):
        doc = store.new_app("com.example.a")
        store.add_fact(doc, "perm:ACCESS_FINE_LOCATION", "granted",
                       tier="T0", source="dumpsys package")
        store.save_app("com.example.a", doc)
        self.assertEqual(store.load_app("com.example.a")["facts"]
                         ["perm:ACCESS_FINE_LOCATION"]["value"], "granted")
        with self.assertRaises(ValueError):
            store.add_fact(doc, "no-namespace", "x", tier="T0", source="s")
        with self.assertRaises(ValueError):
            store.add_fact(doc, "perm:X", "x", tier="T9", source="s")

    def test_unknown_is_a_value(self):
        doc = store.new_app("com.example.b")
        store.add_fact(doc, "unknown:packed", True, tier="T3", source="index",
                       confidence="unknown", reason="no dex entries")
        store.save_app("com.example.b", doc)
        sheet = store.load_app("com.example.b")
        self.assertIn("unknown:packed", sheet["facts"])
        self.assertEqual(sheet["facts"]["unknown:packed"]["reason"], "no dex entries")

    def test_diff_sees_a_changed_fact(self):
        doc = store.new_app("com.example.c")
        store.add_fact(doc, "perm:ACCESS_BACKGROUND_LOCATION", "denied",
                       tier="T0", source="dumpsys package")
        store.save_app("com.example.c", doc)

        updated = store.load_app("com.example.c")
        updated["facts"]["perm:ACCESS_BACKGROUND_LOCATION"]["value"] = "granted"
        store.save_app("com.example.c", updated)
        delta = store.diff_facts(doc, updated)
        self.assertEqual(delta["changed"]["perm:ACCESS_BACKGROUND_LOCATION"]
                         ["to"]["value"], "granted")

    def test_validate_catches_missing_source(self):
        doc = store.new_app("com.example.d")
        doc["facts"]["perm:X"] = {"value": "granted", "tier": "T0", "at": "now"}
        errors = store.validate_app(doc)
        self.assertTrue(any("missing source" in e for e in errors))
