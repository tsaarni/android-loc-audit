"""Install info against the dumps' real shapes. Run: python3 -m unittest discover -s tests"""
import datetime
import os
import shutil
import tempfile
import unittest
from unittest import mock

from locaudit import meta, paths, store

PACKAGE = """Packages:
  Package [com.example.app] (abc123):
    appId=10390
    codePath=/data/app/~~abc==/com.example.app-xyz==
    versionCode=2109 minSdk=24 targetSdk=35
    versionName=4.8.6
    lastUpdateTime=2026-08-17 13:06:50
    installerPackageName=com.android.vending
    installerPackageUid=10284
    packageSource=0
"""

BY_HAND = PACKAGE.replace("installerPackageName=com.android.vending", "installerPackageName=null")


class MetaParseTest(unittest.TestCase):
    def test_store_version_and_dates(self):
        info = meta.parse_package(PACKAGE)
        self.assertEqual(info["installer"], "com.android.vending")
        self.assertEqual(info["version_name"], "4.8.6")
        self.assertEqual(info["version_code"], 2109)
        self.assertEqual(info["first_install"], None)
        self.assertEqual(info["last_update"], "2026-08-17 13:06:50")

    def test_a_null_installer_is_recorded_as_no_answer(self):
        """The phone writes the word null; that is not the fact 'installed by hand'."""
        info = meta.parse_package(BY_HAND)
        self.assertIsNone(info["installer"])
        self.assertEqual(info["version_name"], "4.8.6")

    def test_a_capture_without_the_line_is_not_mistaken_for_a_null(self):
        info = meta.parse_package(PACKAGE.replace("    installerPackageName=com.android.vending\n",
                                                  ""))
        self.assertIsNone(info["installer"])

    def test_age_is_counted_from_the_stamp_the_phone_wrote(self):
        today = datetime.datetime(2026, 10, 18, 12, 0, 0)
        self.assertEqual(meta.age_days("2026-10-08 12:00:00", today), 10)
        self.assertIsNone(meta.age_days(None))
        self.assertIsNone(meta.age_days("not a date"))

    def test_installers_are_named_in_words(self):
        text = meta._stores({"com.android.vending": 114, "com.example.mover": 21,
                             meta.NO_INSTALLER: 2})
        self.assertIn("114 came from Google Play", text)
        self.assertIn("21 came from an app on the phone (com.example.mover)", text)
        self.assertIn("2 have no installer recorded", text)


class MetaRunTest(unittest.TestCase):
    """The phase end to end on a capture it made up itself."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="locaudit-meta-")
        self.addCleanup(shutil.rmtree, self.home)
        patcher = mock.patch.dict(os.environ, {"LOCAUDIT_HOME": self.home})
        patcher.start()
        self.addCleanup(patcher.stop)
        paths.ensure()
        self.rid = store.start_run("0.1.0", rid="2026-01-01T000000Z")
        with open(paths.device("third_party_pkgs.txt"), "w", encoding="utf-8") as f:
            f.write("com.example.app\ncom.example.hand\n")
        for pkg, text in (("com.example.app", PACKAGE),
                          ("com.example.hand", BY_HAND.replace("com.example.app",
                                                               "com.example.hand"))):
            with open(paths.dumpsys(pkg + ".txt"), "w", encoding="utf-8") as f:
                f.write(text)

    def test_every_app_gets_an_installer_answer_including_an_empty_one(self):
        result = meta.run(self.rid)
        self.assertTrue(result["ok"], result["summary"])
        self.assertEqual(result["no_installer"], ["com.example.hand"])
        sheet = store.load_app("com.example.hand", self.rid)
        self.assertIn("installer", sheet["app"])
        self.assertIsNone(sheet["app"]["installer"])
        self.assertEqual(sheet["facts"]["install:from"]["value"], meta.NO_INSTALLER)

    def test_the_installer_fact_is_what_a_diff_compares(self):
        meta.run(self.rid)
        sheet = store.load_app("com.example.app", self.rid)
        self.assertEqual(sheet["facts"]["install:from"]["value"], "com.android.vending")
        self.assertEqual(sheet["facts"]["install:from"]["tier"], "T0")
        self.assertEqual(sheet["app"]["version_name"], "4.8.6")

    def test_a_missing_capture_fails_the_check_instead_of_passing_silently(self):
        os.remove(paths.dumpsys("com.example.app.txt"))
        with self.assertRaises(store.GateFailed):
            meta.run(self.rid)
        gate = store.load_run(self.rid)["gates"]["meta"]
        self.assertFalse(gate["ok"])
        self.assertIn("no capture for com.example.app", gate["summary"])


if __name__ == "__main__":
    unittest.main()
