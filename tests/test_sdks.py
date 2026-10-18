"""Tests for structural component extraction, archive inspection, and bytecode caller scanning."""
import io
import os
import shutil
import tempfile
import unittest
import zipfile
from unittest import mock

from locaudit import paths, sdks, store


class SdksTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="locaudit-sdks-")
        self.addCleanup(shutil.rmtree, self.home)
        patcher = mock.patch.dict(os.environ, {"LOCAUDIT_HOME": self.home})
        patcher.start()
        self.addCleanup(patcher.stop)
        paths.ensure()

    def test_detect_in_dumpsys_extracts_components(self):
        sample = """
        Activity Resolver Table:
          Non-Data Actions:
              com.example.app/com.mapbox.common.location.LocationUpdatesReceiver
              com.appsflyer.referrer/com.appsflyer.referrer.InstallReferrerReceiver
              androidx.core.app/androidx.core.app.CoreComponentFactory
        Packages:
          Package [com.example.app]
        """
        results = sdks.detect_in_dumpsys(sample, pkg="com.example.app")
        prefixes = [p for p, _ in results]
        self.assertIn("com.mapbox.common.location", prefixes)
        # androidx is in FRAMEWORK_PREFIXES and should be omitted
        self.assertNotIn("androidx.core.app", prefixes)

    def test_inspect_archive_standard_dalvik(self):
        pkg = "com.example.dalvik"
        apk_dir = paths.apks(pkg)
        os.makedirs(apk_dir, exist_ok=True)
        apk_path = os.path.join(apk_dir, "base.apk")
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("classes.dex", b"x" * 100000)
            zf.writestr("lib/arm64-v8a/libfoo.so", b"ELF...")

        result = sdks.inspect_archive(pkg)
        self.assertEqual(result["dex_count"], 1)
        self.assertEqual(result["dex_bytes"], 100000)
        self.assertEqual(result["native_count"], 1)
        self.assertEqual(result["native_archs"], ["arm64-v8a"])
        self.assertEqual(result["engine"], "Standard Dalvik")
        self.assertEqual(result["confidence"], "full")

    def test_inspect_archive_react_native_bundle(self):
        pkg = "com.example.rn"
        apk_dir = paths.apks(pkg)
        os.makedirs(apk_dir, exist_ok=True)
        apk_path = os.path.join(apk_dir, "base.apk")
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("classes.dex", b"x" * 1000)
            zf.writestr("assets/index.android.bundle", b"var React = require('react');" * 50000)
            zf.writestr("lib/arm64-v8a/libhermes.so", b"ELF...")

        result = sdks.inspect_archive(pkg)
        self.assertIn("React Native", result["engine"])
        self.assertIn("JavaScript bundle", result["engine"])
        self.assertIn("partial (React Native bundle)", result["confidence"])

    def test_inspect_archive_flutter(self):
        pkg = "com.example.flutter"
        apk_dir = paths.apks(pkg)
        os.makedirs(apk_dir, exist_ok=True)
        apk_path = os.path.join(apk_dir, "base.apk")
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("classes.dex", b"x" * 100000)
            zf.writestr("lib/arm64-v8a/libflutter.so", b"ELF...")
            zf.writestr("lib/arm64-v8a/libapp.so", b"ELF...")

        result = sdks.inspect_archive(pkg)
        self.assertEqual(result["engine"], "Flutter")
        self.assertEqual(result["confidence"], "partial (Flutter Dart AOT)")

    def test_inspect_archive_minimal_dex_stub(self):
        pkg = "com.example.stub"
        apk_dir = paths.apks(pkg)
        os.makedirs(apk_dir, exist_ok=True)
        apk_path = os.path.join(apk_dir, "base.apk")
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("classes.dex", b"x" * 5000)
            zf.writestr("lib/arm64-v8a/libsec.so", b"ELF...")

        result = sdks.inspect_archive(pkg)
        self.assertEqual(result["engine"], "Minimal DEX stub")
        self.assertIn("obstructed", result["confidence"])


if __name__ == "__main__":
    unittest.main()
