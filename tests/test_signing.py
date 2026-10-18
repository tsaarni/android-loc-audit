"""Signing text from apksigner, against the shapes a real phone produces.
Run: python3 -m unittest discover -s tests

No apksigner is run here: these are the texts it printed, so the parser is tested without Java.
"""
import os
import shutil
import tempfile
import unittest
from unittest import mock

from locaudit import paths, signing

VERIFIES = """Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified for SourceStamp: true
Number of signers: 1
Signer #1 certificate DN: CN=Unknown, OU=Unknown, O=Digia, L=Helsinki, ST=Finland, C=FI
Signer #1 certificate SHA-256 digest: dc430566e9fe41aeee008f1a415bb8dc59dc8fe81f797c9c5440c4ad52158782
Signer #1 certificate SHA-1 digest: 35786d3838585c37c5a9ff3b1a352c6261d7ab37
Source Stamp Signer certificate DN: CN=Android, OU=Android, O=Google Inc., L=Mountain View, ST=California, C=US
Source Stamp Signer certificate SHA-256 digest: 3257d599a49d2c961a471ca9843f59d341a405884583fc087df4237b733bbd6d
"""

ROTATED = """Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): false
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): true
Verified for SourceStamp: false
Signer (minSdkVersion=33, maxSdkVersion=2147483647) certificate DN: C=US, O=Meta Platforms Inc., CN=Meta Platforms Inc.
Signer (minSdkVersion=33, maxSdkVersion=2147483647) certificate SHA-256 digest: 911d604446084ca7f4760b775bfc160fa8702441240a7258645d7a72c4312d27
Signer (minSdkVersion=24, maxSdkVersion=32) certificate DN: CN=Facebook Corporation, OU=Facebook, O=Facebook Corporation, C=US
Signer (minSdkVersion=24, maxSdkVersion=32) certificate SHA-256 digest: e3f9e1e0aabbccddeeff00112233445566778899aabbccddeeff001122334455
"""

BROKEN = """DOES NOT VERIFY
ERROR: Missing META-INF/MANIFEST.MF
"""


class SigningParseTest(unittest.TestCase):
    def test_a_verified_file_and_the_name_in_its_key(self):
        found = signing.parse(VERIFIES)
        self.assertTrue(found["verifies"])
        self.assertEqual(found["schemes"], ["v2", "v3"])
        self.assertEqual(found["signers"][0]["sha256"],
                         "dc430566e9fe41aeee008f1a415bb8dc59dc8fe81f797c9c5440c4ad52158782")
        self.assertEqual(signing.owner(found["signers"][0]["dn"]), "Digia")

    def test_the_play_stamp_is_read_apart_from_the_signature(self):
        found = signing.parse(VERIFIES)
        self.assertEqual(signing.owner(found["stamp"]), "Google")
        self.assertIsNone(signing.parse(ROTATED)["stamp"])

    def test_a_rotated_key_lists_more_than_one_signer(self):
        found = signing.parse(ROTATED)
        self.assertEqual(len(found["signers"]), 2)
        self.assertEqual({signing.owner(s["dn"]) for s in found["signers"]},
                         {"Meta Platforms Inc.", "Facebook Corporation"})

    def test_a_file_that_does_not_verify_is_not_a_quiet_result(self):
        found = signing.parse(BROKEN)
        self.assertFalse(found["verifies"])
        self.assertEqual(found["signers"], [])

    def test_a_name_with_a_comma_stays_one_name(self):
        dn = "CN=Example, Inc., OU=Android, O=Example, Inc., C=US"
        self.assertEqual(signing.owner(dn), "Example, Inc.")

    def test_a_quoted_name_is_the_same_company_whatever_it_is_called(self):
        """The same company appears as Google Inc., Google, Inc. and \"Google, Inc\" in real keys."""
        for dn in ('O=Google Inc., C=US', 'O="Google, Inc", C=US', 'CN=Android, O=Google LLC'):
            with self.subTest(dn=dn):
                self.assertEqual(signing.owner(dn), "Google")

    def test_a_key_without_an_owner_name_says_so(self):
        self.assertEqual(signing.owner("CN=Unknown, OU=Unknown, O=Unknown, C=US"),
                         signing.UNNAMED)
        self.assertEqual(signing.owner("CN=Android, OU=Android, O=Google Inc."), "Google")
        self.assertEqual(signing.owner(None), signing.UNNAMED)

    def test_apksigner_that_cannot_run_is_an_error_not_a_pass(self):
        with self.assertRaises(signing.SigningError):
            signing.read_file("/tmp/whatever.apk", "/nonexistent/apksigner")


class MinSdkTest(unittest.TestCase):
    """A split APK must be checked against the version its app asks for, not against version 1."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="locaudit-signing-")
        self.addCleanup(shutil.rmtree, self.home)
        patcher = mock.patch.dict(os.environ, {"LOCAUDIT_HOME": self.home})
        patcher.start()
        self.addCleanup(patcher.stop)
        paths.ensure()

    def test_the_floor_comes_from_the_phone_text(self):
        with open(paths.dumpsys("com.example.app.txt"), "w", encoding="utf-8") as f:
            f.write("  Package [com.example.app] (abc):\n"
                    "    versionCode=2109 minSdk=29 targetSdk=35\n")
        self.assertEqual(signing.min_sdk("com.example.app"), 29)

    def test_an_app_without_text_falls_back_to_the_floor(self):
        self.assertEqual(signing.min_sdk("com.example.absent"), signing.FLOOR_SDK)


if __name__ == "__main__":
    unittest.main()
