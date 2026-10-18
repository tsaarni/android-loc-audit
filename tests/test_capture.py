"""Capture parsing, without a phone. Run: python3 -m unittest discover -s tests"""
import os
import tempfile
import unittest

from locaudit import capture


class ParseTest(unittest.TestCase):
    def test_packages_are_sorted_and_unprefixed(self):
        text = ("package:com.zeta.app\n"
                "package:com.alpha.app\n"
                "\n"
                "package:com.alpha.app\n")
        self.assertEqual(capture.parse_packages(text),
                         ["com.alpha.app", "com.zeta.app"])

    def test_crlf_is_already_gone_but_a_stray_one_is_dropped(self):
        self.assertEqual(capture.parse_packages("package:com.example.a\r\n"),
                         ["com.example.a"])

    def test_props_become_fields(self):
        text = ("[ro.product.brand]: [samsung]\n"
                "[ro.build.id]: [BP4A.251205.006]\n"
                "[ro.build.fingerprint]: [samsung/m1s/m1s:16/BP4A/x:user/release-keys]\n")
        props = capture.parse_props(text)
        self.assertEqual(props["ro.product.brand"], "samsung")
        self.assertEqual(props["ro.build.fingerprint"],
                         "samsung/m1s/m1s:16/BP4A/x:user/release-keys")


if __name__ == "__main__":
    unittest.main()
