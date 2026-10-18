"""The pull skip rule and file naming, without a phone or a copy."""
import os
import tempfile
import unittest
import zipfile

from locaudit import paths, pull


def _zip(path, payload=b"dex"):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", payload)
    return path


class PullTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="locaudit-pull-")
        os.environ["LOCAUDIT_HOME"] = self.home

    def tearDown(self):
        os.environ.pop("LOCAUDIT_HOME", None)

    def test_destination_uses_the_package_folder_and_the_phone_file_name(self):
        source = "/data/app/~~x==/com.example.app-y==/split_config.fi.apk"
        self.assertEqual(pull.destination("com.example.app", source),
                         os.path.join(paths.apks("com.example.app"), "split_config.fi.apk"))

    def test_a_missing_file_is_copied(self):
        self.assertTrue(pull.needs_copy(
            os.path.join(self.home, "nope.apk"), 10))

    def test_a_complete_apk_is_skipped(self):
        dest = _zip(os.path.join(self.home, "base.apk"))
        self.assertFalse(pull.needs_copy(dest, os.path.getsize(dest)))

    def test_a_short_file_is_copied_again(self):
        dest = _zip(os.path.join(self.home, "base.apk"))
        self.assertTrue(pull.needs_copy(dest, os.path.getsize(dest) + 1))

    def test_a_file_of_the_right_size_that_is_not_a_zip_is_copied_again(self):
        dest = os.path.join(self.home, "base.apk")
        with open(dest, "w", encoding="utf-8") as f:
            f.write("truncated")
        self.assertTrue(pull.needs_copy(dest, len("truncated")))

    def test_the_hash_changes_when_the_bytes_change(self):
        one = _zip(os.path.join(self.home, "one.apk"), b"a")
        two = _zip(os.path.join(self.home, "two.apk"), b"b")
        self.assertNotEqual(pull.sha256(one), pull.sha256(two))


if __name__ == "__main__":
    unittest.main()
