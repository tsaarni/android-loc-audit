import os
import tempfile
import unittest

from locaudit import paths, refdata


class RefdataTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_home = os.environ.get("LOCAUDIT_HOME")
        os.environ["LOCAUDIT_HOME"] = self.tmp.name

    def tearDown(self):
        if self.old_home is None:
            os.environ.pop("LOCAUDIT_HOME", None)
        else:
            os.environ["LOCAUDIT_HOME"] = self.old_home
        self.tmp.cleanup()

    def test_cached_feeds_returns_existing_files(self):
        self.assertEqual(refdata.cached_feeds(), [])
        os.makedirs(paths.refdata(), exist_ok=True)
        with open(refdata.feed_path("disconnect.json"), "w") as f:
            f.write("{}")
        self.assertEqual(refdata.cached_feeds(), ["disconnect.json"])


if __name__ == "__main__":
    unittest.main()
