"""Measure parsing and the room calculation, without a phone."""
import unittest

from locaudit import measure

PM_PATH = """package:/data/app/~~x==/com.example.app-y==/base.apk
package:/data/app/~~x==/com.example.app-y==/split_config.arm64_v8a.apk
package:/data/app/~~x==/com.example.app-y==/split_config.en.apk
"""

STAT = """1024 /data/app/~~x==/com.example.app-y==/base.apk
2048 /data/app/~~x==/com.example.app-y==/split_config.arm64_v8a.apk
512 /data/app/~~x==/com.example.app-y==/split_config.en.apk
stat: '/data/app/missing.apk': No such file or directory
"""


class MeasureTest(unittest.TestCase):
    def test_paths_are_stripped_and_ordered(self):
        self.assertEqual(measure.parse_pm_path(PM_PATH), [
            "/data/app/~~x==/com.example.app-y==/base.apk",
            "/data/app/~~x==/com.example.app-y==/split_config.arm64_v8a.apk",
            "/data/app/~~x==/com.example.app-y==/split_config.en.apk",
        ])

    def test_sizes_ignore_a_failed_stat_line(self):
        self.assertEqual(measure.parse_sizes(STAT), {
            "/data/app/~~x==/com.example.app-y==/base.apk": 1024,
            "/data/app/~~x==/com.example.app-y==/split_config.arm64_v8a.apk": 2048,
            "/data/app/~~x==/com.example.app-y==/split_config.en.apk": 512,
        })

    def test_every_split_apk_counts(self):
        sizes = measure.parse_sizes(STAT)
        self.assertEqual(len(sizes), 3)
        self.assertEqual(sum(sizes.values()), 3584)

    def test_a_failed_stat_is_not_a_zero_byte_apk(self):
        self.assertNotIn("/data/app/missing.apk", measure.parse_sizes(STAT))


if __name__ == "__main__":
    unittest.main()
