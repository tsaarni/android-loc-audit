"""Grants parsing against the dumps' real shapes. Run: python3 -m unittest discover -s tests"""
import unittest

from locaudit import grants

PACKAGE = """Packages:
  Package [com.example.app] (abc123):
    appId=10390
    versionCode=1200 minSdk=24 targetSdk=36
    versionName=5.4.0
    requested permissions:
      android.permission.INTERNET
      android.permission.ACCESS_FINE_LOCATION
      android.permission.ACCESS_BACKGROUND_LOCATION
    install permissions:
      android.permission.INTERNET: granted=true
    User 0: installed=true
      runtime permissions:
        android.permission.ACCESS_FINE_LOCATION: granted=true, flags=[ USER_SENSITIVE ]
        android.permission.ACCESS_BACKGROUND_LOCATION: granted=false, flags=[ USER_SENSITIVE ]
"""

APPOPS = """AppOps Service state:
  Uid u0a390:
    state=cch
      FINE_LOCATION: mode=allow
    Package com.example.app:
      FINE_LOCATION (allow):
        null=[
          Access: [top-s] 2026-10-17 11:08:20.634 (-1d0h41m6s961ms) duration=+2s242ms
          Access: [bg-s] 2026-10-16 08:00:00.000 (-2d3h0m0s0ms) duration=+1s0ms
          Reject: [bg-s]2026-10-16 07:00:00.000 (-2d4h0m0s0ms)
        ]
"""

LOCATION = """Location Manager State:
  Location Providers:
    fused provider:
      listeners:
        10277/com.google.android.gms[fused_location_provider]/065DE2BC Request[@0 BALANCED, WorkSource{10277 com.google.android.gms}]
        10390/com.example.app/AB630506 Request[@0 BALANCED, duration=+30s0ms, maxUpdates=1, WorkSource{10390 com.example.app}]
  Historical Aggregate Location Provider Data:
    fused:
      10390/com.example.app: min/max interval = 0s/0s, total/active/foreground duration = +2m25s/+2m24s/+39s, locations = 726
    network:
      10390/com.example.app: min/max interval = 0s/0s, total/active/foreground duration = +343ms/+336ms/+341ms, locations = 5
  Mock Location Record:
"""


class GrantsTest(unittest.TestCase):
    def test_package_grants_and_uid(self):
        info = grants.parse_package(PACKAGE, "com.example.app")
        self.assertEqual(info["app_id"], 10390)
        self.assertEqual(info["version_name"], "5.4.0")
        self.assertTrue(info["grants"]["ACCESS_FINE_LOCATION"])
        self.assertFalse(info["grants"]["ACCESS_BACKGROUND_LOCATION"])
        self.assertIn("ACCESS_BACKGROUND_LOCATION", info["requested"])

    def test_per_user_grant_of_background_counts(self):
        text = PACKAGE.replace("ACCESS_BACKGROUND_LOCATION: granted=false",
                               "ACCESS_BACKGROUND_LOCATION: granted=true")
        self.assertTrue(grants.parse_package(text, "com.example.app")
                        ["grants"]["ACCESS_BACKGROUND_LOCATION"])

    def test_runtime_answer_beats_an_install_time_entry(self):
        text = PACKAGE.replace(
            "      android.permission.INTERNET: granted=true",
            "      android.permission.INTERNET: granted=true\n"
            "      android.permission.ACCESS_BACKGROUND_LOCATION: granted=true")
        info = grants.parse_package(text, "com.example.app")
        self.assertFalse(info["runtime"]["ACCESS_BACKGROUND_LOCATION"])
        self.assertFalse(info["grants"]["ACCESS_BACKGROUND_LOCATION"])
        self.assertTrue(info["grants"]["INTERNET"])
        self.assertEqual(info["users"], ["0"])

    def test_one_user_granting_is_enough(self):
        text = PACKAGE + """    User 10: installed=true
      runtime permissions:
        android.permission.ACCESS_BACKGROUND_LOCATION: granted=true, flags=[ USER_SENSITIVE ]
"""
        self.assertTrue(grants.parse_package(text, "com.example.app")
                        ["grants"]["ACCESS_BACKGROUND_LOCATION"])

    def test_appops_modes_and_access_entries(self):
        appops = grants.parse_appops(APPOPS)
        block = appops["u0a390"]
        self.assertEqual(block["uid"], 10390)
        self.assertEqual(block["state"], "cch")
        self.assertEqual(block["packages"]["com.example.app"]["modes"]["FINE_LOCATION"], "allow")
        entry = block["packages"]["com.example.app"]
        self.assertEqual(len(entry["access"]["FINE_LOCATION"]), 2)
        self.assertTrue(any(a["background"] for a in entry["access"]["FINE_LOCATION"]))
        self.assertEqual(len(entry["rejected"]["FINE_LOCATION"]), 1)

    def test_an_access_entry_belongs_to_its_op_not_to_the_package(self):
        text = APPOPS.replace(
            "      FINE_LOCATION (allow):",
            "      WAKE_LOCK (allow):\n"
            "        null=[\n"
            "          Access: [top-s] 2026-10-17 11:08:20.634 duration=+1s\n"
            "        ]\n"
            "      FINE_LOCATION (allow):")
        entry = grants.parse_appops(text)["u0a390"]["packages"]["com.example.app"]
        self.assertEqual(len(entry["access"]["WAKE_LOCK"]), 1)
        self.assertEqual(len(entry["access"]["FINE_LOCATION"]), 2)

    def test_listeners_and_counters(self):
        found = grants.parse_listeners(LOCATION)
        mine = [l for l in found if l["uid"] == 10390]
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["provider"], "fused")
        counters = grants.parse_counters(LOCATION)
        self.assertEqual(counters[(10390, "com.example.app")], {"fused": 726, "network": 5})

    def test_detect_sdks_in_dumpsys_ignores_queries_packages(self):
        from locaudit import sdks
        sample = (
            "Receiver Resolver Table:\n"
            "  com.example.app/com.mapbox.common.location.LocationUpdatesReceiver\n"
            "  com.example.app/com.braze.BrazeFlushPushDeliveryReceiver\n"
            "  com.example.app/androidx.work.impl.background.systemalarm.RescheduleReceiver\n"
            "  com.example.app/com.example.app.MyOwnReceiver\n"
            "  queriesPackages=[com.facebook.katana, com.appsflyer.other]\n"
        )
        found = dict(sdks.detect_in_dumpsys(sample, "com.example.app"))
        self.assertIn("com.mapbox.common.location", found)
        self.assertEqual(
            found["com.mapbox.common.location"], "com.mapbox.common.location (LocationUpdatesReceiver)"
        )
        self.assertIn("com.braze", found)
        self.assertNotIn("androidx.work.impl", found)
        self.assertNotIn("com.example.app", found)
        self.assertNotIn("com.facebook.katana", found)
        self.assertNotIn("com.appsflyer.other", found)

    def test_rejected_appops_entries_and_monitor_location(self):
        text = """AppOps Service state:
  Uid u0a401:
    state=cch
    Package com.agilexrobotics:
      FINE_LOCATION (allow):
        null=[
          Access: [top-s] 2026-10-18 17:04:20.799 (-20m7s2ms)
          Reject: [bg-s]2026-10-18 16:20:10.032 (-1h4m17s769ms)
        ]
      MONITOR_LOCATION (allow / switch COARSE_LOCATION=allow):
        null=[
          Access: [cch-s] 2026-10-18 17:04:25.536 (-20m2s265ms) duration=+8ms
        ]
"""
        parsed = grants.parse_appops(text)
        entry = parsed["u0a401"]["packages"]["com.agilexrobotics"]
        self.assertEqual(len(entry["access"]["FINE_LOCATION"]), 1)
        self.assertEqual(len(entry["rejected"]["FINE_LOCATION"]), 1)
        self.assertTrue(entry["rejected"]["FINE_LOCATION"][0]["background"])
        self.assertEqual(len(entry["access"]["MONITOR_LOCATION"]), 1)
        self.assertTrue(entry["access"]["MONITOR_LOCATION"][0]["background"])


if __name__ == "__main__":
    unittest.main()
