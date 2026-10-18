"""The manifest reading, against the shapes a real manifest has.
Run: python3 -m unittest discover -s tests
"""
import unittest

from locaudit import manifests

MANIFEST = """N: android=http://schemas.android.com/apk/res/android (line=2)
  E: manifest (line=2)
    A: http://schemas.android.com/apk/res/android:versionCode(0x0101021b)=2109
    A: package="com.example.app" (Raw: "com.example.app")
      E: uses-permission (line=11)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.permission.ACCESS_BACKGROUND_LOCATION" (Raw: "android.permission.ACCESS_BACKGROUND_LOCATION")
      E: uses-permission (line=12)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.permission.ACCESS_FINE_LOCATION " (Raw: "android.permission.ACCESS_FINE_LOCATION ")
        A: http://schemas.android.com/apk/res/android:maxSdkVersion(0x01010271)=30
      E: application (line=14)
        A: http://schemas.android.com/apk/res/android:allowBackup(0x01010280)=false
        E: activity (line=15)
          A: http://schemas.android.com/apk/res/android:exported(0x01010010)=true
        E: service (line=18)
          A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.example.app.Tracker" (Raw: "com.example.app.Tracker")
          A: http://schemas.android.com/apk/res/android:foregroundServiceType(0x01010599)=0x00000018
        E: service (line=22)
          A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.example.app.Bluetooth" (Raw: "com.example.app.Bluetooth")
          A: http://schemas.android.com/apk/res/android:foregroundServiceType(0x01010599)=0x00000010
        E: receiver (line=26)
          A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.example.app.BootReceiver" (Raw: "com.example.app.BootReceiver")
          A: http://schemas.android.com/apk/res/android:exported(0x01010010)=false
          E: intent-filter (line=28)
            E: action (line=29)
              A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.intent.action.BOOT_COMPLETED" (Raw: "android.intent.action.BOOT_COMPLETED")
        E: receiver (line=32)
          A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.example.app.LocationPing" (Raw: "com.example.app.LocationPing")
          E: intent-filter (line=34)
            E: action (line=35)
              A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.intent.action.MY_PACKAGE_REPLACED" (Raw: "android.intent.action.MY_PACKAGE_REPLACED")
        E: provider (line=38)
          A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.example.app.Files" (Raw: "com.example.app.Files")
"""


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.read = manifests.read_manifest(MANIFEST, "com.example.app")

    def test_permissions_are_named_by_their_short_name(self):
        self.assertIn("ACCESS_BACKGROUND_LOCATION", self.read["permissions"])

    def test_a_permission_with_a_maximum_version_keeps_its_limit(self):
        """It is not asked for on a newer phone, so the phone answers 'never asked'."""
        self.assertEqual(self.read["permissions"]["ACCESS_FINE_LOCATION"], 30)
        self.assertIsNone(self.read["permissions"]["ACCESS_BACKGROUND_LOCATION"])

    def test_a_space_in_a_name_does_not_reach_a_fact(self):
        self.assertNotIn("ACCESS_FINE_LOCATION ", self.read["permissions"])

    def test_the_service_type_is_decoded_from_its_bitmask(self):
        self.assertEqual(self.read["services"]["Tracker"], "location, connected device")
        self.assertEqual(self.read["services"]["Bluetooth"], "connected device")

    def test_receivers_for_boot_replacement_and_location(self):
        self.assertTrue(self.read["boot"])
        self.assertTrue(self.read["package_replaced"])
        self.assertEqual(self.read["location_receivers"], ["LocationPing"])

    def test_posture_and_providers(self):
        self.assertFalse(self.read["allow_backup"])
        self.assertIsNone(self.read["debuggable"])
        self.assertEqual(self.read["providers"], ["Files"])
        self.assertEqual(self.read["exported"], 1)

    def test_a_bitmask_with_an_unknown_bit_says_so(self):
        self.assertIn("unknown type 0x1000", manifests._fgs_words("0x1000"))


if __name__ == "__main__":
    unittest.main()
