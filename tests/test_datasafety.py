"""Play data safety, from the page to the quote to the facts.
Run: python3 -m unittest discover -s tests

No network. The markup here is the shape Play served on 2026-10-18: h2 for a section, h3 for a
category, h4 for a data type with its purposes in the div below it.
"""
import os
import shutil
import tempfile
import unittest
from unittest import mock

from locaudit import datasafety, paths, store

HEAD = ('<h1>Data safety</h1>'
        '<div>Here is more information the developer has provided about the kinds of data this '
        'app may collect and share</div>')

SHARED_AND_COLLECTED = (
    HEAD + '<h2>Data shared</h2><div>Data that may be shared with other companies</div>'
           '<h3>Location</h3><div>Approximate location</div>'
           '<div>Data shared and for what purpose</div>'
           '<h4><span>Approximate location</span></h4>'
           '<div>Analytics, Advertising or marketing</div>'
           '<h2>Data collected</h2><div>Data this app may collect</div>'
           '<h3>Location</h3><div>Approximate location and Precise location</div>'
           '<div>Data collected and for what purpose</div>'
           '<h4><span>Approximate location</span></h4>'
           '<div>App functionality, Fraud prevention, security, and compliance</div>'
           '<h2>Security practices</h2><h3>Data is encrypted in transit</h3>'
           '<div>All prices include VAT.</div>')

COLLECTED_ONLY = (
    HEAD + '<h2>No data shared with third parties</h2>'
           '<div>The developer says this app does not share user data</div>'
           '<h2>Data collected</h2><div>Data this app may collect</div>'
           '<h3>Location</h3><div>Precise location</div>'
           '<div>Data collected and for what purpose</div>'
           '<h4><span>Precise location</span></h4><div>App functionality</div>'
           '<h2>Security practices</h2>')

NO_SECTION = ('<h1>Android System Key Verifier</h1><h2>Data safety</h2>'
              '<div>Android System Key Verifier is included with your device to provide system '
              'services. Learn more about data safety</div>')

NOT_A_PAGE = ('<h1>com.microsoft.copilot</h1><div>Microsoft Corporation</div>'
              '<script>AF_initDataCallback({key: "ds:3"});</script>')


class DatasafetyReadTest(unittest.TestCase):
    """The page read by its headings and their order, not by wording or class names."""

    def test_shared_location_and_its_purposes(self):
        found = datasafety.read_page(SHARED_AND_COLLECTED)
        shared = found["sections"]["shared"]
        self.assertTrue(shared["present"])
        self.assertEqual(shared["types"], ["Approximate location"])
        self.assertEqual(shared["purposes"], ["Analytics", "Advertising or marketing"])

    def test_a_purpose_holding_a_comma_stays_one_purpose(self):
        collected = datasafety.read_page(SHARED_AND_COLLECTED)["sections"]["collected"]
        self.assertEqual(collected["purposes"],
                         ["App functionality", "Fraud prevention, security, and compliance"])

    def test_a_line_naming_a_data_type_is_not_a_purpose(self):
        """'Approximate location and Precise location' is a list of types, not a purpose."""
        collected = datasafety.read_page(SHARED_AND_COLLECTED)["sections"]["collected"]
        self.assertNotIn("Approximate location and Precise location", collected["purposes"])
        self.assertEqual(collected["types"], ["Approximate location", "Precise location"])

    def test_no_sharing_is_an_answer_from_the_page(self):
        found = datasafety.read_page(COLLECTED_ONLY)
        self.assertFalse(found["sections"]["shared"]["present"])
        self.assertTrue(found["sections"]["collected"]["present"])

    def test_the_security_practices_and_the_footer_are_not_read(self):
        self.assertNotIn("security", datasafety.read_page(SHARED_AND_COLLECTED)["sections"])

    def test_a_heading_with_no_section_says_so_in_the_pages_own_words(self):
        found = datasafety.read_page(NO_SECTION)
        self.assertIn("included with your device", found["no_section"])
        self.assertNotIn("Learn more", found["no_section"])

    def test_a_page_that_is_not_a_data_safety_page_is_none(self):
        self.assertIsNone(datasafety.read_page(NOT_A_PAGE))


class DatasafetyQuoteTest(unittest.TestCase):
    """The quote is the work product: it can be re-read without the page."""

    def test_the_quote_holds_what_the_facts_claim(self):
        quote = datasafety.quote_of("com.example.app",
                                    {"meta": {"fetched_at": "2026-10-18T10:00:00Z",
                                              "url": "https://example.invalid"}},
                                    datasafety.read_page(SHARED_AND_COLLECTED))
        self.assertIn("section: shared", quote)
        self.assertIn("type: Approximate location", quote)
        self.assertIn("purpose: Advertising or marketing", quote)
        self.assertLess(len(quote), 600)

    def test_a_quote_reads_back_to_the_same_answer(self):
        found = datasafety.read_page(SHARED_AND_COLLECTED)
        quote = datasafety.quote_of("com.example.app",
                                    {"meta": {"fetched_at": "2026-10-18T10:00:00Z",
                                              "url": "https://example.invalid"}}, found)
        back = datasafety.parse_quote(quote)
        self.assertEqual(back, found)

    def test_an_unreadable_page_stays_unreadable_after_the_quote(self):
        quote = datasafety.quote_of("com.example.app",
                                    {"meta": {"fetched_at": "2026-10-18T10:00:00Z",
                                              "url": "https://example.invalid"}},
                                    datasafety.read_page(NOT_A_PAGE))
        self.assertIsNone(datasafety.parse_quote(quote))


class DatasafetyRunTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="locaudit-datasafety-")
        self.addCleanup(shutil.rmtree, self.home)
        patcher = mock.patch.dict(os.environ, {"LOCAUDIT_HOME": self.home})
        patcher.start()
        self.addCleanup(patcher.stop)
        paths.ensure()
        self.rid = store.start_run("0.1.0", rid="2026-01-01T000000Z")
        for pkg, came_from in (("com.example.play", "com.android.vending"),
                                ("com.example.play2", "com.android.vending"),
                                ("com.example.play3", "com.android.vending"),
                                ("com.example.outside", "com.example.lab")):
            def mutate(doc, came_from=came_from):
                store.add_fact(doc, "install:from", came_from, tier="T0",
                               source="dumpsys package")
            store.update_app(pkg, mutate, self.rid)
        self.meta = {"fetched_at": "2026-10-18T10:00:00Z", "url": "https://example.invalid"}
        self.quotes = {pkg: datasafety.quote_of(pkg, {"meta": self.meta},
                                                datasafety.read_page(SHARED_AND_COLLECTED))
                       for pkg in ("com.example.play", "com.example.play2", "com.example.play3")}

    def page_for(self, pkg, refresh=False):
        return {"quote": self.quotes[pkg], "meta": self.meta, "cached": True}

    def test_facts_carry_the_date_and_the_quote_version(self):
        with mock.patch.object(datasafety, "page_for", side_effect=self.page_for):
            result = datasafety.run(self.rid, apps=["com.example.play"], pause=0)
        self.assertTrue(result["ok"], result["summary"])
        facts = store.load_app("com.example.play", self.rid)["facts"]
        self.assertEqual(facts["datasafety:collected:location"]["value"], "yes")
        self.assertEqual(facts["datasafety:shared:location"]["value"], "yes")
        self.assertEqual(facts["datasafety:purposes:location"]["value"],
                         "Analytics, Advertising or marketing")
        self.assertEqual(facts["datasafety:fetched"]["value"], "2026-10-18T10:00:00Z")
        self.assertEqual(facts["datasafety:fetched"]["quote"], datasafety.PARSER)

    def test_an_app_not_from_play_is_unknown_with_a_reason(self):
        with mock.patch.object(datasafety, "page_for", side_effect=self.page_for):
            datasafety.run(self.rid, apps=["com.example.play"], pause=0)
        facts = store.load_app("com.example.outside", self.rid)["facts"]
        self.assertIn("not installed from Google Play", facts["unknown:datasafety"]["reason"])
        self.assertNotIn("datasafety:collected:location", facts)

    def test_a_page_that_stopped_making_sense_is_unknown(self):
        self.quotes["com.example.play"] = datasafety.quote_of(
            "com.example.play", {"meta": self.meta}, None)
        with mock.patch.object(datasafety, "page_for", side_effect=self.page_for):
            result = datasafety.run(self.rid, apps=["com.example.play"], pause=0)
        facts = store.load_app("com.example.play", self.rid)["facts"]
        self.assertIn("did not look like a data safety page", facts["unknown:datasafety"]["reason"])
        self.assertFalse(result["layout_moved"], "one page is a finding, not a moved layout")

    def test_many_pages_that_stopped_making_sense_fail_the_step(self):
        """A layout change must fail loudly instead of being written down once per app."""
        for pkg in ("com.example.play", "com.example.play2", "com.example.play3"):
            self.quotes[pkg] = datasafety.quote_of(pkg, {"meta": self.meta}, None)
        with mock.patch.object(datasafety, "page_for", side_effect=self.page_for):
            with self.assertRaises(store.GateFailed):
                datasafety.run(self.rid, apps=["com.example.play", "com.example.play2",
                                               "com.example.play3"], pause=0, max_doubt=0.0)
        gate = store.load_run(self.rid)["gates"]["datasafety"]
        self.assertFalse(gate["ok"])
        self.assertIn("page layout has probably moved", gate["summary"])


if __name__ == "__main__":
    unittest.main()
