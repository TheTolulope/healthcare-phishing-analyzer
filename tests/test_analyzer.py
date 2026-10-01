"""Basic tests. Run with:  python -m unittest discover tests"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from phishing_analyzer import analyze_email, get_email_domain, base_domain

SAMPLES = Path(__file__).resolve().parent.parent / "sample_emails"


def load(name):
    return (SAMPLES / name).read_text(encoding="utf-8")


class TestHelpers(unittest.TestCase):
    def test_get_email_domain(self):
        self.assertEqual(get_email_domain("Bob <bob@Example.COM>"), "example.com")

    def test_base_domain(self):
        self.assertEqual(base_domain("portal.riversidegeneral.example"), "riversidegeneral.example")


class TestAnalyzer(unittest.TestCase):
    def test_legit_email_is_low_risk(self):
        self.assertLess(analyze_email(load("legit_appointment.txt"))["score"], 30)

    def test_portal_phish_is_high_risk(self):
        self.assertGreaterEqual(analyze_email(load("phish_patient_portal.txt"))["score"], 60)

    def test_ip_link_detected(self):
        result = analyze_email(load("phish_hipaa_notice.txt"))
        categories = [f["category"] for f in result["findings"]]
        self.assertIn("ip_address_link", categories)

    def test_shortener_detected(self):
        result = analyze_email(load("phish_billing_refund.txt"))
        categories = [f["category"] for f in result["findings"]]
        self.assertIn("url_shortener", categories)


if __name__ == "__main__":
    unittest.main()
