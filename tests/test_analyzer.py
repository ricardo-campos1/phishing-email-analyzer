"""Tests for analyzer.py, run against the sample emails.

Run from the repo root:
    python3 -m unittest discover tests
"""

import json
import os
import sys
import tempfile
import unittest

# Let the tests import analyzer.py from the repo root
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import analyzer  # noqa: E402

SAMPLES = os.path.join(REPO_ROOT, "sample_emails")


def run_sample(name):
    """Analyze one sample email and return the results."""
    return analyzer.analyze(analyzer.load_email(os.path.join(SAMPLES, name)))


def details(results):
    """All finding details joined into one string, for easy searching."""
    return "\n".join(f["detail"] for f in results["findings"])


class CleanEmailTests(unittest.TestCase):
    def test_clean_newsletter_is_low_risk(self):
        results = run_sample("clean_newsletter.eml")
        self.assertEqual(results["findings"], [])
        self.assertEqual(results["verdict"], "LOW RISK")

    def test_received_path_is_oldest_first(self):
        hops = run_sample("clean_newsletter.eml")["hops"]
        self.assertEqual(hops[0]["ip"], "198.51.100.10")
        self.assertEqual(hops[-1]["by"], "inbox.recipient.example")


class CredentialPhishTests(unittest.TestCase):
    def setUp(self):
        self.results = run_sample("credential_phish.eml")
        self.text = details(self.results)

    def test_verdict(self):
        self.assertEqual(self.results["verdict"], "LIKELY PHISHING")

    def test_authentication_results(self):
        self.assertEqual(self.results["authentication"],
                         {"spf": "fail", "dkim": "none", "dmarc": "fail"})

    def test_reply_to_mismatch(self):
        self.assertIn("Reply-To goes to freemail.example", self.text)

    def test_fake_address_in_display_name(self):
        self.assertIn("Display name shows security@microsoft.com", self.text)

    def test_ip_link_and_mismatched_text(self):
        self.assertIn("bare IP address", self.text)
        self.assertIn("Text shows account.microsoft.com", self.text)

    def test_brand_in_subdomain(self):
        self.assertIn("puts 'microsoft' in the subdomain", self.text)

    def test_shortener(self):
        self.assertIn("URL shortener", self.text)

    def test_high_findings_come_first(self):
        self.assertEqual(self.results["findings"][0]["severity"], "HIGH")


class AttachmentTests(unittest.TestCase):
    def test_double_extension_and_hash(self):
        results = run_sample("invoice_attachment.eml")
        attachment = results["attachments"][0]
        self.assertEqual(attachment["name"], "invoice_20931.pdf.exe")
        self.assertEqual(len(attachment["sha256"]), 64)
        self.assertIn("double extension", details(results))


class HelperTests(unittest.TestCase):
    def test_lookalike(self):
        self.assertIsNotNone(analyzer.check_lookalike("paypa1.example"))
        self.assertIsNotNone(analyzer.check_lookalike("xn--pple-43d.com"))
        self.assertIsNone(analyzer.check_lookalike("login.microsoft.com"))
        self.assertIsNone(analyzer.check_lookalike("shop.example"))

    def test_defang(self):
        self.assertEqual(analyzer.defang("https://evil.example/login"),
                         "hxxps://evil[.]example/login")

    def test_score_bands(self):
        self.assertEqual(analyzer.score([])[1], "LOW RISK")
        self.assertEqual(analyzer.score([{"severity": "HIGH"}])[1], "SUSPICIOUS")
        self.assertEqual(analyzer.score([{"severity": "HIGH"}] * 3)[1], "LIKELY PHISHING")

    def test_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            sample = os.path.join(SAMPLES, "credential_phish.eml")
            with open(os.devnull, "w") as quiet:
                old_stdout, sys.stdout = sys.stdout, quiet
                try:
                    analyzer.main([sample, "--json", path])
                finally:
                    sys.stdout = old_stdout
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        self.assertEqual(data["verdict"], "LIKELY PHISHING")


if __name__ == "__main__":
    unittest.main()