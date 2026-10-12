import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.detection import analyze_candidate
from app.services.ingestion import assess_url_safety, normalize_url


BRAND = {
    "name": "ApexSecure",
    "official_website": "https://apexsecure.com",
    "known_domains": ["apexsecure.com"],
}


class DetectionEngineTests(unittest.TestCase):
    def test_legitimate_text_is_lower_risk(self):
        result = analyze_candidate(
            BRAND,
            {
                "description": "The city library will close at 5 PM for its annual book fair.",
                "entity_type": "social_profile",
            },
        )

        self.assertEqual(result["risk_category"], "lower_risk")
        self.assertEqual(result["risk_score"], 0)
        self.assertIn("lower-risk result does not guarantee safety", result["explanation"])
        self.assertEqual(result["indicators"], [])

    def test_suspicious_text_returns_explainable_indicators(self):
        result = analyze_candidate(
            BRAND,
            {
                "description": "Verify account now and claim reward by send password.",
                "entity_type": "social_profile",
            },
        )

        self.assertEqual(result["risk_category"], "suspicious")
        self.assertGreaterEqual(result["risk_score"], 35)
        self.assertIn("solicitation_language", {item["code"] for item in result["indicators"]})
        self.assertTrue(result["evidence"])
        self.assertIn("not confirmation of fraud", result["explanation"])

    def test_legitimate_url_is_lower_risk_without_opening_it(self):
        result = assess_url_safety("https://www.apexsecure.com/account", BRAND["name"], BRAND["known_domains"])

        self.assertEqual(result["risk_category"], "lower_risk")
        self.assertEqual(result["normalized_url"], "https://www.apexsecure.com/account")
        self.assertFalse(result["opened"])

    def test_suspicious_looking_url_has_multiple_indicators(self):
        with patch("app.services.detection.urlopen") as open_url:
            result = analyze_candidate(
                BRAND,
                {
                    "url": "http://apexsecure-login-verify.example/login/claim",
                    "entity_type": "social_profile",
                },
            )
            open_url.assert_not_called()

        self.assertEqual(result["risk_category"], "suspicious")
        self.assertGreaterEqual(result["risk_score"], 35)
        self.assertIn("brand_lookalike_domain", {item["code"] for item in result["indicators"]})
        self.assertIn("solicitation_path", {item["code"] for item in result["indicators"]})
        self.assertFalse(result.get("opened", False))
        self.assertEqual(result["url"], "http://apexsecure-login-verify.example/login/claim")

    def test_http_alone_is_not_classified_as_suspicious(self):
        result = assess_url_safety("http://ordinary-example.test")

        self.assertEqual(result["risk_category"], "lower_risk")
        self.assertEqual([item["code"] for item in result["indicators"]], ["no_https"])

    def test_single_solicitation_phrase_is_inconclusive_not_confirmed(self):
        result = analyze_candidate(BRAND, {"description": "Please verify account."})

        self.assertEqual(result["risk_category"], "inconclusive")
        self.assertLess(result["risk_score"], 35)
        self.assertIn("does not confirm fraud", result["explanation"])

    def test_malformed_url_is_rejected(self):
        self.assertEqual(normalize_url("https://bad host.example/path"), "")
        with self.assertRaisesRegex(ValueError, "valid HTTP or HTTPS URL"):
            assess_url_safety("https://bad host.example/path")

    def test_empty_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Enter a candidate name"):
            analyze_candidate(BRAND, {})


if __name__ == "__main__":
    unittest.main()
