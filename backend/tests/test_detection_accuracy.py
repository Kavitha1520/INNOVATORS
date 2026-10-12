import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.detection import analyze_candidate


BRAND = {
    "name": "ApexSecure",
    "official_website": "https://apexsecure.example",
    "known_domains": ["apexsecure.example"],
}
DATASET_PATH = Path(__file__).parent / "data" / "detection_accuracy_cases.json"


class DetectionAccuracyDatasetTests(unittest.TestCase):
    def test_labeled_static_dataset_predictions_match_expected_binary_labels(self):
        cases = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
        self.assertEqual(len(cases), 22)
        self.assertEqual({case["group"] for case in cases}, {
            "clearly_legitimate",
            "benign_trigger_words",
            "suspicious_messages",
            "known_phishing_text_patterns",
        })

        mismatches = []
        for case in cases:
            result = analyze_candidate(
                BRAND,
                {"description": case["text"], "entity_type": "social_profile"},
            )
            predicted = "suspicious" if result["risk_category"] == "suspicious" else "legitimate"
            if predicted != case["label"]:
                mismatches.append(
                    f"{case['id']}: expected={case['label']}, "
                    f"predicted={result['risk_category']} ({result['risk_score']})"
                )
        self.assertEqual(mismatches, [])

    def test_negative_password_safety_advice_is_not_flagged_as_explicit_scam_behavior(self):
        result = analyze_candidate(
            BRAND,
            {
                "description": "Never share your password or one-time passcode with anyone.",
                "entity_type": "social_profile",
            },
        )

        self.assertNotIn("explicit_scam_behavior", {item["code"] for item in result["indicators"]})
        self.assertNotEqual(result["risk_category"], "suspicious")


if __name__ == "__main__":
    unittest.main()
