import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cv2
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy.orm import sessionmaker
from starlette.datastructures import Headers, UploadFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.database import Base, create_database_engine
from app.main import app, get_db
from app.models import Brand, CustomerReport, Organization, User
from app.schema import initialize_database
from app.services.auth import hash_password
from app.services.ingestion import decode_qr_image, extract_screenshot_text, get_tesseract_status


def make_png(width: int = 320, height: int = 160, text: str | None = None) -> bytes:
    image = Image.new("RGB", (width, height), "white")
    if text:
        from PIL import ImageDraw

        ImageDraw.Draw(image).text((8, 8), text, fill="black")
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def make_qr_png(content: str) -> bytes:
    qr = cv2.QRCodeEncoder_create().encode(content)
    bordered = cv2.copyMakeBorder(qr, 24, 24, 24, 24, cv2.BORDER_CONSTANT, value=255)
    enlarged = cv2.resize(bordered, None, fx=4, fy=4, interpolation=cv2.INTER_NEAREST)
    encoded, data = cv2.imencode(".png", enlarged)
    if not encoded:
        raise RuntimeError("OpenCV could not encode the test QR image.")
    return data.tobytes()


def upload_image(data: bytes, filename: str = "upload.png", content_type: str = "image/png") -> UploadFile:
    return UploadFile(
        file=io.BytesIO(data),
        filename=filename,
        headers=Headers({"content-type": content_type}),
    )


class ImageAnalysisApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        database_path = Path(self.temporary_directory.name) / "image-analysis.db"
        self.engine = create_database_engine("sqlite:///" + database_path.as_posix())
        initialize_database(self.engine, Base.metadata)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        with self.Session() as db:
            organization = Organization(name="Image Test Organization")
            db.add(organization)
            db.flush()
            self.brand = Brand(
                organization_id=organization.id,
                name="Test Brand",
                official_website="https://testbrand.example",
                known_domains=["testbrand.example"],
            )
            user = User(
                organization_id=organization.id,
                email="image-test@example.invalid",
                password_hash=hash_password("a-strong-image-test-password"),
                role="admin",
            )
            db.add_all([self.brand, user])
            db.commit()
            self.brand_id = self.brand.id
            self.organization_id = organization.id

        app.dependency_overrides[get_db] = self.override_get_db
        self.client = TestClient(app)
        login = self.client.post(
            "/api/auth/login",
            json={"email": "image-test@example.invalid", "password": "a-strong-image-test-password"},
        )
        self.assertEqual(login.status_code, 200, login.text)
        self.headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    def tearDown(self):
        app.dependency_overrides.pop(get_db, None)
        self.client.close()
        self.engine.dispose()
        self.temporary_directory.cleanup()

    def override_get_db(self):
        db = self.Session()
        try:
            yield db
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def analyze_qr(self, content: str, filename: str = "qr.png"):
        return self.client.post(
            "/api/qr/analyze",
            headers=self.headers,
            data={"brand_id": str(self.brand_id)},
            files={"image": (filename, make_qr_png(content), "image/png")},
        )

    def test_valid_qr_with_legitimate_url_returns_full_assessment(self):
        response = self.analyze_qr("https://testbrand.example/account")

        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["decoded_content"], "https://testbrand.example/account")
        self.assertEqual(result["content_type"], "url")
        self.assertEqual(result["risk_category"], "lower_risk")
        self.assertIn("explanation", result)
        self.assertIn("safe_next_steps", result)
        self.assertFalse(result["opened"])
        self.assertTrue(result["stored"])

    def test_suspicious_url_is_analyzed_without_fetching(self):
        suspicious_url = "http://testbrand-login-verify.attacker.example/login/claim"
        with patch("app.services.detection.urlopen") as outbound_url:
            response = self.analyze_qr(suspicious_url)
            outbound_url.assert_not_called()

        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["decoded_content"], suspicious_url)
        self.assertEqual(result["risk_category"], "suspicious")
        self.assertGreaterEqual(result["risk_score"], 35)
        self.assertIn("brand_lookalike_domain", {item["code"] for item in result["indicators"]})
        self.assertFalse(result["opened"])

    def test_http_only_qr_url_is_not_marked_suspicious(self):
        response = self.analyze_qr("http://ordinary-example.invalid/path")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["risk_category"], "lower_risk")
        self.assertEqual([item["code"] for item in response.json()["indicators"]], ["no_https"])

    def test_malformed_url_qr_content_is_returned_as_inconclusive(self):
        for payload in ("https://bad host.example/login", "www.bad host.example/login"):
            with self.subTest(payload=payload):
                response = self.analyze_qr(payload)

                self.assertEqual(response.status_code, 200, response.text)
                result = response.json()
                self.assertEqual(result["content_type"], "malformed_url")
                self.assertEqual(result["risk_category"], "inconclusive")
                self.assertIn("not opened", result["explanation"])
                self.assertFalse(result["stored"])
                self.assertFalse(result["opened"])

    def test_non_url_qr_content_is_returned_without_url_assessment(self):
        response = self.analyze_qr("one-time reference code 314159")

        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["decoded_content"], "one-time reference code 314159")
        self.assertEqual(result["content_type"], "non_url")
        self.assertEqual(result["risk_category"], "inconclusive")
        self.assertFalse(result["stored"])
        self.assertFalse(result["opened"])

    def test_invalid_image_is_rejected(self):
        response = self.client.post(
            "/api/qr/analyze",
            headers=self.headers,
            files={"image": ("bad.png", b"not an image", "image/png")},
        )

        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("valid PNG", response.json()["detail"])

    def test_image_without_qr_code_is_rejected(self):
        response = self.client.post(
            "/api/qr/analyze",
            headers=self.headers,
            files={"image": ("blank.png", make_png(), "image/png")},
        )

        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("No decodable QR code", response.json()["detail"])

    def test_unsupported_image_format_is_rejected(self):
        gif = io.BytesIO()
        Image.new("RGB", (64, 64), "white").save(gif, format="GIF")
        with self.assertRaisesRegex(ValueError, "PNG, JPG, JPEG, or WEBP"):
            decode_qr_image(upload_image(gif.getvalue(), "animated.gif", "image/gif"))

    def test_screenshot_ocr_reports_missing_tesseract(self):
        import pytesseract

        with patch.object(
            pytesseract,
            "image_to_string",
            side_effect=pytesseract.TesseractNotFoundError(),
        ):
            result = extract_screenshot_text(upload_image(make_png()))

        self.assertEqual(result["ocr_status"], "unavailable")
        self.assertEqual(result["text"], "")
        self.assertIn("winget install", result["message"])
        self.assertIn("manually", result["message"])

    def test_tesseract_executable_can_be_configured_with_environment_variable(self):
        import os
        import pytesseract

        original_command = pytesseract.pytesseract.tesseract_cmd
        with (
            patch.dict(os.environ, {"TESSERACT_CMD": r"C:\OCR Tools\tesseract.exe"}),
            patch.object(pytesseract.pytesseract, "tesseract_cmd", original_command),
            patch.object(pytesseract, "get_tesseract_version", return_value="5.5.0"),
            patch.object(pytesseract, "image_to_string", return_value="Verify your account."),
        ):
            result = extract_screenshot_text(upload_image(make_png()))
            self.assertEqual(pytesseract.pytesseract.tesseract_cmd, r"C:\OCR Tools\tesseract.exe")

        self.assertEqual(result["ocr_status"], "available")
        self.assertEqual(result["text"], "Verify your account.")

    def test_tesseract_uses_standard_windows_install_path_as_fallback(self):
        import os
        import pytesseract
        from app.services import ingestion

        original_command = pytesseract.pytesseract.tesseract_cmd
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(pytesseract.pytesseract, "tesseract_cmd", original_command),
            patch.object(ingestion.shutil, "which", return_value=None),
            patch.object(Path, "is_file", return_value=True),
            patch.object(pytesseract, "get_tesseract_version", return_value="5.5.3"),
            patch.object(pytesseract, "image_to_string", return_value="Please verify your account."),
        ):
            result = extract_screenshot_text(upload_image(make_png()))
            self.assertEqual(
                pytesseract.pytesseract.tesseract_cmd,
                str(ingestion.WINDOWS_TESSERACT_PATH),
            )

        self.assertEqual(result["ocr_status"], "available")
        self.assertEqual(result["text"], "Please verify your account.")

    def test_screenshot_ocr_reports_missing_python_dependency(self):
        import builtins

        original_import = builtins.__import__

        def import_without_pytesseract(name, *args, **kwargs):
            if name == "pytesseract":
                raise ImportError("pytesseract unavailable for test")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=import_without_pytesseract):
            result = extract_screenshot_text(upload_image(make_png()))

        self.assertEqual(result["ocr_status"], "unavailable")
        self.assertEqual(result["text"], "")
        self.assertIn("pytesseract package is not installed", result["message"])

    def test_ocr_settings_report_missing_executable_configuration(self):
        import os
        import pytesseract

        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(pytesseract.pytesseract, "tesseract_cmd", "tesseract"),
            patch.object(
                pytesseract,
                "get_tesseract_version",
                side_effect=pytesseract.TesseractNotFoundError(),
            ),
        ):
            self.assertEqual(
                get_tesseract_status(),
                "unavailable (configure TESSERACT_CMD or PATH)",
            )

    def test_screenshot_ocr_reports_no_readable_text(self):
        with patch("pytesseract.image_to_string", return_value=" \n\t "):
            result = extract_screenshot_text(upload_image(make_png()))

        self.assertEqual(result["ocr_status"], "no_text")
        self.assertEqual(result["text"], "")
        self.assertIn("No readable text", result["message"])

    def test_screenshot_ocr_extracts_text_when_tesseract_returns_text(self):
        recognized = "Please verify your account."
        with patch("pytesseract.image_to_string", return_value=recognized):
            result = extract_screenshot_text(upload_image(make_png()))

        self.assertEqual(result["ocr_status"], "available")
        self.assertEqual(result["text"], recognized)

    def test_ocr_text_is_sent_to_detection_and_returned_with_explanation(self):
        extracted_text = "Verify account now and claim reward by send password."
        with patch(
            "app.main.extract_screenshot_text",
            return_value={
                "text": extracted_text,
                "ocr_status": "available",
                "message": "Screenshot text extracted locally.",
            },
        ):
            response = self.client.post(
                "/api/customer/reports/screenshot",
                data={"brand_id": str(self.brand_id)},
                files={"screenshot": ("screenshot.png", make_png(), "image/png")},
            )

        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["extracted_text"], extracted_text)
        self.assertEqual(result["analysis"]["risk_category"], "suspicious")
        self.assertTrue(result["analysis"]["indicators"])
        self.assertTrue(result["analysis"]["evidence"])
        self.assertIn("explanation", result["analysis"])
        with self.Session() as db:
            report = db.get(CustomerReport, result["report_id"])
            self.assertIn(extracted_text, report.report_text)

    def test_screenshot_with_no_ocr_or_manual_text_returns_clear_error(self):
        with patch(
            "app.main.extract_screenshot_text",
            return_value={
                "text": "",
                "ocr_status": "no_text",
                "message": "No readable text was found in this screenshot.",
            },
        ):
            response = self.client.post(
                "/api/customer/reports/screenshot",
                data={"brand_id": str(self.brand_id)},
                files={"screenshot": ("screenshot.png", make_png(), "image/png")},
            )

        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("No readable text", response.json()["detail"])

    def test_brandless_screenshot_report_uses_authenticated_organization(self):
        extracted = {
            "text": "A suspicious account message was received.",
            "ocr_status": "available",
            "message": "Screenshot text extracted locally.",
        }
        with patch("app.main.extract_screenshot_text", return_value=extracted):
            anonymous = self.client.post(
                "/api/customer/reports/screenshot",
                data={"report_text": "A suspicious account message was received."},
                files={"screenshot": ("screenshot.png", make_png(), "image/png")},
            )
            self.assertEqual(anonymous.status_code, 401, anonymous.text)

            authenticated = self.client.post(
                "/api/customer/reports/screenshot",
                headers=self.headers,
                data={"report_text": "A suspicious account message was received."},
                files={"screenshot": ("screenshot.png", make_png(), "image/png")},
            )
        self.assertEqual(authenticated.status_code, 200, authenticated.text)
        report_id = authenticated.json()["report_id"]
        with self.Session() as db:
            report = db.get(CustomerReport, report_id)
            self.assertIsNone(report.brand_id)
            self.assertEqual(report.organization_id, self.organization_id)
        listed = self.client.get("/api/community/reports", headers=self.headers)
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertIn(report_id, {item["id"] for item in listed.json()})

    def test_authenticated_reporter_cannot_submit_reports_to_another_organization(self):
        with self.Session() as db:
            organization_b = Organization(name="Screenshot Isolation Organization B")
            db.add(organization_b)
            db.flush()
            brand_b = Brand(
                organization_id=organization_b.id,
                name="Private Screenshot Brand",
                known_domains=["private-org-b.example"],
            )
            db.add(brand_b)
            db.commit()
            brand_b_id = brand_b.id
            initial_reports = db.query(CustomerReport).count()

        text_report = self.client.post(
            "/api/customer/reports",
            headers=self.headers,
            json={
                "brand_id": brand_b_id,
                "report_text": "Organization A must not file into organization B.",
            },
        )
        self.assertEqual(text_report.status_code, 404, text_report.text)

        extracted = {
            "text": "Please verify account and claim reward.",
            "ocr_status": "available",
            "message": "Screenshot text extracted locally.",
        }
        with patch("app.main.extract_screenshot_text", return_value=extracted):
            screenshot_report = self.client.post(
                "/api/customer/reports/screenshot",
                headers=self.headers,
                data={"brand_id": str(brand_b_id)},
                files={"screenshot": ("screenshot.png", make_png(), "image/png")},
            )
        self.assertEqual(screenshot_report.status_code, 404, screenshot_report.text)
        with self.Session() as db:
            self.assertEqual(db.query(CustomerReport).count(), initial_reports)

    def test_anonymous_screenshot_analysis_does_not_disclose_selected_brands_private_domains(self):
        with self.Session() as db:
            organization_b = Organization(name="Anonymous Screenshot Organization B")
            db.add(organization_b)
            db.flush()
            brand_b = Brand(
                organization_id=organization_b.id,
                name="Private Screenshot Brand",
                known_domains=["private-org-b.example", "accounts.private-org-b.example"],
            )
            db.add(brand_b)
            db.commit()
            brand_b_id = brand_b.id

        extracted = {
            "text": "Verify account now and claim reward.",
            "ocr_status": "available",
            "message": "Screenshot text extracted locally.",
        }
        with patch("app.main.extract_screenshot_text", return_value=extracted):
            response = self.client.post(
                "/api/customer/reports/screenshot",
                data={"brand_id": str(brand_b_id)},
                files={"screenshot": ("screenshot.png", make_png(), "image/png")},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["extracted_text"], extracted["text"])
        self.assertEqual(response.json()["analysis"]["risk_category"], "suspicious")
        self.assertNotIn("private-org-b.example", response.text)

    def test_ocr_rejects_corrupted_and_unsupported_images(self):
        with self.assertRaisesRegex(ValueError, "valid PNG, JPG, JPEG, or WEBP"):
            extract_screenshot_text(upload_image(b"not an image"))

        gif = io.BytesIO()
        Image.new("RGB", (64, 64), "white").save(gif, format="GIF")
        with self.assertRaisesRegex(ValueError, "valid PNG, JPG, JPEG, or WEBP"):
            extract_screenshot_text(upload_image(gif.getvalue(), "screenshot.gif", "image/gif"))

    def test_oversized_qr_image_is_rejected(self):
        response = self.client.post(
            "/api/qr/analyze",
            headers=self.headers,
            files={"image": ("large.png", b"x" * (5 * 1024 * 1024 + 1), "image/png")},
        )

        self.assertEqual(response.status_code, 413, response.text)
        self.assertIn("5MB", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
