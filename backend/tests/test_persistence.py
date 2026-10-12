import base64
import csv
import hmac
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError as SQLAlchemyIntegrityError, SQLAlchemyError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.database import Base, create_database_engine
from app.main import app, get_db
from app import main as main_module
from app.models import (
    AuditLog,
    Brand,
    Campaign,
    CampaignEvent,
    CustomerReport,
    DetectionResult,
    Entity,
    Evidence,
    Investigation,
    Organization,
    QRAnalysis,
    Relationship,
    ReportMatch,
    User,
)
from app.schema import initialize_database
from app.services.auth import hash_password, verify_password


class PersistenceApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "brandshield-test.db"
        self.database_url = "sqlite:///" + self.database_path.as_posix()
        self.engine = create_database_engine(self.database_url)
        initialize_database(self.engine, Base.metadata)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        with self.Session() as db:
            organization = Organization(name="Test Organization")
            db.add(organization)
            db.flush()
            user = User(
                organization_id=organization.id,
                email="admin@test.invalid",
                password_hash=hash_password("a-strong-test-password"),
                role="admin",
            )
            brand = Brand(
                organization_id=organization.id,
                name="Test Brand",
                official_website="https://testbrand.invalid",
                known_domains=["testbrand.invalid"],
            )
            db.add_all([user, brand])
            db.commit()
            self.organization_id = organization.id
            self.user_id = user.id
            self.brand_id = brand.id

        app.dependency_overrides[get_db] = self.override_get_db
        self.client = TestClient(app)
        response = self.client.post(
            "/api/auth/login",
            json={"email": "admin@test.invalid", "password": "a-strong-test-password"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.headers = {"Authorization": f"Bearer {response.json()['access_token']}"}

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

    def create_finding(self):
        response = self.client.post(
            "/api/analysis/analyze",
            headers=self.headers,
            json={
                "brand_id": self.brand_id,
                "name": "Test Brand Help",
                "entity_type": "social_profile",
                "platform": "Test",
                "url": "http://testbrand-login.invalid/verify/login",
                "description": "verify account and claim reward",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_detection_endpoint_accepts_text_and_returns_structured_result(self):
        with self.Session() as db:
            initial_campaign_count = db.query(Campaign).count()
        legitimate = self.client.post(
            "/api/analysis/analyze",
            headers=self.headers,
            json={
                "brand_id": self.brand_id,
                "url": "https://ordinary-example.test",
                "entity_type": "social_profile",
            },
        )
        self.assertEqual(legitimate.status_code, 200, legitimate.text)
        self.assertEqual(legitimate.json()["risk_category"], "lower_risk")
        self.assertEqual(legitimate.json()["url"], "https://ordinary-example.test")
        self.assertEqual(
            self.client.delete(
                f"/api/detections/{legitimate.json()['id']}",
                headers=self.headers,
            ).status_code,
            200,
        )
        with self.Session() as db:
            self.assertEqual(db.query(Campaign).count(), initial_campaign_count)

        response = self.client.post(
            "/api/analysis/analyze",
            headers=self.headers,
            json={
                "brand_id": self.brand_id,
                "description": "Verify account now and claim reward.",
                "entity_type": "social_profile",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["risk_category"], "suspicious")
        self.assertEqual(result["verdict"], "suspicious")
        self.assertGreaterEqual(result["risk_score"], 35)
        self.assertTrue(result["indicators"])
        self.assertTrue(result["evidence"])
        self.assertIn("explanation", result)

        malformed = self.client.post(
            "/api/analysis/analyze",
            headers=self.headers,
            json={
                "brand_id": self.brand_id,
                "url": "https://not a valid host",
                "entity_type": "social_profile",
            },
        )
        self.assertEqual(malformed.status_code, 422, malformed.text)

        empty = self.client.post(
            "/api/analysis/analyze",
            headers=self.headers,
            json={"brand_id": self.brand_id},
        )
        self.assertEqual(empty.status_code, 422, empty.text)

        deleted = self.client.delete(
            f"/api/detections/{result['id']}",
            headers=self.headers,
        )
        self.assertEqual(deleted.status_code, 200, deleted.text)

    def test_campaigns_require_shared_suspicious_domain_and_keep_historical_events(self):
        phrase_only = self.client.post(
            "/api/analysis/analyze",
            headers=self.headers,
            json={
                "brand_id": self.brand_id,
                "name": "Unrelated Profile",
                "description": "verify account and claim reward",
                "entity_type": "social_profile",
            },
        )
        self.assertEqual(phrase_only.status_code, 200, phrase_only.text)
        self.assertEqual(self.client.get("/api/campaigns", headers=self.headers).json(), [])

        def analyze(name, url):
            response = self.client.post(
                "/api/analysis/analyze",
                headers=self.headers,
                json={
                    "brand_id": self.brand_id,
                    "name": name,
                    "url": url,
                    "description": "verify account and claim reward",
                    "entity_type": "social_profile",
                    "platform": "Test",
                },
            )
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()

        first = analyze("Test Brand Help", "http://testbrand-login.invalid/verify/login")
        second = analyze("Test Brand Support", "http://testbrand-login.invalid/claim/login")
        unrelated_domain = analyze("Test Brand Help", "http://testbrand-account.invalid/verify/login")

        campaigns = self.client.get("/api/campaigns", headers=self.headers)
        self.assertEqual(campaigns.status_code, 200, campaigns.text)
        campaigns_by_key = {campaign["campaign_key"]: campaign for campaign in campaigns.json()}
        self.assertEqual(
            set(campaigns_by_key),
            {"domain:testbrand-login.invalid", "domain:testbrand-account.invalid"},
        )
        shared_domain = campaigns_by_key["domain:testbrand-login.invalid"]
        self.assertEqual(shared_domain["event_count"], 2)
        self.assertEqual(shared_domain["linked_finding_count"], 2)
        self.assertEqual(sum(shared_domain["risk_summary"].values()), 2)
        self.assertTrue(all(event["finding_available"] for event in shared_domain["events"]))
        self.assertTrue(all("supporting_evidence" in event["indicators"] for event in shared_domain["events"]))
        self.assertEqual(campaigns_by_key["domain:testbrand-account.invalid"]["event_count"], 1)

        update = self.client.patch(
            f"/api/detections/{first['id']}",
            headers=self.headers,
            json={"status": "resolved"},
        )
        self.assertEqual(update.status_code, 200, update.text)
        updated_campaign = next(
            campaign for campaign in self.client.get("/api/campaigns", headers=self.headers).json()
            if campaign["campaign_key"] == "domain:testbrand-login.invalid"
        )
        self.assertIn("resolved", {event["finding_status"] for event in updated_campaign["events"]})

        deleted = self.client.delete(f"/api/detections/{first['id']}", headers=self.headers)
        self.assertEqual(deleted.status_code, 200, deleted.text)
        retained = next(
            campaign for campaign in self.client.get("/api/campaigns", headers=self.headers).json()
            if campaign["campaign_key"] == "domain:testbrand-login.invalid"
        )
        self.assertEqual(retained["event_count"], 2)
        self.assertEqual(retained["linked_finding_count"], 1)
        self.assertEqual(sum(retained["risk_summary"].values()), 1)
        self.assertEqual(sum(not event["finding_available"] for event in retained["events"]), 1)

        demo_scan = self.client.post("/api/run-demo-scan", headers=self.headers)
        self.assertEqual(demo_scan.status_code, 200, demo_scan.text)
        after_replacement = next(
            campaign for campaign in self.client.get("/api/campaigns", headers=self.headers).json()
            if campaign["campaign_key"] == "domain:testbrand-login.invalid"
        )
        self.assertEqual(after_replacement["event_count"], 2)
        self.assertEqual(after_replacement["linked_finding_count"], 0)
        self.assertEqual(sum(after_replacement["risk_summary"].values()), 0)
        self.assertTrue(all(not event["finding_available"] for event in after_replacement["events"]))

    def test_campaign_api_handles_empty_data_errors_and_invalid_cross_brand_events(self):
        self.assertEqual(self.client.get("/api/campaigns").status_code, 401)
        empty = self.client.get("/api/campaigns", headers=self.headers)
        self.assertEqual(empty.status_code, 200, empty.text)
        self.assertEqual(empty.json(), [])

        finding = self.create_finding()
        with self.Session() as db:
            db.add(Campaign(
                brand_id=self.brand_id,
                campaign_key="language:verify account|claim reward",
                title="Legacy phrase-only grouping",
            ))
            db.flush()
            campaign = db.query(Campaign).filter(
                Campaign.brand_id == self.brand_id,
                Campaign.campaign_key == "domain:testbrand-login.invalid",
            ).one()
            other_brand = Brand(
                organization_id=self.organization_id,
                name="Test Brand",
                official_website="https://otherbrand.invalid",
                known_domains=["otherbrand.invalid"],
            )
            db.add(other_brand)
            db.flush()
            other_brand_id = other_brand.id
            db.commit()
        other_finding_response = self.client.post(
            "/api/analysis/analyze",
            headers=self.headers,
            json={
                "brand_id": other_brand_id,
                "name": "Test Brand Help",
                "url": "http://testbrand-login.invalid/verify/login",
                "description": "verify account and claim reward",
                "entity_type": "social_profile",
                "platform": "Test",
            },
        )
        self.assertEqual(other_finding_response.status_code, 200, other_finding_response.text)
        other_finding = other_finding_response.json()
        with self.Session() as db:
            campaign = db.query(Campaign).filter(
                Campaign.brand_id == self.brand_id,
                Campaign.campaign_key == "domain:testbrand-login.invalid",
            ).one()
            db.add(CampaignEvent(
                campaign_id=campaign.id,
                detection_id=other_finding["id"],
                event_type="invalid_cross_brand",
                summary="Must not be exposed as a linked finding.",
            ))
            db.commit()
            campaign_key = campaign.campaign_key

        response = self.client.get("/api/campaigns", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        same_domain_campaigns = [
            item for item in response.json()
            if item["campaign_key"] == campaign_key
        ]
        self.assertNotIn(
            "language:verify account|claim reward",
            {item["campaign_key"] for item in response.json()},
        )
        self.assertEqual({item["brand_id"] for item in same_domain_campaigns}, {self.brand_id, other_brand_id})
        for campaign in same_domain_campaigns:
            self.assertEqual(campaign["linked_finding_count"], 1)
            self.assertEqual(campaign["event_count"], 1)
        first_brand_campaign = next(item for item in same_domain_campaigns if item["brand_id"] == self.brand_id)
        other_brand_campaign = next(item for item in same_domain_campaigns if item["brand_id"] == other_brand_id)
        self.assertEqual(first_brand_campaign["events"][0]["detection_id"], finding["id"])
        self.assertEqual(other_brand_campaign["events"][0]["detection_id"], other_finding["id"])

        with patch.object(main_module, "accessible_brand_ids", side_effect=SQLAlchemyError("database unavailable")):
            failed = self.client.get("/api/campaigns", headers=self.headers)
        self.assertEqual(failed.status_code, 500, failed.text)
        self.assertIn("Database operation failed", failed.json()["detail"])

    def test_brand_user_and_organization_crud_are_scoped_and_passwords_are_hashed(self):
        response = self.client.get("/api/organization", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], self.organization_id)
        updated = self.client.patch(
            "/api/organization",
            headers=self.headers,
            json={"name": "Updated Test Organization"},
        )
        self.assertEqual(updated.status_code, 200, updated.text)
        self.assertEqual(updated.json()["name"], "Updated Test Organization")

        created = self.client.post(
            "/api/users",
            headers=self.headers,
            json={"email": " Analyst@Test.Invalid ", "password": "another-strong-password"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        user_id = created.json()["id"]
        users = self.client.get("/api/users", headers=self.headers)
        self.assertEqual(users.status_code, 200)
        self.assertEqual({user["email"] for user in users.json()}, {"admin@test.invalid", "analyst@test.invalid"})
        self.assertNotIn("password_hash", json.dumps(users.json()))
        with self.Session() as db:
            saved_user = db.query(User).filter(User.id == user_id).one()
            self.assertNotIn("another-strong-password", saved_user.password_hash)
            self.assertTrue(verify_password("another-strong-password", saved_user.password_hash))

        changed = self.client.put(
            f"/api/users/{user_id}",
            headers=self.headers,
            json={"email": "analyst2@test.invalid", "password": "updated-strong-password"},
        )
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertEqual(changed.json()["email"], "analyst2@test.invalid")
        self.assertEqual(
            self.client.delete(f"/api/users/{user_id}", headers=self.headers).status_code,
            200,
        )
        self.assertEqual(
            self.client.delete(f"/api/users/{self.user_id}", headers=self.headers).status_code,
            409,
        )
        duplicate_user = self.client.post(
            "/api/users",
            headers=self.headers,
            json={"email": "admin@test.invalid", "password": "a-different-strong-password"},
        )
        self.assertEqual(duplicate_user.status_code, 409)
        self.assertEqual(self.client.get("/api/users", headers=self.headers).status_code, 200)

        created_brand = self.client.post(
            "/api/brands",
            headers=self.headers,
            data={"name": "Second Brand", "known_domains": '["second.invalid"]'},
        )
        self.assertEqual(created_brand.status_code, 200, created_brand.text)
        new_brand_id = created_brand.json()["id"]
        read_brand = self.client.get(f"/api/brands/{new_brand_id}", headers=self.headers)
        self.assertEqual(read_brand.status_code, 200)
        self.assertEqual(read_brand.json()["known_domains"], ["second.invalid"])
        updated_brand = self.client.put(
            f"/api/brands/{new_brand_id}",
            headers=self.headers,
            data={"name": "Renamed Brand", "known_domains": '["renamed.invalid"]'},
        )
        self.assertEqual(updated_brand.status_code, 200, updated_brand.text)
        self.assertEqual(
            self.client.get(f"/api/brands/{new_brand_id}", headers=self.headers).json()["name"],
            "Renamed Brand",
        )
        invalid_brand = self.client.post(
            "/api/brands",
            headers=self.headers,
            data={"name": "Invalid", "known_domains": "{not json"},
        )
        self.assertEqual(invalid_brand.status_code, 422)
        self.assertNotIn("Invalid", {brand["name"] for brand in self.client.get("/api/brands", headers=self.headers).json()})
        self.assertEqual(
            self.client.delete(f"/api/brands/{new_brand_id}", headers=self.headers).status_code,
            200,
        )
        self.assertEqual(self.client.get(f"/api/brands/{new_brand_id}", headers=self.headers).status_code, 404)

    def test_monitoring_source_crud_is_scoped_and_audited(self):
        created = self.client.post(
            "/api/sources",
            headers=self.headers,
            json={
                "brand_id": self.brand_id,
                "source_type": "domain",
                "platform": "Website",
                "locator": "https://brand.invalid",
            },
        )
        self.assertEqual(created.status_code, 200, created.text)
        source_id = created.json()["id"]
        updated = self.client.patch(
            f"/api/sources/{source_id}",
            headers=self.headers,
            json={"platform": "Website Monitor", "enabled": False},
        )
        self.assertEqual(updated.status_code, 200, updated.text)
        self.assertEqual(updated.json()["platform"], "Website Monitor")
        self.assertFalse(updated.json()["enabled"])
        self.assertEqual(
            self.client.patch(
                f"/api/sources/{source_id}",
                headers=self.headers,
                json={"locator": "  "},
            ).status_code,
            422,
        )
        listed = self.client.get("/api/sources", headers=self.headers)
        self.assertEqual(listed.status_code, 200)
        self.assertIn(source_id, {source["id"] for source in listed.json()})
        self.assertEqual(
            self.client.delete(f"/api/sources/{source_id}", headers=self.headers).status_code,
            200,
        )
        self.assertNotIn(
            source_id,
            {source["id"] for source in self.client.get("/api/sources", headers=self.headers).json()},
        )
        with self.Session() as db:
            audit_actions = {
                entry.action
                for entry in db.query(AuditLog).filter(AuditLog.brand_id == self.brand_id).all()
            }
        self.assertTrue({"Monitoring source added", "Monitoring source updated", "Monitoring source removed"} <= audit_actions)

    def test_finding_investigation_reports_campaign_and_qr_persist_after_reopen(self):
        finding = self.create_finding()
        finding_id = finding["id"]
        details = self.client.get(f"/api/detections/{finding_id}", headers=self.headers)
        self.assertEqual(details.status_code, 200, details.text)
        self.assertGreater(len(details.json()["evidence_records"]), 0)
        self.assertEqual(details.json()["investigation_ids"], [])

        changed = self.client.patch(
            f"/api/detections/{finding_id}",
            headers=self.headers,
            json={"status": "resolved"},
        )
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertEqual(changed.json()["status"], "resolved")

        investigation = self.client.post(
            "/api/investigations",
            headers=self.headers,
            json={
                "brand_id": self.brand_id,
                "title": "Test investigation",
                "summary": "Stored test incident evidence.",
                "risk_level": "high",
                "detection_id": finding_id,
            },
        )
        self.assertEqual(investigation.status_code, 200, investigation.text)
        investigation_id = investigation.json()["id"]
        self.assertEqual(investigation.json()["detection_id"], finding_id)
        self.assertEqual(self.client.get(f"/api/investigations/{investigation_id}", headers=self.headers).json()["detection_id"], finding_id)
        self.assertEqual(
            self.client.get(f"/api/detections/{finding_id}", headers=self.headers).json()["investigation_ids"],
            [investigation_id],
        )
        self.assertEqual(
            next(item for item in self.client.get("/api/investigations", headers=self.headers).json() if item["id"] == investigation_id)["detection_id"],
            finding_id,
        )
        changed_investigation = self.client.put(
            f"/api/investigations/{investigation_id}",
            headers=self.headers,
            json={"title": "Updated investigation", "risk_level": "critical", "detection_id": finding_id},
        )
        self.assertEqual(changed_investigation.status_code, 200, changed_investigation.text)
        self.assertEqual(changed_investigation.json()["title"], "Updated investigation")
        self.assertEqual(changed_investigation.json()["detection_id"], finding_id)
        changed_investigation_status = self.client.patch(
            f"/api/investigations/{investigation_id}",
            headers=self.headers,
            data={"status": "investigating"},
        )
        self.assertEqual(changed_investigation_status.status_code, 200, changed_investigation_status.text)
        self.assertEqual(changed_investigation_status.json()["status"], "investigating")

        public_report = self.client.post(
            "/api/customer/reports",
            json={
                "brand_id": self.brand_id,
                "report_text": "A suspicious Test Brand login and reward request was received.",
                "reported_url": "https://testbrand-login.invalid/verify",
            },
        )
        self.assertEqual(public_report.status_code, 200, public_report.text)
        receipt = public_report.json()
        self.assertNotIn("related_findings", receipt)
        report_id = receipt["report_id"]
        queue = self.client.get("/api/community/reports", headers=self.headers)
        self.assertEqual(queue.status_code, 200, queue.text)
        self.assertIn(report_id, {report["id"] for report in queue.json()})
        reviewed = self.client.patch(
            f"/api/community/reports/{report_id}",
            headers=self.headers,
            json={"status": "reviewed", "analyst_verified": True},
        )
        self.assertEqual(reviewed.status_code, 200, reviewed.text)
        self.assertEqual(
            self.client.get("/api/campaigns", headers=self.headers).status_code,
            200,
        )
        self.assertGreater(len(self.client.get("/api/campaigns", headers=self.headers).json()), 0)
        with self.Session() as db:
            campaign_id = db.query(Campaign.id).filter(Campaign.brand_id == self.brand_id).scalar()
            event_ids = [
                row[0]
                for row in db.query(CampaignEvent.id).filter(
                    CampaignEvent.campaign_id == campaign_id,
                    CampaignEvent.detection_id == finding_id,
                ).all()
            ]

        try:
            import cv2
        except ImportError:
            self.skipTest("OpenCV is not installed; QR persistence requires the declared optional dependency.")
        qr = cv2.QRCodeEncoder_create().encode("https://testbrand.invalid/verify")
        encoded_ok, encoded_qr = cv2.imencode(".png", qr)
        self.assertTrue(encoded_ok)
        qr_response = self.client.post(
            "/api/qr/analyze",
            headers=self.headers,
            data={"brand_id": str(self.brand_id)},
            files={"image": ("test-qr.png", encoded_qr.tobytes(), "image/png")},
        )
        self.assertEqual(qr_response.status_code, 200, qr_response.text)
        qr_result = qr_response.json()
        self.assertFalse(qr_result["opened"])
        self.assertIn(
            qr_result["id"],
            {item["id"] for item in self.client.get("/api/qr/history", headers=self.headers).json()},
        )

        self.client.close()
        self.engine.dispose()
        self.engine = create_database_engine(self.database_url)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.client = TestClient(app)
        login = self.client.post(
            "/api/auth/login",
            json={"email": "admin@test.invalid", "password": "a-strong-test-password"},
        )
        self.assertEqual(login.status_code, 200, login.text)
        self.headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        self.assertEqual(self.client.get(f"/api/detections/{finding_id}", headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get(f"/api/investigations/{investigation_id}", headers=self.headers).json()["detection_id"], finding_id)
        self.assertIn(report_id, {item["id"] for item in self.client.get("/api/community/reports", headers=self.headers).json()})
        self.assertIn(qr_result["id"], {item["id"] for item in self.client.get("/api/qr/history", headers=self.headers).json()})

        delete_finding = self.client.delete(f"/api/detections/{finding_id}", headers=self.headers)
        self.assertEqual(delete_finding.status_code, 200, delete_finding.text)
        self.assertEqual(self.client.get(f"/api/detections/{finding_id}", headers=self.headers).status_code, 404)
        with self.Session() as db:
            self.assertEqual(db.query(Evidence).filter(Evidence.detection_id == finding_id).count(), 0)
            self.assertEqual(db.query(ReportMatch).filter(ReportMatch.detection_id == finding_id).count(), 0)
            self.assertEqual(
                db.query(CampaignEvent).filter(CampaignEvent.id.in_(event_ids)).count(),
                len(event_ids),
            )
            self.assertTrue(all(
                db.get(CampaignEvent, event_id).detection_id is None
                for event_id in event_ids
            ))
            self.assertEqual(
                db.query(AuditLog).filter(
                    AuditLog.brand_id == self.brand_id,
                    AuditLog.action == "Finding deleted",
                ).count(),
                1,
            )
            self.assertIsNone(db.get(Investigation, investigation_id).detection_id)
            self.assertGreaterEqual(
                db.query(AuditLog).filter(
                    AuditLog.brand_id == self.brand_id,
                    AuditLog.action.in_(["Finding status changed", "Investigation created", "Investigation updated", "Investigation status changed"]),
                ).count(),
                4,
            )
        delete_investigation = self.client.delete(
            f"/api/investigations/{investigation_id}",
            headers=self.headers,
        )
        self.assertEqual(delete_investigation.status_code, 200, delete_investigation.text)
        with self.Session() as db:
            self.assertIsNone(db.get(Investigation, investigation_id))
            self.assertEqual(
                db.query(AuditLog).filter(
                    AuditLog.brand_id == self.brand_id,
                    AuditLog.action == "Investigation deleted",
                ).count(),
                1,
            )

    def test_investigation_finding_links_validate_brand_and_invalid_api_inputs(self):
        self.assertEqual(self.client.get("/api/detections", headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get("/api/investigations", headers=self.headers).json(), [])
        self.assertEqual(self.client.get("/api/detections/99999", headers=self.headers).status_code, 404)
        self.assertEqual(self.client.get("/api/investigations/99999", headers=self.headers).status_code, 404)
        self.assertEqual(self.client.delete("/api/detections/99999", headers=self.headers).status_code, 404)
        self.assertEqual(self.client.delete("/api/investigations/99999", headers=self.headers).status_code, 404)

        finding = self.create_finding()
        second_brand_response = self.client.post(
            "/api/brands",
            headers=self.headers,
            data={"name": "Second Test Brand", "official_website": "https://second.test"},
        )
        self.assertEqual(second_brand_response.status_code, 200, second_brand_response.text)
        second_brand_id = second_brand_response.json()["id"]
        second_finding_response = self.client.post(
            "/api/analysis/analyze",
            headers=self.headers,
            json={
                "brand_id": second_brand_id,
                "name": "Second Test Brand Help",
                "description": "verify account and claim reward",
                "entity_type": "social_profile",
            },
        )
        self.assertEqual(second_finding_response.status_code, 200, second_finding_response.text)
        second_finding = second_finding_response.json()

        invalid = self.client.post(
            "/api/investigations",
            headers=self.headers,
            json={"brand_id": self.brand_id, "title": "Invalid linked case", "detection_id": second_finding["id"]},
        )
        self.assertEqual(invalid.status_code, 404, invalid.text)
        invalid_brand = self.client.post(
            "/api/investigations",
            headers=self.headers,
            json={"brand_id": 99999, "title": "Unknown brand case"},
        )
        self.assertEqual(invalid_brand.status_code, 404, invalid_brand.text)
        invalid_payload = self.client.post(
            "/api/investigations",
            headers=self.headers,
            json={"brand_id": self.brand_id, "title": "Valid length", "risk_level": "extreme"},
        )
        self.assertEqual(invalid_payload.status_code, 422, invalid_payload.text)
        whitespace_title = self.client.post(
            "/api/investigations",
            headers=self.headers,
            json={"brand_id": self.brand_id, "title": "   "},
        )
        self.assertEqual(whitespace_title.status_code, 422, whitespace_title.text)

        created = self.client.post(
            "/api/investigations",
            headers=self.headers,
            json={
                "brand_id": self.brand_id,
                "title": "Linked test case",
                "detection_id": finding["id"],
            },
        )
        self.assertEqual(created.status_code, 200, created.text)
        investigation_id = created.json()["id"]
        wrong_link_update = self.client.put(
            f"/api/investigations/{investigation_id}",
            headers=self.headers,
            json={"detection_id": second_finding["id"]},
        )
        self.assertEqual(wrong_link_update.status_code, 404, wrong_link_update.text)
        self.assertEqual(
            self.client.get(f"/api/investigations/{investigation_id}", headers=self.headers).json()["detection_id"],
            finding["id"],
        )
        empty_update = self.client.put(
            f"/api/investigations/{investigation_id}",
            headers=self.headers,
            json={},
        )
        self.assertEqual(empty_update.status_code, 422, empty_update.text)
        blank_update = self.client.put(
            f"/api/investigations/{investigation_id}",
            headers=self.headers,
            json={"title": " "},
        )
        self.assertEqual(blank_update.status_code, 422, blank_update.text)
        invalid_status = self.client.patch(
            f"/api/investigations/{investigation_id}",
            headers=self.headers,
            data={"status": "assigned"},
        )
        self.assertEqual(invalid_status.status_code, 422, invalid_status.text)
        invalid_finding_status = self.client.patch(
            f"/api/detections/{finding['id']}",
            headers=self.headers,
            json={"status": "assigned"},
        )
        self.assertEqual(invalid_finding_status.status_code, 422, invalid_finding_status.text)

        unlinked = self.client.put(
            f"/api/investigations/{investigation_id}",
            headers=self.headers,
            json={"detection_id": None},
        )
        self.assertEqual(unlinked.status_code, 200, unlinked.text)
        self.assertIsNone(unlinked.json()["detection_id"])

        with patch.object(main_module, "accessible_brand_ids", side_effect=SQLAlchemyError("database unavailable")):
            failed = self.client.get("/api/investigations", headers=self.headers)
        self.assertEqual(failed.status_code, 500, failed.text)
        self.assertIn("Database operation failed", failed.json()["detail"])

    def test_customer_report_validation_duplicates_matching_review_and_persistence(self):
        self.assertEqual(self.client.get("/api/community/reports").status_code, 401)
        self.assertEqual(self.client.get("/api/community/reports", headers=self.headers).json(), [])

        unauthenticated_unknown_brand = self.client.post(
            "/api/customer/reports",
            json={"report_text": "A report without a selected brand."},
        )
        self.assertEqual(unauthenticated_unknown_brand.status_code, 401, unauthenticated_unknown_brand.text)
        unassigned = self.client.post(
            "/api/customer/reports",
            headers=self.headers,
            json={"report_text": "A report without a selected brand."},
        )
        self.assertEqual(unassigned.status_code, 200, unassigned.text)
        duplicate_unassigned = self.client.post(
            "/api/customer/reports",
            headers=self.headers,
            json={"report_text": "A report without a selected brand."},
        )
        self.assertEqual(duplicate_unassigned.json()["status"], "duplicate")
        with self.Session() as db:
            unassigned_record = db.get(CustomerReport, unassigned.json()["report_id"])
            self.assertIsNone(unassigned_record.brand_id)
            self.assertEqual(unassigned_record.organization_id, self.organization_id)
        self.assertIn(
            unassigned.json()["report_id"],
            {item["id"] for item in self.client.get("/api/community/reports", headers=self.headers).json()},
        )

        missing_text = self.client.post(
            "/api/customer/reports",
            json={"brand_id": self.brand_id},
        )
        self.assertEqual(missing_text.status_code, 422, missing_text.text)
        blank_text = self.client.post(
            "/api/customer/reports",
            json={"brand_id": self.brand_id, "report_text": "     "},
        )
        self.assertEqual(blank_text.status_code, 422, blank_text.text)
        too_long = self.client.post(
            "/api/customer/reports",
            json={"brand_id": self.brand_id, "report_text": "x" * 4001},
        )
        self.assertEqual(too_long.status_code, 422, too_long.text)
        invalid_url = self.client.post(
            "/api/customer/reports",
            json={"brand_id": self.brand_id, "report_text": "A suspicious report", "reported_url": "https://bad url"},
        )
        self.assertEqual(invalid_url.status_code, 422, invalid_url.text)
        unknown_brand = self.client.post(
            "/api/customer/reports",
            json={"brand_id": 99999, "report_text": "A suspicious report"},
        )
        self.assertEqual(unknown_brand.status_code, 404, unknown_brand.text)

        finding = self.create_finding()
        false_text_match = self.client.post(
            "/api/customer/reports",
            json={
                "brand_id": self.brand_id,
                "report_text": finding["detection_reason"],
            },
        )
        self.assertEqual(false_text_match.status_code, 200, false_text_match.text)
        with self.Session() as db:
            false_match_report = db.get(CustomerReport, false_text_match.json()["report_id"])
            self.assertEqual(
                db.query(ReportMatch).filter(ReportMatch.customer_report_id == false_match_report.id).count(),
                0,
            )

        first = self.client.post(
            "/api/customer/reports",
            json={
                "brand_id": self.brand_id,
                "report_text": "I received a message from Test Brand Help.",
                "reported_url": "https://testbrand-login.invalid/phishing#tracking",
                "reporter_contact": "  reporter@example.invalid  ",
            },
        )
        self.assertEqual(first.status_code, 200, first.text)
        receipt = first.json()
        self.assertNotIn("related_findings", receipt)
        self.assertEqual(receipt["status"], "pending")
        duplicate = self.client.post(
            "/api/customer/reports",
            json={
                "brand_id": self.brand_id,
                "report_text": "A different note about the same link.",
                "reported_url": "https://testbrand-login.invalid/phishing",
            },
        )
        self.assertEqual(duplicate.status_code, 200, duplicate.text)
        self.assertEqual(duplicate.json()["status"], "duplicate")
        self.assertNotIn("duplicate_of", duplicate.json())

        with self.Session() as db:
            first_record = db.get(CustomerReport, receipt["report_id"])
            duplicate_record = db.get(CustomerReport, duplicate.json()["report_id"])
            self.assertEqual(first_record.organization_id, self.organization_id)
            self.assertEqual(first_record.brand_id, self.brand_id)
            self.assertEqual(first_record.reporter_contact, "reporter@example.invalid")
            self.assertEqual(first_record.report_text, "I received a message from Test Brand Help.")
            self.assertEqual(first_record.reported_url, "https://testbrand-login.invalid/phishing")
            self.assertEqual(duplicate_record.status, "duplicate")
            matches = db.query(ReportMatch).filter(ReportMatch.customer_report_id == first_record.id).all()
            self.assertEqual({match.detection_id for match in matches}, {finding["id"]})
            self.assertEqual(matches[0].match_reason, "Reported URL domain matches a saved finding.")

        queue_response = self.client.get("/api/community/reports", headers=self.headers)
        self.assertEqual(queue_response.status_code, 200, queue_response.text)
        queue_by_id = {item["id"]: item for item in queue_response.json()}
        self.assertIn(receipt["report_id"], queue_by_id)
        self.assertIn(duplicate.json()["report_id"], queue_by_id)
        self.assertEqual(queue_by_id[receipt["report_id"]]["matches"][0]["detection_id"], finding["id"])
        self.assertEqual(queue_by_id[receipt["report_id"]]["matches"][0]["score"], 100)

        bad_review = self.client.patch(
            f"/api/community/reports/{receipt['report_id']}",
            headers=self.headers,
            json={"status": "invalid", "analyst_verified": True},
        )
        self.assertEqual(bad_review.status_code, 422, bad_review.text)
        reviewed = self.client.patch(
            f"/api/community/reports/{receipt['report_id']}",
            headers=self.headers,
            json={"status": "reviewed", "analyst_verified": True},
        )
        self.assertEqual(reviewed.status_code, 200, reviewed.text)
        updated_report = next(
            item for item in self.client.get("/api/community/reports", headers=self.headers).json()
            if item["id"] == receipt["report_id"]
        )
        self.assertEqual(updated_report["status"], "reviewed")
        self.assertTrue(all(match["analyst_verified"] for match in updated_report["matches"]))
        self.assertEqual(
            self.client.patch(
                "/api/community/reports/99999",
                headers=self.headers,
                json={"status": "dismissed"},
            ).status_code,
            404,
        )
        with self.Session() as db:
            self.assertEqual(
                db.query(AuditLog).filter(
                    AuditLog.brand_id == self.brand_id,
                    AuditLog.action == "Community report reviewed",
                ).count(),
                1,
            )

    def test_customer_report_review_is_organization_scoped_and_submission_surfaces_database_errors(self):
        submitted = self.client.post(
            "/api/customer/reports",
            json={"brand_id": self.brand_id, "report_text": "A customer report for this brand."},
        )
        self.assertEqual(submitted.status_code, 200, submitted.text)
        report_id = submitted.json()["report_id"]

        with self.Session() as db:
            organization = Organization(name="Separate Report Organization")
            db.add(organization)
            db.flush()
            other_user = User(
                organization_id=organization.id,
                email="report-reviewer@test.invalid",
                password_hash=hash_password("other-strong-password"),
                role="admin",
            )
            other_brand = Brand(organization_id=organization.id, name="Separate Brand")
            db.add_all([other_user, other_brand])
            db.commit()
            other_email = other_user.email
        other_login = self.client.post(
            "/api/auth/login",
            json={"email": other_email, "password": "other-strong-password"},
        )
        self.assertEqual(other_login.status_code, 200, other_login.text)
        other_headers = {"Authorization": f"Bearer {other_login.json()['access_token']}"}
        self.assertEqual(self.client.get("/api/community/reports", headers=other_headers).json(), [])
        self.assertEqual(
            self.client.patch(
                f"/api/community/reports/{report_id}",
                headers=other_headers,
                json={"status": "dismissed"},
            ).status_code,
            404,
        )
        with self.Session() as db:
            self.assertEqual(db.get(CustomerReport, report_id).status, "pending")

        with patch.object(main_module, "store_customer_report", side_effect=SQLAlchemyError("database unavailable")):
            failed = self.client.post(
                "/api/customer/reports",
                json={"brand_id": self.brand_id, "report_text": "A report during a database failure."},
            )
        self.assertEqual(failed.status_code, 500, failed.text)
        self.assertIn("Database operation failed", failed.json()["detail"])

    def test_organization_isolation_and_brand_delete_remove_children_atomically(self):
        finding = self.create_finding()
        investigation_response = self.client.post(
            "/api/investigations",
            headers=self.headers,
            json={
                "brand_id": self.brand_id,
                "title": "Organization-private investigation",
                "detection_id": finding["id"],
            },
        )
        self.assertEqual(investigation_response.status_code, 200, investigation_response.text)
        investigation_id = investigation_response.json()["id"]
        with self.Session() as db:
            organization = Organization(name="Other Organization")
            db.add(organization)
            db.flush()
            other_user = User(
                organization_id=organization.id,
                email="other@test.invalid",
                password_hash=hash_password("other-strong-password"),
                role="admin",
            )
            other_brand = Brand(organization_id=organization.id, name="Other Brand")
            db.add_all([other_user, other_brand])
            db.commit()
            other_user_id = other_user.id
            other_brand_id = other_brand.id

        with self.Session() as db:
            other_user = db.query(User).filter(User.id == other_user_id).one()
            other_token = self.client.post(
                "/api/auth/login",
                json={"email": other_user.email, "password": "other-strong-password"},
            ).json()["access_token"]
        other_headers = {"Authorization": f"Bearer {other_token}"}
        self.assertEqual(self.client.get("/api/brands", headers=other_headers).json()[0]["id"], other_brand_id)
        self.assertEqual(self.client.get("/api/community/reports", headers=other_headers).json(), [])
        self.assertEqual(self.client.get("/api/detections", headers=other_headers).json(), [])
        self.assertEqual(self.client.get("/api/investigations", headers=other_headers).json(), [])
        self.assertEqual(
            self.client.get(f"/api/detections/{finding['id']}", headers=other_headers).status_code,
            404,
        )
        self.assertEqual(
            self.client.patch(
                f"/api/detections/{finding['id']}",
                headers=other_headers,
                json={"status": "closed"},
            ).status_code,
            404,
        )
        self.assertEqual(self.client.delete(f"/api/detections/{finding['id']}", headers=other_headers).status_code, 404)
        self.assertEqual(self.client.get(f"/api/investigations/{investigation_id}", headers=other_headers).status_code, 404)
        self.assertEqual(
            self.client.put(
                f"/api/investigations/{investigation_id}",
                headers=other_headers,
                json={"title": "Unauthorized edit"},
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.patch(
                f"/api/investigations/{investigation_id}",
                headers=other_headers,
                data={"status": "closed"},
            ).status_code,
            404,
        )
        self.assertEqual(self.client.delete(f"/api/investigations/{investigation_id}", headers=other_headers).status_code, 404)

        with self.Session() as db:
            brand = db.query(Brand).filter(Brand.id == self.brand_id).one()
            detection = db.query(DetectionResult).filter(DetectionResult.id == finding["id"]).one()
            campaign = db.query(Campaign).filter(Campaign.brand_id == self.brand_id).one()
            investigation = Investigation(
                brand_id=self.brand_id,
                title="Deletion cascade test",
                summary="This child row should be removed with its brand.",
            )
            report = CustomerReport(
                brand_id=self.brand_id,
                organization_id=self.organization_id,
                report_text="Linked report",
            )
            qr = QRAnalysis(brand_id=self.brand_id, decoded_url="https://test.invalid")
            db.add_all([investigation, report, qr])
            db.flush()
            evidence = db.query(Evidence).filter(Evidence.detection_id == detection.id).first()
            report_match = ReportMatch(
                customer_report_id=report.id,
                detection_id=detection.id,
                match_score=91,
                match_reason="Test evidence",
            )
            event = CampaignEvent(
                campaign_id=campaign.id,
                detection_id=detection.id,
                event_type="test",
                summary="Linked campaign event",
            )
            entity = Entity(
                brand_id=self.brand_id,
                entity_type="brand",
                canonical_key=f"brand:{self.brand_id}",
                display_name=brand.name,
            )
            db.add_all([report_match, event, entity])
            db.flush()
            db.add(Relationship(
                source_entity_id=entity.id,
                target_entity_id=entity.id,
                evidence_id=evidence.id,
                relation_type="test",
            ))
            db.commit()

        response = self.client.delete(f"/api/brands/{self.brand_id}", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        with self.Session() as db:
            self.assertIsNone(db.get(Brand, self.brand_id))
            for model, column in [
                (DetectionResult, DetectionResult.brand_id),
                (Investigation, Investigation.brand_id),
                (CustomerReport, CustomerReport.brand_id),
                (Campaign, Campaign.brand_id),
                (QRAnalysis, QRAnalysis.brand_id),
            ]:
                self.assertEqual(db.query(model).filter(column == self.brand_id).count(), 0)
            self.assertEqual(db.query(ReportMatch).count(), 0)
            self.assertEqual(db.query(CampaignEvent).count(), 0)
            self.assertEqual(db.query(Evidence).count(), 0)
            self.assertEqual(db.query(Relationship).count(), 0)
            self.assertEqual(
                db.query(AuditLog).filter(
                    AuditLog.brand_id == self.brand_id,
                    AuditLog.action == "Brand deleted",
                ).count(),
                1,
            )

    def test_cross_organization_api_isolation_for_records_aggregates_and_uploads(self):
        finding_a = self.create_finding()
        investigation_a = self.client.post(
            "/api/investigations",
            headers=self.headers,
            json={
                "brand_id": self.brand_id,
                "title": "Organization A investigation",
                "detection_id": finding_a["id"],
            },
        )
        self.assertEqual(investigation_a.status_code, 200, investigation_a.text)
        report_a = self.client.post(
            "/api/customer/reports",
            headers=self.headers,
            json={"brand_id": self.brand_id, "report_text": "Report belonging to organization A."},
        )
        self.assertEqual(report_a.status_code, 200, report_a.text)

        with self.Session() as db:
            organization_b = Organization(name="Organization B isolation fixture")
            db.add(organization_b)
            db.flush()
            user_b = User(
                organization_id=organization_b.id,
                email="isolation-b@test.invalid",
                password_hash=hash_password("organization-b-strong-password"),
                role="admin",
            )
            brand_b = Brand(
                organization_id=organization_b.id,
                name="Organization B Private Brand",
                known_domains=["private-org-b.example"],
            )
            db.add_all([user_b, brand_b])
            db.flush()
            finding_b = DetectionResult(
                brand_id=brand_b.id,
                entity_name="Organization B confidential finding",
                entity_type="social_profile",
                platform="Test",
                risk_score=87,
                risk_level="high",
                detection_reason="Organization B private finding fixture",
                status="open",
                evidence={"signals": []},
            )
            report_b = CustomerReport(
                brand_id=brand_b.id,
                organization_id=organization_b.id,
                report_text="Organization B private customer report fixture.",
            )
            campaign_b = Campaign(
                brand_id=brand_b.id,
                campaign_key="domain:private-org-b.example",
                title="Organization B private campaign",
            )
            qr_b = QRAnalysis(
                brand_id=brand_b.id,
                decoded_url="https://private-org-b.example/login",
                risk_score=75,
                risk_level="high",
                indicators=[{"code": "private_fixture"}],
            )
            db.add_all([finding_b, report_b, campaign_b, qr_b])
            db.flush()
            investigation_b = Investigation(
                brand_id=brand_b.id,
                detection_id=finding_b.id,
                title="Organization B private investigation",
                summary="Organization B private investigation summary.",
            )
            db.add(investigation_b)
            db.flush()
            db.add(CampaignEvent(
                campaign_id=campaign_b.id,
                detection_id=finding_b.id,
                event_type="finding_detected",
                summary="Organization B private campaign event.",
            ))
            db.commit()
            organization_b_id = organization_b.id
            user_b_email = user_b.email
            brand_b_id = brand_b.id
            finding_b_id = finding_b.id
            report_b_id = report_b.id
            campaign_b_id = campaign_b.id
            investigation_b_id = investigation_b.id
            user_b_id = user_b.id
            qr_b_id = qr_b.id

        login_b = self.client.post(
            "/api/auth/login",
            json={"email": user_b_email, "password": "organization-b-strong-password"},
        )
        self.assertEqual(login_b.status_code, 200, login_b.text)
        headers_b = {"Authorization": f"Bearer {login_b.json()['access_token']}"}

        # Confirm both tenant fixtures exist, then prove A cannot read or mutate B IDs.
        self.assertEqual(
            self.client.get(f"/api/detections/{finding_b_id}", headers=headers_b).status_code,
            200,
        )
        self.assertEqual(
            self.client.get(f"/api/investigations/{investigation_b_id}", headers=headers_b).status_code,
            200,
        )
        self.assertIn(
            report_b_id,
            {item["id"] for item in self.client.get("/api/community/reports", headers=headers_b).json()},
        )
        self.assertIn(
            campaign_b_id,
            {item["id"] for item in self.client.get("/api/campaigns", headers=headers_b).json()},
        )

        findings_a = self.client.get("/api/detections", headers=self.headers)
        self.assertEqual(findings_a.status_code, 200, findings_a.text)
        self.assertNotIn(finding_b_id, {item["id"] for item in findings_a.json()})
        self.assertEqual(
            self.client.get(f"/api/detections/{finding_b_id}", headers=self.headers).status_code,
            404,
        )
        self.assertEqual(
            self.client.get(f"/api/brands/{brand_b_id}", headers=self.headers).status_code,
            404,
        )
        self.assertEqual(
            self.client.get(f"/api/brands/{brand_b_id}/trust", headers=self.headers).status_code,
            404,
        )
        self.assertEqual(
            self.client.put(
                f"/api/brands/{brand_b_id}",
                headers=self.headers,
                data={"name": "Unauthorized organization A brand edit"},
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.delete(f"/api/brands/{brand_b_id}", headers=self.headers).status_code,
            404,
        )
        self.assertEqual(
            self.client.put(
                f"/api/users/{user_b_id}",
                headers=self.headers,
                json={"email": "stolen-user@test.invalid"},
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.delete(f"/api/users/{user_b_id}", headers=self.headers).status_code,
            404,
        )
        self.assertEqual(
            self.client.patch(
                f"/api/detections/{finding_b_id}",
                headers=self.headers,
                json={"status": "resolved"},
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.delete(f"/api/detections/{finding_b_id}", headers=self.headers).status_code,
            404,
        )

        reports_a = self.client.get("/api/community/reports", headers=self.headers)
        self.assertEqual(reports_a.status_code, 200, reports_a.text)
        self.assertNotIn(report_b_id, {item["id"] for item in reports_a.json()})
        self.assertEqual(
            self.client.patch(
                f"/api/community/reports/{report_b_id}",
                headers=self.headers,
                json={"status": "dismissed"},
            ).status_code,
            404,
        )
        investigations_a = self.client.get("/api/investigations", headers=self.headers)
        self.assertNotIn(investigation_b_id, {item["id"] for item in investigations_a.json()})
        self.assertEqual(
            self.client.get(f"/api/investigations/{investigation_b_id}", headers=self.headers).status_code,
            404,
        )
        self.assertEqual(
            self.client.get(f"/api/investigations/{investigation_b_id}/copilot", headers=self.headers).status_code,
            404,
        )
        self.assertEqual(
            self.client.put(
                f"/api/investigations/{investigation_b_id}",
                headers=self.headers,
                json={"title": "Unauthorized A edit"},
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.patch(
                f"/api/investigations/{investigation_b_id}",
                headers=self.headers,
                data={"status": "closed"},
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.delete(f"/api/investigations/{investigation_b_id}", headers=self.headers).status_code,
            404,
        )

        campaigns_a = self.client.get("/api/campaigns", headers=self.headers)
        self.assertNotIn(campaign_b_id, {item["id"] for item in campaigns_a.json()})
        qr_history_a = self.client.get("/api/qr/history", headers=self.headers)
        self.assertEqual(qr_history_a.status_code, 200, qr_history_a.text)
        self.assertNotIn(qr_b_id, {item["id"] for item in qr_history_a.json()})
        graph_a = self.client.get("/api/scam-dna/graph", headers=self.headers)
        self.assertEqual(graph_a.status_code, 200, graph_a.text)
        graph_node_ids = {node["id"] for node in graph_a.json()["nodes"]}
        self.assertNotIn(f"brand:{brand_b_id}", graph_node_ids)
        self.assertNotIn(f"finding:{finding_b_id}", graph_node_ids)
        self.assertNotIn(f"campaign:{campaign_b_id}", graph_node_ids)
        self.assertNotIn(f"community-report:{report_b_id}", graph_node_ids)
        self.assertNotIn(f"qr-analysis:{qr_b_id}", graph_node_ids)
        self.assertNotIn("private-org-b.example", json.dumps(graph_a.json()))
        self.assertNotIn("Organization B private", json.dumps(graph_a.json()))
        self.assertEqual(
            self.client.get(
                f"/api/scam-dna/graph?brand_id={brand_b_id}",
                headers=self.headers,
            ).status_code,
            404,
        )

        dashboard_a = self.client.get("/api/dashboard", headers=self.headers)
        self.assertEqual(dashboard_a.status_code, 200, dashboard_a.text)
        self.assertEqual(dashboard_a.json()["summary"]["total_brands"], 1)
        self.assertEqual(dashboard_a.json()["summary"]["potential_impersonations"], 1)
        report_summary_a = self.client.get("/api/reports", headers=self.headers)
        self.assertEqual(report_summary_a.status_code, 200, report_summary_a.text)
        self.assertNotIn(
            "Organization B confidential finding",
            json.dumps(report_summary_a.json()),
        )
        csv_a = self.client.get("/api/reports/export.csv", headers=self.headers)
        self.assertEqual(csv_a.status_code, 200, csv_a.text)
        self.assertNotIn("Organization B confidential finding", csv_a.text)
        exported_finding_ids = {int(row[0]) for row in csv.reader(csv_a.text.splitlines()) if row and row[0].isdigit()}
        self.assertNotIn(finding_b_id, exported_finding_ids)

        self.assertEqual(
            self.client.post(
                "/api/analysis/analyze",
                headers=self.headers,
                json={"brand_id": brand_b_id, "description": "Organization A must not analyze B's brand."},
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.post(
                "/api/investigations",
                headers=self.headers,
                json={"brand_id": brand_b_id, "title": "Cross tenant create attempt"},
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.post(
                "/api/sources",
                headers=self.headers,
                json={
                    "brand_id": brand_b_id,
                    "source_type": "domain",
                    "platform": "Test",
                    "locator": "private-org-b.example",
                },
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.post(
                "/api/ingestion/csv",
                headers=self.headers,
                data={"brand_id": str(brand_b_id)},
                files={"file": ("findings.csv", b"name,url\nOther,https://other.example\n", "text/csv")},
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.post(
                "/api/ingestion/screenshot/analyze",
                headers=self.headers,
                data={"brand_id": str(brand_b_id)},
                files={"screenshot": ("image.png", b"not an image", "image/png")},
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.post(
                "/api/qr/analyze",
                headers=self.headers,
                data={"brand_id": str(brand_b_id)},
                files={"image": ("image.png", b"not an image", "image/png")},
            ).status_code,
            404,
        )

        with self.Session() as db:
            self.assertEqual(db.get(DetectionResult, finding_b_id).status, "open")
            self.assertEqual(db.get(Investigation, investigation_b_id).status, "open")
            self.assertEqual(db.get(CustomerReport, report_b_id).status, "pending")
            self.assertEqual(db.get(Campaign, campaign_b_id).title, "Organization B private campaign")
            self.assertEqual(db.get(Brand, brand_b_id).organization_id, organization_b_id)

    def test_unauthenticated_requests_cannot_access_or_mutate_company_data(self):
        protected_gets = [
            "/api/auth/me",
            "/api/ai/chat",
            "/api/organization",
            "/api/users",
            "/api/brands",
            "/api/detections",
            "/api/community/reports",
            "/api/qr/history",
            "/api/campaigns",
            "/api/scam-dna/graph",
            "/api/investigations",
            "/api/dashboard",
            "/api/reports",
            "/api/reports/export.csv",
        ]
        for path in protected_gets:
            with self.subTest(method="GET", path=path):
                self.assertEqual(self.client.get(path).status_code, 401)

        protected_mutations = [
            ("POST", "/api/analysis/analyze", {"json": {}}),
            ("POST", "/api/investigations", {"json": {}}),
            ("POST", "/api/sources", {"json": {}}),
            ("POST", "/api/ingestion/csv", {"data": {}, "files": {}}),
            ("POST", "/api/qr/analyze", {"data": {}, "files": {}}),
            ("POST", "/api/run-demo-scan", {}),
            ("PUT", "/api/investigations/1", {"json": {}}),
            ("PATCH", "/api/investigations/1", {"data": {"status": "closed"}}),
            ("PATCH", "/api/detections/1", {"json": {"status": "closed"}}),
            ("PATCH", "/api/community/reports/1", {"json": {"status": "dismissed"}}),
            ("DELETE", "/api/investigations/1", {}),
            ("DELETE", "/api/detections/1", {}),
            ("DELETE", "/api/brands/1", {}),
        ]
        for method, path, kwargs in protected_mutations:
            with self.subTest(method=method, path=path):
                response = self.client.request(method, path, **kwargs)
                self.assertEqual(response.status_code, 401, response.text)

    def test_ai_chat_uses_configured_nvidia_model_and_returns_answer(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self, _limit):
                return json.dumps({
                    "choices": [{"message": {"content": "Check the sender and do not open suspicious links."}}],
                }).encode()

        with patch.dict(os.environ, {"NVIDIA_API_KEY": "test-nvidia-key"}):
            with patch.object(main_module.urllib.request, "urlopen", return_value=FakeResponse()) as request_call:
                response = self.client.post(
                    "/api/ai/chat",
                    headers=self.headers,
                    json={"message": "  How should I check a suspicious message?  "},
                )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["answer"], "Check the sender and do not open suspicious links.")
        self.assertEqual(response.json()["model"], "meta/llama-3.2-11b-vision-instruct")
        outbound_request = request_call.call_args.args[0]
        outbound_body = json.loads(outbound_request.data)
        self.assertEqual(outbound_body["model"], "meta/llama-3.2-11b-vision-instruct")
        self.assertEqual(outbound_body["messages"][-1], {
            "role": "user",
            "content": "How should I check a suspicious message?",
        })
        self.assertTrue(outbound_request.get_header("Authorization").startswith("Bearer "))

    def test_ai_chat_reports_missing_key_blank_input_and_provider_rate_limit(self):
        with patch.dict(os.environ, {"NVIDIA_API_KEY": ""}):
            missing_key = self.client.post(
                "/api/ai/chat",
                headers=self.headers,
                json={"message": "Hello"},
            )
        self.assertEqual(missing_key.status_code, 503)
        self.assertIn("NVIDIA_API_KEY", missing_key.json()["detail"])

        blank = self.client.post(
            "/api/ai/chat",
            headers=self.headers,
            json={"message": "    "},
        )
        self.assertEqual(blank.status_code, 422)

        rate_limit = urllib.error.HTTPError(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            429,
            "limited",
            {},
            None,
        )
        with patch.dict(os.environ, {"NVIDIA_API_KEY": "test-nvidia-key"}):
            with patch.object(main_module.urllib.request, "urlopen", side_effect=rate_limit):
                limited = self.client.post(
                    "/api/ai/chat",
                    headers=self.headers,
                    json={"message": "Hello"},
                )
        self.assertEqual(limited.status_code, 503)
        self.assertIn("rate limit", limited.json()["detail"])

        rejected = urllib.error.HTTPError(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            401,
            "unauthorized",
            {},
            None,
        )
        with patch.dict(os.environ, {"NVIDIA_API_KEY": "test-nvidia-key"}):
            with patch.object(main_module.urllib.request, "urlopen", side_effect=rejected):
                denied = self.client.post(
                    "/api/ai/chat",
                    headers=self.headers,
                    json={"message": "Hello"},
                )
        self.assertEqual(denied.status_code, 502)
        self.assertIn("authentication", denied.json()["detail"])

        with patch.dict(os.environ, {"NVIDIA_API_KEY": "test-nvidia-key"}):
            with patch.object(
                main_module.urllib.request,
                "urlopen",
                side_effect=urllib.error.URLError("offline"),
            ):
                unavailable = self.client.post(
                    "/api/ai/chat",
                    headers=self.headers,
                    json={"message": "Hello"},
                )
        self.assertEqual(unavailable.status_code, 504)
        self.assertIn("connect", unavailable.json()["detail"])

    def test_forged_token_signed_with_public_demo_secret_is_rejected(self):
        payload = {
            "sub": self.user_id,
            "organization_id": self.organization_id,
            "role": "admin",
            "exp": int(time.time()) + 3600,
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        ).decode().rstrip("=")
        signature = hmac.new(
            b"local-demo-secret-change-me",
            encoded.encode(),
            "sha256",
        ).hexdigest()
        forged_headers = {"Authorization": f"Bearer {encoded}.{signature}"}

        response = self.client.get("/api/brands", headers=forged_headers)

        self.assertEqual(response.status_code, 401, response.text)
        self.assertEqual(self.client.get("/api/brands").status_code, 401)

    def test_authentication_requires_configured_secret_outside_local_development(self):
        import os
        import subprocess

        environment = os.environ.copy()
        environment["BRANDSHIELD_TOKEN_SECRET"] = ""
        environment["APP_ENV"] = "production"
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.path.insert(0, 'backend'); import app.services.auth",
            ],
            cwd=Path(__file__).resolve().parents[2],
            env=environment,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("BRANDSHIELD_TOKEN_SECRET must be configured", result.stderr)

    def test_authentication_rejects_weak_or_default_configured_secrets(self):
        import os
        import subprocess

        for secret in ("local-demo-secret-change-me", "too-short"):
            with self.subTest(secret_kind="default" if secret.startswith("local-demo") else "short"):
                environment = os.environ.copy()
                environment["BRANDSHIELD_TOKEN_SECRET"] = secret
                environment["APP_ENV"] = "production"
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        "import sys; sys.path.insert(0, 'backend'); import app.services.auth",
                    ],
                    cwd=Path(__file__).resolve().parents[2],
                    env=environment,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("non-default secret of at least 32 characters", result.stderr)


    def test_scam_dna_graph_uses_persisted_findings_evidence_and_relationships(self):
        finding = self.create_finding()
        finding_id = finding["id"]
        response = self.client.get("/api/scam-dna/graph", headers=self.headers)

        self.assertEqual(response.status_code, 200, response.text)
        graph = response.json()
        nodes = {node["id"]: node for node in graph["nodes"]}
        edges = graph["edges"]
        self.assertIn(f"brand:{self.brand_id}", nodes)
        self.assertIn(f"finding:{finding_id}", nodes)
        self.assertEqual(nodes[f"finding:{finding_id}"]["label"], finding["entity_name"])
        self.assertTrue(any(node_id.startswith("evidence:") for node_id in nodes))
        self.assertTrue(any(node_id.startswith("entity:") for node_id in nodes))
        self.assertTrue({"candidate_for", "identifies", "supported_by", "suspected_impersonation"} <= {
            edge["relation"] for edge in edges
        })
        self.assertTrue(all(edge["source"] in nodes and edge["target"] in nodes for edge in edges))
        entity_relationship = next(edge for edge in edges if edge["relation"] == "suspected_impersonation")
        self.assertIsNotNone(entity_relationship["evidence_id"])

        changed = self.client.patch(
            f"/api/detections/{finding_id}",
            headers=self.headers,
            json={"status": "resolved"},
        )
        self.assertEqual(changed.status_code, 200, changed.text)
        updated_graph = self.client.get("/api/scam-dna/graph", headers=self.headers).json()
        updated_node = next(node for node in updated_graph["nodes"] if node["id"] == f"finding:{finding_id}")
        self.assertEqual(updated_node["status"], "resolved")

        deleted = self.client.delete(f"/api/detections/{finding_id}", headers=self.headers)
        self.assertEqual(deleted.status_code, 200, deleted.text)
        deleted_graph = self.client.get("/api/scam-dna/graph", headers=self.headers).json()
        remaining_nodes = {node["id"] for node in deleted_graph["nodes"]}
        self.assertNotIn(f"finding:{finding_id}", remaining_nodes)
        self.assertTrue(all(edge["source"] in remaining_nodes and edge["target"] in remaining_nodes for edge in deleted_graph["edges"]))

    def test_scam_dna_graph_excludes_cross_brand_and_unmatched_report_links(self):
        self.create_finding()
        with self.Session() as db:
            brand_b = Brand(
                organization_id=self.organization_id,
                name="Other Test Brand",
                official_website="https://otherbrand.invalid",
            )
            db.add(brand_b)
            db.commit()
            brand_b_id = brand_b.id
        finding_b_response = self.client.post(
            "/api/analysis/analyze",
            headers=self.headers,
            json={
                "brand_id": brand_b_id,
                "name": "Other Test Brand Help",
                "url": "https://otherbrand-login.invalid/verify",
                "description": "verify account and claim reward",
                "entity_type": "social_profile",
                "platform": "Test",
            },
        )
        self.assertEqual(finding_b_response.status_code, 200, finding_b_response.text)
        finding_b = finding_b_response.json()

        with self.Session() as db:
            brand_entity_a = db.query(Entity).filter(
                Entity.brand_id == self.brand_id,
                Entity.canonical_key == f"brand:{self.brand_id}",
            ).one()
            candidate_entity_b = db.query(Entity).filter(
                Entity.brand_id == brand_b_id,
                Entity.canonical_key == finding_b["entity_name"].strip().lower(),
                Entity.entity_type == finding_b["entity_type"],
            ).one()
            report_a = CustomerReport(
                brand_id=self.brand_id,
                organization_id=self.organization_id,
                report_text="Report belonging to the first brand.",
            )
            report_b = CustomerReport(
                brand_id=brand_b_id,
                organization_id=self.organization_id,
                report_text="Report belonging to the second brand.",
            )
            campaign_a = Campaign(
                brand_id=self.brand_id,
                campaign_key="test:brand-a",
                title="First brand campaign",
            )
            db.add_all([report_a, report_b, campaign_a])
            db.flush()
            db.add_all([
                Relationship(
                    source_entity_id=brand_entity_a.id,
                    target_entity_id=candidate_entity_b.id,
                    relation_type="invalid_cross_brand",
                ),
                ReportMatch(
                    customer_report_id=report_a.id,
                    detection_id=finding_b["id"],
                    match_score=100,
                    match_reason="Invalid cross-brand test reference",
                ),
                CampaignEvent(
                    campaign_id=campaign_a.id,
                    detection_id=finding_b["id"],
                    event_type="invalid_cross_brand",
                    summary="Invalid cross-brand test reference",
                    indicators={"report_id": report_b.id},
                ),
            ])
            db.commit()
            campaign_a_id = campaign_a.id
            report_a_id = report_a.id
            report_b_id = report_b.id

        response = self.client.get("/api/scam-dna/graph", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        edges = response.json()["edges"]
        self.assertFalse(any(edge["relation"] == "invalid_cross_brand" for edge in edges))
        self.assertFalse(any(
            {edge["source"], edge["target"]} == {f"community-report:{report_a_id}", f"finding:{finding_b['id']}"}
            for edge in edges
        ))
        self.assertFalse(any(
            {edge["source"], edge["target"]} == {f"campaign:{campaign_a_id}", f"finding:{finding_b['id']}"}
            for edge in edges
        ))
        self.assertFalse(any(
            {edge["source"], edge["target"]} == {f"campaign:{campaign_a_id}", f"community-report:{report_b_id}"}
            for edge in edges
        ))
        scoped_response = self.client.get(
            f"/api/scam-dna/graph?brand_id={self.brand_id}",
            headers=self.headers,
        )
        self.assertEqual(scoped_response.status_code, 200, scoped_response.text)
        scoped_node_ids = {node["id"] for node in scoped_response.json()["nodes"]}
        self.assertNotIn(f"finding:{finding_b['id']}", scoped_node_ids)
        self.assertNotIn(f"community-report:{report_b_id}", scoped_node_ids)

    def test_scam_dna_graph_handles_empty_data_invalid_scope_and_api_errors(self):
        self.assertEqual(self.client.get("/api/scam-dna/graph").status_code, 401)
        self.assertEqual(
            self.client.get("/api/scam-dna/graph?brand_id=99999", headers=self.headers).status_code,
            404,
        )
        with patch.object(main_module, "accessible_brand_ids", side_effect=SQLAlchemyError("database unavailable")):
            failed = self.client.get("/api/scam-dna/graph", headers=self.headers)
        self.assertEqual(failed.status_code, 500, failed.text)
        self.assertIn("Database operation failed", failed.json()["detail"])

        deleted = self.client.delete(f"/api/brands/{self.brand_id}", headers=self.headers)
        self.assertEqual(deleted.status_code, 200, deleted.text)
        empty = self.client.get("/api/scam-dna/graph", headers=self.headers)
        self.assertEqual(empty.status_code, 200, empty.text)
        self.assertEqual(empty.json(), {"nodes": [], "edges": []})

    def test_scam_dna_graph_returns_all_nodes_for_larger_graphs(self):
        for index in range(6):
            response = self.client.post(
                "/api/analysis/analyze",
                headers=self.headers,
                json={
                    "brand_id": self.brand_id,
                    "name": f"Test Brand Support {index}",
                    "url": f"https://testbrand-login-{index}.invalid/verify",
                    "description": "verify account and claim reward",
                    "entity_type": "social_profile",
                    "platform": "Test",
                },
            )
            self.assertEqual(response.status_code, 200, response.text)
        graph_response = self.client.get("/api/scam-dna/graph", headers=self.headers)
        self.assertEqual(graph_response.status_code, 200, graph_response.text)
        graph = graph_response.json()
        self.assertGreater(len(graph["nodes"]), 16)
        node_ids = {node["id"] for node in graph["nodes"]}
        self.assertTrue(all(edge["source"] in node_ids and edge["target"] in node_ids for edge in graph["edges"]))


class MigrationTests(unittest.TestCase):
    def test_application_startup_seeds_once_and_keeps_hashed_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = create_database_engine("sqlite:///" + (Path(folder) / "startup.db").as_posix())
            TestSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            try:
                with patch.object(main_module, "engine", engine), patch.object(main_module, "SessionLocal", TestSession):
                    main_module.startup_event()
                    main_module.startup_event()
                with TestSession() as db:
                    self.assertEqual(db.query(Organization).count(), 1)
                    self.assertEqual(db.query(Brand).count(), 1)
                    self.assertEqual(db.query(DetectionResult).count(), 6)
                    self.assertEqual(db.query(Investigation).count(), 2)
                    self.assertEqual(db.query(AuditLog).count(), 1)
                    demo_user = db.query(User).filter(User.email == "analyst@brandshield.local").one()
                    self.assertNotEqual(demo_user.password_hash, "brandshield-demo")
                    self.assertTrue(verify_password("brandshield-demo", demo_user.password_hash))
            finally:
                engine.dispose()

    def test_additive_migration_preserves_legacy_brand_and_report_rows(self):
        temporary_directory = tempfile.TemporaryDirectory()
        database_path = Path(temporary_directory.name) / "legacy.db"
        connection = sqlite3.connect(database_path)
        connection.executescript("""
            CREATE TABLE organizations (id INTEGER PRIMARY KEY, name VARCHAR(255), created_at DATETIME);
            CREATE TABLE brands (
                id INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL,
                company_description TEXT, industry VARCHAR(255), official_website VARCHAR(500),
                official_social_accounts JSON, official_mobile_apps JSON, official_package_ids JSON,
                official_developer_names JSON, brand_keywords JSON, known_domains JSON,
                logo_path VARCHAR(500), additional_identifiers JSON, is_sample INTEGER,
                created_at DATETIME, updated_at DATETIME
            );
            CREATE TABLE customer_reports (
                id INTEGER PRIMARY KEY, brand_id INTEGER, reporter_contact VARCHAR(255),
                report_text TEXT NOT NULL, reported_url VARCHAR(2048), status VARCHAR(30),
                created_at DATETIME
            );
            CREATE TABLE investigations (
                id INTEGER PRIMARY KEY, brand_id INTEGER NOT NULL, title VARCHAR(255) NOT NULL,
                summary TEXT, status VARCHAR(20), risk_level VARCHAR(20), created_at DATETIME
            );
            INSERT INTO organizations VALUES (1, 'Legacy Organization', CURRENT_TIMESTAMP);
            INSERT INTO brands (id, name) VALUES (7, 'Legacy Brand');
            INSERT INTO customer_reports (id, brand_id, report_text, status)
                VALUES (12, 7, 'Legacy report content', 'pending');
            INSERT INTO investigations (id, brand_id, title, summary, status, risk_level)
                VALUES (15, 7, 'Legacy investigation', 'Preserve this record', 'open', 'high');
        """)
        connection.commit()
        connection.close()

        engine = create_database_engine("sqlite:///" + database_path.as_posix())
        try:
            initialize_database(engine, Base.metadata)
            initialize_database(engine, Base.metadata)
            with engine.connect() as db:
                brand = db.exec_driver_sql("SELECT id, name, logo_perceptual_hash, organization_id FROM brands WHERE id=7").one()
                report = db.exec_driver_sql("SELECT id, brand_id, report_text, organization_id FROM customer_reports WHERE id=12").one()
                investigation = db.exec_driver_sql("SELECT id, brand_id, title, detection_id FROM investigations WHERE id=15").one()
                versions = db.exec_driver_sql("SELECT version FROM schema_migrations ORDER BY version").scalars().all()
            self.assertEqual(brand[:2], (7, "Legacy Brand"))
            self.assertEqual(report[:3], (12, 7, "Legacy report content"))
            self.assertEqual(investigation, (15, 7, "Legacy investigation", None))
            self.assertEqual(len(versions), 5)
            self.assertEqual(
                set(versions),
                {
                    "0001_brand_metadata",
                    "0002_customer_report_organization",
                    "0003_legacy_relationship_guards",
                    "0004_investigation_finding_link",
                    "0005_threat_monitoring_schedule",
                },
            )
            with self.assertRaises(SQLAlchemyIntegrityError):
                with engine.begin() as db:
                    db.execute(
                        text(
                            "INSERT INTO detection_results "
                            "(brand_id, entity_name, entity_type, platform) "
                            "VALUES (999, 'orphan', 'social_profile', 'test')"
                        )
                    )
            with engine.begin() as db:
                db.execute(text("INSERT INTO brands (id, name) VALUES (8, 'Second Legacy Brand')"))
                finding_id = db.execute(text(
                    "INSERT INTO detection_results (brand_id, entity_name, entity_type, platform) "
                    "VALUES (8, 'Second brand finding', 'social_profile', 'test')"
                )).lastrowid
            with self.assertRaises(SQLAlchemyIntegrityError):
                with engine.begin() as db:
                    db.execute(text(
                        "INSERT INTO investigations (brand_id, detection_id, title) "
                        "VALUES (7, :detection_id, 'Cross-brand link')"
                    ), {"detection_id": finding_id})
        finally:
            engine.dispose()
            temporary_directory.cleanup()


if __name__ == "__main__":
    unittest.main()
