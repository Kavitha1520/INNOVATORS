import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from fastapi.testclient import TestClient
from sqlalchemy import inspect, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import main as main_module
from app.database import Base, create_database_engine
from app.main import app, get_db
from app.models import Brand, DetectionResult, MonitoringSource, Organization, User
from app.schema import initialize_database
from app.services import monitoring
from app.services.auth import hash_password


class MonitoringServiceTests(unittest.TestCase):
    def test_feed_adapter_requests_only_phishtank_and_bounds_response(self):
        response_payload = [{"url": "https://example.invalid", "verified": "yes", "online": "yes"}]

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self, limit):
                self.limit = limit
                return json.dumps(response_payload).encode("utf-8")

        class FakeOpener:
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return FakeResponse()

        fake_opener = FakeOpener()
        with patch.object(monitoring.urllib.request, "build_opener", return_value=fake_opener):
            records = monitoring.fetch_phishtank_feed("test-key")

        self.assertEqual(records, response_payload)
        request = fake_opener.request
        timeout = fake_opener.timeout
        self.assertEqual(request.full_url, "https://data.phishtank.com/data/test-key/online-valid.json")
        self.assertEqual(request.get_header("User-agent"), monitoring.PHISHTANK_USER_AGENT)
        self.assertEqual(timeout, monitoring.FEED_TIMEOUT_SECONDS)
        self.assertNotIn("example.invalid", request.full_url)

    def test_feed_adapter_surfaces_rate_limits_and_rejects_bad_json(self):
        rate_limit = HTTPError("https://data.phishtank.com/feed", 429, "limited", {}, None)
        with patch.object(monitoring, "_open_feed_request", side_effect=rate_limit):
            with self.assertRaises(monitoring.ThreatFeedError) as caught:
                monitoring.fetch_phishtank_feed("test-key")
        self.assertEqual(caught.exception.status, "ERROR")
        self.assertIn("rate-limited", str(caught.exception))
        self.assertNotIn("test-key", str(caught.exception))

        class InvalidResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self, _limit):
                return b"<html>not json</html>"

        with patch.object(monitoring, "_open_feed_request", return_value=InvalidResponse()):
            with self.assertRaises(monitoring.ThreatFeedError) as caught:
                monitoring.fetch_phishtank_feed("test-key")
        self.assertIn("invalid JSON", str(caught.exception))

    def test_feed_adapter_handles_timeouts_and_rejects_unsafe_keys(self):
        with patch.object(monitoring, "_open_feed_request", side_effect=URLError("timeout")):
            with self.assertRaises(monitoring.ThreatFeedError) as caught:
                monitoring.fetch_phishtank_feed("test-key")
        self.assertEqual(caught.exception.status, "ERROR")
        self.assertIn("temporarily unavailable", str(caught.exception))

        with patch.object(monitoring, "_open_feed_request") as open_feed:
            with self.assertRaises(monitoring.ThreatFeedError) as caught:
                monitoring.fetch_phishtank_feed("key/with/path")
        self.assertEqual(caught.exception.status, "CONFIGURATION REQUIRED")
        open_feed.assert_not_called()


class MonitoringApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.engine = create_database_engine(
            "sqlite:///" + (Path(self.temp_dir.name) / "monitoring-test.db").as_posix()
        )
        initialize_database(self.engine, Base.metadata)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        with self.Session() as db:
            org_a = Organization(name="Organization A")
            org_b = Organization(name="Organization B")
            db.add_all([org_a, org_b])
            db.flush()
            user_a = User(
                organization_id=org_a.id,
                email="monitor-a@test.invalid",
                password_hash=hash_password("organization-a-password"),
                role="admin",
            )
            user_b = User(
                organization_id=org_b.id,
                email="monitor-b@test.invalid",
                password_hash=hash_password("organization-b-password"),
                role="admin",
            )
            brand_a = Brand(
                organization_id=org_a.id,
                name="Test Brand",
                official_website="https://testbrand.invalid",
                known_domains=["testbrand.invalid"],
            )
            brand_b = Brand(organization_id=org_b.id, name="Other Brand")
            db.add_all([user_a, user_b, brand_a, brand_b])
            db.commit()
            self.brand_a_id = brand_a.id
            self.brand_b_id = brand_b.id

        app.dependency_overrides[get_db] = self.override_get_db
        self.client = TestClient(app)
        login = self.client.post(
            "/api/auth/login",
            json={"email": "monitor-a@test.invalid", "password": "organization-a-password"},
        )
        self.assertEqual(login.status_code, 200, login.text)
        self.headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    def tearDown(self):
        app.dependency_overrides.pop(get_db, None)
        self.client.close()
        self.engine.dispose()
        self.temp_dir.cleanup()

    def override_get_db(self):
        db = self.Session()
        try:
            yield db
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def create_feed_source(self):
        response = self.client.post(
            "/api/sources",
            headers=self.headers,
            json={
                "brand_id": self.brand_a_id,
                "source_type": "threat_feed",
                "platform": "PhishTank",
                "locator": "online-valid",
                "interval_minutes": 60,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["id"]

    def test_source_setup_run_persistence_deduplication_and_tenant_isolation(self):
        source_id = self.create_feed_source()
        source_status = self.client.get("/api/monitoring/status", headers=self.headers).json()
        self.assertEqual(source_status["status"], "CONFIGURATION REQUIRED")
        self.assertEqual(source_status["sources"][0]["status"], "CONFIGURATION REQUIRED")

        not_configured = self.client.post(
            f"/api/monitoring/sources/{source_id}/run",
            headers=self.headers,
        )
        self.assertEqual(not_configured.status_code, 503)
        self.assertIn("PHISHTANK_API_KEY", not_configured.json()["detail"])

        feed = [
            {
                "url": "https://testbrand-security-login.evil.invalid/verify",
                "verified": "yes",
                "online": "yes",
                "target": "Test Brand",
                "submission_time": "2025-01-01 12:00:00",
                "verification_time": "2025-01-01 13:00:00",
                "phish_detail_url": "https://www.phishtank.com/phish_detail.php?phish_id=1",
            },
            {
                "url": "https://unrelated.evil.invalid",
                "verified": "yes",
                "online": "yes",
                "target": "Unrelated Brand",
            },
            {
                "url": "https://unverified.evil.invalid",
                "verified": "no",
                "online": "yes",
                "target": "Test Brand",
            },
            {
                "url": "invalid URL",
                "verified": "yes",
                "online": "yes",
                "target": "Test Brand",
            },
            {
                "url": "https://testbrand.invalid/login",
                "verified": "yes",
                "online": "yes",
                "target": "Test Brand",
            },
        ]
        with patch.dict(os.environ, {"PHISHTANK_API_KEY": "test-key"}):
            with patch.object(monitoring, "fetch_phishtank_feed", return_value=feed) as fetch_feed:
                first_run = self.client.post(
                    f"/api/monitoring/sources/{source_id}/run",
                    headers=self.headers,
                )
                self.assertEqual(first_run.status_code, 200, first_run.text)
                self.assertEqual(fetch_feed.call_count, 1)
                self.assertEqual(first_run.json()["status"], "LIVE")
                self.assertEqual(first_run.json()["findings_created"], 1)
                self.assertEqual(first_run.json()["records_ignored"], 4)

                with self.Session() as db:
                    findings = db.query(DetectionResult).filter(
                        DetectionResult.brand_id == self.brand_a_id,
                        DetectionResult.platform == "PhishTank",
                    ).all()
                    self.assertEqual(len(findings), 1)
                    finding = findings[0]
                    self.assertEqual(finding.entity_name, "testbrand-security-login.evil.invalid")
                    self.assertEqual(finding.entity_type, "domain")
                    self.assertEqual(finding.risk_level, "high")
                    evidence = finding.evidence["signals"]
                    feed_evidence = next(item for item in evidence if item["type"] == "verified_threat_feed")
                    self.assertEqual(feed_evidence["details"]["discovered_at"], "2025-01-01 12:00:00")
                    self.assertEqual(feed_evidence["details"]["source"], "PhishTank")
                    saved_source = db.query(MonitoringSource).filter(MonitoringSource.id == source_id).one()
                    self.assertEqual(saved_source.last_status, "LIVE")
                    self.assertEqual(saved_source.interval_minutes, 60)
                    self.assertIsNotNone(saved_source.next_run_at)

                second_run = self.client.post(
                    f"/api/monitoring/sources/{source_id}/run",
                    headers=self.headers,
                )
                self.assertEqual(second_run.status_code, 200, second_run.text)
                self.assertEqual(second_run.json()["findings_created"], 0)
                self.assertEqual(second_run.json()["duplicates_skipped"], 1)

        self.assertEqual(
            self.client.post(
                "/api/sources",
                headers=self.headers,
                json={
                    "brand_id": self.brand_a_id,
                    "source_type": "threat_feed",
                    "platform": "PhishTank",
                    "locator": "online-valid",
                },
            ).status_code,
            409,
        )

        with self.Session() as db:
            org_b = db.query(Organization).filter(Organization.name == "Organization B").one()
            db.add(MonitoringSource(
                brand_id=self.brand_b_id,
                source_type="threat_feed",
                platform="PhishTank",
                locator="online-valid",
                interval_minutes=360,
            ))
            db.commit()
            source_b = db.query(MonitoringSource).filter(
                MonitoringSource.brand_id == self.brand_b_id
            ).one()
            source_b_id = source_b.id
            self.assertNotEqual(org_b.id, 0)

        cross_tenant = self.client.post(
            f"/api/monitoring/sources/{source_b_id}/run",
            headers=self.headers,
        )
        self.assertEqual(cross_tenant.status_code, 404)
        self.assertEqual(self.client.get("/api/monitoring/status").status_code, 401)

    def test_feed_error_is_recorded_and_returned(self):
        source_id = self.create_feed_source()
        failure = monitoring.ThreatFeedError("ERROR", "PhishTank feed is temporarily unavailable.")
        with patch.dict(os.environ, {"PHISHTANK_API_KEY": "test-key"}):
            with patch.object(monitoring, "fetch_phishtank_feed", side_effect=failure):
                response = self.client.post(
                    f"/api/monitoring/sources/{source_id}/run",
                    headers=self.headers,
                )
        self.assertEqual(response.status_code, 502)
        self.assertIn("temporarily unavailable", response.json()["detail"])
        with self.Session() as db:
            source = db.query(MonitoringSource).filter(MonitoringSource.id == source_id).one()
            self.assertEqual(source.last_status, "ERROR")
            self.assertIn("temporarily unavailable", source.last_error)
            self.assertIsNotNone(source.next_run_at)

    def test_configured_scheduler_processes_due_sources_only(self):
        source_id = self.create_feed_source()
        with self.Session() as db:
            source = db.query(MonitoringSource).filter(MonitoringSource.id == source_id).one()
            source.next_run_at = main_module.datetime.utcnow()
            db.commit()

        with patch.dict(os.environ, {"PHISHTANK_API_KEY": "test-key"}):
            with patch.object(main_module, "SessionLocal", self.Session):
                with patch.object(monitoring, "fetch_phishtank_feed", return_value=[]) as fetch_feed:
                    main_module._run_due_monitoring_sources()

        self.assertEqual(fetch_feed.call_count, 1)
        with self.Session() as db:
            source = db.query(MonitoringSource).filter(MonitoringSource.id == source_id).one()
            self.assertEqual(source.last_status, "LIVE")
            self.assertGreater(source.next_run_at, main_module.datetime.utcnow())


class MonitoringMigrationTests(unittest.TestCase):
    def test_additive_monitoring_migration_keeps_legacy_table_data(self):
        temp_dir = tempfile.TemporaryDirectory()
        try:
            engine = create_database_engine(
                "sqlite:///" + (Path(temp_dir.name) / "legacy.db").as_posix()
            )
            with engine.begin() as connection:
                connection.execute(text(
                    "CREATE TABLE brands (id INTEGER PRIMARY KEY, organization_id INTEGER, "
                    "name VARCHAR(255), logo_perceptual_hash VARCHAR(64))"
                ))
                connection.execute(text(
                    "INSERT INTO brands (id, organization_id, name) VALUES (1, NULL, 'Legacy Brand')"
                ))
                connection.execute(text(
                    "CREATE TABLE monitoring_sources ("
                    "id INTEGER PRIMARY KEY, brand_id INTEGER NOT NULL, "
                    "source_type VARCHAR(50) NOT NULL, platform VARCHAR(80) NOT NULL, "
                    "locator VARCHAR(1000) NOT NULL, enabled BOOLEAN, created_at DATETIME)"
                ))
                connection.execute(text(
                    "INSERT INTO monitoring_sources "
                    "(id, brand_id, source_type, platform, locator, enabled) "
                    "VALUES (1, 1, 'domain', 'Website', 'https://existing.invalid', 1)"
                ))

            initialize_database(engine, Base.metadata)

            with engine.connect() as connection:
                names = {column["name"] for column in inspect(connection).get_columns("monitoring_sources")}
                row = connection.execute(text(
                    "SELECT locator, interval_minutes, last_status FROM monitoring_sources WHERE id=1"
                )).one()
                brand_name = connection.execute(text(
                    "SELECT name FROM brands WHERE id=1"
                )).scalar_one()
            self.assertTrue({
                "interval_minutes", "last_status", "last_checked_at", "next_run_at", "last_error"
            } <= names)
            self.assertEqual(row.locator, "https://existing.invalid")
            self.assertEqual(row.interval_minutes, 360)
            self.assertEqual(row.last_status, "DISCONNECTED")
            self.assertEqual(brand_name, "Legacy Brand")
            engine.dispose()
        finally:
            temp_dir.cleanup()
