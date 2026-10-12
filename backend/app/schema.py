from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import SQLAlchemyError


logger = logging.getLogger(__name__)


class DatabaseIntegrityError(RuntimeError):
    pass


def initialize_database(engine: Engine, metadata: Any) -> None:
    """Create missing tables and apply tracked, additive SQLite migrations."""
    try:
        metadata.create_all(bind=engine)
        with engine.begin() as connection:
            connection.execute(text(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "version VARCHAR(100) PRIMARY KEY, applied_at DATETIME NOT NULL)"
            ))
            applied = {
                row[0]
                for row in connection.execute(text("SELECT version FROM schema_migrations"))
            }

            if "0001_brand_metadata" not in applied:
                columns = {
                    column["name"]
                    for column in inspect(connection).get_columns("brands")
                }
                if "logo_perceptual_hash" not in columns:
                    connection.execute(text(
                        "ALTER TABLE brands ADD COLUMN logo_perceptual_hash VARCHAR(64) DEFAULT ''"
                    ))
                if "organization_id" not in columns:
                    connection.execute(text(
                        "ALTER TABLE brands ADD COLUMN organization_id INTEGER REFERENCES organizations(id)"
                    ))
                connection.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_brands_organization_id "
                    "ON brands (organization_id)"
                ))
                connection.execute(
                    text("INSERT INTO schema_migrations (version, applied_at) VALUES (:version, CURRENT_TIMESTAMP)"),
                    {"version": "0001_brand_metadata"},
                )

            applied.add("0001_brand_metadata")
            if "0002_customer_report_organization" not in applied:
                columns = {
                    column["name"]
                    for column in inspect(connection).get_columns("customer_reports")
                }
                if "organization_id" not in columns:
                    connection.execute(text(
                        "ALTER TABLE customer_reports ADD COLUMN organization_id "
                        "INTEGER REFERENCES organizations(id)"
                    ))
                connection.execute(text(
                    "UPDATE customer_reports SET organization_id = ("
                    "SELECT brands.organization_id FROM brands "
                    "WHERE brands.id = customer_reports.brand_id"
                    ") WHERE organization_id IS NULL AND brand_id IS NOT NULL"
                ))
                connection.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_customer_reports_organization_id "
                    "ON customer_reports (organization_id)"
                ))
                connection.execute(
                    text("INSERT INTO schema_migrations (version, applied_at) VALUES (:version, CURRENT_TIMESTAMP)"),
                    {"version": "0002_customer_report_organization"},
                )

            connection.execute(text("""
                CREATE TRIGGER IF NOT EXISTS trg_detection_brand_insert
                BEFORE INSERT ON detection_results
                WHEN NOT EXISTS (SELECT 1 FROM brands WHERE id = NEW.brand_id)
                BEGIN
                    SELECT RAISE(ABORT, 'detection_results.brand_id must reference a brand');
                END
            """))
            connection.execute(text("""
                CREATE TRIGGER IF NOT EXISTS trg_detection_brand_update
                BEFORE UPDATE OF brand_id ON detection_results
                WHEN NOT EXISTS (SELECT 1 FROM brands WHERE id = NEW.brand_id)
                BEGIN
                    SELECT RAISE(ABORT, 'detection_results.brand_id must reference a brand');
                END
            """))
            connection.execute(text("""
                CREATE TRIGGER IF NOT EXISTS trg_investigation_brand_insert
                BEFORE INSERT ON investigations
                WHEN NOT EXISTS (SELECT 1 FROM brands WHERE id = NEW.brand_id)
                BEGIN
                    SELECT RAISE(ABORT, 'investigations.brand_id must reference a brand');
                END
            """))
            connection.execute(text("""
                CREATE TRIGGER IF NOT EXISTS trg_investigation_brand_update
                BEFORE UPDATE OF brand_id ON investigations
                WHEN NOT EXISTS (SELECT 1 FROM brands WHERE id = NEW.brand_id)
                BEGIN
                    SELECT RAISE(ABORT, 'investigations.brand_id must reference a brand');
                END
            """))
            connection.execute(text("""
                CREATE TRIGGER IF NOT EXISTS trg_audit_brand_insert
                BEFORE INSERT ON audit_logs
                WHEN NOT EXISTS (SELECT 1 FROM brands WHERE id = NEW.brand_id)
                BEGIN
                    SELECT RAISE(ABORT, 'audit_logs.brand_id must reference a brand at insert time');
                END
            """))
            connection.execute(text("""
                CREATE TRIGGER IF NOT EXISTS trg_brand_delete_requires_cleanup
                BEFORE DELETE ON brands
                WHEN EXISTS (SELECT 1 FROM detection_results WHERE brand_id = OLD.id)
                  OR EXISTS (SELECT 1 FROM investigations WHERE brand_id = OLD.id)
                BEGIN
                    SELECT RAISE(ABORT, 'brand findings and investigations must be removed before deleting a brand');
                END
            """))
            if "0003_legacy_relationship_guards" not in applied:
                connection.execute(
                    text("INSERT INTO schema_migrations (version, applied_at) VALUES (:version, CURRENT_TIMESTAMP)"),
                    {"version": "0003_legacy_relationship_guards"},
                )

            if "0004_investigation_finding_link" not in applied:
                columns = {
                    column["name"]
                    for column in inspect(connection).get_columns("investigations")
                }
                if "detection_id" not in columns:
                    connection.execute(text(
                        "ALTER TABLE investigations ADD COLUMN detection_id "
                        "INTEGER REFERENCES detection_results(id)"
                    ))
                connection.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_investigations_detection_id "
                    "ON investigations (detection_id)"
                ))
                connection.execute(text("""
                    CREATE TRIGGER IF NOT EXISTS trg_investigation_detection_brand_insert
                    BEFORE INSERT ON investigations
                    WHEN NEW.detection_id IS NOT NULL AND NOT EXISTS (
                        SELECT 1 FROM detection_results
                        WHERE id = NEW.detection_id AND brand_id = NEW.brand_id
                    )
                    BEGIN
                        SELECT RAISE(ABORT, 'investigations.detection_id must reference a finding for the same brand');
                    END
                """))
                connection.execute(text("""
                    CREATE TRIGGER IF NOT EXISTS trg_investigation_detection_brand_update
                    BEFORE UPDATE OF detection_id, brand_id ON investigations
                    WHEN NEW.detection_id IS NOT NULL AND NOT EXISTS (
                        SELECT 1 FROM detection_results
                        WHERE id = NEW.detection_id AND brand_id = NEW.brand_id
                    )
                    BEGIN
                        SELECT RAISE(ABORT, 'investigations.detection_id must reference a finding for the same brand');
                    END
                """))
                connection.execute(
                    text("INSERT INTO schema_migrations (version, applied_at) VALUES (:version, CURRENT_TIMESTAMP)"),
                    {"version": "0004_investigation_finding_link"},
                )

            if "0005_threat_monitoring_schedule" not in applied:
                columns = {
                    column["name"]
                    for column in inspect(connection).get_columns("monitoring_sources")
                }
                additions = {
                    "interval_minutes": "INTEGER NOT NULL DEFAULT 360",
                    "last_status": "VARCHAR(30) NOT NULL DEFAULT 'DISCONNECTED'",
                    "last_checked_at": "DATETIME",
                    "next_run_at": "DATETIME",
                    "last_error": "TEXT NOT NULL DEFAULT ''",
                }
                for column_name, column_definition in additions.items():
                    if column_name not in columns:
                        connection.execute(text(
                            f"ALTER TABLE monitoring_sources ADD COLUMN {column_name} {column_definition}"
                        ))
                connection.execute(text(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (:version, CURRENT_TIMESTAMP)"
                ), {"version": "0005_threat_monitoring_schedule"})

        validate_database_integrity(engine)
    except SQLAlchemyError:
        logger.exception("Database schema initialization failed.")
        raise


def validate_database_integrity(engine: Engine) -> None:
    """Reject broken active-data links without rewriting historical audit rows."""
    references = [
        ("brands.organization_id", "SELECT COUNT(*) FROM brands c LEFT JOIN organizations p ON c.organization_id=p.id WHERE c.organization_id IS NOT NULL AND p.id IS NULL"),
        ("detection_results.brand_id", "SELECT COUNT(*) FROM detection_results c LEFT JOIN brands p ON c.brand_id=p.id WHERE p.id IS NULL"),
        ("investigations.brand_id", "SELECT COUNT(*) FROM investigations c LEFT JOIN brands p ON c.brand_id=p.id WHERE p.id IS NULL"),
        ("investigations.detection_id", "SELECT COUNT(*) FROM investigations c LEFT JOIN detection_results p ON c.detection_id=p.id WHERE c.detection_id IS NOT NULL AND (p.id IS NULL OR p.brand_id != c.brand_id)"),
        ("monitoring_sources.brand_id", "SELECT COUNT(*) FROM monitoring_sources c LEFT JOIN brands p ON c.brand_id=p.id WHERE p.id IS NULL"),
        ("evidence.detection_id", "SELECT COUNT(*) FROM evidence c LEFT JOIN detection_results p ON c.detection_id=p.id WHERE p.id IS NULL"),
        ("entities.brand_id", "SELECT COUNT(*) FROM entities c LEFT JOIN brands p ON c.brand_id=p.id WHERE p.id IS NULL"),
        ("relationships.source_entity_id", "SELECT COUNT(*) FROM relationships c LEFT JOIN entities p ON c.source_entity_id=p.id WHERE p.id IS NULL"),
        ("relationships.target_entity_id", "SELECT COUNT(*) FROM relationships c LEFT JOIN entities p ON c.target_entity_id=p.id WHERE p.id IS NULL"),
        ("relationships.evidence_id", "SELECT COUNT(*) FROM relationships c LEFT JOIN evidence p ON c.evidence_id=p.id WHERE c.evidence_id IS NOT NULL AND p.id IS NULL"),
        ("report_metadata.brand_id", "SELECT COUNT(*) FROM report_metadata c LEFT JOIN brands p ON c.brand_id=p.id WHERE p.id IS NULL"),
        ("customer_reports.brand_id", "SELECT COUNT(*) FROM customer_reports c LEFT JOIN brands p ON c.brand_id=p.id WHERE c.brand_id IS NOT NULL AND p.id IS NULL"),
        ("customer_reports.organization_id", "SELECT COUNT(*) FROM customer_reports c LEFT JOIN organizations p ON c.organization_id=p.id WHERE c.organization_id IS NOT NULL AND p.id IS NULL"),
        ("report_matches.customer_report_id", "SELECT COUNT(*) FROM report_matches c LEFT JOIN customer_reports p ON c.customer_report_id=p.id WHERE p.id IS NULL"),
        ("report_matches.detection_id", "SELECT COUNT(*) FROM report_matches c LEFT JOIN detection_results p ON c.detection_id=p.id WHERE p.id IS NULL"),
        ("campaigns.brand_id", "SELECT COUNT(*) FROM campaigns c LEFT JOIN brands p ON c.brand_id=p.id WHERE p.id IS NULL"),
        ("campaign_events.campaign_id", "SELECT COUNT(*) FROM campaign_events c LEFT JOIN campaigns p ON c.campaign_id=p.id WHERE p.id IS NULL"),
        ("campaign_events.detection_id", "SELECT COUNT(*) FROM campaign_events c LEFT JOIN detection_results p ON c.detection_id=p.id WHERE c.detection_id IS NOT NULL AND p.id IS NULL"),
        ("qr_analyses.brand_id", "SELECT COUNT(*) FROM qr_analyses c LEFT JOIN brands p ON c.brand_id=p.id WHERE c.brand_id IS NOT NULL AND p.id IS NULL"),
        ("users.organization_id", "SELECT COUNT(*) FROM users c LEFT JOIN organizations p ON c.organization_id=p.id WHERE p.id IS NULL"),
    ]
    try:
        with engine.connect() as connection:
            broken = [
                f"{name}: {count}"
                for name, query in references
                if (count := connection.execute(text(query)).scalar_one()) > 0
            ]
            foreign_key_errors = connection.execute(text("PRAGMA foreign_key_check")).fetchall()
        if broken or foreign_key_errors:
            details = "; ".join(broken)
            if foreign_key_errors:
                details += ("; " if details else "") + f"foreign_key_check: {len(foreign_key_errors)} violation(s)"
            raise DatabaseIntegrityError(
                "Database contains broken active-data references; records were not modified. " + details
            )
    except SQLAlchemyError:
        logger.exception("Database integrity validation failed.")
        raise
