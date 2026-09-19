"""Tests for the SQLite database layer.
Uses a temporary directory to clean up after test runs.
"""

import tempfile
from pathlib import Path

import pytest

from osint_recon.database import Database
from osint_recon.models import Finding, RiskLevel


@pytest.fixture
def db(tmp_path):
    """Provide a fresh Database instance backed by a temp file."""
    d = Database(db_path=tmp_path / "test.db")
    yield d
    d.close()


class TestTargets:
    def test_upsert_creates_target(self, db):
        tid = db.upsert_target(name="example.com", domain="example.com")
        assert isinstance(tid, int)
        assert tid > 0

    def test_upsert_idempotent(self, db):
        tid1 = db.upsert_target(name="example.com", domain="example.com")
        tid2 = db.upsert_target(name="example.com", domain="example.com")
        assert tid1 == tid2


class TestScanRuns:
    def test_create_and_complete(self, db):
        tid = db.upsert_target(name="example.com", domain="example.com")
        run_id = db.create_scan_run(tid)
        assert isinstance(run_id, int)
        db.complete_scan_run(run_id, status="success")  # should not raise


class TestFindings:
    def _sample_findings(self):
        return [
            Finding(module_name="dns", finding_type="A", value="1.2.3.4"),
            Finding(
                module_name="dns",
                finding_type="MX",
                value="mail.example.com",
                risk_level=RiskLevel.LOW,
                extra={"priority": 10},
            ),
        ]

    def test_save_and_retrieve(self, db):
        tid = db.upsert_target(name="example.com", domain="example.com")
        run_id = db.create_scan_run(tid)
        findings = self._sample_findings()
        db.save_findings(run_id, findings)

        rows = db.get_findings_for_run(run_id)
        assert len(rows) == 2

    def test_findings_indexed_by_run(self, db):
        tid = db.upsert_target(name="a.com", domain="a.com")
        run1 = db.create_scan_run(tid)
        run2 = db.create_scan_run(tid)

        db.save_findings(run1, self._sample_findings())
        db.save_findings(run2, [self._sample_findings()[0]])

        assert len(db.get_findings_for_run(run1)) == 2
        assert len(db.get_findings_for_run(run2)) == 1

    def test_empty_findings_ok(self, db):
        tid = db.upsert_target(name="b.com", domain="b.com")
        run_id = db.create_scan_run(tid)
        db.save_findings(run_id, [])  # should not raise
        assert db.get_findings_for_run(run_id) == []

    def test_legacy_migration(self, tmp_path):
        import sqlite3
        db_path = tmp_path / "legacy.db"
        
        # Create a database using the legacy schema manually
        conn = sqlite3.connect(str(db_path))
        conn.executescript("""
            CREATE TABLE targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                domain TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT '2023-01-01T00:00:00Z'
            );
            CREATE TABLE scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL REFERENCES targets(id),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT NOT NULL DEFAULT 'running'
                /* missing confirmation_method and modules_run */
            );
        """)
        conn.execute("INSERT INTO targets (name, domain) VALUES ('legacy.com', 'legacy.com')")
        conn.execute("INSERT INTO scan_runs (target_id, started_at) VALUES (1, '2023-01-01T00:00:00Z')")
        conn.commit()
        conn.close()
        
        # Now instantiate Database, which should trigger the _init_schema migration
        from osint_recon.database import Database
        migrated_db = Database(db_path=db_path)
        
        # Validate we can create a new scan run with the new columns
        run_id = migrated_db.create_scan_run(
            target_id=1, 
            confirmation_method="mock", 
            modules_run=["whois_dns"]
        )
        assert run_id == 2
        
        # Validate get_previous_scan_run works (run 1 was legacy, no modules_run)
        # Note: run 1 status was 'running', so get_previous_scan_run might not return it unless we complete it.
        migrated_db.complete_scan_run(1, status="success")
        prev = migrated_db.get_previous_scan_run(1, 2)
        assert prev is not None
        assert prev[0] == 1
        assert prev[1] == "success"
        # Since it had no modules_run (null or empty depending on how SQLite added default), it should return empty list.
        # Actually, DEFAULT '[]' populates it for existing rows.
        assert prev[2] == []
        migrated_db.close()

