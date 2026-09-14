"""
tests/test_database.py
----------------------
Tests for the SQLite persistence layer.
Uses a temporary in-memory path so no files are left on disk after tests.
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
