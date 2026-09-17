"""Tests for the confirmation_method audit trail feature.

Covers:
- CLI flag derivation logic (interactive, bypassed, mock, mock+no-confirm)
- Database persistence of confirmation_method
- SQLite migration path for pre-existing databases
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from osint_recon.database import Database
from osint_recon.models import ConfirmationMethod, ScanResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str]):
    """Run build_arg_parser().parse_args() against a synthetic argv."""
    import sys
    # Import here so the test does not trigger side effects at collection time
    import importlib.util, types
    # We only need the parser, not asyncio.run(main())
    import main as m
    return m.build_arg_parser().parse_args(argv)


def _derive_confirmation(args) -> ConfirmationMethod:
    """Replicate the flag-to-enum derivation logic from main.py."""
    if args.mock:
        return ConfirmationMethod.MOCK
    elif args.no_confirm:
        return ConfirmationMethod.BYPASSED
    else:
        return ConfirmationMethod.INTERACTIVE


# ---------------------------------------------------------------------------
# Check 3: CLI flag -> ConfirmationMethod derivation
# ---------------------------------------------------------------------------

class TestConfirmationMethodDerivation:
    """Verifies the correct enum value is derived for every flag combination."""

    def test_no_flags_gives_interactive(self):
        args = _parse_args(["example.com"])
        assert _derive_confirmation(args) == ConfirmationMethod.INTERACTIVE

    def test_no_confirm_gives_bypassed(self):
        args = _parse_args(["example.com", "--no-confirm"])
        assert _derive_confirmation(args) == ConfirmationMethod.BYPASSED

    def test_mock_gives_mock(self):
        args = _parse_args(["example.com", "--mock"])
        assert _derive_confirmation(args) == ConfirmationMethod.MOCK

    def test_mock_and_no_confirm_together_gives_mock(self):
        """--mock takes precedence over --no-confirm.

        When both flags are present, MOCK is the correct label because
        the run makes no real network calls regardless of confirmation state.
        A scan that never touches the network does not meaningfully bypass
        a safety confirmation.
        """
        args = _parse_args(["example.com", "--mock", "--no-confirm"])
        assert _derive_confirmation(args) == ConfirmationMethod.MOCK


# ---------------------------------------------------------------------------
# Check 1/3: Database confirmation_method persistence
# ---------------------------------------------------------------------------

class TestConfirmationMethodPersistence:
    """Verifies that confirmation_method is stored and readable from SQLite."""

    @pytest.fixture
    def db(self, tmp_path):
        d = Database(db_path=tmp_path / "test.db")
        yield d
        d.close()

    def test_interactive_persisted(self, db):
        tid = db.upsert_target(name="example.com", domain="example.com")
        run_id = db.create_scan_run(tid, confirmation_method="interactive")
        row = db._conn.execute(
            "SELECT confirmation_method FROM scan_runs WHERE id = ?", (run_id,)
        ).fetchone()
        assert row[0] == "interactive"

    def test_bypassed_persisted(self, db):
        tid = db.upsert_target(name="example.com", domain="example.com")
        run_id = db.create_scan_run(tid, confirmation_method="bypassed")
        row = db._conn.execute(
            "SELECT confirmation_method FROM scan_runs WHERE id = ?", (run_id,)
        ).fetchone()
        assert row[0] == "bypassed"

    def test_mock_persisted(self, db):
        tid = db.upsert_target(name="example.com", domain="example.com")
        run_id = db.create_scan_run(tid, confirmation_method="mock")
        row = db._conn.execute(
            "SELECT confirmation_method FROM scan_runs WHERE id = ?", (run_id,)
        ).fetchone()
        assert row[0] == "mock"

    def test_default_is_interactive_when_not_passed(self, db):
        """Calling create_scan_run without confirmation_method defaults to interactive."""
        tid = db.upsert_target(name="example.com", domain="example.com")
        run_id = db.create_scan_run(tid)
        row = db._conn.execute(
            "SELECT confirmation_method FROM scan_runs WHERE id = ?", (run_id,)
        ).fetchone()
        assert row[0] == "interactive"


# ---------------------------------------------------------------------------
# Check 4: SQLite migration path against real pre-migration data
# ---------------------------------------------------------------------------

class TestConfirmationMethodMigration:
    """
    Tests that existing databases without the confirmation_method column
    are migrated correctly when the new Database class opens them.
    """

    def _build_legacy_db(self, db_path: Path) -> None:
        """Create a database file matching the pre-migration schema."""
        conn = sqlite3.connect(str(db_path))
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS targets (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT    NOT NULL,
                domain     TEXT    NOT NULL UNIQUE,
                created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            );

            CREATE TABLE IF NOT EXISTS scan_runs (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id    INTEGER NOT NULL REFERENCES targets(id),
                started_at   TEXT    NOT NULL,
                completed_at TEXT,
                status       TEXT    NOT NULL DEFAULT 'running'
            );

            CREATE TABLE IF NOT EXISTS findings (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_run_id   INTEGER NOT NULL REFERENCES scan_runs(id),
                module_name   TEXT    NOT NULL,
                finding_type  TEXT    NOT NULL,
                value         TEXT    NOT NULL,
                risk_level    TEXT    NOT NULL DEFAULT 'info',
                extra_json    TEXT    NOT NULL DEFAULT '{}',
                discovered_at TEXT    NOT NULL
            );
            """
        )
        conn.execute(
            "INSERT INTO targets (name, domain) VALUES (?, ?)",
            ("legacy.com", "legacy.com"),
        )
        conn.execute(
            "INSERT INTO scan_runs (target_id, started_at, status) VALUES (?, ?, ?)",
            (1, "2024-01-01T00:00:00", "success"),
        )
        conn.commit()
        conn.close()

    def test_column_absent_before_migration(self, tmp_path):
        db_path = tmp_path / "legacy.db"
        self._build_legacy_db(db_path)
        conn = sqlite3.connect(str(db_path))
        cols = {row[1] for row in conn.execute("PRAGMA table_info(scan_runs)")}
        conn.close()
        assert "confirmation_method" not in cols

    def test_old_row_gets_interactive_default_after_migration(self, tmp_path):
        """Existing rows should read back as 'interactive' after ALTER TABLE."""
        db_path = tmp_path / "legacy.db"
        self._build_legacy_db(db_path)

        db = Database(db_path=db_path)
        row = db._conn.execute(
            "SELECT confirmation_method FROM scan_runs WHERE id = 1"
        ).fetchone()
        db.close()

        assert row is not None
        assert row[0] == "interactive"

    def test_new_run_after_migration_persists_correct_value(self, tmp_path):
        """A new run created after migration should store exactly what was passed."""
        db_path = tmp_path / "legacy.db"
        self._build_legacy_db(db_path)

        db = Database(db_path=db_path)
        tid = db.upsert_target(name="new.com", domain="new.com")
        new_id = db.create_scan_run(tid, confirmation_method="bypassed")
        row = db._conn.execute(
            "SELECT confirmation_method FROM scan_runs WHERE id = ?", (new_id,)
        ).fetchone()
        db.close()

        assert row[0] == "bypassed"

    def test_migration_is_idempotent(self, tmp_path):
        """Opening an already-migrated database a second time should not error."""
        db_path = tmp_path / "legacy.db"
        self._build_legacy_db(db_path)

        db1 = Database(db_path=db_path)
        db1.close()
        db2 = Database(db_path=db_path)  # should not raise
        db2.close()


# ---------------------------------------------------------------------------
# Check 1: ScanResult carries confirmation_method through to the model
# ---------------------------------------------------------------------------

class TestScanResultConfirmationMethod:
    """Verifies ScanResult stores and exposes confirmation_method correctly."""

    def _make_scan(self, method: ConfirmationMethod) -> ScanResult:
        from datetime import datetime
        return ScanResult(
            target="example.com",
            scan_run_id=1,
            started_at=datetime(2024, 1, 1, 12, 0, 0),
            confirmation_method=method,
        )

    def test_default_is_interactive(self):
        from datetime import datetime
        scan = ScanResult(
            target="example.com",
            scan_run_id=1,
            started_at=datetime(2024, 1, 1),
        )
        assert scan.confirmation_method == ConfirmationMethod.INTERACTIVE

    def test_interactive_stored(self):
        scan = self._make_scan(ConfirmationMethod.INTERACTIVE)
        assert scan.confirmation_method == ConfirmationMethod.INTERACTIVE

    def test_bypassed_stored(self):
        scan = self._make_scan(ConfirmationMethod.BYPASSED)
        assert scan.confirmation_method == ConfirmationMethod.BYPASSED

    def test_mock_stored(self):
        scan = self._make_scan(ConfirmationMethod.MOCK)
        assert scan.confirmation_method == ConfirmationMethod.MOCK
