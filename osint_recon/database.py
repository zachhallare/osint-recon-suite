"""SQLite storage for targets, scan runs, and findings."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_UTC = timezone.utc

from osint_recon.models import Finding

logger = logging.getLogger(__name__)

_DDL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS targets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    domain     TEXT    NOT NULL UNIQUE,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id           INTEGER NOT NULL REFERENCES targets(id),
    started_at          TEXT    NOT NULL,
    completed_at        TEXT,
    status              TEXT    NOT NULL DEFAULT 'running',
    confirmation_method TEXT    NOT NULL DEFAULT 'interactive'
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

CREATE INDEX IF NOT EXISTS idx_findings_run    ON findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module_name);
"""


class Database:
    """Wrapper around local SQLite database."""

    def __init__(self, db_path: str | Path = "data/osint.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        logger.info("Database ready at %s", self.db_path)

    def _init_schema(self) -> None:
        self._conn.executescript(_DDL)
        # Migrate existing databases that pre-date the confirmation_method column.
        cols = {row[1] for row in self._conn.execute("PRAGMA table_info(scan_runs)")}
        if "confirmation_method" not in cols:
            self._conn.execute(
                "ALTER TABLE scan_runs ADD COLUMN "
                "confirmation_method TEXT NOT NULL DEFAULT 'interactive'"
            )
        self._conn.commit()

    def upsert_target(self, *, name: str, domain: str) -> int:
        """Insert target if the domain is new and return its id."""
        cur = self._conn.execute(
            "SELECT id FROM targets WHERE domain = ?", (domain,)
        )
        row = cur.fetchone()
        if row:
            return int(row["id"])
        cur = self._conn.execute(
            "INSERT INTO targets (name, domain) VALUES (?, ?)", (name, domain)
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def create_scan_run(
        self,
        target_id: int,
        confirmation_method: str = "interactive",
    ) -> int:
        """Start a new scan run and return its id."""
        started_at = datetime.now(_UTC).isoformat()
        cur = self._conn.execute(
            "INSERT INTO scan_runs (target_id, started_at, confirmation_method) VALUES (?, ?, ?)",
            (target_id, started_at, confirmation_method),
        )
        self._conn.commit()
        logger.debug(
            "Created scan_run id=%d for target_id=%d (confirmation=%s)",
            cur.lastrowid, target_id, confirmation_method,
        )
        return cur.lastrowid  # type: ignore[return-value]

    def complete_scan_run(self, run_id: int, *, status: str = "success") -> None:
        completed_at = datetime.now(_UTC).isoformat()
        self._conn.execute(
            "UPDATE scan_runs SET completed_at=?, status=? WHERE id=?",
            (completed_at, status, run_id),
        )
        self._conn.commit()

    def save_findings(self, scan_run_id: int, findings: list[Finding]) -> None:
        """Save a list of findings to the database."""
        rows = [
            (
                scan_run_id,
                f.module_name,
                f.finding_type,
                f.value,
                f.risk_level.value,
                json.dumps(f.extra),
                f.discovered_at.isoformat(),
            )
            for f in findings
        ]
        self._conn.executemany(
            """INSERT INTO findings
               (scan_run_id, module_name, finding_type, value,
                risk_level, extra_json, discovered_at)
               VALUES (?,?,?,?,?,?,?)""",
            rows,
        )
        self._conn.commit()
        logger.debug("Saved %d findings for scan_run_id=%d", len(rows), scan_run_id)

    def get_findings_for_run(self, scan_run_id: int) -> list[sqlite3.Row]:
        cur = self._conn.execute(
            "SELECT * FROM findings WHERE scan_run_id=? ORDER BY module_name, id",
            (scan_run_id,),
        )
        return cur.fetchall()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
