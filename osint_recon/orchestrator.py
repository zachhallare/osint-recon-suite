"""
osint_recon/orchestrator.py
---------------------------
Drives the full recon pipeline for a single target.

Responsibilities
----------------
  1. Validates / confirms the target (security guardrail from TRD).
  2. Opens a scan_run row in SQLite.
  3. Runs each enabled module (sequentially for MVP; async-ready).
  4. Persists all findings.
  5. Closes the scan_run row.
  6. Returns a ScanResult ready for the report generator.

Usage
-----
    from osint_recon.orchestrator import Orchestrator

    orch = Orchestrator(db_path="data/osint.db")
    scan = await orch.run("example.com")
"""

from __future__ import annotations

import asyncio
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

_UTC = timezone.utc

from osint_recon.base_module import BaseModule
from osint_recon.database import Database
from osint_recon.models import ScanResult

logger = logging.getLogger(__name__)


class Orchestrator:
    """
    Coordinates all recon modules and persists results.

    Parameters
    ----------
    modules  : Ordered list of BaseModule instances to run.
    db_path  : Path to the SQLite database file.
    confirm  : When True (default), prompt the user to confirm the target
               before any network calls — TRD security guardrail.
    """

    def __init__(
        self,
        modules: Sequence[BaseModule],
        db_path: str | Path = "data/osint.db",
        confirm: bool = True,
    ) -> None:
        self.modules = list(modules)
        self.db = Database(db_path)
        self.confirm = confirm

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(self, target: str) -> ScanResult:
        """
        Execute the full suite against *target*.

        Returns a fully-populated ScanResult; never raises (module-level
        failures are captured as FAILED ModuleResults).
        """
        target = target.strip().lower()

        # Security guardrail: confirm before touching any external resource
        if self.confirm and not self._confirm_target(target):
            logger.warning("Run aborted by user.")
            sys.exit(0)

        logger.info("=" * 60)
        logger.info("Starting OSINT Recon Suite for target: %s", target)
        logger.info("Modules enabled: %s", [m.MODULE_NAME for m in self.modules])
        logger.info("=" * 60)

        # Persist target + open scan_run
        target_id = self.db.upsert_target(name=target, domain=target)
        run_id = self.db.create_scan_run(target_id)
        started_at = datetime.now(_UTC)

        scan = ScanResult(
            target=target,
            scan_run_id=run_id,
            started_at=started_at,
        )

        # Run modules — sequential for MVP, but each module is async-ready
        for module in self.modules:
            result = await module.run(target)
            scan.results.append(result)

            # Persist findings immediately so a crash mid-run still saves data
            if result.findings:
                self.db.save_findings(run_id, result.findings)

        # Close the scan_run
        scan.completed_at = datetime.now(_UTC)
        overall_status = self._overall_status(scan)
        self.db.complete_scan_run(run_id, status=overall_status)

        logger.info("=" * 60)
        logger.info(
            "Scan complete — %d module(s), %d finding(s), %.1fs total",
            len(scan.results),
            len(scan.all_findings),
            scan.total_duration_s,
        )
        logger.info("=" * 60)

        return scan

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _confirm_target(target: str) -> bool:
        """
        Print a clear warning and require explicit 'yes' before proceeding.
        Prevents accidental scans of domains the user doesn't own.
        """
        print()
        print("=" * 60)
        print("  ⚠️  OSINT RECON SUITE — TARGET CONFIRMATION")
        print("=" * 60)
        print(f"  Target : {target}")
        print()
        print("  Only scan domains / entities you own or have explicit")
        print("  written permission to test.  This tool is for passive")
        print("  reconnaissance only.")
        print("=" * 60)
        answer = input("  Confirm scan? [yes/no]: ").strip().lower()
        return answer == "yes"

    @staticmethod
    def _overall_status(scan: ScanResult) -> str:
        """Derive a top-level status string from individual module results."""
        statuses = {r.status.value for r in scan.results}
        if not statuses or statuses == {"failed"}:
            return "failed"
        if "failed" in statuses or "partial" in statuses:
            return "partial"
        return "success"
