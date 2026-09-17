"""Coordinates recon modules and saves scan results."""

from __future__ import annotations

import asyncio
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

_UTC = timezone.utc

import re
from urllib.parse import urlparse

from osint_recon.base_module import BaseModule
from osint_recon.database import Database
from osint_recon.models import ConfirmationMethod, ScanResult

logger = logging.getLogger(__name__)


def normalize_target(target: str) -> str:
    """Strip protocol, port, and path from the target to get a clean domain."""
    t = target.strip()
    if "://" in t:
        parsed = urlparse(t)
        t = parsed.netloc or parsed.path
    t = re.split(r"[/?#]", t)[0]
    if ":" in t and not t.startswith("["):
        t = t.split(":")[0]
    return t.strip().lower()


class Orchestrator:
    """Runs recon modules against a target and records findings."""

    def __init__(
        self,
        modules: Sequence[BaseModule],
        db_path: str | Path = "data/osint.db",
        confirm: bool = True,
    ) -> None:
        self.modules = list(modules)
        self.db = Database(db_path)
        self.confirm = confirm

    async def run(
        self,
        target: str,
        progress=None,
        task_id=None,
        confirmation_method: ConfirmationMethod = ConfirmationMethod.INTERACTIVE,
    ) -> ScanResult:
        """Run all configured modules against the target.

        Pass a rich.progress.Progress and a task_id to get per-module updates.
        confirmation_method records how the scan was authorized.
        """
        raw_target = target.strip()
        target = normalize_target(raw_target)
        if target != raw_target.lower():
            logger.info("Target normalized: '%s' -> '%s'", raw_target, target)

        if self.confirm and not self._confirm_target(target):
            logger.warning("Run aborted by user.")
            sys.exit(0)

        logger.info("Starting OSINT Recon Suite for target: %s", target)
        logger.info("Modules enabled: %s", [m.MODULE_NAME for m in self.modules])

        target_id = self.db.upsert_target(name=target, domain=target)
        run_id = self.db.create_scan_run(
            target_id,
            confirmation_method=confirmation_method.value,
        )
        started_at = datetime.now(_UTC)

        scan = ScanResult(
            target=target,
            scan_run_id=run_id,
            started_at=started_at,
            confirmation_method=confirmation_method,
        )

        for module in self.modules:
            if progress is not None and task_id is not None:
                progress.update(task_id, description=f"[bold]{module.MODULE_NAME}")

            result = await module.run(target)
            scan.results.append(result)

            if result.findings:
                self.db.save_findings(run_id, result.findings)

            if progress is not None and task_id is not None:
                progress.advance(task_id)

        scan.completed_at = datetime.now(_UTC)
        overall_status = self._overall_status(scan)
        self.db.complete_scan_run(run_id, status=overall_status)

        logger.info(
            "Scan complete -- %d module(s), %d finding(s), %.1fs total",
            len(scan.results),
            len(scan.all_findings),
            scan.total_duration_s,
        )

        return scan

    @staticmethod
    def _confirm_target(target: str) -> bool:
        """Use the Rich console helper to confirm the scan target."""
        from osint_recon.console import confirm_target
        return confirm_target(target)

    @staticmethod
    def _overall_status(scan: ScanResult) -> str:
        """Calculate overall scan status from individual module results."""
        statuses = {r.status.value for r in scan.results}
        if not statuses or statuses == {"failed"}:
            return "failed"
        if "failed" in statuses or "partial" in statuses:
            return "partial"
        return "success"
