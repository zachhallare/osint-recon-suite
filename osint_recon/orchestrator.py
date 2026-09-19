"""Coordinates recon modules and saves scan results."""

from __future__ import annotations

import asyncio
import json
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
from osint_recon.models import ConfirmationMethod, ScanResult, ModuleStatus, Finding, RiskLevel
from osint_recon.scoring import post_process_findings

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
        original_target: str | None = None,
        resolved_company_name: str | None = None,
        progress=None,
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

        if self.confirm and not self._confirm_target(target, original_target, resolved_company_name):
            logger.warning("Run aborted by user.")
            sys.exit(0)

        logger.info("Starting OSINT Recon Suite for target: %s", target)
        logger.info("Modules enabled: %s", [m.MODULE_NAME for m in self.modules])

        target_id = self.db.upsert_target(name=target, domain=target)
        run_id = self.db.create_scan_run(
            target_id,
            confirmation_method=confirmation_method.value,
            modules_run=[m.MODULE_NAME for m in self.modules],
        )
        started_at = datetime.now(_UTC)

        scan = ScanResult(
            target=target,
            scan_run_id=run_id,
            started_at=started_at,
            confirmation_method=confirmation_method,
            modules_run=[m.MODULE_NAME for m in self.modules],
        )

        db_lock = asyncio.Lock()

        async def _execute_module(module: BaseModule) -> None:
            mod_task_id = None
            if progress is not None:
                # total=None makes it pulse/indeterminate until complete
                mod_task_id = progress.add_task(f"[cyan]Running {module.MODULE_NAME}...", total=None)

            result = await module.run(target, previous_findings=scan.all_findings)
            if result.findings:
                result.findings = post_process_findings(result.findings)
            
            async with db_lock:
                try:
                    scan.results.append(result)
                    if result.findings:
                        self.db.save_findings(run_id, result.findings)
                except Exception as exc:
                    logger.error("[%s] Failed to persist findings to DB: %s", module.MODULE_NAME, exc)
                    result.status = ModuleStatus.FAILED
                    result.error = f"Database persistence error: {exc}"

            if progress is not None and mod_task_id is not None:
                if result.status == ModuleStatus.FAILED:
                    progress.update(mod_task_id, description=f"[red]Failed: {module.MODULE_NAME}[/red]", total=1, completed=1)
                else:
                    progress.update(mod_task_id, description=f"[bold cyan]Done: {module.MODULE_NAME}[/bold cyan]", total=1, completed=1)

        phase1_modules = [m for m in self.modules if not getattr(m, "RUN_AFTER_OTHERS", False)]
        phase2_modules = [m for m in self.modules if getattr(m, "RUN_AFTER_OTHERS", False)]

        await asyncio.gather(*[_execute_module(m) for m in phase1_modules])
        if phase2_modules:
            await asyncio.gather(*[_execute_module(m) for m in phase2_modules])

        # Diffing logic
        prev_run = self.db.get_previous_scan_run(target_id, run_id)
        if prev_run is not None:
            prev_run_id, prev_status, prev_modules = prev_run
            scan.previous_scan_run_id = prev_run_id
            scan.previous_scan_was_partial = (prev_status == "partial")
            scan.previous_scan_modules = prev_modules
            prev_findings = self.db.get_findings_for_run(prev_run_id)
            prev_signatures = {
                (row["module_name"], row["finding_type"], row["value"].strip())
                for row in prev_findings
            }
            scan.new_findings = [
                f for f in scan.all_findings
                if (f.module_name, f.finding_type, f.value.strip()) not in prev_signatures
            ]
            
            curr_signatures = {
                (f.module_name, f.finding_type, f.value.strip())
                for f in scan.all_findings
            }
            
            # Only consider findings as 'resolved' if the module that found them ran successfully this time.
            # If a module failed, we don't know if the finding is resolved or not.
            successful_modules = {res.module_name for res in scan.results if res.status in (ModuleStatus.SUCCESS, ModuleStatus.PARTIAL)}
            
            scan.resolved_findings = [
                Finding(
                    module_name=row["module_name"],
                    finding_type=row["finding_type"],
                    value=row["value"],
                    risk_level=RiskLevel(row["risk_level"]),
                    extra=json.loads(row["extra_json"])
                )
                for row in prev_findings
                if row["module_name"] in successful_modules and (row["module_name"], row["finding_type"], row["value"].strip()) not in curr_signatures
            ]

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
    def _confirm_target(target: str, original_target: str | None = None, resolved_company_name: str | None = None) -> bool:
        """Use the Rich console helper to confirm the scan target."""
        from osint_recon.console import confirm_target
        return confirm_target(target, original_target, resolved_company_name)

    @staticmethod
    def _overall_status(scan: ScanResult) -> str:
        """Calculate overall scan status from individual module results."""
        statuses = {r.status.value for r in scan.results}
        if not statuses or statuses == {"failed"}:
            return "failed"
        if "failed" in statuses or "partial" in statuses:
            return "partial"
        return "success"
