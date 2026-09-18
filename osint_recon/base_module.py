"""Base class for all recon modules."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod

from osint_recon.models import Finding, ModuleResult, ModuleStatus

logger = logging.getLogger(__name__)


class BaseModule(ABC):
    """Base recon module. Subclasses implement _run."""

    MODULE_NAME: str = "base"

    async def run(self, target: str) -> ModuleResult:
        """Run the module against the target and catch any errors."""
        logger.info("[%s] Starting module for target=%r", self.MODULE_NAME, target)
        t_start = time.perf_counter()

        try:
            findings = await self._run(target)
            duration = time.perf_counter() - t_start

            if findings:
                status = ModuleStatus.SUCCESS
                logger.info(
                    "[%s] Finished — %d finding(s) in %.2fs",
                    self.MODULE_NAME, len(findings), duration,
                )
            else:
                # No findings returned but the run succeeded
                status = ModuleStatus.SUCCESS
                logger.info(
                    "[%s] Finished — no findings in %.2fs", self.MODULE_NAME, duration
                )

            source_status = getattr(self, "source_status", None)
            return ModuleResult(
                module_name=self.MODULE_NAME,
                status=status,
                findings=findings,
                duration_s=duration,
                source_status=source_status,
            )

        except Exception as exc:  # noqa: BLE001
            duration = time.perf_counter() - t_start
            error_msg = f"{type(exc).__name__}: {exc}"
            logger.error("[%s] FAILED after %.2fs — %s", self.MODULE_NAME, duration, error_msg)
            source_status = getattr(self, "source_status", None)
            return ModuleResult(
                module_name=self.MODULE_NAME,
                status=ModuleStatus.FAILED,
                findings=[],
                error=error_msg,
                duration_s=duration,
                source_status=source_status,
            )

    @abstractmethod
    async def _run(self, target: str) -> list[Finding]:
        """Collect findings for the given target."""
        ...
