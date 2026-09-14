"""
osint_recon/base_module.py
--------------------------
Abstract base class that every recon module must inherit from.

Contract
--------
  • Subclass must set CLASS attribute `MODULE_NAME: str`
  • Subclass must implement `async def _run(self, target: str) -> list[Finding]`
  • Call `super().run(target)` from the orchestrator — it handles timing,
    error catching, and wrapping into a ModuleResult automatically.

Example skeleton
----------------
    class WhoisModule(BaseModule):
        MODULE_NAME = "whois"

        async def _run(self, target: str) -> list[Finding]:
            ...  # do the work
            return [Finding(module_name=self.MODULE_NAME, ...)]
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod

from osint_recon.models import Finding, ModuleResult, ModuleStatus

logger = logging.getLogger(__name__)


class BaseModule(ABC):
    """Abstract recon module.  Override ``_run`` in every concrete subclass."""

    MODULE_NAME: str = "base"

    # ------------------------------------------------------------------
    # Public entry point (called by Orchestrator)
    # ------------------------------------------------------------------

    async def run(self, target: str) -> ModuleResult:
        """
        Execute the module against *target* and return a ModuleResult.

        Guarantees
        ----------
        • Never raises — all exceptions are caught and surfaced as a
          FAILED ModuleResult so the orchestrator always keeps running.
        • Always records wall-clock duration in ModuleResult.duration_s.
        """
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
                # Module ran without error but found nothing — still SUCCESS,
                # zero findings is valid (clean target).
                status = ModuleStatus.SUCCESS
                logger.info(
                    "[%s] Finished — no findings in %.2fs", self.MODULE_NAME, duration
                )

            return ModuleResult(
                module_name=self.MODULE_NAME,
                status=status,
                findings=findings,
                duration_s=duration,
            )

        except Exception as exc:  # noqa: BLE001
            duration = time.perf_counter() - t_start
            error_msg = f"{type(exc).__name__}: {exc}"
            logger.error("[%s] FAILED after %.2fs — %s", self.MODULE_NAME, duration, error_msg)
            return ModuleResult(
                module_name=self.MODULE_NAME,
                status=ModuleStatus.FAILED,
                findings=[],
                error=error_msg,
                duration_s=duration,
            )

    # ------------------------------------------------------------------
    # Abstract — implemented by each concrete module
    # ------------------------------------------------------------------

    @abstractmethod
    async def _run(self, target: str) -> list[Finding]:
        """
        Perform the actual reconnaissance.

        Parameters
        ----------
        target : Domain name or entity string supplied by the user.

        Returns
        -------
        A (possibly empty) list of Finding objects.
        Raise any exception on unrecoverable failure; BaseModule.run()
        will catch it and produce a FAILED ModuleResult.
        """
        ...
