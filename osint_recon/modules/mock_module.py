"""
osint_recon/modules/mock_module.py
----------------------------------
A fake recon module that returns hard-coded findings.
Used to:
  • Smoke-test the orchestrator + report pipeline with no network calls.
  • Serve as a reference implementation / copy-paste skeleton for real modules.

DO NOT include in production runs.
"""

from __future__ import annotations

from osint_recon.base_module import BaseModule
from osint_recon.models import Finding, RiskLevel


class MockModule(BaseModule):
    """Returns a small set of fake findings for pipeline testing."""

    MODULE_NAME = "mock"

    async def _run(self, target: str) -> list[Finding]:
        return [
            Finding(
                module_name=self.MODULE_NAME,
                finding_type="mock_info",
                value=f"Fake informational finding for {target}",
                risk_level=RiskLevel.INFO,
                extra={"source": "mock", "note": "delete before prod"},
            ),
            Finding(
                module_name=self.MODULE_NAME,
                finding_type="mock_medium",
                value="Simulated medium-risk item (e.g. exposed admin panel URL)",
                risk_level=RiskLevel.MEDIUM,
                extra={"url": f"https://{target}/admin", "source": "mock"},
            ),
            Finding(
                module_name=self.MODULE_NAME,
                finding_type="mock_high",
                value="Simulated high-risk item (e.g. .git directory exposed)",
                risk_level=RiskLevel.HIGH,
                extra={"url": f"https://{target}/.git/HEAD", "source": "mock"},
            ),
        ]
