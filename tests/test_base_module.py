"""
tests/test_base_module.py
-------------------------
Tests for the BaseModule error-isolation guarantee:
  a failing _run() must produce a FAILED ModuleResult, not propagate.
"""

import pytest

from osint_recon.base_module import BaseModule
from osint_recon.models import Finding, ModuleStatus, RiskLevel


class GoodModule(BaseModule):
    MODULE_NAME = "good"

    async def _run(self, target: str) -> list[Finding]:
        return [Finding(module_name=self.MODULE_NAME, finding_type="test", value="ok")]


class EmptyModule(BaseModule):
    MODULE_NAME = "empty"

    async def _run(self, target: str) -> list[Finding]:
        return []


class BrokenModule(BaseModule):
    MODULE_NAME = "broken"

    async def _run(self, target: str) -> list[Finding]:
        raise RuntimeError("Simulated network failure")


@pytest.mark.anyio
async def test_good_module_returns_success():
    result = await GoodModule().run("example.com")
    assert result.status == ModuleStatus.SUCCESS
    assert len(result.findings) == 1
    assert result.duration_s >= 0


@pytest.mark.anyio
async def test_empty_module_returns_success_with_no_findings():
    result = await EmptyModule().run("example.com")
    assert result.status == ModuleStatus.SUCCESS
    assert result.findings == []


@pytest.mark.anyio
async def test_broken_module_does_not_raise():
    """Critical: a crashing module must NOT propagate — orchestrator must keep running."""
    result = await BrokenModule().run("example.com")
    assert result.status == ModuleStatus.FAILED
    assert result.findings == []
    assert "RuntimeError" in result.error
    assert result.duration_s >= 0
