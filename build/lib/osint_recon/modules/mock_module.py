"""Fake recon module that returns hardcoded findings for tests."""

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
                finding_type="config_file",
                value=f"Exposed administrator login panel at https://{target}/admin",
                extra={"url": f"https://{target}/admin", "source": "mock"},
            ),
            Finding(
                module_name=self.MODULE_NAME,
                finding_type="git_exposure",
                value=f"Sensitive .git directory exposed at https://{target}/.git/config",
                extra={"url": f"https://{target}/.git/config", "source": "mock"},
            ),
            Finding(
                module_name=self.MODULE_NAME,
                finding_type="private_key",
                value="AWS IAM Access Key leaked on public GitHub repository",
                extra={"url": f"https://github.com/{target}/repo", "source": "mock"},
            ),
        ]
