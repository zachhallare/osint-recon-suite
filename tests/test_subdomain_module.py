"""
tests/test_subdomain_module.py
------------------------------
Unit tests for SubdomainModule.

All HTTP and DNS calls are mocked — no live network required.
Fixtures stored in tests/fixtures/crtsh_example_com.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.resolver
import httpx
import pytest

from osint_recon.models import ModuleStatus, RiskLevel
from osint_recon.modules.subdomain_module import SubdomainModule

FIXTURES = Path(__file__).parent / "fixtures"


# ── helpers ──────────────────────────────────────────────────────────────────

def _load_crtsh_fixture() -> list[dict]:
    return json.loads((FIXTURES / "crtsh_example_com.json").read_text())


def _make_mock_response(status_code: int = 200, json_data=None) -> MagicMock:
    """Build a fake httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or []
    return resp


class _FakeAsyncClient:
    """Minimal async context-manager fake for httpx.AsyncClient."""
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def get(self, url, **kwargs):
        return self._response


# ── _fetch_crtsh tests ────────────────────────────────────────────────────────

class TestFetchCrtsh:

    @pytest.mark.anyio
    async def test_returns_subdomains_from_fixture(self):
        mod = SubdomainModule()
        fixture = _load_crtsh_fixture()
        mock_resp = _make_mock_response(200, fixture)
        with patch("httpx.AsyncClient", return_value=_FakeAsyncClient(mock_resp)):
            subdomains, err = await mod._fetch_crtsh("example.com")
        assert err is None
        assert "www.example.com" in subdomains
        assert "mail.example.com" in subdomains
        assert "dev.example.com" in subdomains

    @pytest.mark.anyio
    async def test_root_domain_excluded_from_results(self):
        mod = SubdomainModule()
        fixture = _load_crtsh_fixture()
        mock_resp = _make_mock_response(200, fixture)
        with patch("httpx.AsyncClient", return_value=_FakeAsyncClient(mock_resp)):
            subdomains, _ = await mod._fetch_crtsh("example.com")
        assert "example.com" not in subdomains

    @pytest.mark.anyio
    async def test_wildcard_included(self):
        mod = SubdomainModule()
        fixture = _load_crtsh_fixture()
        mock_resp = _make_mock_response(200, fixture)
        with patch("httpx.AsyncClient", return_value=_FakeAsyncClient(mock_resp)):
            subdomains, _ = await mod._fetch_crtsh("example.com")
        assert "*.example.com" in subdomains

    @pytest.mark.anyio
    async def test_multiline_san_parsed(self):
        """test.example.com and qa.example.com are in one newline-joined SAN field."""
        mod = SubdomainModule()
        fixture = _load_crtsh_fixture()
        mock_resp = _make_mock_response(200, fixture)
        with patch("httpx.AsyncClient", return_value=_FakeAsyncClient(mock_resp)):
            subdomains, _ = await mod._fetch_crtsh("example.com")
        assert "test.example.com" in subdomains
        assert "qa.example.com" in subdomains

    @pytest.mark.anyio
    async def test_non_200_returns_error(self):
        mod = SubdomainModule()
        mock_resp = _make_mock_response(503)
        with patch("httpx.AsyncClient", return_value=_FakeAsyncClient(mock_resp)):
            subdomains, err = await mod._fetch_crtsh("example.com")
        assert err is not None
        assert "503" in err
        assert subdomains == set()

    @pytest.mark.anyio
    async def test_timeout_returns_error(self):
        mod = SubdomainModule()
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        with patch("httpx.AsyncClient", return_value=client):
            subdomains, err = await mod._fetch_crtsh("example.com")
        assert err is not None
        assert "timed out" in err.lower()
        assert subdomains == set()

    @pytest.mark.anyio
    async def test_empty_response_returns_no_error(self):
        mod = SubdomainModule()
        mock_resp = _make_mock_response(200, [])
        with patch("httpx.AsyncClient", return_value=_FakeAsyncClient(mock_resp)):
            subdomains, err = await mod._fetch_crtsh("example.com")
        assert err is None
        assert subdomains == set()


# ── _check_subdomain tests ────────────────────────────────────────────────────

class TestCheckSubdomain:

    @pytest.mark.anyio
    async def test_live_subdomain_has_ips(self):
        mod = SubdomainModule()
        with patch.object(mod, "_resolve", return_value=["1.2.3.4"]):
            finding = await mod._check_subdomain("www.example.com", "example.com")
        assert finding is not None
        assert finding.extra["live"] is True
        assert "1.2.3.4" in finding.extra["resolved_ips"]

    @pytest.mark.anyio
    async def test_dead_subdomain_not_live(self):
        mod = SubdomainModule()
        with patch.object(mod, "_resolve", return_value=[]):
            finding = await mod._check_subdomain("old.example.com", "example.com")
        assert finding is not None
        assert finding.extra["live"] is False

    @pytest.mark.anyio
    async def test_wildcard_is_low_risk(self):
        mod = SubdomainModule()
        with patch.object(mod, "_resolve", return_value=[]):
            finding = await mod._check_subdomain("*.example.com", "example.com")
        assert finding.risk_level == RiskLevel.LOW
        assert finding.extra["wildcard"] is True

    @pytest.mark.anyio
    async def test_sensitive_keyword_is_medium_risk(self):
        mod = SubdomainModule()
        with patch.object(mod, "_resolve", return_value=["10.0.0.1"]):
            finding = await mod._check_subdomain("admin.example.com", "example.com")
        assert finding.risk_level == RiskLevel.MEDIUM
        assert "admin" in finding.extra.get("sensitive_keywords", [])

    @pytest.mark.anyio
    async def test_vpn_subdomain_is_medium_risk(self):
        mod = SubdomainModule()
        with patch.object(mod, "_resolve", return_value=["10.0.0.2"]):
            finding = await mod._check_subdomain("vpn.example.com", "example.com")
        assert finding.risk_level == RiskLevel.MEDIUM

    @pytest.mark.anyio
    async def test_dev_subdomain_is_medium_risk(self):
        mod = SubdomainModule()
        with patch.object(mod, "_resolve", return_value=[]):
            finding = await mod._check_subdomain("dev.example.com", "example.com")
        assert finding.risk_level == RiskLevel.MEDIUM

    @pytest.mark.anyio
    async def test_plain_subdomain_is_info(self):
        mod = SubdomainModule()
        with patch.object(mod, "_resolve", return_value=["93.184.216.34"]):
            finding = await mod._check_subdomain("www.example.com", "example.com")
        assert finding.risk_level == RiskLevel.INFO


# ── risk classification tests ─────────────────────────────────────────────────

class TestClassifyRisk:
    def test_wildcard_always_low(self):
        assert SubdomainModule._classify_risk("*.example.com", [], True) == RiskLevel.LOW

    def test_admin_keyword_medium(self):
        assert SubdomainModule._classify_risk("admin.example.com", ["1.2.3.4"], False) == RiskLevel.MEDIUM

    def test_live_plain_is_info(self):
        assert SubdomainModule._classify_risk("www.example.com", ["1.2.3.4"], False) == RiskLevel.INFO

    def test_dead_plain_is_info(self):
        # "blog.example.com" has no sensitive keywords — dead → INFO
        assert SubdomainModule._classify_risk("blog.example.com", [], False) == RiskLevel.INFO


# ── full async run integration ─────────────────────────────────────────────────

@pytest.mark.anyio
async def test_full_run_success():
    """End-to-end: mocked crt.sh + DNS → valid ModuleResult."""
    mod = SubdomainModule()
    fixture = _load_crtsh_fixture()
    mock_resp = _make_mock_response(200, fixture)

    with patch("httpx.AsyncClient", return_value=_FakeAsyncClient(mock_resp)):
        with patch.object(mod, "_resolve", return_value=["1.2.3.4"]):
            result = await mod.run("example.com")

    assert result.status == ModuleStatus.SUCCESS
    assert result.module_name == "subdomain"
    assert len(result.findings) > 0
    finding_values = [f.value for f in result.findings]
    assert "www.example.com" in finding_values
    assert "dev.example.com" in finding_values


@pytest.mark.anyio
async def test_full_run_crtsh_error_produces_error_finding():
    """crt.sh failure → FAILED module status with error finding surfaced."""
    mod = SubdomainModule()
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.get = AsyncMock(side_effect=httpx.RequestError("network error"))

    with patch("httpx.AsyncClient", return_value=client):
        result = await mod.run("example.com")

    # BaseModule wraps this into FAILED, or _run returns an error finding
    assert result.module_name == "subdomain"
    # Either a FAILED status or an error-type finding — both are acceptable
    has_error = (
        result.status == ModuleStatus.FAILED
        or any(f.finding_type == "crtsh_error" for f in result.findings)
    )
    assert has_error


@pytest.mark.anyio
async def test_full_run_empty_crtsh_returns_no_findings():
    mod = SubdomainModule()
    mock_resp = _make_mock_response(200, [])
    with patch("httpx.AsyncClient", return_value=_FakeAsyncClient(mock_resp)):
        result = await mod.run("example.com")
    assert result.status == ModuleStatus.SUCCESS
    assert result.findings == []
