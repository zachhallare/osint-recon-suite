"""Unit tests for DocumentScannerModule using mocked HTTP calls."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from osint_recon.models import ModuleStatus, RiskLevel
from osint_recon.modules.document_scanner_module import DocumentScannerModule




def _make_head_response(status_code: int, content_length: str = "1024",
                        content_type: str = "text/plain") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"content-length": content_length, "content-type": content_type}
    return resp


class _FakeAsyncClient:
    """Async context manager fake for httpx.AsyncClient."""
    def __init__(self, response_map: dict | None = None, default_status: int = 404):
        self._map = response_map or {}
        self._default_status = default_status

    async def __aenter__(self): return self
    async def __aexit__(self, *a): pass

    async def head(self, url: str, **kw):
        for key, resp in self._map.items():
            if key in url:
                return resp
        return _make_head_response(self._default_status)




class TestProbeUrl:

    @pytest.mark.anyio
    async def test_200_creates_finding(self):
        mod = DocumentScannerModule(schemes=["https"])
        resp = _make_head_response(200)
        with patch("httpx.AsyncClient", return_value=_FakeAsyncClient({".git/HEAD": resp})):
            finding = await mod._probe_url(
                "https://example.com/.git/HEAD",
                ".git/HEAD",
                "git_exposure",
                RiskLevel.HIGH,
                "Git HEAD exposed",
            )
        assert finding is not None
        assert finding.finding_type == "git_exposure"
        assert finding.risk_level == RiskLevel.HIGH
        assert "https://example.com/.git/HEAD" in finding.value

    @pytest.mark.anyio
    async def test_404_returns_none(self):
        mod = DocumentScannerModule(schemes=["https"])
        resp = _make_head_response(404)
        with patch("httpx.AsyncClient", return_value=_FakeAsyncClient({".git/HEAD": resp})):
            finding = await mod._probe_url(
                "https://example.com/.git/HEAD", ".git/HEAD",
                "git_exposure", RiskLevel.HIGH, ""
            )
        assert finding is None

    @pytest.mark.anyio
    async def test_oversized_file_skipped(self):
        mod = DocumentScannerModule(schemes=["https"])
        # 11 MB payload exceeds the 10 MB limit
        resp = _make_head_response(200, content_length=str(11 * 1024 * 1024))
        with patch("httpx.AsyncClient", return_value=_FakeAsyncClient({"backup.zip": resp})):
            finding = await mod._probe_url(
                "https://example.com/backup.zip", "backup.zip",
                "archive_exposure", RiskLevel.HIGH, ""
            )
        assert finding is None

    @pytest.mark.anyio
    async def test_timeout_returns_none(self):
        mod = DocumentScannerModule(schemes=["https"])
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        client.head = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        with patch("httpx.AsyncClient", return_value=client):
            finding = await mod._probe_url(
                "https://example.com/.env", ".env",
                "env_file", RiskLevel.HIGH, ""
            )
        assert finding is None

    @pytest.mark.anyio
    async def test_connect_error_returns_none(self):
        mod = DocumentScannerModule(schemes=["https"])
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        client.head = AsyncMock(side_effect=httpx.ConnectError("refused"))
        with patch("httpx.AsyncClient", return_value=client):
            finding = await mod._probe_url(
                "https://example.com/.env", ".env",
                "env_file", RiskLevel.HIGH, ""
            )
        assert finding is None




class TestRiskClassification:

    @pytest.mark.anyio
    async def test_git_head_is_high_risk(self):
        mod = DocumentScannerModule(schemes=["https"])
        resp = _make_head_response(200)
        with patch("httpx.AsyncClient", return_value=_FakeAsyncClient({".git/HEAD": resp})):
            finding = await mod._probe_url(
                "https://example.com/.git/HEAD", ".git/HEAD",
                "git_exposure", RiskLevel.HIGH, ""
            )
        assert finding.risk_level == RiskLevel.HIGH

    @pytest.mark.anyio
    async def test_env_file_is_high_risk(self):
        mod = DocumentScannerModule(schemes=["https"])
        resp = _make_head_response(200)
        with patch("httpx.AsyncClient", return_value=_FakeAsyncClient({".env": resp})):
            finding = await mod._probe_url(
                "https://example.com/.env", ".env",
                "env_file", RiskLevel.HIGH, ""
            )
        assert finding.risk_level == RiskLevel.HIGH

    @pytest.mark.anyio
    async def test_robots_txt_is_info(self):
        mod = DocumentScannerModule(schemes=["https"])
        resp = _make_head_response(200)
        with patch("httpx.AsyncClient", return_value=_FakeAsyncClient({"robots.txt": resp})):
            finding = await mod._probe_url(
                "https://example.com/robots.txt", "robots.txt",
                "robots_txt", RiskLevel.INFO, ""
            )
        assert finding.risk_level == RiskLevel.INFO

    @pytest.mark.anyio
    async def test_phpinfo_is_medium_risk(self):
        mod = DocumentScannerModule(schemes=["https"])
        resp = _make_head_response(200)
        with patch("httpx.AsyncClient", return_value=_FakeAsyncClient({"phpinfo.php": resp})):
            finding = await mod._probe_url(
                "https://example.com/phpinfo.php", "phpinfo.php",
                "php_info", RiskLevel.MEDIUM, ""
            )
        assert finding.risk_level == RiskLevel.MEDIUM




@pytest.mark.anyio
async def test_full_run_finds_exposed_git(self=None):
    """When .git/HEAD returns 200, the run produces a HIGH-risk git finding."""
    mod = DocumentScannerModule(schemes=["https"])
    resp_200 = _make_head_response(200)
    resp_404 = _make_head_response(404)

    class _SmartClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def head(self, url, **kw):
            if ".git/HEAD" in url:
                return resp_200
            return resp_404

    with patch("httpx.AsyncClient", return_value=_SmartClient()):
        result = await mod.run("example.com")

    assert result.status == ModuleStatus.SUCCESS
    git_findings = [f for f in result.findings if f.finding_type == "git_exposure"]
    assert git_findings
    assert git_findings[0].risk_level == RiskLevel.HIGH


@pytest.mark.anyio
async def test_full_run_all_404_returns_no_findings():
    """When all paths return 404, the module succeeds with no findings."""
    mod = DocumentScannerModule(schemes=["https"])

    class _AllMiss:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def head(self, url, **kw):
            return _make_head_response(404)

    with patch("httpx.AsyncClient", return_value=_AllMiss()):
        result = await mod.run("example.com")

    assert result.status == ModuleStatus.SUCCESS
    assert result.findings == []


@pytest.mark.anyio
async def test_deduplication_across_schemes():
    """A path found on HTTPS should not also appear as HTTP."""
    mod = DocumentScannerModule(schemes=["https", "http"])
    resp_200 = _make_head_response(200)
    resp_404 = _make_head_response(404)

    class _OnlyHttps:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def head(self, url, **kw):
            if url.startswith("https://") and ".git/HEAD" in url:
                return resp_200
            return resp_404

    with patch("httpx.AsyncClient", return_value=_OnlyHttps()):
        result = await mod.run("example.com")

    git_findings = [f for f in result.findings if f.finding_type == "git_exposure"
                    and ".git/HEAD" in f.value]
    assert len(git_findings) == 1  # deduplicated to one
