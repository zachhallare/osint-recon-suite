"""
tests/test_company_mapper_module.py
------------------------------------
Unit tests for CompanyMapperModule.

All HTTP and DNS calls are mocked — no live network required.
Fixtures stored in tests/fixtures/.
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
from osint_recon.modules.company_mapper_module import CompanyMapperModule

FIXTURES = Path(__file__).parent / "fixtures"

TARGET = "example.com"
TEST_IP = "93.184.216.34"


# ── HTTP fake helpers ─────────────────────────────────────────────────────────

def _mock_response(status_code: int = 200, body=None, text: str | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    if text is not None:
        resp.text = text
        resp.json = MagicMock(side_effect=ValueError("not json"))
    else:
        data = body if body is not None else {}
        resp.json = MagicMock(return_value=data)
        resp.text = json.dumps(data)
    return resp


class _AsyncClientCtx:
    """Fake async context manager for httpx.AsyncClient that routes URLs to handlers."""

    def __init__(self, url_map: dict):
        self._url_map = url_map

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def get(self, url: str, **kwargs):
        for pattern, response in self._url_map.items():
            if pattern in url:
                return response
        return _mock_response(404)


# ── _shodan_internetdb tests ──────────────────────────────────────────────────

class TestShodanInternetDB:

    def _load(self) -> dict:
        return json.loads((FIXTURES / "shodan_internetdb_93_184_216_34.json").read_text())

    @pytest.mark.anyio
    async def test_open_ports_discovered(self):
        mod = CompanyMapperModule()
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new=AsyncMock(
                return_value=_mock_response(200, self._load())
            )):
                findings = await mod._shodan_internetdb(client, TEST_IP)

        port_findings = [f for f in findings if f.finding_type == "open_port"]
        assert len(port_findings) == 5  # fixture has 5 ports
        values = [f.value for f in port_findings]
        assert f"{TEST_IP}:80" in values
        assert f"{TEST_IP}:443" in values

    @pytest.mark.anyio
    async def test_high_risk_port_redis(self):
        mod = CompanyMapperModule()
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new=AsyncMock(
                return_value=_mock_response(200, self._load())
            )):
                findings = await mod._shodan_internetdb(client, TEST_IP)

        redis_finding = next(
            (f for f in findings if f.finding_type == "open_port" and ":6379" in f.value), None
        )
        assert redis_finding is not None
        assert redis_finding.risk_level == RiskLevel.HIGH

    @pytest.mark.anyio
    async def test_medium_risk_port_ssh(self):
        mod = CompanyMapperModule()
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new=AsyncMock(
                return_value=_mock_response(200, self._load())
            )):
                findings = await mod._shodan_internetdb(client, TEST_IP)

        ssh = next(
            (f for f in findings if f.finding_type == "open_port" and ":22" in f.value), None
        )
        assert ssh is not None
        assert ssh.risk_level == RiskLevel.MEDIUM

    @pytest.mark.anyio
    async def test_cves_are_high_risk(self):
        mod = CompanyMapperModule()
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new=AsyncMock(
                return_value=_mock_response(200, self._load())
            )):
                findings = await mod._shodan_internetdb(client, TEST_IP)

        cve_findings = [f for f in findings if f.finding_type == "known_cve"]
        assert len(cve_findings) == 2
        assert all(f.risk_level == RiskLevel.HIGH for f in cve_findings)
        cve_ids = [f.extra["cve_id"] for f in cve_findings]
        assert "CVE-2023-44487" in cve_ids

    @pytest.mark.anyio
    async def test_cpes_collected(self):
        mod = CompanyMapperModule()
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new=AsyncMock(
                return_value=_mock_response(200, self._load())
            )):
                findings = await mod._shodan_internetdb(client, TEST_IP)

        cpe = next((f for f in findings if f.finding_type == "software_cpe"), None)
        assert cpe is not None
        assert "apache" in cpe.value.lower()

    @pytest.mark.anyio
    async def test_404_returns_empty(self):
        mod = CompanyMapperModule()
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new=AsyncMock(return_value=_mock_response(404))):
                findings = await mod._shodan_internetdb(client, TEST_IP)
        assert findings == []

    @pytest.mark.anyio
    async def test_network_error_returns_empty(self):
        mod = CompanyMapperModule()
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new=AsyncMock(
                side_effect=httpx.RequestError("refused")
            )):
                findings = await mod._shodan_internetdb(client, TEST_IP)
        assert findings == []


# ── _geolocate_ip tests ───────────────────────────────────────────────────────

class TestGeolocateIP:

    def _load(self) -> dict:
        return json.loads((FIXTURES / "ipapi_93_184_216_34.json").read_text())

    @pytest.mark.anyio
    async def test_geolocation_finding_created(self):
        mod = CompanyMapperModule()
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new=AsyncMock(
                return_value=_mock_response(200, self._load())
            )):
                findings = await mod._geolocate_ip(client, TEST_IP)

        geo = next((f for f in findings if f.finding_type == "ip_geolocation"), None)
        assert geo is not None
        assert "Los Angeles" in geo.value
        assert "United States" in geo.value
        assert geo.risk_level == RiskLevel.INFO

    @pytest.mark.anyio
    async def test_asn_finding_created(self):
        mod = CompanyMapperModule()
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new=AsyncMock(
                return_value=_mock_response(200, self._load())
            )):
                findings = await mod._geolocate_ip(client, TEST_IP)

        asn = next((f for f in findings if f.finding_type == "ip_asn"), None)
        assert asn is not None
        assert "AS15133" in asn.value

    @pytest.mark.anyio
    async def test_api_error_flag_returns_empty(self):
        mod = CompanyMapperModule()
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new=AsyncMock(
                return_value=_mock_response(200, {"error": True, "reason": "Reserved IP"})
            )):
                findings = await mod._geolocate_ip(client, TEST_IP)
        assert findings == []

    @pytest.mark.anyio
    async def test_non_200_returns_empty(self):
        mod = CompanyMapperModule()
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new=AsyncMock(return_value=_mock_response(429))):
                findings = await mod._geolocate_ip(client, TEST_IP)
        assert findings == []


# ── _reverse_ip_lookup tests ──────────────────────────────────────────────────

class TestReverseIPLookup:

    @pytest.mark.anyio
    async def test_shared_hosting_detected(self):
        body = "example.com\nother1.com\nother2.com\nother3.com"
        mod = CompanyMapperModule()
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new=AsyncMock(
                return_value=_mock_response(200, text=body)
            )):
                findings = await mod._reverse_ip_lookup(client, TEST_IP, TARGET)

        sh = next((f for f in findings if f.finding_type == "shared_hosting"), None)
        assert sh is not None
        assert sh.risk_level == RiskLevel.LOW
        assert sh.extra["co_hosted_count"] == 3

    @pytest.mark.anyio
    async def test_single_domain_is_not_shared_hosting(self):
        body = "example.com"
        mod = CompanyMapperModule()
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new=AsyncMock(
                return_value=_mock_response(200, text=body)
            )):
                findings = await mod._reverse_ip_lookup(client, TEST_IP, TARGET)
        assert not any(f.finding_type == "shared_hosting" for f in findings)

    @pytest.mark.anyio
    async def test_hackertarget_rate_limit_ignored(self):
        mod = CompanyMapperModule()
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new=AsyncMock(
                return_value=_mock_response(200, text="error check your API usage")
            )):
                findings = await mod._reverse_ip_lookup(client, TEST_IP, TARGET)
        assert findings == []

    @pytest.mark.anyio
    async def test_network_error_returns_empty(self):
        mod = CompanyMapperModule()
        async with httpx.AsyncClient() as client:
            with patch.object(client, "get", new=AsyncMock(
                side_effect=httpx.RequestError("refused")
            )):
                findings = await mod._reverse_ip_lookup(client, TEST_IP, TARGET)
        assert findings == []


# ── _fingerprint_stack tests ──────────────────────────────────────────────────

class TestFingerprintStack:

    def _make_rdata(self, text: str):
        rd = MagicMock()
        rd.to_text.return_value = text
        rd.exchange = MagicMock()
        rd.exchange.to_text.return_value = text
        return rd

    def test_google_workspace_detected_from_mx(self):
        mod = CompanyMapperModule()
        mod._resolver.resolve = MagicMock(
            side_effect=lambda name, rtype: (
                [self._make_rdata("aspmx.l.google.com.")] if rtype == "MX"
                else (_ for _ in ()).throw(dns.resolver.NoAnswer())
            )
        )
        findings = mod._fingerprint_stack(TARGET)
        email_f = next((f for f in findings if f.finding_type == "email_provider"), None)
        assert email_f is not None
        assert "Google" in email_f.value

    def test_cloudflare_dns_detected_from_ns(self):
        mod = CompanyMapperModule()
        def resolver(name, rtype):
            if rtype == "NS":
                return [self._make_rdata("ns1.cloudflare.com.")]
            raise dns.resolver.NoAnswer()
        mod._resolver.resolve = MagicMock(side_effect=resolver)
        findings = mod._fingerprint_stack(TARGET)
        dns_f = next((f for f in findings if f.finding_type == "dns_provider"), None)
        assert dns_f is not None
        assert "Cloudflare" in dns_f.value

    def test_noanswer_does_not_crash(self):
        mod = CompanyMapperModule()
        mod._resolver.resolve = MagicMock(side_effect=dns.resolver.NoAnswer())
        findings = mod._fingerprint_stack(TARGET)
        assert isinstance(findings, list)


# ── Port classification tests ─────────────────────────────────────────────────

class TestPortClassification:
    def test_redis_is_high(self):
        assert CompanyMapperModule._classify_port(6379) == RiskLevel.HIGH

    def test_mongodb_is_high(self):
        assert CompanyMapperModule._classify_port(27017) == RiskLevel.HIGH

    def test_mysql_is_high(self):
        assert CompanyMapperModule._classify_port(3306) == RiskLevel.HIGH

    def test_ssh_is_medium(self):
        assert CompanyMapperModule._classify_port(22) == RiskLevel.MEDIUM

    def test_alt_web_is_medium(self):
        assert CompanyMapperModule._classify_port(8080) == RiskLevel.MEDIUM

    def test_unknown_port_is_low(self):
        assert CompanyMapperModule._classify_port(12345) == RiskLevel.LOW


# ── Full async run integration ────────────────────────────────────────────────

@pytest.mark.anyio
async def test_full_run_no_ips_returns_error_finding():
    mod = CompanyMapperModule()
    mod._resolver.resolve = MagicMock(side_effect=dns.resolver.NXDOMAIN())
    result = await mod.run("nonexistent-target-xyz.invalid")
    assert result.module_name == "company_mapper"
    assert any(f.finding_type == "resolution_error" for f in result.findings)


@pytest.mark.anyio
async def test_full_run_with_mocked_apis():
    mod = CompanyMapperModule()

    shodan_data = json.loads(
        (FIXTURES / "shodan_internetdb_93_184_216_34.json").read_text()
    )
    geo_data = json.loads(
        (FIXTURES / "ipapi_93_184_216_34.json").read_text()
    )

    # Stub DNS resolution
    def fake_resolve(name, rtype):
        if rtype == "A":
            r = MagicMock(); r.to_text.return_value = TEST_IP; return [r]
        raise dns.resolver.NoAnswer()
    mod._resolver.resolve = MagicMock(side_effect=fake_resolve)

    url_map = {
        "internetdb.shodan.io": _mock_response(200, shodan_data),
        "ipapi.co":             _mock_response(200, geo_data),
        "hackertarget.com":     _mock_response(200, text="example.com\nother.com"),
    }

    with patch("httpx.AsyncClient", return_value=_AsyncClientCtx(url_map)):
        result = await mod.run(TARGET)

    assert result.status == ModuleStatus.SUCCESS
    types = {f.finding_type for f in result.findings}
    assert "resolved_ip"    in types
    assert "open_port"      in types
    assert "known_cve"      in types
    assert "ip_geolocation" in types
    assert "ip_asn"         in types
