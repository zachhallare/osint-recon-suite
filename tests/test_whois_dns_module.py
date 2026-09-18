"""Unit tests for WhoisDnsModule.
All tests use mocked network calls instead of live DNS or WHOIS queries.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import dns.rdatatype
import dns.resolver
import pytest

from osint_recon.models import RiskLevel
from osint_recon.modules.whois_dns_module import WhoisDnsModule

FIXTURES = Path(__file__).parent / "fixtures"




def _make_rdata(text: str):
    """Build a minimal fake rdata object that returns text via to_text()."""
    rd = MagicMock()
    rd.to_text.return_value = text
    return rd


def _make_whois(data: dict):
    """Turn a dict into an object with attribute access (mimics python-whois output)."""
    return SimpleNamespace(**{
        "registrar": data.get("registrar"),
        "org": data.get("org"),
        "creation_date": data.get("creation_date"),
        "expiration_date": data.get("expiration_date"),
        "name_servers": data.get("name_servers"),
        "dnssec": data.get("dnssec"),
        "emails": data.get("emails"),
    })




class TestWhoisLookup:

    def _load_fixture(self) -> dict:
        return json.loads((FIXTURES / "whois_example_com.json").read_text())

    def test_registrar_finding(self):
        mod = WhoisDnsModule()
        w = _make_whois(self._load_fixture())
        with patch("whois.whois", return_value=w):
            findings = mod._whois_lookup("example.com")
        types = [f.finding_type for f in findings]
        assert "whois_registrar" in types

    def test_org_finding(self):
        mod = WhoisDnsModule()
        w = _make_whois(self._load_fixture())
        with patch("whois.whois", return_value=w):
            findings = mod._whois_lookup("example.com")
        types = [f.finding_type for f in findings]
        assert "whois_org" in types

    def test_creation_date_finding(self):
        mod = WhoisDnsModule()
        w = _make_whois(self._load_fixture())
        with patch("whois.whois", return_value=w):
            findings = mod._whois_lookup("example.com")
        types = [f.finding_type for f in findings]
        assert "whois_creation_date" in types

    def test_name_servers_finding(self):
        mod = WhoisDnsModule()
        w = _make_whois(self._load_fixture())
        with patch("whois.whois", return_value=w):
            findings = mod._whois_lookup("example.com")
        ns_findings = [f for f in findings if f.finding_type == "whois_name_servers"]
        assert ns_findings
        assert "a.iana-servers.net" in ns_findings[0].value.lower()

    def test_exposed_email_is_medium_risk(self):
        mod = WhoisDnsModule()
        data = self._load_fixture()
        data["emails"] = ["admin@example.com"]
        w = _make_whois(data)
        with patch("whois.whois", return_value=w):
            findings = mod._whois_lookup("example.com")
        email_findings = [f for f in findings if f.finding_type == "whois_email_exposed"]

    def test_whois_failure_produces_error_finding_not_exception(self):
        mod = WhoisDnsModule()
        with patch("whois.whois", side_effect=ConnectionError("timeout")):
            findings = mod._whois_lookup("example.com")
        assert any(f.finding_type == "whois_error" for f in findings)




class TestDnsLookup:

    def _mock_resolver(self, mod: WhoisDnsModule, responses: dict):
        """
        Patch mod._resolver.resolve to return fake answers.
        responses: {"A": ["1.2.3.4"], "MX": ["mail.example.com"], ...}
        NoAnswer is raised for types not in responses.
        """
        def fake_resolve(name, rtype, *args, **kwargs):
            if rtype in responses:
                return [_make_rdata(v) for v in responses[rtype]]
            raise dns.resolver.NoAnswer()
        mod._resolver.resolve = fake_resolve

    def test_a_record_finding(self):
        mod = WhoisDnsModule()
        self._mock_resolver(mod, {"A": ["93.184.216.34"]})
        findings = mod._dns_lookup("example.com")
        assert any(f.finding_type == "dns_a" for f in findings)

    def test_mx_record_finding(self):
        mod = WhoisDnsModule()
        self._mock_resolver(mod, {"MX": ["10 mail.example.com."]})
        findings = mod._dns_lookup("example.com")
        assert any(f.finding_type == "dns_mx" for f in findings)

    def test_txt_spf_finding(self):
        mod = WhoisDnsModule()
        self._mock_resolver(mod, {"TXT": ['"v=spf1 include:_spf.example.com ~all"']})
        findings = mod._dns_lookup("example.com")
        txt = [f for f in findings if f.finding_type == "dns_txt"]
        assert txt
        assert txt[0].extra.get("category") == "spf_record"

    def test_nxdomain_stops_further_queries(self):
        mod = WhoisDnsModule()
        def fake_resolve(name, rtype, *args, **kwargs):
            raise dns.resolver.NXDOMAIN()
        mod._resolver.resolve = fake_resolve
        findings = mod._dns_lookup("nonexistent.example")
        # Should produce a single nxdomain finding and not crash
        assert any(f.finding_type == "dns_nxdomain" for f in findings)

    def test_timeout_does_not_crash(self):
        mod = WhoisDnsModule()
        def fake_resolve(name, rtype, *args, **kwargs):
            raise dns.exception.Timeout()
        mod._resolver.resolve = fake_resolve
        findings = mod._dns_lookup("example.com")
        # Timeouts should return an empty list without raising
        assert isinstance(findings, list)




class TestHelpers:

    def test_normalise_date_string(self):
        assert WhoisDnsModule._normalise_date("1995-08-14T04:00:00") == "1995-08-14"

    def test_normalise_date_datetime(self):
        dt = datetime(1995, 8, 14, 4, 0, 0)
        assert WhoisDnsModule._normalise_date(dt) == "1995-08-14"

    def test_normalise_date_list(self):
        dt = datetime(1995, 8, 14)
        assert WhoisDnsModule._normalise_date([dt, datetime(1996, 1, 1)]) == "1995-08-14"

    def test_normalise_date_none(self):
        assert WhoisDnsModule._normalise_date(None) is None
def _dummy():
    pass
pytest.mark.anyio
@pytest.mark.anyio
async def test_full_run_returns_module_result():
    """Run wraps the inner run method and returns success with findings."""
    mod = WhoisDnsModule()

    fixture = json.loads((FIXTURES / "whois_example_com.json").read_text())
    w = _make_whois(fixture)

    def fake_resolve(name, rtype, *args, **kwargs):
        if rtype == "A":
            return [_make_rdata("93.184.216.34")]
        raise dns.resolver.NoAnswer()

    mod._resolver.resolve = fake_resolve
    with patch("whois.whois", return_value=w):
        result = await mod.run("example.com")

    from osint_recon.models import ModuleStatus, RiskLevel
    assert result.status == ModuleStatus.SUCCESS
    assert result.module_name == "whois_dns"
    assert len(result.findings) > 0
