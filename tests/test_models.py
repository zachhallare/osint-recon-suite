"""
tests/test_models.py
--------------------
Unit tests for shared data models — no network, no DB.
"""

from datetime import datetime

import pytest

from osint_recon.models import (
    Finding,
    ModuleResult,
    ModuleStatus,
    RiskLevel,
    ScanResult,
)


class TestFinding:
    def test_defaults(self):
        f = Finding(module_name="whois", finding_type="registrar", value="GoDaddy")
        assert f.risk_level == RiskLevel.INFO
        assert f.extra == {}
        assert isinstance(f.discovered_at, datetime)

    def test_to_dict_keys(self):
        f = Finding(module_name="dns", finding_type="A", value="1.2.3.4")
        d = f.to_dict()
        assert set(d.keys()) == {
            "module_name", "finding_type", "value",
            "risk_level", "extra", "discovered_at",
        }

    def test_risk_level_serialised(self):
        f = Finding(module_name="x", finding_type="y", value="z", risk_level=RiskLevel.HIGH)
        assert f.to_dict()["risk_level"] == "high"


class TestModuleResult:
    def test_failed_result(self):
        r = ModuleResult(
            module_name="whois",
            status=ModuleStatus.FAILED,
            error="ConnectionError: timeout",
        )
        assert r.findings == []
        assert r.to_dict()["status"] == "failed"
        assert r.to_dict()["error"] == "ConnectionError: timeout"

    def test_success_with_findings(self):
        findings = [
            Finding(module_name="dns", finding_type="A", value="1.2.3.4"),
            Finding(module_name="dns", finding_type="MX", value="mail.example.com"),
        ]
        r = ModuleResult(module_name="dns", status=ModuleStatus.SUCCESS, findings=findings)
        assert len(r.to_dict()["findings"]) == 2


class TestScanResult:
    def _make_scan(self):
        return ScanResult(
            target="example.com",
            scan_run_id=1,
            started_at=datetime(2024, 1, 1, 12, 0, 0),
            completed_at=datetime(2024, 1, 1, 12, 0, 30),
        )

    def test_all_findings_flattened(self):
        scan = self._make_scan()
        scan.results = [
            ModuleResult(
                module_name="dns",
                status=ModuleStatus.SUCCESS,
                findings=[
                    Finding(module_name="dns", finding_type="A", value="1.2.3.4"),
                ],
            ),
            ModuleResult(
                module_name="whois",
                status=ModuleStatus.SUCCESS,
                findings=[
                    Finding(module_name="whois", finding_type="registrar", value="GoDaddy"),
                    Finding(module_name="whois", finding_type="expiry", value="2025-01-01"),
                ],
            ),
        ]
        assert len(scan.all_findings) == 3

    def test_total_duration(self):
        scan = self._make_scan()
        assert scan.total_duration_s == 30.0

    def test_to_dict_shape(self):
        scan = self._make_scan()
        d = scan.to_dict()
        assert d["target"] == "example.com"
        assert d["scan_run_id"] == 1
        assert isinstance(d["results"], list)
