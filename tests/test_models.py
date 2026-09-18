"""Unit tests for shared data models without network or database dependencies."""

from datetime import datetime

import pytest

from osint_recon.models import (
    Finding,
    ModuleResult,
    ModuleStatus,
    RiskLevel,
    ScanResult,
    score_to_tier,
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

    def test_risk_level_score(self):
        assert RiskLevel.INFO.score == 0
        assert RiskLevel.LOW.score == 1
        assert RiskLevel.MEDIUM.score == 5
        assert RiskLevel.HIGH.score == 10
        assert RiskLevel.CRITICAL.score == 25

def test_score_to_tier():
    assert score_to_tier(0) == "Informational"
    assert score_to_tier(1) == "Low"
    assert score_to_tier(4) == "Low"
    assert score_to_tier(5) == "Low"
    assert score_to_tier(9) == "Low"
    assert score_to_tier(10) == "Medium"
    assert score_to_tier(24) == "Medium"
    assert score_to_tier(25) == "High"
    assert score_to_tier(49) == "High"
    assert score_to_tier(50) == "Critical"
    assert score_to_tier(100) == "Critical"


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

    def test_scan_risk_scores(self):
        scan = self._make_scan()
        
        # Test zero findings
        assert scan.total_risk_score == 0
        assert scan.overall_risk_tier == "Informational"
        
        # Test findings across all severity tiers
        scan.results = [
            ModuleResult(
                module_name="dns",
                status=ModuleStatus.SUCCESS,
                findings=[
                    Finding(module_name="dns", finding_type="x", value="1", risk_level=RiskLevel.INFO),
                    Finding(module_name="dns", finding_type="x", value="2", risk_level=RiskLevel.LOW),
                ],
            ),
            ModuleResult(
                module_name="whois",
                status=ModuleStatus.SUCCESS,
                findings=[
                    Finding(module_name="whois", finding_type="y", value="3", risk_level=RiskLevel.MEDIUM),
                    Finding(module_name="whois", finding_type="y", value="4", risk_level=RiskLevel.HIGH),
                    Finding(module_name="whois", finding_type="y", value="5", risk_level=RiskLevel.CRITICAL),
                ],
            ),
        ]
        
        # INFO(0) + LOW(1) + MEDIUM(5) + HIGH(10) + CRITICAL(25) = 41
        assert scan.results[0].risk_score == 1
        assert scan.results[0].risk_tier == "Low"
        
        assert scan.results[1].risk_score == 40
        assert scan.results[1].risk_tier == "High"
        
        assert scan.total_risk_score == 41
        assert scan.overall_risk_tier == "High"
