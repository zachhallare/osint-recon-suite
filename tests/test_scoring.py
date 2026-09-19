import pytest
from osint_recon.models import Finding, RiskLevel, ModuleResult, ModuleStatus, ScanResult
from osint_recon.scoring import post_process_findings, get_base_risk

def test_base_risk_mapping():
    assert get_base_risk(Finding("m", "robots_txt", "")) == RiskLevel.INFO
    assert get_base_risk(Finding("m", "shared_hosting", "")) == RiskLevel.LOW
    assert get_base_risk(Finding("m", "php_info", "")) == RiskLevel.MEDIUM
    assert get_base_risk(Finding("m", "git_exposure", "")) == RiskLevel.HIGH
    assert get_base_risk(Finding("m", "private_key", "")) == RiskLevel.CRITICAL
    
def test_open_port_base_risk():
    assert get_base_risk(Finding("m", "open_port", "", extra={"port": 80})) == RiskLevel.LOW
    assert get_base_risk(Finding("m", "open_port", "", extra={"port": 8080})) == RiskLevel.MEDIUM
    assert get_base_risk(Finding("m", "open_port", "", extra={"port": 3306})) == RiskLevel.HIGH
    assert get_base_risk(Finding("m", "open_port", "", extra={"port": 22})) == RiskLevel.HIGH

def test_email_breach_base_risk():
    # Sensitive breach is HIGH
    f1 = Finding("m", "email_breach", "", extra={"is_sensitive": True, "breach_date": "2010-01-01"})
    assert get_base_risk(f1) == RiskLevel.HIGH
    
    # Recent breach (< 3 years) is MEDIUM
    from datetime import datetime, timedelta
    recent_date = (datetime.now() - timedelta(days=365)).strftime("%Y-%m-%d")
    f2 = Finding("m", "email_breach", "", extra={"is_sensitive": False, "breach_date": recent_date})
    assert get_base_risk(f2) == RiskLevel.MEDIUM
    
    # Old breach (> 3 years) is LOW
    old_date = (datetime.now() - timedelta(days=2000)).strftime("%Y-%m-%d")
    f3 = Finding("m", "email_breach", "", extra={"is_sensitive": False, "breach_date": old_date})
    assert get_base_risk(f3) == RiskLevel.LOW
    
    # Missing date/sensitivity is LOW
    f4 = Finding("m", "email_breach", "", extra={})
    assert get_base_risk(f4) == RiskLevel.LOW

def test_escalation_path():
    # 1. No CVE -> no escalation
    findings = [
        Finding("m", "open_port", "1.1.1.1:80", extra={"ip": "1.1.1.1", "port": 80}),
        Finding("m", "open_port", "1.1.1.1:8080", extra={"ip": "1.1.1.1", "port": 8080}),
        Finding("m", "open_port", "1.1.1.1:3389", extra={"ip": "1.1.1.1", "port": 3389}),
    ]
    processed = post_process_findings(findings)
    assert processed[0].risk_level == RiskLevel.LOW
    assert processed[1].risk_level == RiskLevel.MEDIUM
    assert processed[2].risk_level == RiskLevel.HIGH
    
    # 2. With CVE -> all ports for that IP escalate
    findings.append(Finding("m", "known_cve", "CVE-123", extra={"ip": "1.1.1.1"}))
    processed = post_process_findings(findings)
    # 1.1.1.1:80 -> HIGH (escalated from LOW)
    assert processed[0].risk_level == RiskLevel.HIGH
    # 1.1.1.1:8080 -> HIGH (escalated from MEDIUM)
    assert processed[1].risk_level == RiskLevel.HIGH
    # 1.1.1.1:3389 -> CRITICAL (escalated from HIGH, risky port)
    assert processed[2].risk_level == RiskLevel.CRITICAL
    assert processed[3].risk_level == RiskLevel.HIGH

def test_escalation_is_host_scoped():
    findings = [
        # Host A has open port and CVE
        Finding("m", "open_port", "1.1.1.1:80", extra={"ip": "1.1.1.1", "port": 80}),
        Finding("m", "known_cve", "CVE-123", extra={"ip": "1.1.1.1"}),
        # Host B only has open port
        Finding("m", "open_port", "2.2.2.2:80", extra={"ip": "2.2.2.2", "port": 80}),
    ]
    processed = post_process_findings(findings)
    
    # Host A's port is escalated
    assert processed[0].risk_level == RiskLevel.HIGH
    # Host B's port remains LOW
    assert processed[2].risk_level == RiskLevel.LOW

def test_target_spanning_all_severity_tiers():
    findings = [
        Finding("m", "robots_txt", ""), # INFO (0)
        Finding("m", "shared_hosting", ""), # LOW (1)
        Finding("m", "php_info", ""), # MEDIUM (5)
        Finding("m", "git_exposure", ""), # HIGH (10)
        Finding("m", "private_key", ""), # CRITICAL (25)
    ]
    processed = post_process_findings(findings)
    
    from datetime import datetime
    scan = ScanResult(target="example.com", scan_run_id=1, started_at=datetime.now())
    scan.results = [
        ModuleResult(
            module_name="test_mod",
            status=ModuleStatus.SUCCESS,
            findings=processed
        )
    ]
    
    # 0 + 1 + 5 + 10 + 25 = 41
    assert scan.total_risk_score == 41
    assert scan.overall_risk_tier == "High"
