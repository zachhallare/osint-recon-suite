"""
tests/test_reporter.py
----------------------
Tests for the HTML report generator.
Verifies the rendered output contains expected structural elements
without requiring a running browser.
"""

from datetime import datetime
from pathlib import Path

import pytest

from osint_recon.models import Finding, ModuleResult, ModuleStatus, RiskLevel, ScanResult
from osint_recon.reporter import Reporter


@pytest.fixture
def sample_scan():
    scan = ScanResult(
        target="example.com",
        scan_run_id=42,
        started_at=datetime(2024, 6, 1, 10, 0, 0),
        completed_at=datetime(2024, 6, 1, 10, 0, 25),
    )
    scan.results = [
        ModuleResult(
            module_name="mock",
            status=ModuleStatus.SUCCESS,
            findings=[
                Finding(
                    module_name="mock",
                    finding_type="mock_info",
                    value="test finding",
                    risk_level=RiskLevel.INFO,
                ),
                Finding(
                    module_name="mock",
                    finding_type="mock_high",
                    value="high risk finding",
                    risk_level=RiskLevel.HIGH,
                    extra={"url": "https://example.com/.git/HEAD"},
                ),
            ],
            duration_s=0.001,
        ),
        ModuleResult(
            module_name="broken",
            status=ModuleStatus.FAILED,
            error="ConnectionError: timeout",
            duration_s=5.0,
        ),
    ]
    return scan


def test_report_creates_file(tmp_path, sample_scan):
    reporter = Reporter(output_dir=tmp_path)
    path = reporter.render(sample_scan)
    assert path.exists()
    assert path.suffix == ".html"


def test_report_contains_target(tmp_path, sample_scan):
    reporter = Reporter(output_dir=tmp_path)
    path = reporter.render(sample_scan)
    content = path.read_text(encoding="utf-8")
    assert "example.com" in content


def test_report_contains_scan_id(tmp_path, sample_scan):
    reporter = Reporter(output_dir=tmp_path)
    path = reporter.render(sample_scan)
    content = path.read_text(encoding="utf-8")
    assert "#42" in content


def test_report_shows_findings(tmp_path, sample_scan):
    reporter = Reporter(output_dir=tmp_path)
    path = reporter.render(sample_scan)
    content = path.read_text(encoding="utf-8")
    assert "test finding" in content
    assert "high risk finding" in content


def test_report_shows_error_module(tmp_path, sample_scan):
    reporter = Reporter(output_dir=tmp_path)
    path = reporter.render(sample_scan)
    content = path.read_text(encoding="utf-8")
    assert "ConnectionError: timeout" in content


def test_report_contains_risk_badges(tmp_path, sample_scan):
    reporter = Reporter(output_dir=tmp_path)
    path = reporter.render(sample_scan)
    content = path.read_text(encoding="utf-8")
    # Both INFO and HIGH findings should be represented
    assert 'class="risk info"' in content
    assert 'class="risk high"' in content
