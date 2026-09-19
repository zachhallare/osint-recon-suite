import pytest
import os
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timedelta

from osint_recon.modules.breach_module import BreachModule
from osint_recon.models import Finding, RiskLevel
from osint_recon.scoring import post_process_findings

@pytest.fixture
def breach_module():
    mod = BreachModule()
    mod.previous_findings = [
        Finding(module_name="test_mod", finding_type="whois_email", value="test@example.com"),
        Finding(module_name="test_mod", finding_type="other", value="not an email"),
        # Duplicates or mixed case
        Finding(module_name="test_mod", finding_type="doc_email", value="TEST@example.com")
    ]
    return mod

@pytest.mark.asyncio
async def test_zero_email_available():
    mod = BreachModule()
    mod.previous_findings = [
        Finding(module_name="test", finding_type="other", value="no emails here")
    ]
    findings = await mod._run("example.com")
    assert len(findings) == 0
    assert mod.source_status == "Skipped - No target emails discovered"

@pytest.mark.asyncio
@patch.dict(os.environ, clear=True)
async def test_missing_api_key(breach_module):
    findings = await breach_module._run("example.com")
    assert len(findings) == 1
    assert findings[0].finding_type == "breach_error"
    assert "HIBP_API_KEY" in findings[0].value
    assert breach_module.source_status == "Skipped - Missing HIBP API Key"

@pytest.mark.asyncio
@patch.dict(os.environ, {"HIBP_API_KEY": "dummy_key"})
@patch("httpx.AsyncClient.get")
async def test_no_breach_found(mock_get, breach_module):
    # Setup mock response 404
    mock_response = MagicMock()
    mock_response.status_code = 404
    
    # httpx.AsyncClient.get returns a response, not an async context manager
    mock_get.return_value = mock_response
    
    findings = await breach_module._run("example.com")
    # No breaches, so no findings returned
    assert len(findings) == 0

@pytest.mark.asyncio
@patch.dict(os.environ, {"HIBP_API_KEY": "dummy_key"})
@patch("httpx.AsyncClient.get")
# Mock asyncio.sleep to speed up tests
@patch("asyncio.sleep", new_callable=AsyncMock)
async def test_breach_found(mock_sleep, mock_get, breach_module):
    # Return breach data
    mock_response = MagicMock()
    mock_response.status_code = 200
    
    recent_date = (datetime.now() - timedelta(days=100)).strftime("%Y-%m-%d")
    old_date = (datetime.now() - timedelta(days=2000)).strftime("%Y-%m-%d")
    
    mock_response.json.return_value = [
        {"Name": "SensitiveBreach", "BreachDate": old_date, "IsSensitive": True},
        {"Name": "RecentBreach", "BreachDate": recent_date, "IsSensitive": False},
        {"Name": "OldBreach", "BreachDate": old_date, "IsSensitive": False}
    ]
    
    mock_get.return_value = mock_response
    
    findings = await breach_module._run("example.com")
    findings = post_process_findings(findings)
    
    # We should have 3 findings (one for each breach, for the single unique email test@example.com)
    assert len(findings) == 3
    
    # Sensitive should be HIGH
    sensitive_f = next(f for f in findings if f.extra["breach_name"] == "SensitiveBreach")
    assert sensitive_f.risk_level == RiskLevel.HIGH
    
    # Recent non-sensitive should be MEDIUM
    recent_f = next(f for f in findings if f.extra["breach_name"] == "RecentBreach")
    assert recent_f.risk_level == RiskLevel.MEDIUM
    
    # Old non-sensitive should be LOW
    old_f = next(f for f in findings if f.extra["breach_name"] == "OldBreach")
    assert old_f.risk_level == RiskLevel.LOW

@pytest.mark.asyncio
@patch.dict(os.environ, {"HIBP_API_KEY": "dummy_key"})
@patch("httpx.AsyncClient.get")
async def test_api_rate_limited(mock_get, breach_module):
    mock_response = MagicMock()
    mock_response.status_code = 429
    
    mock_get.return_value = mock_response
    
    findings = await breach_module._run("example.com")
    
    assert len(findings) == 1
    assert findings[0].finding_type == "breach_error"
    assert "Rate limited" in findings[0].value
