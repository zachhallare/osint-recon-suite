"""Checks discovered email addresses against Have I Been Pwned (HIBP) API."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime

import httpx

from osint_recon.base_module import BaseModule
from osint_recon.models import Finding, RiskLevel

logger = logging.getLogger(__name__)

class BreachModule(BaseModule):
    """Checks discovered email addresses against Have I Been Pwned API."""

    MODULE_NAME = "breach_check"
    RUN_AFTER_OTHERS = True
    
    EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

    async def _run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        
        # 1. Extract unique emails from previous findings matching the target domain
        emails: set[str] = set()
        for finding in self.previous_findings:
            if isinstance(finding.value, str):
                matches = self.EMAIL_REGEX.findall(finding.value)
                for match in matches:
                    email_clean = match.lower()
                    domain_part = email_clean.split('@')[-1]
                    if domain_part == target or domain_part.endswith(f".{target}"):
                        emails.add(email_clean)
                
        if not emails:
            logger.info("[%s] No emails found to check for breaches.", self.MODULE_NAME)
            self.source_status = "Skipped - No target emails discovered"
            return findings
            
        api_key = os.environ.get("HIBP_API_KEY")
        if not api_key:
            logger.warning("[%s] HIBP_API_KEY missing. Skipping breach checks.", self.MODULE_NAME)
            self.source_status = "Skipped - Missing HIBP API Key"
            findings.append(Finding(
                module_name=self.MODULE_NAME,
                finding_type="breach_error",
                value="HIBP_API_KEY environment variable is not set. Skipped.",
                risk_level=RiskLevel.INFO,
                extra={"source": "hibp"}
            ))
            return findings

        # 2. Check each email against HIBP
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "OSINT-Recon-Suite"
        }
        
        async with httpx.AsyncClient(headers=headers, timeout=10.0) as client:
            for email in emails:
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                try:
                    response = await client.get(url, params={"truncateResponse": "false"})
                    if response.status_code == 404:
                        # Not found in any breaches
                        logger.debug("[%s] Email %s not found in breaches.", self.MODULE_NAME, email)
                        continue
                    elif response.status_code == 429:
                        logger.warning("[%s] Rate limited by HIBP API.", self.MODULE_NAME)
                        findings.append(Finding(
                            module_name=self.MODULE_NAME,
                            finding_type="breach_error",
                            value=f"Rate limited by HIBP API while checking {email}",
                            risk_level=RiskLevel.INFO,
                            extra={"source": "hibp", "email": email}
                        ))
                        break
                    elif response.status_code == 401:
                        logger.error("[%s] Invalid HIBP API Key.", self.MODULE_NAME)
                        findings.append(Finding(
                            module_name=self.MODULE_NAME,
                            finding_type="breach_error",
                            value="Invalid HIBP API Key.",
                            risk_level=RiskLevel.INFO,
                            extra={"source": "hibp"}
                        ))
                        break
                    
                    response.raise_for_status()
                    breaches = response.json()
                    
                    for breach in breaches:
                        name = breach.get("Name", "Unknown")
                        breach_date_str = breach.get("BreachDate", "")
                        is_sensitive = breach.get("IsSensitive", False)
                                
                        findings.append(Finding(
                            module_name=self.MODULE_NAME,
                            finding_type="email_breach",
                            value=f"{email} found in {name} breach",
                            extra={
                                "source": "hibp",
                                "email": email,
                                "breach_name": name,
                                "breach_date": breach_date_str,
                                "is_sensitive": is_sensitive
                            }
                        ))
                            
                    # Respect HIBP rate limit (delay of 1.5s between requests is recommended, minimum is 1500ms)
                    await asyncio.sleep(1.6)
                except Exception as exc:
                    logger.error("[%s] Error checking email %s: %s", self.MODULE_NAME, email, exc)
                    findings.append(Finding(
                        module_name=self.MODULE_NAME,
                        finding_type="breach_error",
                        value=f"Error checking email {email}: {exc}",
                        risk_level=RiskLevel.INFO,
                        extra={"source": "hibp", "email": email}
                    ))
                    
        return findings
