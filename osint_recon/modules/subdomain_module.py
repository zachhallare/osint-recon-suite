"""
osint_recon/modules/subdomain_module.py
---------------------------------------
Step 3 of the Critical Path: Subdomain Enumerator.

Sources (passive only, no active scanning)
------------------------------------------
  1. crt.sh  — Certificate Transparency log search (primary source)
     Endpoint: https://crt.sh/?q=%25.<domain>&output=json
     Returns every certificate ever issued for the domain and its subdomains.

  2. DNS validation  — each discovered subdomain is resolved via DNS to
     confirm it is currently live (A or AAAA record exists).

Risk classification
-------------------
  • Wildcard subdomains (*.domain.com)  → LOW   (broad surface, worth noting)
  • Subdomain resolves to a live IP    → INFO   (confirmed live)
  • Subdomain found but DNS fails      → INFO   (may be stale cert entry)
  • Unusual / interesting names        → MEDIUM (e.g. dev, staging, admin, vpn, git)

Error handling
--------------
  • crt.sh timeout or non-200 → module returns with error finding, no crash.
  • Per-subdomain DNS failures are silently skipped; only live ones flagged.

Dependencies
------------
  httpx       — async HTTP client for crt.sh
  dnspython   — live DNS validation of discovered subdomains
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import httpx

from osint_recon.base_module import BaseModule
from osint_recon.models import Finding, RiskLevel

logger = logging.getLogger(__name__)

_UTC = timezone.utc

# crt.sh endpoint — %25 is URL-encoded %
_CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"

# Substrings in subdomain names that are operationally interesting
_SENSITIVE_KEYWORDS = {
    "admin", "administrator", "portal", "dashboard",
    "dev", "development", "staging", "stage", "uat", "test", "qa",
    "vpn", "remote", "access", "citrix", "rdp",
    "api", "rest", "graphql", "internal", "intranet",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "jira", "confluence",
    "mail", "smtp", "imap", "webmail", "autodiscover",
    "ftp", "sftp", "backup", "db", "database", "sql", "mysql", "mongo",
    "phpmyadmin", "cpanel", "plesk", "whm",
    "s3", "storage", "cdn", "assets", "static",
    "old", "legacy", "archive", "temp", "tmp",
    "login", "auth", "sso", "oauth",
}

# Request timeout for crt.sh (seconds)
_HTTP_TIMEOUT = 20.0


class SubdomainModule(BaseModule):
    """
    Discovers subdomains via Certificate Transparency (crt.sh)
    and validates live ones via DNS.
    """

    MODULE_NAME = "subdomain"

    def __init__(
        self,
        http_timeout: float = _HTTP_TIMEOUT,
        dns_timeout: float = 5.0,
        max_dns_concurrency: int = 20,
    ) -> None:
        self.http_timeout = http_timeout
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = dns_timeout
        self._resolver.lifetime = dns_timeout
        self._semaphore = asyncio.Semaphore(max_dns_concurrency)

    # ------------------------------------------------------------------
    # Main implementation
    # ------------------------------------------------------------------

    async def _run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []

        # Step 1: fetch subdomains from crt.sh
        subdomains, fetch_error = await self._fetch_crtsh(target)

        if fetch_error:
            findings.append(Finding(
                module_name=self.MODULE_NAME,
                finding_type="crtsh_error",
                value=fetch_error,
                risk_level=RiskLevel.INFO,
                extra={"source": "crt.sh"},
            ))
            return findings

        if not subdomains:
            logger.info("[subdomain] No subdomains found in crt.sh for %s", target)
            return findings

        logger.info(
            "[subdomain] crt.sh returned %d unique subdomain(s) for %s",
            len(subdomains), target,
        )

        # Step 2: DNS-validate all subdomains concurrently
        dns_tasks = [self._check_subdomain(sd, target) for sd in subdomains]
        results = await asyncio.gather(*dns_tasks, return_exceptions=False)

        for finding in results:
            if finding is not None:
                findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # crt.sh fetch
    # ------------------------------------------------------------------

    async def _fetch_crtsh(self, domain: str) -> tuple[set[str], str | None]:
        """
        Query crt.sh for all certificate entries for *domain*.

        Returns (set_of_subdomains, error_string_or_None).
        """
        url = _CRTSH_URL.format(domain=domain)
        logger.debug("[subdomain] Querying crt.sh: %s", url)

        try:
            async with httpx.AsyncClient(timeout=self.http_timeout, follow_redirects=True) as client:
                resp = await client.get(url)

            if resp.status_code != 200:
                return set(), f"crt.sh returned HTTP {resp.status_code}"

            data = resp.json()

        except httpx.TimeoutException:
            return set(), f"crt.sh request timed out after {self.http_timeout}s"
        except httpx.RequestError as exc:
            return set(), f"crt.sh request failed: {exc}"
        except Exception as exc:  # noqa: BLE001
            return set(), f"crt.sh unexpected error: {exc}"

        # Parse and deduplicate subdomains
        subdomains: set[str] = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            # crt.sh returns multi-value SANs separated by newlines
            for name in name_value.splitlines():
                name = name.strip().lower()
                if not name or name == domain:
                    continue
                # Strip leading wildcard marker for deduplication
                canonical = name.lstrip("*.")
                if canonical.endswith(f".{domain}") or canonical == domain:
                    subdomains.add(name)

        return subdomains, None

    # ------------------------------------------------------------------
    # DNS validation
    # ------------------------------------------------------------------

    async def _check_subdomain(self, subdomain: str, root_domain: str) -> Finding | None:
        """
        Resolve *subdomain* via DNS. Returns a Finding regardless of result.
        Uses a semaphore to cap concurrent DNS queries.
        """
        is_wildcard = subdomain.startswith("*.")
        lookup_name = subdomain.lstrip("*.") if is_wildcard else subdomain

        async with self._semaphore:
            live_ips = await self._resolve(lookup_name)

        # Determine risk level
        risk = self._classify_risk(subdomain, live_ips, is_wildcard)

        extra: dict = {
            "source": "crt.sh + dns",
            "live": bool(live_ips),
            "wildcard": is_wildcard,
        }
        if live_ips:
            extra["resolved_ips"] = live_ips

        # Flag interesting subdomain keywords
        matched_keywords = [
            kw for kw in _SENSITIVE_KEYWORDS
            if re.search(rf"(?:^|[.\-]){re.escape(kw)}(?:[.\-]|$)", lookup_name)
        ]
        if matched_keywords:
            extra["sensitive_keywords"] = matched_keywords

        return Finding(
            module_name=self.MODULE_NAME,
            finding_type="subdomain",
            value=subdomain,
            risk_level=risk,
            extra=extra,
        )

    async def _resolve(self, name: str) -> list[str]:
        """Try to resolve *name* to IP addresses. Returns empty list on failure."""
        loop = asyncio.get_event_loop()
        try:
            answers = await loop.run_in_executor(
                None, lambda: self._resolver.resolve(name, "A")
            )
            return [r.to_text() for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except dns.exception.Timeout:
            logger.debug("[subdomain] DNS timeout for %s", name)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[subdomain] DNS error for %s: %s", name, exc)

        # Try AAAA if A fails
        try:
            answers = await loop.run_in_executor(
                None, lambda: self._resolver.resolve(name, "AAAA")
            )
            return [r.to_text() for r in answers]
        except Exception:  # noqa: BLE001
            pass

        return []

    # ------------------------------------------------------------------
    # Risk classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_risk(subdomain: str, live_ips: list[str], is_wildcard: bool) -> RiskLevel:
        if is_wildcard:
            return RiskLevel.LOW  # wildcard cert = broad attack surface

        lookup_name = subdomain.lower()
        if any(kw in lookup_name for kw in _SENSITIVE_KEYWORDS):
            return RiskLevel.MEDIUM  # interesting hostname (dev, admin, vpn…)

        if live_ips:
            return RiskLevel.INFO  # confirmed live, nothing special

        return RiskLevel.INFO  # stale cert entry, not currently live
