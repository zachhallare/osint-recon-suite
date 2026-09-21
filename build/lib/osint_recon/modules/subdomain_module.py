"""Discovers subdomains via Certificate Transparency and DNS records."""

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

# Query crt.sh with a wildcard pattern
_CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"

# Keywords that suggest administrative or staging services
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

# Request timeout for crt.sh in seconds
_HTTP_TIMEOUT = 20.0


class SubdomainModule(BaseModule):
    """Discovers subdomains via Certificate Transparency and validates live ones with DNS."""

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

    async def _run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        source_name = "crt.sh"
        self.source_status = "crtsh_ok"

        # Fetch subdomains from crt.sh
        subdomains, fetch_error = await self._fetch_crtsh(target)

        if fetch_error:
            logger.warning("[subdomain] crt.sh failed: %s. Falling back to Certspotter.", fetch_error)
            source_name = "certspotter"
            self.source_status = "crtsh_failed_fallback_used"
            
            subdomains, fallback_error = await self._fetch_certspotter(target)
            
            if fallback_error:
                logger.error("[subdomain] Certspotter also failed: %s", fallback_error)
                self.source_status = "all_sources_failed"
                
                findings.append(Finding(
                    module_name=self.MODULE_NAME,
                    finding_type="crtsh_error",
                    value=fetch_error,
                    extra={"source": "crt.sh"},
                ))
                findings.append(Finding(
                    module_name=self.MODULE_NAME,
                    finding_type="certspotter_error",
                    value=fallback_error,
                    extra={"source": "certspotter"},
                ))
                return findings

        if not subdomains:
            logger.info("[subdomain] No subdomains found in %s for %s", source_name, target)
            return findings

        logger.info(
            "[subdomain] %s returned %d unique subdomain(s) for %s",
            source_name, len(subdomains), target,
        )

        # Check all subdomains concurrently with DNS
        dns_tasks = [self._check_subdomain(sd, target, source_name) for sd in subdomains]
        results = await asyncio.gather(*dns_tasks, return_exceptions=False)

        for finding in results:
            if finding is not None:
                findings.append(finding)

        return findings

    async def _fetch_crtsh(self, domain: str) -> tuple[set[str], str | None]:
        """Query crt.sh for certificate records matching the domain."""
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
            # Split multi-value certificate names
            for name in name_value.splitlines():
                name = name.strip().lower()
                if not name or name == domain:
                    continue
                # Strip leading wildcard marker
                canonical = name.lstrip("*.")
                if canonical.endswith(f".{domain}") or canonical == domain:
                    subdomains.add(name)

        return subdomains, None

    async def _fetch_certspotter(self, domain: str) -> tuple[set[str], str | None]:
        """Query Certspotter for certificate records matching the domain."""
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        logger.debug("[subdomain] Querying Certspotter: %s", url)

        try:
            async with httpx.AsyncClient(timeout=self.http_timeout, follow_redirects=True) as client:
                resp = await client.get(url)

            if resp.status_code != 200:
                return set(), f"Certspotter returned HTTP {resp.status_code}"

            data = resp.json()

        except httpx.TimeoutException:
            return set(), f"Certspotter request timed out after {self.http_timeout}s"
        except httpx.RequestError as exc:
            return set(), f"Certspotter request failed: {exc}"
        except Exception as exc:  # noqa: BLE001
            return set(), f"Certspotter unexpected error: {exc}"

        subdomains: set[str] = set()
        for entry in data:
            dns_names = entry.get("dns_names", [])
            for name in dns_names:
                name = name.strip().lower()
                if not name or name == domain:
                    continue
                canonical = name.lstrip("*.")
                if canonical.endswith(f".{domain}") or canonical == domain:
                    subdomains.add(name)

        return subdomains, None

    async def _check_subdomain(self, subdomain: str, root_domain: str, source_name: str) -> Finding | None:
        """Resolve a subdomain and return a finding."""
        is_wildcard = subdomain.startswith("*.")
        lookup_name = subdomain.lstrip("*.") if is_wildcard else subdomain

        async with self._semaphore:
            live_ips = await self._resolve(lookup_name)

        # Determine risk level
        risk = self._classify_risk(subdomain, live_ips, is_wildcard)

        extra: dict = {
            "source": f"{source_name} + dns",
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
            extra=extra,
        )

    async def _resolve(self, name: str) -> list[str]:
        """Resolve a hostname to IP addresses."""
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

        # Try IPv6 if IPv4 yields no records
        try:
            answers = await loop.run_in_executor(
                None, lambda: self._resolver.resolve(name, "AAAA")
            )
            return [r.to_text() for r in answers]
        except Exception:  # noqa: BLE001
            pass

        return []

    @staticmethod
    def _classify_risk(subdomain: str, live_ips: list[str], is_wildcard: bool) -> RiskLevel:
        if is_wildcard:
            return RiskLevel.LOW  # Wildcards suggest broader attack surface

        lookup_name = subdomain.lower()
        if any(kw in lookup_name for kw in _SENSITIVE_KEYWORDS):
            return RiskLevel.MEDIUM  # Flag sensitive names like admin or vpn

        if live_ips:
            return RiskLevel.INFO  # Active host

        return RiskLevel.INFO  # Inactive host
