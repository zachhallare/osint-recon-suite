"""Maps attack surface including open ports, geolocation, and co-hosted domains."""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Any

import dns.exception
import dns.resolver
import httpx

from osint_recon.base_module import BaseModule
from osint_recon.models import Finding, RiskLevel

logger = logging.getLogger(__name__)

_UTC = timezone.utc

_SHODAN_INTERNETDB  = "https://internetdb.shodan.io/{ip}"
_SHODAN_DISCLAIMER  = "Source: Shodan InternetDB — passive historical cache, may be stale or incomplete. Not a live port scan."
_IPAPI_URL          = "https://ipapi.co/{ip}/json/"
_HACKERTARGET_RIPLOOKUP = "https://api.hackertarget.com/reverseiplookup/?q={ip}"

_HTTP_TIMEOUT = 15.0

# Port risk classifications
_HIGH_RISK_PORTS = {
    21, 23, 3389, 5900, 5901,          # FTP, Telnet, RDP, VNC
    1433, 1521, 3306, 5432, 27017,     # MSSQL, Oracle, MySQL, Postgres, MongoDB
    6379, 11211,                        # Redis, Memcached
    2375, 2376,                         # Docker API
    9200, 9300,                         # Elasticsearch
    8500,                               # Consul
}
_MEDIUM_RISK_PORTS = {
    22, 25, 110, 143, 587, 993, 995,   # SSH, SMTP, POP3, IMAP
    8080, 8443, 8888,                   # Alternate web ports
    4848, 7001, 7002,                   # Application servers
    9090, 9091,                         # Admin ports
}

# Known email providers from MX records
_MX_PROVIDERS: list[tuple[str, str]] = [
    ("google",          "Google Workspace (Gmail)"),
    ("googlemail",      "Google Workspace (Gmail)"),
    ("aspmx.l.google",  "Google Workspace (Gmail)"),
    ("outlook.com",     "Microsoft 365 / Exchange Online"),
    ("protection.outlook", "Microsoft 365 / Exchange Online"),
    ("pphosted.com",    "Proofpoint Email Security"),
    ("mimecast.com",    "Mimecast Email Security"),
    ("barracuda",       "Barracuda Email Security"),
    ("zoho",            "Zoho Mail"),
    ("mail.protection", "Microsoft 365 / Exchange Online"),
    ("amazonses",       "Amazon SES"),
    ("sendgrid",        "SendGrid"),
    ("mailgun",         "Mailgun"),
]

# Known DNS providers from NS records
_NS_PROVIDERS: list[tuple[str, str]] = [
    ("awsdns",          "Amazon Route 53"),
    ("cloudflare",      "Cloudflare DNS"),
    ("ns.cloudflare",   "Cloudflare DNS"),
    ("azure-dns",       "Azure DNS"),
    ("googledomains",   "Google Domains DNS"),
    ("dnsmadeeasy",     "DNS Made Easy"),
    ("ultradns",        "UltraDNS"),
    ("dnsimple",        "DNSimple"),
    ("nsone",           "NS1 DNS"),
    ("akam",            "Akamai DNS"),
]


class CompanyMapperModule(BaseModule):
    """Maps attack surface including open ports, geolocation, and co-hosted domains."""

    MODULE_NAME = "company_mapper"

    def __init__(self, http_timeout: float = _HTTP_TIMEOUT, dns_timeout: float = 5.0) -> None:
        self.http_timeout = http_timeout
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = dns_timeout
        self._resolver.lifetime = dns_timeout

    async def _run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []

        # Resolve target IP addresses
        ips = self._resolve_ips(target)
        if not ips:
            findings.append(Finding(
                module_name=self.MODULE_NAME,
                finding_type="resolution_error",
                value=f"Could not resolve any IP for {target}",
                risk_level=RiskLevel.INFO,
            ))
            return findings

        logger.info("[company_mapper] Resolved %d IP(s) for %s: %s", len(ips), target, ips)

        # Run IP lookups concurrently
        ip_tasks = [self._analyse_ip(ip, target) for ip in ips]
        ip_finding_lists = await asyncio.gather(*ip_tasks, return_exceptions=False)
        for fl in ip_finding_lists:
            findings.extend(fl)

        # Fingerprint email and DNS providers
        findings.extend(self._fingerprint_stack(target))

        return findings

    def _resolve_ips(self, target: str) -> list[str]:
        ips: list[str] = []
        for rtype in ("A", "AAAA"):
            try:
                answers = self._resolver.resolve(target, rtype)
                ips.extend(r.to_text() for r in answers)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception as exc:
                logger.debug("[company_mapper] DNS %s failed for %s: %s", rtype, target, exc)
        return list(dict.fromkeys(ips))  # Deduplicate while preserving order

    async def _analyse_ip(self, ip: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.append(Finding(
            module_name=self.MODULE_NAME,
            finding_type="resolved_ip",
            value=ip,
            risk_level=RiskLevel.INFO,
            extra={"target": target},
        ))

        async with httpx.AsyncClient(timeout=self.http_timeout, follow_redirects=True) as client:
            shodan_f, geo_f, rip_f = await asyncio.gather(
                self._shodan_internetdb(client, ip),
                self._geolocate_ip(client, ip),
                self._reverse_ip_lookup(client, ip, target),
                return_exceptions=False,
            )

        findings.extend(shodan_f)
        findings.extend(geo_f)
        findings.extend(rip_f)
        return findings

    async def _shodan_internetdb(self, client: httpx.AsyncClient, ip: str) -> list[Finding]:
        findings: list[Finding] = []
        url = _SHODAN_INTERNETDB.format(ip=ip)
        try:
            resp = await client.get(url)
            if resp.status_code == 404:
                return findings  # IP not in Shodan database
            if resp.status_code != 200:
                logger.debug("[company_mapper] Shodan InternetDB %s: HTTP %d", ip, resp.status_code)
                return findings
            data: dict[str, Any] = resp.json()
        except Exception as exc:
            logger.warning("[company_mapper] Shodan InternetDB failed for %s: %s", ip, exc)
            return findings

        # Open ports
        for port in data.get("ports", []):
            risk = self._classify_port(port)
            findings.append(Finding(
                module_name=self.MODULE_NAME,
                finding_type="open_port",
                value=f"{ip}:{port}",
                risk_level=risk,
                extra={"ip": ip, "port": port, "source": "shodan_internetdb", "disclaimer": _SHODAN_DISCLAIMER},
            ))

        # CVEs
        for cve in data.get("vulns", []):
            findings.append(Finding(
                module_name=self.MODULE_NAME,
                finding_type="known_cve",
                value=f"{cve} on {ip}",
                risk_level=RiskLevel.HIGH,
                extra={"ip": ip, "cve_id": cve, "source": "shodan_internetdb", "disclaimer": _SHODAN_DISCLAIMER},
            ))

        # Software fingerprints
        cpes = data.get("cpes", [])
        if cpes:
            findings.append(Finding(
                module_name=self.MODULE_NAME,
                finding_type="software_cpe",
                value=", ".join(cpes[:5]),  # Limit to five items
                risk_level=RiskLevel.INFO,
                extra={"ip": ip, "cpes": cpes, "source": "shodan_internetdb", "disclaimer": _SHODAN_DISCLAIMER},
            ))

        # Hostnames associated with the IP
        for hostname in data.get("hostnames", []):
            findings.append(Finding(
                module_name=self.MODULE_NAME,
                finding_type="shodan_hostname",
                value=hostname,
                risk_level=RiskLevel.INFO,
                extra={"ip": ip, "source": "shodan_internetdb", "disclaimer": _SHODAN_DISCLAIMER},
            ))

        # Shodan tags
        tags = data.get("tags", [])
        if tags:
            findings.append(Finding(
                module_name=self.MODULE_NAME,
                finding_type="shodan_tags",
                value=", ".join(tags),
                risk_level=RiskLevel.INFO,
                extra={"ip": ip, "tags": tags, "source": "shodan_internetdb", "disclaimer": _SHODAN_DISCLAIMER},
            ))

        return findings

    async def _geolocate_ip(self, client: httpx.AsyncClient, ip: str) -> list[Finding]:
        findings: list[Finding] = []
        url = _IPAPI_URL.format(ip=ip)
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return findings
            data: dict[str, Any] = resp.json()
        except Exception as exc:
            logger.warning("[company_mapper] ipapi.co failed for %s: %s", ip, exc)
            return findings

        if data.get("error"):
            logger.debug("[company_mapper] ipapi.co error for %s: %s", ip, data.get("reason"))
            return findings

        # Format location string
        city    = data.get("city", "")
        region  = data.get("region", "")
        country = data.get("country_name", "")
        location = ", ".join(filter(None, [city, region, country]))

        if location:
            findings.append(Finding(
                module_name=self.MODULE_NAME,
                finding_type="ip_geolocation",
                value=f"{ip} → {location}",
                risk_level=RiskLevel.INFO,
                extra={
                    "ip": ip,
                    "city": city,
                    "region": region,
                    "country": country,
                    "country_code": data.get("country_code", ""),
                    "source": "ipapi.co",
                },
            ))

        # ASN and hosting provider
        asn     = data.get("asn", "")
        org     = data.get("org", "")
        if asn or org:
            findings.append(Finding(
                module_name=self.MODULE_NAME,
                finding_type="ip_asn",
                value=f"{ip} → {asn} {org}".strip(),
                risk_level=RiskLevel.INFO,
                extra={"ip": ip, "asn": asn, "org": org, "source": "ipapi.co"},
            ))

        return findings

    async def _reverse_ip_lookup(
        self, client: httpx.AsyncClient, ip: str, target: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        url = _HACKERTARGET_RIPLOOKUP.format(ip=ip)
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return findings
            body = resp.text.strip()
        except Exception as exc:
            logger.warning("[company_mapper] Reverse IP lookup failed for %s: %s", ip, exc)
            return findings

        # HackerTarget returns plain text errors on failure
        if body.lower().startswith("error") or "api count" in body.lower():
            logger.debug("[company_mapper] HackerTarget rate-limited or error: %s", body[:80])
            return findings

        co_hosted = [
            h.strip() for h in body.splitlines()
            if h.strip() and h.strip() != target
        ]

        if len(co_hosted) > 1:
            # Shared hosting if multiple domains share this IP
            findings.append(Finding(
                module_name=self.MODULE_NAME,
                finding_type="shared_hosting",
                value=f"{ip} hosts {len(co_hosted)} domain(s) including the target",
                risk_level=RiskLevel.LOW,
                extra={
                    "ip": ip,
                    "co_hosted_count": len(co_hosted),
                    "co_hosted_sample": co_hosted[:10],
                    "source": "hackertarget_reverseip",
                    "note": "Shared hosting with other domains",
                },
            ))
        elif co_hosted:
            # Single co-hosted domain
            findings.append(Finding(
                module_name=self.MODULE_NAME,
                finding_type="co_hosted_domain",
                value=co_hosted[0],
                risk_level=RiskLevel.INFO,
                extra={"ip": ip, "source": "hackertarget_reverseip"},
            ))

        return findings

    def _fingerprint_stack(self, target: str) -> list[Finding]:
        findings: list[Finding] = []

        # Email provider from MX records
        try:
            mx_answers = self._resolver.resolve(target, "MX")
            for rdata in mx_answers:
                mx_host = rdata.exchange.to_text().lower().rstrip(".")
                for keyword, provider in _MX_PROVIDERS:
                    if keyword in mx_host:
                        findings.append(Finding(
                            module_name=self.MODULE_NAME,
                            finding_type="email_provider",
                            value=provider,
                            risk_level=RiskLevel.INFO,
                            extra={"mx_record": mx_host, "source": "dns_mx"},
                        ))
                        break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as exc:
            logger.debug("[company_mapper] MX fingerprint failed: %s", exc)

        # DNS provider from NS records
        try:
            ns_answers = self._resolver.resolve(target, "NS")
            ns_hosts = [r.to_text().lower().rstrip(".") for r in ns_answers]
            detected_dns: set[str] = set()
            for ns_host in ns_hosts:
                for keyword, provider in _NS_PROVIDERS:
                    if keyword in ns_host and provider not in detected_dns:
                        detected_dns.add(provider)
                        findings.append(Finding(
                            module_name=self.MODULE_NAME,
                            finding_type="dns_provider",
                            value=provider,
                            risk_level=RiskLevel.INFO,
                            extra={"ns_record": ns_host, "source": "dns_ns"},
                        ))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as exc:
            logger.debug("[company_mapper] NS fingerprint failed: %s", exc)

        return findings

    @staticmethod
    def _classify_port(port: int) -> RiskLevel:
        if port in _HIGH_RISK_PORTS:
            return RiskLevel.HIGH
        if port in _MEDIUM_RISK_PORTS:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
