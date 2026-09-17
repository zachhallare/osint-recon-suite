"""Queries WHOIS records and resolves common DNS entries."""

from __future__ import annotations

import logging
import socket
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import whois

from osint_recon.base_module import BaseModule
from osint_recon.models import Finding, RiskLevel

logger = logging.getLogger(__name__)

_UTC = timezone.utc

# DNS record types to query
_DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

# Common service verification markers in TXT records
_INTERESTING_TXT = {
    "v=spf1": ("spf_record", RiskLevel.INFO),
    "v=dmarc1": ("dmarc_record", RiskLevel.INFO),
    "v=dkim1": ("dkim_record", RiskLevel.INFO),
    "google-site-verification": ("google_verification", RiskLevel.LOW),
    "ms=ms": ("microsoft_verification", RiskLevel.LOW),
    "atlassian-domain-verification": ("atlassian_verification", RiskLevel.LOW),
    "docusign=": ("docusign_verification", RiskLevel.LOW),
    "stripe-verification=": ("stripe_verification", RiskLevel.LOW),
    "have-i-been-pwned-verification=": ("hibp_verification", RiskLevel.LOW),
}


class WhoisDnsModule(BaseModule):
    """Performs WHOIS lookup and full DNS record enumeration."""

    MODULE_NAME = "whois_dns"

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

    async def _run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._whois_lookup(target))
        findings.extend(self._dns_lookup(target))
        return findings

    def _whois_lookup(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            w = whois.whois(target)
            logger.debug("[whois_dns] WHOIS raw: %s", w)

            # Registrar
            if w.registrar:
                findings.append(Finding(
                    module_name=self.MODULE_NAME,
                    finding_type="whois_registrar",
                    value=str(w.registrar),
                    risk_level=RiskLevel.INFO,
                    extra={"source": "whois"},
                ))

            # Registrant org
            if w.org:
                findings.append(Finding(
                    module_name=self.MODULE_NAME,
                    finding_type="whois_org",
                    value=str(w.org),
                    risk_level=RiskLevel.INFO,
                    extra={"source": "whois"},
                ))

            # Creation date
            created = self._normalise_date(w.creation_date)
            if created:
                findings.append(Finding(
                    module_name=self.MODULE_NAME,
                    finding_type="whois_creation_date",
                    value=created,
                    risk_level=RiskLevel.INFO,
                    extra={"source": "whois"},
                ))

            # Expiry date, flag if expiring within 60 days
            expiry = self._normalise_date(w.expiration_date)
            if expiry:
                risk = self._expiry_risk(expiry)
                findings.append(Finding(
                    module_name=self.MODULE_NAME,
                    finding_type="whois_expiry_date",
                    value=expiry,
                    risk_level=risk,
                    extra={
                        "source": "whois",
                        "note": "Domain expiring soon" if risk == RiskLevel.HIGH else "",
                    },
                ))

            # Name servers from WHOIS
            if w.name_servers:
                ns_list = sorted({ns.lower() for ns in w.name_servers if ns})
                findings.append(Finding(
                    module_name=self.MODULE_NAME,
                    finding_type="whois_name_servers",
                    value=", ".join(ns_list),
                    risk_level=RiskLevel.INFO,
                    extra={"source": "whois", "count": len(ns_list)},
                ))

            # DNSSEC status
            if w.dnssec:
                findings.append(Finding(
                    module_name=self.MODULE_NAME,
                    finding_type="whois_dnssec",
                    value=str(w.dnssec),
                    risk_level=RiskLevel.INFO,
                    extra={"source": "whois"},
                ))

            # Look for exposed contact emails
            if w.emails:
                emails = w.emails if isinstance(w.emails, list) else [w.emails]
                for email in emails:
                    if email:
                        findings.append(Finding(
                            module_name=self.MODULE_NAME,
                            finding_type="whois_email_exposed",
                            value=str(email),
                            risk_level=RiskLevel.MEDIUM,
                            extra={"source": "whois", "note": "Email exposed in public WHOIS record"},
                        ))

        except Exception as exc:  # noqa: BLE001
            logger.warning("[whois_dns] WHOIS lookup failed for %s: %s", target, exc)
            findings.append(Finding(
                module_name=self.MODULE_NAME,
                finding_type="whois_error",
                value=f"WHOIS lookup failed: {type(exc).__name__}: {exc}",
                risk_level=RiskLevel.INFO,
                extra={"source": "whois"},
            ))

        return findings

    def _dns_lookup(self, target: str) -> list[Finding]:
        findings: list[Finding] = []

        for rtype in _DNS_RECORD_TYPES:
            try:
                answers = self._resolver.resolve(target, rtype)
                for rdata in answers:
                    value = rdata.to_text()
                    risk = RiskLevel.INFO
                    extra: dict = {"record_type": rtype, "source": "dns"}

                    # Flag interesting TXT records
                    if rtype == "TXT":
                        value_lower = value.lower().replace('"', "")
                        for keyword, (ftype_override, risk_override) in _INTERESTING_TXT.items():
                            if keyword in value_lower:
                                extra["category"] = ftype_override
                                break

                    findings.append(Finding(
                        module_name=self.MODULE_NAME,
                        finding_type=f"dns_{rtype.lower()}",
                        value=value,
                        risk_level=risk,
                        extra=extra,
                    ))

            except dns.resolver.NoAnswer:
                logger.debug("[whois_dns] No %s records for %s", rtype, target)
            except dns.resolver.NXDOMAIN:
                logger.warning("[whois_dns] Domain not found (NXDOMAIN): %s", target)
                findings.append(Finding(
                    module_name=self.MODULE_NAME,
                    finding_type="dns_nxdomain",
                    value=f"{target} - domain does not exist (NXDOMAIN)",
                    risk_level=RiskLevel.INFO,
                    extra={"record_type": rtype, "source": "dns"},
                ))
                break  # Stop querying if domain does not exist
            except dns.exception.Timeout:
                logger.warning("[whois_dns] DNS timeout for %s %s", rtype, target)
            except Exception as exc:  # noqa: BLE001
                logger.warning("[whois_dns] DNS %s lookup failed for %s: %s", rtype, target, exc)

        return findings

    @staticmethod
    def _normalise_date(raw) -> str | None:
        """Convert python-whois date field to ISO string."""
        if raw is None:
            return None
        if isinstance(raw, list):
            raw = raw[0]
        if isinstance(raw, datetime):
            return raw.strftime("%Y-%m-%d")
        return str(raw)[:10]

    @staticmethod
    def _expiry_risk(expiry_str: str) -> RiskLevel:
        """Flag high risk if domain expires within 60 days."""
        try:
            expiry = datetime.strptime(expiry_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                return RiskLevel.HIGH  # Already expired
            if days_left < 60:
                return RiskLevel.HIGH
            if days_left < 180:
                return RiskLevel.MEDIUM
        except ValueError:
            pass
        return RiskLevel.INFO
