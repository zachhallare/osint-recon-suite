"""Centralized risk scoring and escalation logic."""

from __future__ import annotations

from typing import Iterable

from osint_recon.models import Finding, RiskLevel

_BASE_RISK_MAP = {
    # Whois / DNS Module
    "whois_registrar": RiskLevel.INFO,
    "whois_org": RiskLevel.INFO,
    "whois_creation_date": RiskLevel.INFO,
    "whois_expiry_date": RiskLevel.INFO,  # Dynamic evaluation logic in module could be moved here, but for now INFO base
    "whois_name_servers": RiskLevel.INFO,
    "whois_dnssec": RiskLevel.INFO,
    "whois_error": RiskLevel.INFO,
    "whois_email_exposed": RiskLevel.LOW,
    "dns_nxdomain": RiskLevel.INFO,
    "google_verification": RiskLevel.LOW,
    "microsoft_verification": RiskLevel.LOW,
    "atlassian_verification": RiskLevel.LOW,
    "docusign_verification": RiskLevel.LOW,
    "stripe_verification": RiskLevel.LOW,
    "hibp_verification": RiskLevel.LOW,
    "spf_record": RiskLevel.INFO,
    "dmarc_record": RiskLevel.INFO,
    "dkim_record": RiskLevel.INFO,

    # Subdomain Module
    "subdomain": RiskLevel.INFO,
    "crtsh_error": RiskLevel.INFO,
    "certspotter_error": RiskLevel.INFO,

    # Company Mapper Module
    "resolution_error": RiskLevel.LOW,
    "resolved_ip": RiskLevel.INFO,
    "software_cpe": RiskLevel.INFO,
    "shodan_hostname": RiskLevel.INFO,
    "shodan_tags": RiskLevel.INFO,
    "ip_geolocation": RiskLevel.INFO,
    "ip_asn": RiskLevel.INFO,
    "co_hosted_domain": RiskLevel.INFO,
    "email_provider": RiskLevel.INFO,
    "dns_provider": RiskLevel.INFO,
    "shared_hosting": RiskLevel.LOW,
    "known_cve": RiskLevel.HIGH,
    "open_port": RiskLevel.MEDIUM, # base risk, handled dynamically below

    # Document Scanner Module
    "robots_txt": RiskLevel.INFO,
    "sitemap": RiskLevel.INFO,
    "security_txt": RiskLevel.INFO,
    "humans_txt": RiskLevel.INFO,
    "crossdomain_policy": RiskLevel.LOW,
    "ds_store": RiskLevel.LOW,
    "thumbs_db": RiskLevel.LOW,
    "dependency_manifest": RiskLevel.LOW,
    "php_info": RiskLevel.MEDIUM,
    "config_file": RiskLevel.MEDIUM,
    "deployment_file": RiskLevel.MEDIUM,
    "log_file": RiskLevel.MEDIUM,
    "server_status": RiskLevel.MEDIUM,
    "server_info": RiskLevel.MEDIUM,
    "git_exposure": RiskLevel.HIGH,
    "svn_exposure": RiskLevel.HIGH,
    "cvs_exposure": RiskLevel.HIGH,
    "env_file": RiskLevel.HIGH,
    "private_key": RiskLevel.CRITICAL,  # Escalated from High
    "db_dump": RiskLevel.HIGH,
    "archive_exposure": RiskLevel.HIGH,
    "cms_config": RiskLevel.HIGH,

    # Metadata Extractor Module
    "pdf_producer": RiskLevel.INFO,
    "pdf_title": RiskLevel.INFO,
    "pdf_subject": RiskLevel.INFO,
    "pdf_keywords": RiskLevel.INFO,
    "pdf_creator": RiskLevel.LOW,
    "office_company": RiskLevel.LOW,
    "pdf_author": RiskLevel.HIGH,  # Escalated from Medium
    "image_gps_coordinates": RiskLevel.HIGH,

    # Social Media Module
    "github_repos_summary": RiskLevel.INFO,
    "github_entity": RiskLevel.LOW,
    "social_profile": RiskLevel.MEDIUM,
    "github_email": RiskLevel.MEDIUM,
    "github_sensitive_repo": RiskLevel.HIGH,
    
    # Mock Module
    "mock_info": RiskLevel.INFO,
    "mock_medium": RiskLevel.MEDIUM,
    "mock_high": RiskLevel.HIGH,
}

_HIGH_RISK_PORTS = {
    21, 22, 23, 3389, 5900, 5901,      # FTP, SSH, Telnet, RDP, VNC
    1433, 1521, 3306, 5432, 27017,     # MSSQL, Oracle, MySQL, Postgres, MongoDB
    6379, 11211,                       # Redis, Memcached
    2375, 2376,                        # Docker API
    9200, 9300,                        # Elasticsearch
    8500,                              # Consul
}

_MEDIUM_RISK_PORTS = {
    25, 110, 143, 587, 993, 995,       # SMTP, POP3, IMAP
    8080, 8443, 8888,                  # Alternate web ports
    4848, 7001, 7002,                  # Application servers
    9090, 9091,                        # Admin ports
}

def get_base_risk(finding: Finding) -> RiskLevel:
    """Get the base risk level for a finding type, accounting for some dynamic conditions."""
    if finding.finding_type == "open_port":
        port = finding.extra.get("port")
        if port in _HIGH_RISK_PORTS:
            return RiskLevel.HIGH
        if port in _MEDIUM_RISK_PORTS:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
        
    if finding.finding_type == "subdomain":
        if finding.extra.get("is_wildcard"):
            return RiskLevel.LOW
        return RiskLevel.INFO
        
    if finding.finding_type == "whois_expiry_date":
        # Keep original dynamic logic for expiry
        note = finding.extra.get("note", "")
        if "Already expired" in note or "soon" in note:
            return RiskLevel.HIGH
        if "within 30 days" in note:
            return RiskLevel.MEDIUM
        return RiskLevel.INFO

    # Fallback to wildcard DNS matching
    if finding.finding_type.startswith("dns_"):
        return RiskLevel.INFO
        
    if finding.finding_type.startswith("office_"):
        # Metadata extractor generates dynamic types
        if "company" in finding.finding_type:
            return RiskLevel.LOW
        return RiskLevel.INFO

    return _BASE_RISK_MAP.get(finding.finding_type, RiskLevel.INFO)

def post_process_findings(findings: Iterable[Finding]) -> list[Finding]:
    """
    Applies centralized risk scoring and cross-finding escalations.
    Returns the updated list of findings.
    """
    findings_list = list(findings)
    
    # 1. Apply base risk scoring to all findings
    for f in findings_list:
        f.risk_level = get_base_risk(f)
        
    # 2. Cross-finding Escalations
    # e.g., open_port + known_cve on the same IP
    cve_ips = {
        f.extra.get("ip") for f in findings_list 
        if f.finding_type == "known_cve" and f.extra.get("ip")
    }
    
    for f in findings_list:
        if f.finding_type == "open_port":
            ip = f.extra.get("ip")
            if ip and ip in cve_ips:
                # Escalate port severity
                if f.risk_level == RiskLevel.HIGH:
                    f.risk_level = RiskLevel.CRITICAL
                elif f.risk_level in (RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO):
                    f.risk_level = RiskLevel.HIGH
                    
    return findings_list
