"""
osint_recon/modules/document_scanner_module.py
----------------------------------------------
Step 5a of the Critical Path: Public Document Exposure Scanner.

What it does
------------
Probes the target web server for commonly exposed sensitive paths using
HTTP HEAD requests (and GET where content is needed). No authentication
bypass, no rate-limit evasion, no exploitation — only checking whether
publicly accessible URLs return 200.

Sensitive paths checked
-----------------------
  • Source control leakage : .git/HEAD, .git/config, .svn/entries
  • Environment / secrets  : .env, .env.local, .env.production, .env.backup
  • Config files           : web.config, .htaccess, phpinfo.php, config.php
  • Database dumps         : *.sql, *.db, backup.zip, dump.tar.gz
  • CMS config             : wp-config.php, wp-config.php.bak
  • Cloud / deployment     : Dockerfile, docker-compose.yml, .travis.yml
  • Misc sensitive         : .DS_Store, crossdomain.xml, security.txt, robots.txt

Risk classification
-------------------
  HIGH   : .git exposure, .env files, DB dumps, private key files
  MEDIUM : phpinfo.php, config files, deployment files
  LOW    : sitemap.xml, robots.txt, crossdomain.xml, security.txt
  INFO   : anything else that returns 200

TRD requirements enforced
--------------------------
  • Per-file timeout: 15 seconds max (configurable)
  • Per-file size limit: 10 MB max before skipping download
  • All errors caught per-URL; one failure does not abort the scan

Dependencies
------------
  httpx   — async HTTP client
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx

from osint_recon.base_module import BaseModule
from osint_recon.models import Finding, RiskLevel

logger = logging.getLogger(__name__)

_UTC = timezone.utc

# Maximum per-file download size (bytes) — TRD requirement
_MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB

# Per-request timeout — TRD requirement
_REQUEST_TIMEOUT = 15.0

# Concurrent probes (HEAD requests are fast; cap to avoid flooding)
_MAX_CONCURRENT = 15

# ── Sensitive path definitions ────────────────────────────────────────────────
# Each entry: (path, finding_type, risk_level, description)
_SENSITIVE_PATHS: list[tuple[str, str, RiskLevel, str]] = [
    # Source control — critical leakage
    (".git/HEAD",           "git_exposure",         RiskLevel.HIGH,   "Git repository HEAD exposed"),
    (".git/config",         "git_exposure",         RiskLevel.HIGH,   "Git config file exposed"),
    (".git/COMMIT_EDITMSG", "git_exposure",         RiskLevel.HIGH,   "Git commit message exposed"),
    (".svn/entries",        "svn_exposure",         RiskLevel.HIGH,   "SVN repository entries exposed"),
    (".svn/wc.db",          "svn_exposure",         RiskLevel.HIGH,   "SVN working copy database exposed"),
    ("CVS/Root",            "cvs_exposure",         RiskLevel.HIGH,   "CVS repository root exposed"),

    # Environment / secrets
    (".env",                "env_file",             RiskLevel.HIGH,   ".env secrets file exposed"),
    (".env.local",          "env_file",             RiskLevel.HIGH,   ".env.local secrets file exposed"),
    (".env.production",     "env_file",             RiskLevel.HIGH,   ".env.production secrets file exposed"),
    (".env.backup",         "env_file",             RiskLevel.HIGH,   ".env backup exposed"),
    (".env.bak",            "env_file",             RiskLevel.HIGH,   ".env backup exposed"),
    ("config/.env",         "env_file",             RiskLevel.HIGH,   "Config .env file exposed"),

    # Private keys / certificates
    ("id_rsa",              "private_key",          RiskLevel.HIGH,   "RSA private key exposed"),
    ("server.key",          "private_key",          RiskLevel.HIGH,   "Server private key exposed"),
    (".ssh/id_rsa",         "private_key",          RiskLevel.HIGH,   "SSH private key exposed"),

    # Database dumps
    ("backup.sql",          "db_dump",              RiskLevel.HIGH,   "SQL backup exposed"),
    ("dump.sql",            "db_dump",              RiskLevel.HIGH,   "SQL dump exposed"),
    ("database.sql",        "db_dump",              RiskLevel.HIGH,   "Database SQL file exposed"),
    ("db.sql",              "db_dump",              RiskLevel.HIGH,   "Database SQL file exposed"),
    ("backup.db",           "db_dump",              RiskLevel.HIGH,   "Database file exposed"),
    ("data.db",             "db_dump",              RiskLevel.HIGH,   "Database file exposed"),
    ("backup.zip",          "archive_exposure",     RiskLevel.HIGH,   "Backup archive exposed"),
    ("backup.tar.gz",       "archive_exposure",     RiskLevel.HIGH,   "Backup archive exposed"),
    ("dump.tar.gz",         "archive_exposure",     RiskLevel.HIGH,   "Dump archive exposed"),

    # CMS config
    ("wp-config.php",       "cms_config",           RiskLevel.HIGH,   "WordPress config exposed"),
    ("wp-config.php.bak",   "cms_config",           RiskLevel.HIGH,   "WordPress config backup exposed"),
    ("configuration.php",   "cms_config",           RiskLevel.HIGH,   "Joomla config exposed"),
    ("LocalSettings.php",   "cms_config",           RiskLevel.HIGH,   "MediaWiki config exposed"),

    # Config / PHP info
    ("phpinfo.php",         "php_info",             RiskLevel.MEDIUM, "PHP info page exposed"),
    ("php_info.php",        "php_info",             RiskLevel.MEDIUM, "PHP info page exposed"),
    ("info.php",            "php_info",             RiskLevel.MEDIUM, "PHP info page exposed"),
    ("config.php",          "config_file",          RiskLevel.MEDIUM, "Config PHP file exposed"),
    ("web.config",          "config_file",          RiskLevel.MEDIUM, "ASP.NET web.config exposed"),
    (".htaccess",           "config_file",          RiskLevel.MEDIUM, ".htaccess file exposed"),
    ("application.yml",     "config_file",          RiskLevel.MEDIUM, "Application YAML config exposed"),
    ("database.yml",        "config_file",          RiskLevel.MEDIUM, "Database config YAML exposed"),
    ("settings.py",         "config_file",          RiskLevel.MEDIUM, "Django settings exposed"),
    ("config.json",         "config_file",          RiskLevel.MEDIUM, "JSON config file exposed"),
    ("appsettings.json",    "config_file",          RiskLevel.MEDIUM, ".NET appsettings exposed"),

    # Deployment / CI
    ("Dockerfile",          "deployment_file",      RiskLevel.MEDIUM, "Dockerfile exposed"),
    ("docker-compose.yml",  "deployment_file",      RiskLevel.MEDIUM, "Docker Compose file exposed"),
    (".travis.yml",         "deployment_file",      RiskLevel.MEDIUM, "Travis CI config exposed"),
    (".github/workflows",   "deployment_file",      RiskLevel.MEDIUM, "GitHub Actions directory exposed"),
    ("Jenkinsfile",         "deployment_file",      RiskLevel.MEDIUM, "Jenkinsfile exposed"),
    ("ansible.cfg",         "deployment_file",      RiskLevel.MEDIUM, "Ansible config exposed"),

    # Logs
    ("error.log",           "log_file",             RiskLevel.MEDIUM, "Error log exposed"),
    ("access.log",          "log_file",             RiskLevel.MEDIUM, "Access log exposed"),
    ("debug.log",           "log_file",             RiskLevel.MEDIUM, "Debug log exposed"),
    ("laravel.log",         "log_file",             RiskLevel.MEDIUM, "Laravel log exposed"),
    ("storage/logs/laravel.log", "log_file",        RiskLevel.MEDIUM, "Laravel storage log exposed"),

    # Package manager / dependency manifests (reveals tech stack)
    ("package.json",        "dependency_manifest",  RiskLevel.LOW,    "Node.js package.json exposed"),
    ("composer.json",       "dependency_manifest",  RiskLevel.LOW,    "PHP composer.json exposed"),
    ("requirements.txt",    "dependency_manifest",  RiskLevel.LOW,    "Python requirements.txt exposed"),
    ("Gemfile",             "dependency_manifest",  RiskLevel.LOW,    "Ruby Gemfile exposed"),
    ("yarn.lock",           "dependency_manifest",  RiskLevel.LOW,    "Yarn lock file exposed"),

    # Misc / info
    ("robots.txt",          "robots_txt",           RiskLevel.INFO,   "robots.txt — may reveal hidden paths"),
    ("sitemap.xml",         "sitemap",              RiskLevel.INFO,   "sitemap.xml — URL enumeration"),
    ("crossdomain.xml",     "crossdomain_policy",   RiskLevel.LOW,    "Flash/Adobe crossdomain policy"),
    (".well-known/security.txt", "security_txt",    RiskLevel.INFO,   "security.txt — security contact info"),
    ("humans.txt",          "humans_txt",           RiskLevel.INFO,   "humans.txt — may reveal staff names"),
    (".DS_Store",           "ds_store",             RiskLevel.LOW,    ".DS_Store — macOS folder metadata"),
    ("Thumbs.db",           "thumbs_db",            RiskLevel.LOW,    "Thumbs.db — Windows thumbnail cache"),
    ("server-status",       "server_status",        RiskLevel.MEDIUM, "Apache server-status page"),
    ("server-info",         "server_info",          RiskLevel.MEDIUM, "Apache server-info page"),
]

# ── URL schemes to try ────────────────────────────────────────────────────────
_SCHEMES = ["https", "http"]


class DocumentScannerModule(BaseModule):
    """
    Probes a target domain for commonly exposed sensitive files and paths.
    Uses HEAD requests to check existence; stores URL + status in findings.
    """

    MODULE_NAME = "document_scanner"

    def __init__(
        self,
        timeout: float = _REQUEST_TIMEOUT,
        max_concurrent: int = _MAX_CONCURRENT,
        schemes: list[str] | None = None,
    ) -> None:
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self.schemes = schemes or _SCHEMES

    # ------------------------------------------------------------------
    # Main implementation
    # ------------------------------------------------------------------

    async def _run(self, target: str) -> list[Finding]:
        # Build full URL list — try HTTPS first, then HTTP
        tasks = []
        for scheme in self.schemes:
            base_url = f"{scheme}://{target}"
            for path, ftype, risk, desc in _SENSITIVE_PATHS:
                url = f"{base_url}/{path}"
                tasks.append(self._probe_url(url, path, ftype, risk, desc))

        results = await asyncio.gather(*tasks, return_exceptions=False)

        # Deduplicate: if a path was found on HTTPS, don't also report HTTP
        seen_paths: set[str] = set()
        findings: list[Finding] = []
        for finding in results:
            if finding is None:
                continue
            # key on path portion (not full URL) to deduplicate across schemes
            path_key = "/".join(finding.value.split("/")[3:])  # strip scheme+host
            if path_key not in seen_paths:
                seen_paths.add(path_key)
                findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Per-URL probe
    # ------------------------------------------------------------------

    async def _probe_url(
        self,
        url: str,
        path: str,
        finding_type: str,
        risk: RiskLevel,
        description: str,
    ) -> Finding | None:
        """
        Send a HEAD request to *url*. Return a Finding if the resource
        exists (HTTP 200), None otherwise.
        """
        async with self._semaphore:
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=False,  # don't follow — we want the exact status
                    verify=False,            # ignore TLS errors on unusual domains
                ) as client:
                    resp = await client.head(url)

                if resp.status_code == 200:
                    content_length = resp.headers.get("content-length", "unknown")
                    content_type = resp.headers.get("content-type", "unknown")

                    # Skip if file is over the size limit (don't even flag it to
                    # avoid downloading later in the metadata extractor)
                    try:
                        if int(content_length) > _MAX_FILE_BYTES:
                            logger.info(
                                "[document_scanner] %s exceeds size limit (%s bytes), skipping",
                                url, content_length,
                            )
                            return None
                    except (ValueError, TypeError):
                        pass  # content-length missing or non-numeric — proceed

                    logger.info("[document_scanner] FOUND: %s (HTTP 200)", url)
                    return Finding(
                        module_name=self.MODULE_NAME,
                        finding_type=finding_type,
                        value=url,
                        risk_level=risk,
                        extra={
                            "path": path,
                            "description": description,
                            "http_status": 200,
                            "content_type": content_type,
                            "content_length": content_length,
                            "source": "http_probe",
                        },
                    )

            except httpx.TimeoutException:
                logger.debug("[document_scanner] Timeout: %s", url)
            except httpx.ConnectError:
                logger.debug("[document_scanner] Connect error: %s", url)
            except Exception as exc:  # noqa: BLE001
                logger.debug("[document_scanner] Error probing %s: %s", url, exc)

        return None
