"""Scans targets for publicly exposed sensitive files and paths."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx

from osint_recon.base_module import BaseModule
from osint_recon.models import Finding, RiskLevel

logger = logging.getLogger(__name__)

_UTC = timezone.utc

# Maximum per-file download size in bytes
_MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB

# Request timeout in seconds
_REQUEST_TIMEOUT = 15.0

# Maximum concurrent requests
_MAX_CONCURRENT = 15

# Sensitive path definitions: (path, finding_type, risk_level, description)
_SENSITIVE_PATHS: list[tuple[str, str, RiskLevel, str]] = [
    # Source control files
    (".git/HEAD",           "git_exposure",         RiskLevel.HIGH,   "Git repository HEAD exposed"),
    (".git/config",         "git_exposure",         RiskLevel.HIGH,   "Git config file exposed"),
    (".git/COMMIT_EDITMSG", "git_exposure",         RiskLevel.HIGH,   "Git commit message exposed"),
    (".svn/entries",        "svn_exposure",         RiskLevel.HIGH,   "SVN repository entries exposed"),
    (".svn/wc.db",          "svn_exposure",         RiskLevel.HIGH,   "SVN working copy database exposed"),
    ("CVS/Root",            "cvs_exposure",         RiskLevel.HIGH,   "CVS repository root exposed"),

    # Environment and secrets
    (".env",                "env_file",             RiskLevel.HIGH,   ".env secrets file exposed"),
    (".env.local",          "env_file",             RiskLevel.HIGH,   ".env.local secrets file exposed"),
    (".env.production",     "env_file",             RiskLevel.HIGH,   ".env.production secrets file exposed"),
    (".env.backup",         "env_file",             RiskLevel.HIGH,   ".env backup exposed"),
    (".env.bak",            "env_file",             RiskLevel.HIGH,   ".env backup exposed"),
    ("config/.env",         "env_file",             RiskLevel.HIGH,   "Config .env file exposed"),

    # Private keys and certificates
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

    # Config and PHP info
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

    # Deployment and CI
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

    # Dependency manifests
    ("package.json",        "dependency_manifest",  RiskLevel.LOW,    "Node.js package.json exposed"),
    ("composer.json",       "dependency_manifest",  RiskLevel.LOW,    "PHP composer.json exposed"),
    ("requirements.txt",    "dependency_manifest",  RiskLevel.LOW,    "Python requirements.txt exposed"),
    ("Gemfile",             "dependency_manifest",  RiskLevel.LOW,    "Ruby Gemfile exposed"),
    ("yarn.lock",           "dependency_manifest",  RiskLevel.LOW,    "Yarn lock file exposed"),

    # Information files
    ("robots.txt",          "robots_txt",           RiskLevel.INFO,   "robots.txt path list"),
    ("sitemap.xml",         "sitemap",              RiskLevel.INFO,   "sitemap.xml URL list"),
    ("crossdomain.xml",     "crossdomain_policy",   RiskLevel.LOW,    "Flash crossdomain policy"),
    (".well-known/security.txt", "security_txt",    RiskLevel.INFO,   "security.txt contact info"),
    ("humans.txt",          "humans_txt",           RiskLevel.INFO,   "humans.txt staff info"),
    (".DS_Store",           "ds_store",             RiskLevel.LOW,    ".DS_Store folder metadata"),
    ("Thumbs.db",           "thumbs_db",            RiskLevel.LOW,    "Thumbs.db thumbnail cache"),
    ("server-status",       "server_status",        RiskLevel.MEDIUM, "Apache server-status page"),
    ("server-info",         "server_info",          RiskLevel.MEDIUM, "Apache server-info page"),
]

_SCHEMES = ["https", "http"]


class DocumentScannerModule(BaseModule):
    """Probes a target domain for commonly exposed files and paths."""

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

    async def _run(self, target: str) -> list[Finding]:
        # Try HTTPS first, then HTTP
        tasks = []
        for scheme in self.schemes:
            base_url = f"{scheme}://{target}"
            for path, ftype, risk, desc in _SENSITIVE_PATHS:
                url = f"{base_url}/{path}"
                tasks.append(self._probe_url(url, path, ftype, risk, desc))

        results = await asyncio.gather(*tasks, return_exceptions=False)

        # Prefer HTTPS results over HTTP for the same path
        seen_paths: set[str] = set()
        findings: list[Finding] = []
        for finding in results:
            if finding is None:
                continue
            # Key on path portion to deduplicate across schemes
            path_key = "/".join(finding.value.split("/")[3:])
            if path_key not in seen_paths:
                seen_paths.add(path_key)
                findings.append(finding)

        return findings

    async def _probe_url(
        self,
        url: str,
        path: str,
        finding_type: str,
        risk: RiskLevel,
        description: str,
    ) -> Finding | None:
        """Check if a URL returns HTTP 200 via HEAD request."""
        async with self._semaphore:
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=False,  # Keep redirect responses as is
                    verify=False,            # Ignore TLS errors on self-signed certs
                ) as client:
                    resp = await client.head(url)

                if resp.status_code == 200:
                    content_length = resp.headers.get("content-length", "unknown")
                    content_type = resp.headers.get("content-type", "unknown")

                    # Skip files over the size limit
                    try:
                        if int(content_length) > _MAX_FILE_BYTES:
                            logger.info(
                                "[document_scanner] %s exceeds size limit (%s bytes), skipping",
                                url, content_length,
                            )
                            return None
                    except (ValueError, TypeError):
                        pass  # Proceed if content length is not available

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
