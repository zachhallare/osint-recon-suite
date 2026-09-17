"""Discovers social media accounts and public GitHub profiles."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx

from osint_recon.base_module import BaseModule
from osint_recon.models import Finding, RiskLevel

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = 12.0
_MAX_CONCURRENT = 10

# Repo keywords that suggest sensitive infrastructure or secrets
_SENSITIVE_REPO_KEYWORDS = {
    "infra", "infrastructure", "terraform", "ansible", "kubernetes", "k8s",
    "helm", "deploy", "deployment", "secrets", "vault", "credentials", "creds",
    "config", "configs", "internal", "private", "hidden", "ops", "devops",
    "ci-cd", "pipeline", "prod", "production", "staging", "backup", "restore",
    "pentest", "security", "firewall", "vpn", "ssh", "keys", "certificates",
}

# Format: (platform_name, url_template, check_method, success_status)
_PLATFORMS: list[tuple[str, str, str, set[int]]] = [
    ("GitHub",       "https://github.com/{slug}",                          "head", {200}),
    ("Twitter/X",    "https://twitter.com/{slug}",                         "head", {200}),
    ("Instagram",    "https://www.instagram.com/{slug}/",                  "head", {200}),
    ("LinkedIn",     "https://www.linkedin.com/company/{slug}",            "head", {200}),
    ("LinkedIn",     "https://www.linkedin.com/in/{slug}",                 "head", {200}),
    ("YouTube",      "https://www.youtube.com/@{slug}",                    "head", {200}),
    ("Reddit Subreddit", "https://www.reddit.com/r/{slug}/",               "head", {200}),
    ("Reddit User",  "https://www.reddit.com/user/{slug}/",                "head", {200}),
    ("Facebook",     "https://www.facebook.com/{slug}",                    "head", {200}),
    ("Keybase",      "https://keybase.io/{slug}",                          "head", {200}),
    ("Telegram",     "https://t.me/{slug}",                                "head", {200}),
    ("npmjs",        "https://www.npmjs.com/~{slug}",                      "head", {200}),
    ("PyPI",         "https://pypi.org/user/{slug}/",                      "head", {200}),
    ("Docker Hub",   "https://hub.docker.com/u/{slug}/",                   "head", {200}),
    ("Medium",       "https://medium.com/@{slug}",                         "head", {200}),
    ("HackerNews",   "https://hacker-news.firebaseio.com/v0/user/{slug}.json", "get", {200}),
]

# Public GitHub endpoints without authentication
_GH_ORG_URL  = "https://api.github.com/orgs/{slug}"
_GH_USER_URL = "https://api.github.com/users/{slug}"
_GH_REPOS_URL = "https://api.github.com/orgs/{slug}/repos?per_page=100&type=public"
_GH_USER_REPOS_URL = "https://api.github.com/users/{slug}/repos?per_page=100&type=public"


def _slugify(domain: str) -> list[str]:
    """Derive username candidates from a domain."""
    # Strip protocol, path, and port
    d = domain.strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/")[0].split(":")[0]

    # Strip TLDs to keep the core name
    parts = d.split(".")
    # Known two-part TLDs
    two_part_tlds = {"co.uk", "com.au", "co.nz", "co.za", "com.br", "org.uk"}
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_part_tlds:
        base = ".".join(parts[:-2])
    elif len(parts) >= 2:
        base = ".".join(parts[:-1])
    else:
        base = parts[0]

    slugs = [base]
    # Add variant without hyphens for strict platforms
    no_hyphen = base.replace("-", "").replace(".", "")
    if no_hyphen and no_hyphen != base:
        slugs.append(no_hyphen)
    return slugs


class SocialMediaModule(BaseModule):
    """Discovers public social media presence and GitHub assets."""

    MODULE_NAME = "social_media"

    def __init__(
        self,
        http_timeout: float = _HTTP_TIMEOUT,
        max_concurrent: int = _MAX_CONCURRENT,
    ) -> None:
        self.http_timeout = http_timeout
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def _run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        slugs = _slugify(target)

        logger.info("[social_media] Probing %d slug(s) across %d platforms: %s",
                    len(slugs), len(_PLATFORMS), slugs)

        async with httpx.AsyncClient(
            timeout=self.http_timeout,
            follow_redirects=True,
            headers={"User-Agent": "OSINT-Recon-Suite/1.0 (passive research tool)"},
        ) as client:
            # Probe social platforms concurrently
            platform_tasks = [
                self._probe_platform(client, platform, url_tpl, method, ok_statuses, slug)
                for slug in slugs
                for platform, url_tpl, method, ok_statuses in _PLATFORMS
            ]
            platform_results = await asyncio.gather(*platform_tasks, return_exceptions=False)
            for finding in platform_results:
                if finding is not None:
                    findings.append(finding)

            # Enrich confirmed GitHub profiles
            gh_slugs_found = {
                f.extra.get("slug") for f in findings
                if f.finding_type == "social_profile"
                and f.extra.get("platform") == "GitHub"
            }
            gh_tasks = [self._enrich_github(client, slug) for slug in gh_slugs_found]
            gh_results = await asyncio.gather(*gh_tasks, return_exceptions=False)
            for finding_list in gh_results:
                findings.extend(finding_list)

        return findings

    async def _probe_platform(
        self,
        client: httpx.AsyncClient,
        platform: str,
        url_template: str,
        method: str,
        ok_statuses: set[int],
        slug: str,
    ) -> Finding | None:
        url = url_template.format(slug=slug)
        async with self._semaphore:
            try:
                if method == "head":
                    resp = await client.head(url)
                else:
                    resp = await client.get(url)

                if resp.status_code not in ok_statuses:
                    return None

                # HackerNews returns error JSON with HTTP 200 for missing users
                if "firebaseio.com" in url and method == "get":
                    try:
                        data = resp.json()
                        if data is None or (isinstance(data, dict) and "error" in data):
                            return None
                    except Exception:
                        return None

                logger.info("[social_media] FOUND: %s @ %s", platform, url)
                return Finding(
                    module_name=self.MODULE_NAME,
                    finding_type="social_profile",
                    value=url,
                    risk_level=RiskLevel.MEDIUM,
                    extra={
                        "platform": platform,
                        "slug": slug,
                        "http_status": resp.status_code,
                        "source": "http_probe",
                    },
                )

            except httpx.TimeoutException:
                logger.debug("[social_media] Timeout: %s", url)
            except httpx.ConnectError:
                logger.debug("[social_media] Connect error: %s", url)
            except Exception as exc:  # noqa: BLE001
                logger.debug("[social_media] Error probing %s: %s", url, exc)

        return None

    async def _enrich_github(self, client: httpx.AsyncClient, slug: str) -> list[Finding]:
        findings: list[Finding] = []
        if not slug:
            return findings

        # Try as org first, then user
        org_data = await self._gh_get(client, _GH_ORG_URL.format(slug=slug))
        is_org = org_data is not None

        entity_data = org_data or await self._gh_get(client, _GH_USER_URL.format(slug=slug))
        if entity_data is None:
            return findings

        entity_type = "org" if is_org else "user"

        # Basic entity info
        findings.append(Finding(
            module_name=self.MODULE_NAME,
            finding_type="github_entity",
            value=entity_data.get("html_url", f"https://github.com/{slug}"),
            risk_level=RiskLevel.LOW,
            extra={
                "slug": slug,
                "type": entity_type,
                "name": entity_data.get("name", ""),
                "description": (entity_data.get("description") or "")[:200],
                "public_repos": entity_data.get("public_repos", 0),
                "followers": entity_data.get("followers", 0),
                "public_members": entity_data.get("public_members_url", "").split("{")[0],
                "location": entity_data.get("location", ""),
                "blog": entity_data.get("blog", ""),
                "email": entity_data.get("email", ""),
                "source": "github_api",
            },
        ))

        # Check profile for exposed email address
        profile_email = entity_data.get("email", "")
        if profile_email:
            findings.append(Finding(
                module_name=self.MODULE_NAME,
                finding_type="github_email",
                value=profile_email,
                risk_level=RiskLevel.MEDIUM,
                extra={
                    "slug": slug,
                    "source": "github_api",
                    "note": "Email exposed on public GitHub profile",
                },
            ))

        # Fetch public repos
        repos_url = (_GH_REPOS_URL if is_org else _GH_USER_REPOS_URL).format(slug=slug)
        repos = await self._gh_get(client, repos_url)
        if not isinstance(repos, list):
            return findings

        total_stars = sum(r.get("stargazers_count", 0) for r in repos)
        languages = {r.get("language") for r in repos if r.get("language")}

        # Summary finding
        if repos:
            findings.append(Finding(
                module_name=self.MODULE_NAME,
                finding_type="github_repos_summary",
                value=f"{len(repos)} public repo(s), {total_stars} total stars",
                risk_level=RiskLevel.INFO,
                extra={
                    "slug": slug,
                    "repo_count": len(repos),
                    "total_stars": total_stars,
                    "languages": sorted(languages),
                    "source": "github_api",
                },
            ))

        # Flag repositories with sensitive names
        for repo in repos:
            name = repo.get("name", "").lower()
            desc = (repo.get("description") or "").lower()
            matched = [
                kw for kw in _SENSITIVE_REPO_KEYWORDS
                if kw in name or kw in desc
            ]
            if matched:
                findings.append(Finding(
                    module_name=self.MODULE_NAME,
                    finding_type="github_sensitive_repo",
                    value=repo.get("html_url", ""),
                    risk_level=RiskLevel.HIGH,
                    extra={
                        "slug": slug,
                        "repo_name": repo.get("name"),
                        "description": repo.get("description", ""),
                        "matched_keywords": matched,
                        "stars": repo.get("stargazers_count", 0),
                        "language": repo.get("language", ""),
                        "last_pushed": repo.get("pushed_at", ""),
                        "source": "github_api",
                        "note": "Repository name/description matches sensitive keyword list",
                    },
                ))

        return findings

    async def _gh_get(self, client: httpx.AsyncClient, url: str) -> Any:
        """Fetch GitHub API endpoint and return parsed JSON."""
        async with self._semaphore:
            try:
                resp = await client.get(
                    url,
                    headers={
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                )
                if resp.status_code == 404:
                    return None
                if resp.status_code == 403:
                    logger.warning("[social_media] GitHub rate-limited: %s", url)
                    return None
                if resp.status_code != 200:
                    return None
                return resp.json()
            except Exception as exc:  # noqa: BLE001
                logger.debug("[social_media] GitHub API error %s: %s", url, exc)
                return None

    @staticmethod
    def slugify(domain: str) -> list[str]:
        """Public wrapper for unit tests."""
        return _slugify(domain)
