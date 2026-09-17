"""Unit tests for SocialMediaModule using mocked HTTP responses."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from osint_recon.models import ModuleStatus, RiskLevel
from osint_recon.modules.social_media_module import SocialMediaModule




def _resp(status: int, body=None, text: str | None = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    if text is not None:
        r.text = text
        r.json = MagicMock(return_value=None)
    elif body is not None:
        r.json = MagicMock(return_value=body)
        r.text = json.dumps(body)
    else:
        r.json = MagicMock(return_value=None)
        r.text = ""
    return r


class _RouterClient:
    """Fake async client that routes URLs to canned responses.
    Routes match by substring, with longer patterns taking priority.
    """
    def __init__(self, routes: dict, default_status: int = 404):
        # Sort routes by key length descending so more-specific patterns match first.
        self._routes = dict(sorted(routes.items(), key=lambda kv: len(kv[0]), reverse=True))
        self._default = _resp(default_status)

    async def __aenter__(self): return self
    async def __aexit__(self, *a): pass

    async def head(self, url, **kw):
        for pattern, response in self._routes.items():
            if pattern in url:
                return response
        return self._default

    async def get(self, url, **kw):
        for pattern, response in self._routes.items():
            if pattern in url:
                return response
        return self._default




class TestSlugify:
    def test_simple_domain(self):
        assert "example" in SocialMediaModule.slugify("example.com")

    def test_hyphenated_domain(self):
        slugs = SocialMediaModule.slugify("my-company.io")
        assert "my-company" in slugs
        assert "mycompany" in slugs

    def test_two_part_tld(self):
        slugs = SocialMediaModule.slugify("acme.co.uk")
        assert "acme" in slugs

    def test_subdomain_not_included(self):
        # only the base domain label is used
        slugs = SocialMediaModule.slugify("example.com")
        assert all("." not in s for s in slugs)

    def test_dot_in_base_stripped(self):
        slugs = SocialMediaModule.slugify("my.company.com")
        # "my.company" -> "my.company" and "mycompany"
        no_dot = [s for s in slugs if "." not in s]
        assert no_dot  # at least one slug without dot




class TestProbePlatform:

    @pytest.mark.anyio
    async def test_200_creates_medium_risk_finding(self):
        mod = SocialMediaModule()
        resp = _resp(200)
        client = _RouterClient({"github.com/example": resp})
        async with httpx.AsyncClient() as _:
            finding = await mod._probe_platform(
                client, "GitHub", "https://github.com/{slug}",
                "head", {200}, "example"
            )
        assert finding is not None
        assert finding.finding_type == "social_profile"
        assert finding.risk_level == RiskLevel.MEDIUM
        assert finding.extra["platform"] == "GitHub"

    @pytest.mark.anyio
    async def test_404_returns_none(self):
        mod = SocialMediaModule()
        resp = _resp(404)
        client = _RouterClient({"github.com/noone": resp})
        async with httpx.AsyncClient() as _:
            finding = await mod._probe_platform(
                client, "GitHub", "https://github.com/{slug}",
                "head", {200}, "noone"
            )
        assert finding is None

    @pytest.mark.anyio
    async def test_timeout_returns_none(self):
        mod = SocialMediaModule()
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        client.head = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        finding = await mod._probe_platform(
            client, "GitHub", "https://github.com/{slug}",
            "head", {200}, "example"
        )
        assert finding is None

    @pytest.mark.anyio
    async def test_hackernews_null_body_returns_none(self):
        """HackerNews API returns null JSON for non-existent users (still HTTP 200)."""
        mod = SocialMediaModule()
        resp = _resp(200, body=None)
        resp.json = MagicMock(return_value=None)
        client = _RouterClient({"firebaseio.com": resp})
        async with httpx.AsyncClient() as _:
            finding = await mod._probe_platform(
                client, "HackerNews",
                "https://hacker-news.firebaseio.com/v0/user/{slug}.json",
                "get", {200}, "nobody"
            )
        assert finding is None

    @pytest.mark.anyio
    async def test_hackernews_valid_user_returns_finding(self):
        """HackerNews API returns user object for existing users."""
        mod = SocialMediaModule()
        resp = _resp(200, body={"id": "pg", "karma": 155111})
        client = _RouterClient({"firebaseio.com": resp})
        async with httpx.AsyncClient() as _:
            finding = await mod._probe_platform(
                client, "HackerNews",
                "https://hacker-news.firebaseio.com/v0/user/{slug}.json",
                "get", {200}, "pg"
            )
        assert finding is not None
        assert finding.finding_type == "social_profile"




class TestGhGet:

    @pytest.mark.anyio
    async def test_200_returns_json(self):
        mod = SocialMediaModule()
        resp = _resp(200, body={"login": "example"})
        client = _RouterClient({"api.github.com": resp})
        result = await mod._gh_get(client, "https://api.github.com/orgs/example")
        assert result == {"login": "example"}

    @pytest.mark.anyio
    async def test_404_returns_none(self):
        mod = SocialMediaModule()
        client = _RouterClient({}, default_status=404)
        result = await mod._gh_get(client, "https://api.github.com/orgs/nobody")
        assert result is None

    @pytest.mark.anyio
    async def test_403_rate_limit_returns_none(self):
        mod = SocialMediaModule()
        resp = _resp(403, body={"message": "API rate limit exceeded"})
        client = _RouterClient({"api.github.com": resp})
        result = await mod._gh_get(client, "https://api.github.com/orgs/example")
        assert result is None




class TestEnrichGitHub:

    def _org_data(self) -> dict:
        return {
            "login": "example",
            "html_url": "https://github.com/example",
            "name": "Example Corp",
            "description": "We make things",
            "public_repos": 12,
            "followers": 500,
            "email": "oss@example.com",
            "location": "San Francisco, CA",
            "blog": "https://example.com",
        }

    def _repos_data(self) -> list:
        return [
            {
                "name": "website",
                "html_url": "https://github.com/example/website",
                "description": "Public website",
                "stargazers_count": 10,
                "language": "JavaScript",
                "pushed_at": "2026-01-01T00:00:00Z",
            },
            {
                "name": "terraform-infra",
                "html_url": "https://github.com/example/terraform-infra",
                "description": "Production infrastructure as code",
                "stargazers_count": 0,
                "language": "HCL",
                "pushed_at": "2026-09-01T00:00:00Z",
            },
            {
                "name": "ansible-deploy",
                "html_url": "https://github.com/example/ansible-deploy",
                "description": "Deploy scripts",
                "stargazers_count": 2,
                "language": "Python",
                "pushed_at": "2026-08-01T00:00:00Z",
            },
        ]

    @pytest.mark.anyio
    async def test_entity_finding_created(self):
        mod = SocialMediaModule()
        routes = {
            "api.github.com/orgs/example": _resp(200, self._org_data()),
            "api.github.com/orgs/example/repos": _resp(200, self._repos_data()),
        }
        client = _RouterClient(routes)
        findings = await mod._enrich_github(client, "example")
        entity = next((f for f in findings if f.finding_type == "github_entity"), None)
        assert entity is not None
        assert entity.risk_level == RiskLevel.LOW
        assert "Example Corp" in entity.extra["name"]

    @pytest.mark.anyio
    async def test_email_in_profile_is_medium_risk(self):
        mod = SocialMediaModule()
        routes = {
            "api.github.com/orgs/example": _resp(200, self._org_data()),
            "api.github.com/orgs/example/repos": _resp(200, self._repos_data()),
        }
        client = _RouterClient(routes)
        findings = await mod._enrich_github(client, "example")
        email_f = next((f for f in findings if f.finding_type == "github_email"), None)
        assert email_f is not None
        assert email_f.value == "oss@example.com"
        assert email_f.risk_level == RiskLevel.MEDIUM

    @pytest.mark.anyio
    async def test_sensitive_repos_flagged_as_high(self):
        mod = SocialMediaModule()
        routes = {
            "api.github.com/orgs/example": _resp(200, self._org_data()),
            "api.github.com/orgs/example/repos": _resp(200, self._repos_data()),
        }
        client = _RouterClient(routes)
        findings = await mod._enrich_github(client, "example")
        sensitive = [f for f in findings if f.finding_type == "github_sensitive_repo"]
        assert len(sensitive) == 2  # terraform-infra and ansible-deploy
        assert all(f.risk_level == RiskLevel.HIGH for f in sensitive)

    @pytest.mark.anyio
    async def test_repos_summary_finding_created(self):
        mod = SocialMediaModule()
        routes = {
            "api.github.com/orgs/example": _resp(200, self._org_data()),
            "api.github.com/orgs/example/repos": _resp(200, self._repos_data()),
        }
        client = _RouterClient(routes)
        findings = await mod._enrich_github(client, "example")
        summary = next((f for f in findings if f.finding_type == "github_repos_summary"), None)
        assert summary is not None
        assert summary.extra["repo_count"] == 3

    @pytest.mark.anyio
    async def test_404_org_falls_back_to_user(self):
        mod = SocialMediaModule()
        user_data = {
            "login": "example",
            "html_url": "https://github.com/example",
            "name": "Example User",
            "description": None,
            "public_repos": 5,
            "followers": 20,
            "email": None,
            "location": "",
            "blog": "",
        }
        routes = {
            # org returns 404, user returns 200
            "api.github.com/orgs/example": _resp(404),
            "api.github.com/users/example": _resp(200, user_data),
            "api.github.com/users/example/repos": _resp(200, []),
        }
        client = _RouterClient(routes)
        findings = await mod._enrich_github(client, "example")
        entity = next((f for f in findings if f.finding_type == "github_entity"), None)
        assert entity is not None
        assert entity.extra["type"] == "user"

    @pytest.mark.anyio
    async def test_empty_slug_returns_no_findings(self):
        mod = SocialMediaModule()
        client = _RouterClient({})
        findings = await mod._enrich_github(client, "")
        assert findings == []




@pytest.mark.anyio
async def test_full_run_github_profile_found():
    mod = SocialMediaModule()

    org_data = {
        "login": "example",
        "html_url": "https://github.com/example",
        "name": "Example Corp",
        "description": "Test org",
        "public_repos": 1,
        "followers": 10,
        "email": "",
        "location": "",
        "blog": "",
    }
    repos_data = [{
        "name": "public-site",
        "html_url": "https://github.com/example/public-site",
        "description": "Our website",
        "stargazers_count": 1,
        "language": "HTML",
        "pushed_at": "2026-01-01T00:00:00Z",
    }]

    routes = {
        "github.com/example":               _resp(200),
        "api.github.com/orgs/example":      _resp(200, org_data),
        "api.github.com/orgs/example/repos": _resp(200, repos_data),
    }

    with patch("httpx.AsyncClient", return_value=_RouterClient(routes)):
        result = await mod.run("example.com")

    assert result.status == ModuleStatus.SUCCESS
    assert result.module_name == "social_media"
    types = {f.finding_type for f in result.findings}
    assert "social_profile" in types
    assert "github_entity" in types


@pytest.mark.anyio
async def test_full_run_no_profiles_returns_success():
    """Unmatched profile probes should return success with no findings."""
    mod = SocialMediaModule()
    with patch("httpx.AsyncClient", return_value=_RouterClient({}, default_status=404)):
        result = await mod.run("example.com")
    assert result.status == ModuleStatus.SUCCESS
    assert result.findings == []
