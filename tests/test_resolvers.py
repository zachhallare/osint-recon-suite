import pytest
import httpx
from unittest.mock import patch, AsyncMock, MagicMock
from osint_recon.resolvers import resolve_target

@pytest.mark.anyio
async def test_resolve_target_domain_passthrough():
    # A domain should pass through without making a network call
    domain, name, is_resolved = await resolve_target("example.com")
    assert domain == "example.com"
    assert name is None
    assert is_resolved is False

class _FakeResponse:
    def __init__(self, json_data):
        self._json_data = json_data
    def raise_for_status(self):
        pass
    def json(self):
        return self._json_data

class _FakeAsyncClientSuccess:
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
    async def get(self, url):
        return _FakeResponse([
            {"name": "Tesla", "domain": "tesla.com"}
        ])

class _FakeAsyncClientAmbiguous:
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
    async def get(self, url):
        return _FakeResponse([
            {"name": "Tesla", "domain": "tesla.com"},
            {"name": "Tesla Motors Club", "domain": "teslamotorsclub.com"}
        ])

@pytest.mark.anyio
async def test_resolve_target_company_success():
    with patch("httpx.AsyncClient", return_value=_FakeAsyncClientSuccess()):
        domain, name, is_resolved = await resolve_target("Tesla")
        assert domain == "tesla.com"
        assert name == "Tesla"
        assert is_resolved is True

class _FakeAsyncClientEmpty:
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
    async def get(self, url):
        return _FakeResponse([])

@pytest.mark.anyio
async def test_resolve_target_empty_fails():
    with patch("httpx.AsyncClient", return_value=_FakeAsyncClientEmpty()):
        with pytest.raises(ValueError, match="Could not resolve"):
            await resolve_target("FakeCompany")

from osint_recon.resolvers import AmbiguousResolutionError

@pytest.mark.anyio
async def test_resolve_target_ambiguous_fails():
    with patch("httpx.AsyncClient", return_value=_FakeAsyncClientAmbiguous()):
        with pytest.raises(AmbiguousResolutionError, match="Multiple candidates"):
            await resolve_target("Ambiguous")

class _FakeAsyncClientError:
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
    async def get(self, url):
        raise httpx.ConnectError("Connection failed")

@pytest.mark.anyio
async def test_resolve_target_network_error():
    with patch("httpx.AsyncClient", return_value=_FakeAsyncClientError()):
        with pytest.raises(RuntimeError, match="Network error"):
            await resolve_target("Tesla")
