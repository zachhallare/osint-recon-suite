"""Global pytest fixtures.

Locks anyio tests to asyncio since trio is not installed.
"""

import pytest


@pytest.fixture(params=["asyncio"])
def anyio_backend(request):
    return request.param
