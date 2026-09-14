"""
tests/conftest.py
-----------------
Global pytest fixtures and configuration.

Lock anyio tests to the asyncio backend only (trio is not installed).
"""

import pytest


@pytest.fixture(params=["asyncio"])
def anyio_backend(request):
    return request.param
