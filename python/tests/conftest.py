"""Shared fixtures for sync and async client tests."""

import pytest
import respx

from modus.client import ModusClient
from modus.async_client import AsyncModusClient

BASE_URL = "https://modustrust.ai"
API_KEY = "mod_test_xxx"


@pytest.fixture
def client():
    c = ModusClient(api_key=API_KEY, base_url=BASE_URL)
    yield c
    c.close()


@pytest.fixture
async def async_client():
    c = AsyncModusClient(api_key=API_KEY, base_url=BASE_URL)
    yield c
    await c.close()


@pytest.fixture
def mock_api():
    with respx.mock(base_url=BASE_URL) as router:
        yield router
