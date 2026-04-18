"""Shared fixtures for sync and async client tests."""

import pytest
import respx

from modei.client import ModeiClient
from modei.async_client import AsyncModeiClient

BASE_URL = "https://modeioperator.com"
API_KEY = "mod_test_xxx"


@pytest.fixture
def client():
    c = ModeiClient(api_key=API_KEY, base_url=BASE_URL)
    yield c
    c.close()


@pytest.fixture
async def async_client():
    c = AsyncModeiClient(api_key=API_KEY, base_url=BASE_URL)
    yield c
    await c.close()


@pytest.fixture
def mock_api():
    with respx.mock(base_url=BASE_URL) as router:
        yield router
