import os

os.environ["AUTH_DISABLED"] = "true"

from unittest.mock import MagicMock, patch

import httpx
import pytest

from app import app


@pytest.fixture(autouse=True)
def setup_env():
    os.environ["API_KEYS"] = "test-key"
    os.environ["DISABLE_SSRF_CHECK"] = "true"
    yield
    if "API_KEYS" in os.environ:
        del os.environ["API_KEYS"]
    if "DISABLE_SSRF_CHECK" in os.environ:
        del os.environ["DISABLE_SSRF_CHECK"]


@pytest.fixture
async def async_client():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_structured_json_extraction_mocked(async_client):
    original_post = httpx.AsyncClient.post

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": '{"title": "Test Title", "links": ["http://test.com"]}'
                }
            }
        ]
    }

    async def fake_post(self, url, *args, **kwargs):
        if "api.openai.com" in str(url):
            return mock_response
        return await original_post(self, url, *args, **kwargs)

    with patch("httpx.AsyncClient.post", new=fake_post):
        headers = {"x-api-key": "test-key"}
        payload = {
            "url": "https://example.com",
            "output_format": "structured",
            "json_schema": {
                "type": "object",
                "properties": {"title": {"type": "string"}},
            },
            "llm_provider": "openai",
            "llm_api_key": "sk-test",
        }

        with patch("routers.fetch.DEMO_MODE", False):
            response = await async_client.post("/fetch", headers=headers, json=payload)
        print("RESPONSE STATUS:", response.status_code)
        data = response.json()
        print("RESPONSE DATA:", data)
        assert data.get("success") is True, f"Failed: {data}"
        assert data["content"] == {"title": "Test Title", "links": ["http://test.com"]}
