import os
import sys

if sys.platform == "win32":
    import asyncio

    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

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
        data = response.json()
        assert data.get("success") is True, f"Failed: {data}"
        assert data["content"] == {"title": "Test Title", "links": ["http://test.com"]}


@pytest.mark.asyncio
async def test_content_processor_markdown_and_html():
    from services.content import process_content

    html_doc = """
    <html>
      <head><title>Airline Quotes</title></head>
      <body>
        <nav><a href="/home">Home</a></nav>
        <div id="fares">
          <h1>DEL-BOM Fares</h1>
          <p>IndiGo 6E-204: <strong>₹6,250</strong></p>
          <a href="https://goindigo.in">Book Now</a>
        </div>
        <footer>Copyright MoSPI</footer>
      </body>
    </html>
    """

    # Test markdown format
    md = await process_content(
        html=html_doc,
        output_format="markdown",
        base_url="https://example.com/flights",
        strip_links=False,
    )
    assert "# DEL-BOM Fares" in md
    assert "₹6,250" in md
    assert "Copyright MoSPI" not in md  # footer stripped

    # Test css_selector pruning
    md_pruned = await process_content(
        html=html_doc,
        output_format="markdown",
        base_url="https://example.com/flights",
        css_selector="#fares",
    )
    assert "# DEL-BOM Fares" in md_pruned
    assert "Home" not in md_pruned

    # Test html passthrough
    raw = await process_content(
        html=html_doc,
        output_format="html",
        base_url="https://example.com/flights",
    )
    assert "<title>Airline Quotes</title>" in raw


@pytest.mark.asyncio
async def test_ssrf_protection(monkeypatch):
    from services.ssrf import is_ssrf_safe

    monkeypatch.delenv("DISABLE_SSRF_CHECK", raising=False)
    assert await is_ssrf_safe("https://google.com") is True
    assert await is_ssrf_safe("http://127.0.0.1:8000") is False
    assert await is_ssrf_safe("http://localhost:8000") is False
    assert await is_ssrf_safe("http://10.0.0.1") is False
    assert await is_ssrf_safe("http://169.254.169.254/latest/meta-data/") is False
