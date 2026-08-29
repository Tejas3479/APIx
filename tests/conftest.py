import os
import pathlib
import sys

if sys.platform == "win32":
    import asyncio
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

import pytest

test_db = "data/test_apix.db"
# Always remove stale test DB to avoid schema mismatch after model changes
_test_db_path = pathlib.Path(test_db)
try:
    if _test_db_path.exists():
        _test_db_path.unlink(missing_ok=True)
except Exception:
    pass
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{test_db}"
os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-key-32-chars-long-abcdef"
os.environ["API_KEYS"] = "test-api-key"
os.environ["AUTH_DISABLED"] = "true"
os.environ["DEMO_MODE"] = "true"

from fakeredis import FakeAsyncRedis

import app


@pytest.fixture(autouse=True)
def mock_redis(monkeypatch):
    fake_redis = FakeAsyncRedis(decode_responses=True)
    # Patch the single source and every module that imported the reference
    import services.session_manager

    monkeypatch.setattr(services.session_manager, "redis_client", fake_redis)
    monkeypatch.setattr(app, "redis_client", fake_redis)
    import routers.health

    monkeypatch.setattr(routers.health, "redis_client", fake_redis)
    yield fake_redis


@pytest.fixture
async def async_client():
    import httpx
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app.app), base_url="http://test"
    ) as ac:
        yield ac
