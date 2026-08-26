import os
import pathlib

import pytest

test_db = "data/test_apix.db"
# Always remove stale test DB to avoid schema mismatch after model changes
_test_db_path = pathlib.Path(test_db)
if _test_db_path.exists():
    _test_db_path.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{test_db}"
os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-key-32-chars-long-abcdef"
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
