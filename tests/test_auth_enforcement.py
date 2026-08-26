"""Test JWT Authentication Enforcement across APIx endpoints."""

import os

import httpx
import pytest
from fastapi.testclient import TestClient

from app import app
from database import init_db

client = TestClient(app)


@pytest.fixture(autouse=True)
async def setup_env():
    os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-key-32-chars-long-abcdef"
    await init_db()
    yield


def _register_and_login() -> str:
    """Register + login a real statistical officer, returning a JWT access token."""
    reg = client.post(
        "/auth/register",
        json={
            "name": "Dr. S. K. Mukherjee",
            "email": "sk.mukherjee@mospi.gov.in",
            "password": "SecurePass123",
            "department": "National Statistical Office",
        },
    )
    assert reg.status_code in (200, 409), reg.text
    login = client.post(
        "/auth/login",
        json={"email": "sk.mukherjee@mospi.gov.in", "password": "SecurePass123"},
    )
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


@pytest.mark.asyncio
async def test_demo_login_flow():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as ac:
        r = await ac.post(
            "/auth/demo-login",
            json={
                "name": "Dr. S. K. Mukherjee",
                "email": "sk.mukherjee@mospi.gov.in",
                "department": "National Statistical Office (Price Statistics)",
                "role": "senior_officer",
            },
        )
        assert r.status_code == 200
        token = r.json().get("access_token")
        assert token is not None
        assert len(token) > 20


@pytest.mark.asyncio
async def test_auth_disabled_allows_anonymous():
    import os as _os
    from unittest.mock import patch

    with patch.dict(_os.environ, {"AUTH_DISABLED": "true"}):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as ac:
            r = await ac.get("/api/v1/routes")
            assert r.status_code == 200, r.text