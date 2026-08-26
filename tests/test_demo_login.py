"""Tests for the DEMO_MODE-gated one-click simulated officer login."""

import os
from unittest.mock import patch

import httpx
import pytest
from sqlalchemy import select

from app import app
from database import User, async_session_maker, init_db


@pytest.fixture(autouse=True)
async def setup_env():
    os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-key-32-chars-long-abcdef"
    await init_db()
    yield


@pytest.fixture
async def demo_client():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_demo_login_requires_demo_mode(demo_client):
    with patch.dict(os.environ, {"DEMO_MODE": "false"}):
        r = await demo_client.post(
            "/auth/demo-login",
            json={
                "name": "Shri R. K. Sharma",
                "email": "r.sharma@mod.gov.in",
                "department": "Ministry of Defence",
            },
        )
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_demo_login_creates_profile_and_returns_token(demo_client):
    with patch.dict(os.environ, {"DEMO_MODE": "true"}):
        r = await demo_client.post(
            "/auth/demo-login",
            json={
                "name": "Shri R. K. Sharma",
                "email": "r.sharma@mod.gov.in",
                "department": "Ministry of Defence",
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["token_type"] == "bearer"
        assert body["access_token"]

        # Profile is persisted
        async with async_session_maker() as session:
            stmt = select(User).where(User.email == "r.sharma@mod.gov.in")
            user = (await session.execute(stmt)).scalars().first()
            assert user is not None
            assert user.name == "Shri R. K. Sharma"
            # Password must be a hashed value, never the literal demo secret
            assert "APIx@SIH2026" not in user.hashed_password


@pytest.mark.asyncio
async def test_demo_login_reuses_existing_profile(demo_client):
    with patch.dict(os.environ, {"DEMO_MODE": "true"}):
        payload = {
            "name": "Ms. Priya Iyer",
            "email": "p.iyer@meity.gov.in",
            "department": "MeitY / NIC",
        }
        r1 = await demo_client.post("/auth/demo-login", json=payload)
        assert r1.status_code == 200
        r2 = await demo_client.post("/auth/demo-login", json=payload)
        assert r2.status_code == 200

        # Exactly one profile row, re-used across clicks.
        async with async_session_maker() as session:
            stmt = select(User).where(User.email == "p.iyer@meity.gov.in")
            users = (await session.execute(stmt)).scalars().all()
            assert len(users) == 1
