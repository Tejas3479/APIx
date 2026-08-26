import os
from unittest.mock import patch

import httpx
import pytest
from sqlalchemy import select

from app import app
from database import User, async_session_maker, init_db
from routers.auth_routes import get_jwt_secret_key


@pytest.fixture(autouse=True)
async def setup_auth_env():
    os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-key-32-chars-long-abcdef"
    await init_db()
    yield


@pytest.fixture
async def auth_client():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


def test_get_jwt_secret_key_success():
    with patch.dict(
        os.environ, {"JWT_SECRET_KEY": "a-very-secret-key-for-jwt-testing-123"}
    ):
        assert get_jwt_secret_key() == "a-very-secret-key-for-jwt-testing-123"


def test_get_jwt_secret_key_missing_fail_fast():
    with (
        patch.dict(os.environ, {"JWT_SECRET_KEY": ""}),
        pytest.raises(
            RuntimeError, match="JWT_SECRET_KEY environment variable is not set"
        ),
    ):
        get_jwt_secret_key()


def test_get_jwt_secret_key_whitespace_fail_fast():
    with (
        patch.dict(os.environ, {"JWT_SECRET_KEY": "   "}),
        pytest.raises(
            RuntimeError, match="JWT_SECRET_KEY environment variable is not set"
        ),
    ):
        get_jwt_secret_key()


@pytest.mark.asyncio
async def test_auth_register_and_login_flow(auth_client):
    test_email = "officer.test@nic.in"
    test_password = "SecurePassword#2026"

    # 1. Clean up user if exists
    async with async_session_maker() as session:
        stmt = select(User).where(User.email == test_email)
        res = await session.execute(stmt)
        existing = res.scalars().first()
        if existing:
            await session.delete(existing)
            await session.commit()

    # 2. Register user
    reg_payload = {
        "name": "Test Officer",
        "email": test_email,
        "password": test_password,
        "department": "IT Procurement",
        "organization": "MeitY",
    }
    r_reg = await auth_client.post("/auth/register", json=reg_payload)
    assert r_reg.status_code == 200
    reg_data = r_reg.json()
    assert reg_data["email"] == test_email
    assert reg_data["name"] == "Test Officer"

    # 3. Duplicate registration -> 409 Conflict
    r_dup = await auth_client.post("/auth/register", json=reg_payload)
    assert r_dup.status_code == 409

    # 4. Login with correct credentials
    login_payload = {"email": test_email, "password": test_password}
    r_login = await auth_client.post("/auth/login", json=login_payload)
    assert r_login.status_code == 200
    token_data = r_login.json()
    assert "access_token" in token_data
    token = token_data["access_token"]
    assert token_data["token_type"] == "bearer"

    # 5. Access /auth/me with valid token
    headers = {"Authorization": f"Bearer {token}"}
    r_me = await auth_client.get("/auth/me", headers=headers)
    assert r_me.status_code == 200
    me_data = r_me.json()
    assert me_data["email"] == test_email
    assert me_data["department"] == "IT Procurement"

    # 6. Access /auth/me with invalid token -> 401
    r_invalid_token = await auth_client.get(
        "/auth/me", headers={"Authorization": "Bearer invalid.jwt.token"}
    )
    assert r_invalid_token.status_code == 401


@pytest.mark.asyncio
async def test_login_fails_fast_when_jwt_secret_unset(auth_client):
    test_email = "officer.failfast@nic.in"
    test_password = "Password123!"

    # Ensure user exists
    async with async_session_maker() as session:
        stmt = select(User).where(User.email == test_email)
        res = await session.execute(stmt)
        if not res.scalars().first():
            user = User(
                name="Failfast Officer",
                email=test_email,
                hashed_password="$argon2id$v=19$m=65536,t=3,p=4$fakehash",
            )
            session.add(user)
            await session.commit()

    # When JWT_SECRET_KEY is removed/empty in env, login returns 500 configuration error
    with (
        patch.dict(os.environ, {"JWT_SECRET_KEY": ""}),
        patch("routers.auth_routes.password_hash.verify", return_value=True),
    ):
        r_login = await auth_client.post(
            "/auth/login",
            json={"email": test_email, "password": test_password},
        )
        assert r_login.status_code == 500
        assert "JWT_SECRET_KEY is not configured" in r_login.json()["detail"]
