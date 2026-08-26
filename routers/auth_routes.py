"""APIx Authentication API — thin JWT login for procurement officers."""

import logging
import os
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    OAuth2PasswordBearer,
)
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from sqlalchemy import select

from database import User, async_session_maker
from models import DemoLoginRequest, TokenResponse, UserCreate, UserLogin, UserResponse

# Load environment variables
load_dotenv()

logger = logging.getLogger("APIx.auth_routes")

router = APIRouter(prefix="/auth", tags=["auth"])

# JWT configuration
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))  # 8 hours


def get_jwt_secret_key() -> str:
    """Retrieve the JWT secret key from environment, failing fast if not configured."""
    secret = os.getenv("JWT_SECRET_KEY")
    if not secret or not secret.strip():
        raise RuntimeError(
            "JWT_SECRET_KEY environment variable is not set. "
            "A secure secret key must be configured in environment or .env file."
        )
    return secret.strip()


# Password hashing
password_hash = PasswordHash((Argon2Hasher(),))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def _create_token(user_id: str, email: str) -> str:
    """Create a JWT access token."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "email": email,
        "exp": expire,
    }
    return jwt.encode(payload, get_jwt_secret_key(), algorithm=ALGORITHM)


async def get_current_user(token: str) -> User | None:
    """Validate JWT token and return the user. Returns None if invalid."""
    try:
        payload = jwt.decode(token, get_jwt_secret_key(), algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            return None
    except (jwt.exceptions.PyJWTError, RuntimeError):
        return None

    async with async_session_maker() as session:
        user = await session.get(User, user_id)
        return user


bearer_security = HTTPBearer(auto_error=False)


async def require_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer_security),
) -> User | None:
    """Require a valid JWT unless AUTH_DISABLED=true.

    In demo/dev mode (AUTH_DISABLED=true) requests are allowed without a
    token so the UI works offline. Otherwise a valid Bearer JWT is mandatory.
    """
    if os.getenv("AUTH_DISABLED") == "true":
        return None
    if not creds or not creds.credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await get_current_user(creds.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user


@router.post("/register", response_model=UserResponse)
async def register(req: UserCreate):
    """Register a new user account."""
    async with async_session_maker() as session:
        # Check if email already exists
        stmt = select(User).where(User.email == req.email)
        result = await session.execute(stmt)
        existing = result.scalars().first()

        if existing:
            raise HTTPException(status_code=409, detail="Email already registered")

        user = User(
            name=req.name,
            email=req.email,
            hashed_password=password_hash.hash(req.password),
            department=req.department,
            organization=req.organization,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        logger.info("New user registered: %s (%s)", user.name, user.email)

        return UserResponse(
            id=user.id,
            name=user.name,
            email=user.email,
            department=user.department,
            organization=user.organization,
            role=user.role,
        )


@router.post("/login", response_model=TokenResponse)
async def login(req: UserLogin):
    """Authenticate and return a JWT token."""
    async with async_session_maker() as session:
        stmt = select(User).where(User.email == req.email)
        result = await session.execute(stmt)
        user = result.scalars().first()

    if not user or not password_hash.verify(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    try:
        token = _create_token(user.id, user.email)
    except RuntimeError as e:
        logger.error("Authentication configuration failure: %s", e)
        raise HTTPException(
            status_code=500,
            detail="Authentication configuration error: JWT_SECRET_KEY is not configured.",
        ) from e

    logger.info("User logged in: %s", user.email)

    return TokenResponse(access_token=token)


@router.post("/demo-login", response_model=TokenResponse)
async def demo_login(req: DemoLoginRequest):
    """One-click simulated officer login for demo/demo-gated deployments.

    Only active while DEMO_MODE=true. Creates or reuses the simulated profile
    (with an ephemeral, non-recoverable password) and returns a valid token.
    """
    if os.getenv("DEMO_MODE", "false").lower() not in ("1", "true", "yes"):
        raise HTTPException(
            status_code=403,
            detail="Demo login is only available when DEMO_MODE=true",
        )

    # Non-recoverable random password — the profile can only ever be used
    # through this endpoint, never with a client-visible credential.
    ephemeral_password = os.urandom(24).hex()

    async with async_session_maker() as session:
        stmt = select(User).where(User.email == req.email)
        result = await session.execute(stmt)
        user = result.scalars().first()

        if not user:
            user = User(
                name=req.name,
                email=req.email,
                hashed_password=password_hash.hash(ephemeral_password),
                department=req.department,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            logger.info("Demo profile created: %s (%s)", user.name, user.email)
        else:
            # Reuse the existing profile; rotate its password so it can never
            # be logged into with a known/shared credential.
            user.hashed_password = password_hash.hash(ephemeral_password)
            session.add(user)
            await session.commit()

    try:
        token = _create_token(user.id, user.email)
    except RuntimeError as e:
        logger.error("Authentication configuration failure: %s", e)
        raise HTTPException(
            status_code=500,
            detail="Authentication configuration error: JWT_SECRET_KEY is not configured.",
        ) from e

    logger.info("Demo login for simulated officer: %s", user.email)
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserResponse)
async def get_me(token: str = Depends(oauth2_scheme)):
    """Get current user profile. Requires Authorization header."""
    user = await get_current_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return UserResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        department=user.department,
        organization=user.organization,
        role=user.role,
    )
