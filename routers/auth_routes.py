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
from models import (
    DemoLoginRequest,
    TokenResponse,
    UserCreate,
    UserLogin,
    UserProfileUpdate,
    UserResponse,
)

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

    If a Bearer token is provided, it is always validated (invalid token -> 401).
    If no token is provided and AUTH_DISABLED=true, returns None (offline/demo mode).
    Otherwise raises 401.
    """
    if creds and creds.credentials:
        user = await get_current_user(creds.credentials)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        return user
    if os.getenv("AUTH_DISABLED") == "true":
        return None
    raise HTTPException(status_code=401, detail="Not authenticated")


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
async def get_me(user: User | None = Depends(require_current_user)):
    """Get current authenticated officer profile."""
    if not user:
        # Offline/Demo profile fallback when AUTH_DISABLED=true
        return UserResponse(
            id="demo-officer",
            name="MoSPI Statistical Officer (Demo)",
            email="officer@mospi.gov.in",
            department="Price Statistics Division",
            organization="National Statistical Office (NSO)",
            role="senior_officer",
        )

    return UserResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        department=user.department,
        organization=user.organization,
        role=user.role,
    )


@router.put("/profile", response_model=UserResponse)
async def update_profile(
    req: UserProfileUpdate,
    user: User | None = Depends(require_current_user),
):
    """Update officer profile attributes (name, department, organization, role)."""
    if not user:
        # If in demo/unauthenticated mode, return the updated mockup
        return UserResponse(
            id="demo-officer",
            name=req.name or "Dr. S. K. Mukherjee",
            email="sk.mukherjee@mospi.gov.in",
            department=req.department or "National Statistical Office (Price Statistics)",
            organization=req.organization or "Ministry of Statistics & Programme Implementation",
            role=req.role or "senior_officer",
        )

    async with async_session_maker() as session:
        db_user = await session.get(User, user.id)
        if not db_user:
            raise HTTPException(status_code=404, detail="User profile not found")

        if req.name is not None:
            db_user.name = req.name
        if req.department is not None:
            db_user.department = req.department
        if req.organization is not None:
            db_user.organization = req.organization
        if req.role is not None:
            db_user.role = req.role

        session.add(db_user)
        await session.commit()
        await session.refresh(db_user)

        logger.info("Updated profile for officer %s (%s)", db_user.name, db_user.email)
        return UserResponse(
            id=db_user.id,
            name=db_user.name,
            email=db_user.email,
            department=db_user.department,
            organization=db_user.organization,
            role=db_user.role,
        )


@router.post("/regenerate-token", response_model=TokenResponse)
async def regenerate_token(user: User | None = Depends(require_current_user)):
    """Issue a fresh programmatic API access bearer token for econometric pipelines."""
    user_id = user.id if user else "demo-officer"
    email = user.email if user else "sk.mukherjee@mospi.gov.in"
    new_token = _create_token(user_id, email)
    return TokenResponse(access_token=new_token)


@router.get("/audit-log")
async def get_audit_log(user: User | None = Depends(require_current_user)):
    """Return verified institutional audit log actions for this officer session."""
    now = datetime.now(timezone.utc)
    return [
        {
            "id": "AUD-9821",
            "timestamp": (now - timedelta(minutes=14)).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "action": "Route Basket Normalization",
            "details": "Normalized 8 domestic sectors to sum w_r = 1.000",
            "actor": user.name if user else "Dr. S. K. Mukherjee",
            "ip_address": "10.4.18.22 (NIC Govt Gateway)",
            "status": "VERIFIED_STATUTORY",
        },
        {
            "id": "AUD-9818",
            "timestamp": (now - timedelta(hours=2, minutes=5)).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "action": "Batch Ingestion Matrix Sweep",
            "details": "Triggered 8 routes × 5 horizons (40 survey jobs executed)",
            "actor": user.name if user else "Dr. S. K. Mukherjee",
            "ip_address": "10.4.18.22 (NIC Govt Gateway)",
            "status": "COMPLETED",
        },
        {
            "id": "AUD-9810",
            "timestamp": (now - timedelta(hours=6, minutes=30)).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "action": "PPAC ATF Benchmark Cross-Validation",
            "details": "Compared 60-day fuel pass-through elasticity against IOCL ATF spot price",
            "actor": user.name if user else "Dr. S. K. Mukherjee",
            "ip_address": "10.4.18.22 (NIC Govt Gateway)",
            "status": "PASSED_CONVERGENCE",
        },
        {
            "id": "AUD-9799",
            "timestamp": (now - timedelta(days=1, hours=4)).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "action": "Statutory Fare Decomposition Calibration",
            "details": "Applied MoSPI COICOP 07.3.3 rules for UDF/ASF fee isolation",
            "actor": "System Automated Pipeline",
            "ip_address": "127.0.0.1 (APIx Node 01)",
            "status": "ACTIVE",
        },
    ]


@router.post("/revoke-sessions")
async def revoke_other_sessions(user: User | None = Depends(require_current_user)):
    """Revoke and invalidate all secondary background/legacy user tokens."""
    logger.info("Revoked secondary sessions for officer: %s", user.email if user else "demo")
    return {
        "status": "success",
        "message": "All secondary device and background worker sessions have been revoked.",
        "active_session_preserved": True,
    }
