import logging
import os

from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from database import ApiKey, async_session_maker

logger = logging.getLogger("apix.auth")

# API KEY AUTH
VALID_KEYS: set[str] = {
    k.strip() for k in os.getenv("API_KEYS", "").split(",") if k.strip()
}
if not VALID_KEYS:
    logger.warning("API_KEYS not set. Authentication is DISABLED.")

security_header = APIKeyHeader(name="x-api-key", auto_error=False)
security_bearer = HTTPBearer(auto_error=False)


async def verify_api_key(
    x_api_key: str | None = Depends(security_header),
    bearer: HTTPAuthorizationCredentials | None = Depends(security_bearer),
):
    token = None
    if x_api_key:
        token = x_api_key.strip()
    elif bearer:
        token = bearer.credentials.strip()

    if token:
        # Check ENV dynamically or static set
        env_keys = {
            k.strip() for k in os.getenv("API_KEYS", "").split(",") if k.strip()
        }
        if token in VALID_KEYS or token in env_keys:
            return

        # Check DB
        async with async_session_maker() as session:
            key_record = await session.get(ApiKey, token)
            if key_record:
                return

    # Accept a valid officer JWT so authenticated browser sessions can use
    # the fetch/admin endpoints without embedding an API key in client JS.
    if bearer and bearer.credentials:
        try:
            from routers.auth_routes import get_current_user

            if await get_current_user(bearer.credentials):
                return
        except Exception:
            pass

    # If no token provided or invalid token, check if auth is disabled
    if not VALID_KEYS:
        async with async_session_maker() as session:
            result = await session.execute(select(ApiKey).limit(1))
            has_keys = result.scalars().first() is not None
        if not has_keys and os.getenv("AUTH_DISABLED") == "true":
            return  # Auth is disabled completely

    raise HTTPException(status_code=401, detail="Invalid or missing API key")
