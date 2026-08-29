import asyncio
import json
import os
from datetime import datetime as dt_class
from datetime import timezone

import redis.asyncio as redis
from fastapi import HTTPException

from .log_filter import logger

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.from_url(
    REDIS_URL,
    decode_responses=True,
    socket_connect_timeout=float(os.getenv("REDIS_CONNECT_TIMEOUT", "0.5")),
    socket_timeout=float(os.getenv("REDIS_SOCKET_TIMEOUT", "0.5")),
    retry_on_timeout=False,
)

SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "30"))
MAX_SESSIONS = int(os.getenv("MAX_SESSIONS", "100"))


class SessionManager:
    """
    Manages both curl_cffi and Playwright sessions keyed by session_id.
    Metadata is persisted in Redis, while actual connections are held in local memory.
    """

    def __init__(self):
        self.local_sessions: dict[str, dict] = {}
        self.ttl_seconds: int = SESSION_TTL_MINUTES * 60
        self._lock: asyncio.Lock = asyncio.Lock()

    async def get_session_meta(self, session_id: str) -> dict | None:
        data = await redis_client.get(f"session:{session_id}")
        if data:
            return json.loads(data)
        return None

    async def count_sessions(self) -> int:
        try:
            cursor = 0
            count = 0
            while True:
                cursor, keys = await redis_client.scan(
                    cursor, match="session:*", count=100
                )
                count += len(keys)
                if cursor == 0:
                    break
            return count
        except Exception:
            return len(self.local_sessions)

    async def get_or_create(self, session_id: str, engine: str) -> dict:
        async with self._lock:
            now_str = dt_class.now(timezone.utc).isoformat()
            redis_key = f"session:{session_id}"

            data = await redis_client.get(redis_key)
            if data:
                session_meta = json.loads(data)
                if session_meta["engine"] != engine:
                    logger.info(
                        f"Switching session engine for {session_id} from {session_meta['engine']} to {engine}"
                    )
                    session_meta["engine"] = engine
                    if session_id in self.local_sessions:
                        await self._close_local(session_id)
                session_meta["last_active"] = now_str
                session_meta["request_count"] += 1
            else:
                current_count = await self.count_sessions()
                if current_count >= MAX_SESSIONS:
                    logger.warning(
                        f"Session limit reached ({MAX_SESSIONS}). Rejecting new session {session_id}."
                    )
                    raise HTTPException(
                        status_code=429,
                        detail=f"Maximum concurrent sessions ({MAX_SESSIONS}) reached.",
                    )

                logger.info(
                    f"Creating new session context: {session_id} (engine: {engine})"
                )
                session_meta = {
                    "session_id": session_id,
                    "cookies": {},
                    "last_active": now_str,
                    "created_at": now_str,
                    "request_count": 1,
                    "engine": engine,
                }

            await redis_client.setex(
                redis_key, self.ttl_seconds, json.dumps(session_meta)
            )

            if session_id not in self.local_sessions:
                self.local_sessions[session_id] = {
                    "curl_session": None,
                    "playwright_context": None,
                }

            self.local_sessions[session_id].update(session_meta)
            return self.local_sessions[session_id]

    async def update_cookies(self, session_id: str, new_cookies: dict):
        async with self._lock:
            redis_key = f"session:{session_id}"
            data = await redis_client.get(redis_key)
            if data:
                session_meta = json.loads(data)
                session_meta["cookies"].update(new_cookies)
                await redis_client.setex(
                    redis_key, self.ttl_seconds, json.dumps(session_meta)
                )

    async def delete_session(self, session_id: str):
        async with self._lock:
            await redis_client.delete(f"session:{session_id}")
            await self._close_local(session_id)

    async def _close_local(self, session_id: str):
        if session_id in self.local_sessions:
            logger.info(f"Deleting local session context: {session_id}")
            session = self.local_sessions.pop(session_id)
            if session.get("curl_session"):
                try:
                    await session["curl_session"].close()
                except Exception:
                    pass
            if session.get("playwright_context"):
                try:
                    await session["playwright_context"].close()
                except Exception:
                    pass

    async def close_all(self):
        logger.info("Closing all active local session contexts...")
        for sid in list(self.local_sessions.keys()):
            await self._close_local(sid)

    async def cleanup_loop(self):
        try:
            while True:
                await asyncio.sleep(300)
                expired_ids = []
                async with self._lock:
                    for sid in list(self.local_sessions.keys()):
                        if not await redis_client.exists(f"session:{sid}"):
                            expired_ids.append(sid)
                for sid in expired_ids:
                    logger.info(f"Session {sid} expired in Redis. Cleaning up locally.")
                    await self._close_local(sid)
        except asyncio.CancelledError:
            logger.info("Session cleanup loop cancelled gracefully.")
            raise

    async def list_sessions(self) -> list[dict]:
        result = []
        cursor = 0
        while True:
            cursor, keys = await redis_client.scan(cursor, match="session:*", count=100)
            if keys:
                values = await redis_client.mget(keys)
                for val in values:
                    if val:
                        s = json.loads(val)
                        created_str = s["created_at"]
                        last_active_str = s["last_active"]
                        result.append(
                            {
                                "session_id": s["session_id"],
                                "engine": s["engine"],
                                "created_at": created_str
                                + ("Z" if not created_str.endswith("Z") else ""),
                                "last_active": last_active_str
                                + ("Z" if not last_active_str.endswith("Z") else ""),
                                "request_count": s["request_count"],
                                "cookie_count": len(s["cookies"]),
                            }
                        )
            if cursor == 0:
                break
        return result


session_manager = SessionManager()
