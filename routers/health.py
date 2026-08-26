"""APIx health & readiness probe — status, database, redis, playwright & index counts."""

import os

from fastapi import APIRouter
from sqlalchemy import func, select, text

from database import DailyIndex, FareQuote, RouteConfig, ScrapeJob, async_session_maker
from fetcher import playwright_mgr, redis_client, session_manager

router = APIRouter(tags=["health"])

APP_VERSION = "1.0.0"
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in ("1", "true", "yes")


@router.get("/api/health")
async def health():
    # Check Database
    db_status = "ok"
    try:
        async with async_session_maker() as session:
            await session.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"error: {e!s}"

    # Check Redis
    redis_status = "ok"
    try:
        await redis_client.ping()
    except Exception as e:
        redis_status = f"offline (local memory mode: {e!s})"

    active_sessions = 0
    try:
        active_sessions = await session_manager.count_sessions()
    except Exception:
        active_sessions = 0

    # APIx Data Counts
    counts = {
        "routes_configured": 0,
        "total_fare_quotes": 0,
        "computed_daily_indices": 0,
        "scrape_jobs_count": 0,
    }
    try:
        async with async_session_maker() as session:
            counts["routes_configured"] = (
                await session.execute(select(func.count()).select_from(RouteConfig))
            ).scalar() or 0
            counts["total_fare_quotes"] = (
                await session.execute(select(func.count()).select_from(FareQuote))
            ).scalar() or 0
            counts["computed_daily_indices"] = (
                await session.execute(select(func.count()).select_from(DailyIndex))
            ).scalar() or 0
            counts["scrape_jobs_count"] = (
                await session.execute(select(func.count()).select_from(ScrapeJob))
            ).scalar() or 0
    except Exception:
        pass

    return {
        "status": "ok" if db_status == "ok" else "degraded",
        "app": "APIx",
        "version": APP_VERSION,
        "demo_mode": DEMO_MODE,
        "database": db_status,
        "redis": redis_status,
        "active_sessions": active_sessions,
        "playwright_slots_free": playwright_mgr.slots_free,
        "apix_metrics": {
            "routes_configured": counts["routes_configured"],
            "total_fare_quotes": counts["total_fare_quotes"],
            "computed_daily_indices": counts["computed_daily_indices"],
            "scrape_jobs_count": counts["scrape_jobs_count"],
        },
    }
