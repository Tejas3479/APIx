"""Scrape Scheduler & Matrix Task Dispatcher for APIx.

Generates the survey matrix (Routes × Advance Windows) and executes batch scraping jobs,
logging progress, quote counts, and telemetry events into ScrapeJob and live ring buffer.
"""

import asyncio
from collections import deque
import logging
import os
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from database import RouteConfig, ScrapeJob, async_session_maker
from services.search_orchestrator import run_fare_survey

logger = logging.getLogger("apix.scheduler")

STANDARD_WINDOWS = [1, 7, 15, 30, 45]
SCHEDULED_INTERVAL_HOURS = int(os.getenv("SCRAPE_INTERVAL_HOURS", "24"))

# Live In-Memory Telemetry Ring Buffer (bounded to last 100 events)
_TELEMETRY_LOGS: deque[dict[str, Any]] = deque(maxlen=100)


def emit_telemetry(event_type: str, text: str, level: str = "ok"):
    """Append a live event to the in-memory telemetry ring buffer."""
    event = {
        "id": str(uuid.uuid4())[:8],
        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type.upper(),
        "text": text,
        "level": level,  # "ok", "info", "warn", "error"
    }
    _TELEMETRY_LOGS.append(event)
    logger.debug("Telemetry [%s]: %s", event["type"], text)


def get_live_telemetry_logs(limit: int = 30) -> list[dict[str, Any]]:
    """Retrieve recent live telemetry log items."""
    logs = list(_TELEMETRY_LOGS)
    return logs[-limit:] if limit > 0 else logs


# Pre-populate initial system start events
emit_telemetry("INIT", "APIx Automated Ingestion Engine initialized (Playwright 3-slot pool active)", "info")
emit_telemetry("ROBOTS", "Robots.txt compliance engine active with async domain cache", "ok")


class ScrapeScheduler:
    """Manages scheduled and on-demand scraping execution across route baskets."""

    @staticmethod
    def generate_scrape_matrix(
        route_ids: list[str],
        windows: list[int] | None = None,
        target_dates: list[date] | None = None,
    ) -> list[dict[str, Any]]:
        """Generate cartesian product of routes and advance booking windows."""
        adv_windows = windows or STANDARD_WINDOWS
        today = datetime.now(timezone.utc).date()
        tasks = []

        for r in route_ids:
            for w in adv_windows:
                dep_date = today + timedelta(days=w)
                tasks.append(
                    {
                        "route_id": r,
                        "advance_days": w,
                        "departure_date": dep_date,
                    }
                )
        return tasks

    @classmethod
    async def run_batch_scrape(
        cls,
        route_ids: list[str] | None = None,
        windows: list[int] | None = None,
        force_live: bool = False,
        job_type: str = "manual",
    ) -> str:
        """Run a batch scrape across target routes and windows, logging to ScrapeJob."""
        job_id = str(uuid.uuid4())
        adv_windows = windows or [1, 7, 15, 30]

        async with async_session_maker() as session:
            if not route_ids:
                stmt = select(RouteConfig).where(RouteConfig.is_active == True)
                routes = (await session.execute(stmt)).scalars().all()
                target_routes = [r.id for r in routes]
            else:
                target_routes = route_ids

            total_tasks = len(target_routes) * len(adv_windows)

            job = ScrapeJob(
                id=job_id,
                job_type=job_type,
                status="running",
                routes_targeted=len(target_routes),
                routes_completed=0,
                quotes_collected=0,
                started_at=datetime.now(timezone.utc),
            )
            session.add(job)
            await session.commit()

        emit_telemetry(
            "DISPATCH",
            f"Job [{job_id[:8]}] started ({job_type}): {len(target_routes)} routes × {len(adv_windows)} windows ({total_tasks} tasks)",
            "info",
        )

        asyncio.create_task(
            cls._execute_matrix(job_id, target_routes, adv_windows, force_live)
        )
        return job_id

    @classmethod
    async def _execute_matrix(
        cls,
        job_id: str,
        routes: list[str],
        windows: list[int],
        force_live: bool,
    ):
        """Execute the scrape tasks with controlled concurrency and telemetry."""
        total_quotes = 0
        routes_done = 0
        errors = []

        for r_id in routes:
            try:
                emit_telemetry("SURVEY", f"Processing route: {r_id} across {len(windows)} advance horizons", "info")
                for w in windows:
                    quotes = await run_fare_survey(
                        route=r_id,
                        advance_days=w,
                        save_to_db=True,
                        force_live=force_live,
                    )
                    total_quotes += len(quotes)
                    emit_telemetry("EXTRACT", f"{r_id} (T+{w}): collected {len(quotes)} carrier quotes", "ok")
                    await asyncio.sleep(0.4)  # Politeness interval
                routes_done += 1
            except Exception as e:
                logger.error("Error scraping route %s in job %s: %s", r_id, job_id, e)
                errors.append({"route": r_id, "error": str(e)})
                emit_telemetry("ERROR", f"Failed route {r_id}: {e}", "error")

        # Update ScrapeJob status
        async with async_session_maker() as session:
            stmt = select(ScrapeJob).where(ScrapeJob.id == job_id)
            res = await session.execute(stmt)
            job = res.scalars().first()
            if job:
                job.status = "completed" if not errors else "completed_with_errors"
                job.routes_completed = routes_done
                job.quotes_collected = total_quotes
                job.errors = errors
                job.completed_at = datetime.now(timezone.utc)
                session.add(job)
                await session.commit()

        emit_telemetry(
            "COMPLETE",
            f"Job [{job_id[:8]}] finished: {routes_done}/{len(routes)} routes completed ({total_quotes} total quotes saved)",
            "ok",
        )


async def run_scheduler_loop():
    """Background recurring scheduler loop running inside FastAPI lifespan."""
    logger.info("APIx Automated Background Scheduler started (Interval: %dh).", SCHEDULED_INTERVAL_HOURS)
    emit_telemetry("SCHEDULER", f"Background daily scheduler active (Interval: {SCHEDULED_INTERVAL_HOURS}h)", "info")

    while True:
        try:
            # Sleep for interval (e.g. 24 hours)
            await asyncio.sleep(SCHEDULED_INTERVAL_HOURS * 3600)
            logger.info("Triggering automated daily batch airfare scrape...")
            emit_telemetry("AUTO", "Triggering automated scheduled daily multi-carrier airfare survey", "info")
            await ScrapeScheduler.run_batch_scrape(job_type="scheduled")
        except asyncio.CancelledError:
            logger.info("Background scheduler loop gracefully cancelled.")
            break
        except Exception as e:
            logger.error("Error in background scheduler loop: %s", e)
            emit_telemetry("ERROR", f"Scheduler loop error: {e}", "error")
            await asyncio.sleep(60)
