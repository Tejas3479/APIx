"""Scraper Router for APIx — on-demand scraping triggers, job history, and live telemetry."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select

from auth import verify_api_key
from database import ScrapeJob, async_session_maker
from models import ScrapeJobResponse, ScrapeRequest
from services.scrape_scheduler import ScrapeScheduler, get_live_telemetry_logs
from services.search_orchestrator import run_fare_survey

logger = logging.getLogger("apix.routers.scraper")

router = APIRouter(prefix="/api/v1/scraper", tags=["scraper"])


@router.post(
    "/run", response_model=dict[str, Any], dependencies=[Depends(verify_api_key)]
)
async def trigger_scrape(req: ScrapeRequest):
    """Trigger an on-demand airfare survey for designated routes and advance windows."""
    if not req.routes:
        raise HTTPException(
            status_code=400, detail="At least one route must be specified."
        )

    # Launch background batch job
    job_id = await ScrapeScheduler.run_batch_scrape(
        route_ids=req.routes,
        windows=req.advance_days,
        force_live=req.force_live,
        job_type="manual",
    )

    return {
        "status": "started",
        "job_id": job_id,
        "routes": req.routes,
        "advance_windows": req.advance_days,
        "message": f"Scrape job {job_id} dispatched successfully across {len(req.routes)} routes.",
    }


@router.post(
    "/survey-instant",
    response_model=list[dict[str, Any]],
    dependencies=[Depends(verify_api_key)],
)
async def run_single_survey_instant(
    route: str = "DEL-BOM",
    advance_days: int = 7,
    force_live: bool = False,
):
    """Synchronously run a single fare survey for a route and advance window and return quotes."""
    quotes = await run_fare_survey(
        route=route,
        advance_days=advance_days,
        save_to_db=True,
        force_live=force_live,
    )
    return quotes


@router.get("/jobs", response_model=list[ScrapeJobResponse])
async def list_scrape_jobs(limit: int = 20):
    """List recent scrape jobs and their progress/quote metrics."""
    async with async_session_maker() as session:
        stmt = select(ScrapeJob).order_by(desc(ScrapeJob.created_at)).limit(limit)
        jobs = (await session.execute(stmt)).scalars().all()
        return jobs


@router.get("/jobs/{job_id}", response_model=ScrapeJobResponse)
async def get_scrape_job(job_id: str):
    """Retrieve details and errors for a specific scrape job."""
    async with async_session_maker() as session:
        stmt = select(ScrapeJob).where(ScrapeJob.id == job_id)
        job = (await session.execute(stmt)).scalars().first()
        if not job:
            raise HTTPException(status_code=404, detail="Scrape job not found.")
        return job


@router.get("/live-logs")
async def get_live_logs(limit: int = 30):
    """Retrieve live in-memory telemetry logs for the scraper operations stream."""
    return get_live_telemetry_logs(limit=limit)
