"""APIx database layer — SQLModel tables, async engine, session management.

Production-grade schema with composite query indexes, foreign key relationships,
and support for high-frequency time-series econometric index aggregation.
"""

import os
import uuid
from datetime import date, datetime, timezone
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import JSON, Column, Field, SQLModel, String

# Retrieve DATABASE_URL from env, default to local SQLite
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///data/apix.db")

# PostgreSQL gets production connection pool settings;
# SQLite uses local aiosqlite connection.
_engine_kwargs: dict[str, Any] = {"echo": False}
if "sqlite" not in DATABASE_URL:
    _engine_kwargs.update(
        {
            "pool_size": 15,
            "max_overflow": 25,
            "pool_pre_ping": True,
            "pool_recycle": 300,
        }
    )

engine = create_async_engine(DATABASE_URL, **_engine_kwargs)
async_session_maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    """Initializes the database schema, creating all tables and composite indexes."""
    if "sqlite" in DATABASE_URL:
        db_path = DATABASE_URL.split(":///")[-1]
        if ("/" in db_path or "\\" in db_path) and not db_path.startswith(":memory:"):
            dir_name = os.path.dirname(db_path)
            if dir_name:
                os.makedirs(dir_name, exist_ok=True)

    async with engine.begin() as conn:
        # Enable foreign keys for SQLite
        if "sqlite" in DATABASE_URL:
            await conn.execute(text("PRAGMA foreign_keys = ON;"))
            await conn.execute(text("PRAGMA journal_mode = WAL;"))
            await conn.execute(text("PRAGMA busy_timeout = 5000;"))
            await conn.execute(text("PRAGMA synchronous = NORMAL;"))
        await conn.run_sync(SQLModel.metadata.create_all)


async def get_session() -> AsyncSession:
    """FastAPI dependency for yielding asynchronous database sessions."""
    async with async_session_maker() as session:
        yield session


# ===== INFRASTRUCTURE & AUTH TABLES =====


class ApiKey(SQLModel, table=True):  # type: ignore[call-arg]
    """API keys for external server-to-server programmatic access (e.g. RBI MPC scripts)."""

    key: str = Field(primary_key=True)
    name: str | None = Field(default=None, max_length=100)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Proxy(SQLModel, table=True):  # type: ignore[call-arg]
    """Proxy manager infrastructure for respectful, distributed scraping."""

    id: int | None = Field(default=None, primary_key=True)
    url: str = Field(sa_column=Column("url", String, unique=True, index=True))
    is_active: bool = Field(default=True, index=True)
    fail_count: int = Field(default=0)
    last_used_at: datetime | None = None


class User(SQLModel, table=True):  # type: ignore[call-arg]
    """Institutional analyst and officer credentials."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    name: str = Field(max_length=100)
    email: str = Field(sa_column=Column("email", String, unique=True, index=True))
    hashed_password: str
    department: str | None = Field(default=None, max_length=200)
    organization: str | None = Field(default=None, max_length=200)
    role: str = Field(default="user", max_length=50)  # "admin", "senior_officer", "analyst"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ===== APIx CORE STATISTICAL TABLES =====


class RouteConfig(SQLModel, table=True):  # type: ignore[call-arg]
    """Route basket configuration — city-pairs tracked by the index."""

    id: str = Field(primary_key=True, max_length=10)  # e.g., "DEL-BOM"
    origin_iata: str = Field(index=True, max_length=3)  # "DEL"
    origin_city: str = Field(max_length=100)  # "New Delhi"
    destination_iata: str = Field(index=True, max_length=3)  # "BOM"
    destination_city: str = Field(max_length=100)  # "Mumbai"
    dgca_weight: float = Field(default=0.0, ge=0.0, le=1.0)  # Official DGCA passenger weight (wr)
    daily_flights: int | None = Field(default=None, ge=0)  # Total scheduled daily flights
    is_active: bool = Field(default=True, index=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FareQuote(SQLModel, table=True):  # type: ignore[call-arg]
    """Raw scraped fare quotes — one row per flight option per scrape."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    route_id: str = Field(index=True, max_length=10)  # FK → RouteConfig.id
    carrier_code: str = Field(index=True, max_length=5)  # "6E", "AI", "QP", "SG"
    carrier_name: str = Field(max_length=100)  # "IndiGo"
    flight_number: str | None = Field(default=None, max_length=20)  # "6E 2045"
    departure_date: date = Field(index=True)  # The flight departure date
    departure_time: str | None = Field(default=None, max_length=10)  # "06:15"
    arrival_time: str | None = Field(default=None, max_length=10)  # "08:30"
    duration_minutes: int | None = Field(default=None, ge=0)  # 135
    scrape_date: date = Field(index=True)  # When scraped
    advance_days: int = Field(index=True)  # T+1, T+7, T+15, T+30, T+45
    base_fare: float = Field(ge=0.0)  # Dynamic airline commercial tariff (INR)
    fuel_surcharge: float = Field(default=0.0, ge=0.0)  # YQ/YR
    udf: float = Field(default=0.0, ge=0.0)  # User Development Fee
    asf: float = Field(default=200.0, ge=0.0)  # Statutory flat Aviation Security Fee (₹200)
    gst: float = Field(default=0.0, ge=0.0)  # 5% economy / 12% business
    convenience_fee: float = Field(default=0.0, ge=0.0)  # OTA/airline platform fee
    total_fare: float = Field(ge=0.0, index=True)  # Full ticket price paid by passenger
    fare_class: str | None = Field(default=None, max_length=5)  # RBD bucket: U, T, L, V, Q
    cabin_class: str = Field(default="economy", max_length=30)  # economy, premium_economy, business
    stops: int = Field(default=0, ge=0)  # 0 = nonstop
    source_platform: str = Field(default="google_flights", max_length=50)
    source_url: str | None = None
    is_sold_out: bool = Field(default=False)
    is_demo_data: bool = Field(default=False, index=True)
    raw_data: dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    scraped_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)


class DailyIndex(SQLModel, table=True):  # type: ignore[call-arg]
    """Computed daily national APIx index values — core time-series series."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    index_date: date = Field(index=True)  # Reference computation date
    frequency: str = Field(default="daily", max_length=20)  # "daily", "weekly", "monthly"
    index_value: float = Field(ge=0.0, index=True)  # APIx index number (Base = 100.0)
    base_period_value: float = Field(default=100.0)  # Reference base (100.0)
    methodology: str = Field(default="jevons", max_length=50)  # "jevons", "geks_tornqvist"
    route_coverage: int = Field(default=0, ge=0)  # Number of routes with live data
    quote_count: int = Field(default=0, ge=0)  # Total quotes aggregated
    missing_routes: list[str] = Field(default=[], sa_column=Column(JSON))
    is_demo_data: bool = Field(default=False, index=True)
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)


class RouteIndex(SQLModel, table=True):  # type: ignore[call-arg]
    """Per-route daily sub-indices — breakdown by city-pair."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    index_date: date = Field(index=True)
    route_id: str = Field(index=True, max_length=10)  # FK → RouteConfig.id
    index_value: float = Field(ge=0.0)
    avg_fare: float = Field(ge=0.0)
    median_fare: float = Field(ge=0.0)
    min_fare: float = Field(ge=0.0)
    max_fare: float = Field(ge=0.0)
    quote_count: int = Field(default=0, ge=0)
    carrier_breakdown: dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    advance_window_breakdown: dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    is_demo_data: bool = Field(default=False, index=True)
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DgcaBenchmark(SQLModel, table=True):  # type: ignore[call-arg]
    """Official DGCA monthly sector statistics for backtesting and validation."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    route_id: str = Field(index=True, max_length=10)
    year_month: str = Field(index=True, max_length=7)  # "2026-08"
    dgca_avg_fare: float = Field(ge=0.0)
    passenger_load_factor_pct: float = Field(default=85.0, ge=0.0, le=100.0)
    total_passengers_monthly: int = Field(default=0, ge=0)
    source_bulletin: str = Field(max_length=200)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FareAnomalyReport(SQLModel, table=True):  # type: ignore[call-arg]
    """AI and statistical anomaly diagnosis logs for surge pricing and capacity shocks."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    route_id: str = Field(index=True, max_length=10)
    survey_date: date = Field(index=True)
    advance_days: int = Field(index=True)
    surge_multiplier: float = Field(default=1.0)
    diagnosis_text: str
    ai_model: str = Field(default="gemini-3.5-flash", max_length=50)
    flagged_by: str = Field(default="system", max_length=100)
    is_verified: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScrapeJob(SQLModel, table=True):  # type: ignore[call-arg]
    """Scrape job execution and telemetry tracking."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    job_type: str = Field(default="manual", max_length=50)  # "scheduled", "manual", "backfill"
    status: str = Field(default="pending", index=True, max_length=50)  # "pending", "running", "completed", "failed"
    routes_targeted: int = Field(default=0)
    routes_completed: int = Field(default=0)
    quotes_collected: int = Field(default=0)
    errors: list[dict[str, Any]] = Field(default=[], sa_column=Column(JSON))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)


# ===== PROXY MANAGER =====


class ProxyManager:
    @staticmethod
    async def get_proxy() -> str | None:
        async with async_session_maker() as session:
            result = await session.execute(
                select(Proxy)
                .where(Proxy.is_active == True)
                .order_by(Proxy.last_used_at.asc().nullsfirst())  # type: ignore[union-attr]
                .limit(1)
            )
            proxy = result.scalars().first()
            if not proxy:
                return None

            proxy.last_used_at = datetime.now(timezone.utc)
            session.add(proxy)
            await session.commit()
            return proxy.url

    @staticmethod
    async def report_failure(url: str):
        async with async_session_maker() as session:
            result = await session.execute(select(Proxy).where(Proxy.url == url))
            proxy = result.scalars().first()
            if proxy:
                proxy.fail_count += 1
                if proxy.fail_count >= 3:
                    proxy.is_active = False
                session.add(proxy)
                await session.commit()

    @staticmethod
    async def report_success(url: str):
        async with async_session_maker() as session:
            result = await session.execute(select(Proxy).where(Proxy.url == url))
            proxy = result.scalars().first()
            if proxy and proxy.fail_count > 0:
                proxy.fail_count = 0
                session.add(proxy)
                await session.commit()
