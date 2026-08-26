"""Airfare Data Seeder for APIx.

Seeds the standard 8-route DGCA basket, 30-day realistic historical airfare quotes,
and pre-computed daily index points into the database on application startup.
"""

import json
import logging
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select

from database import FareQuote, RouteConfig, async_session_maker

logger = logging.getLogger("apix.seeder")

ROUTE_BASKET_PATH = Path("data/route_basket.json")
FARE_DEMO_CACHE_PATH = Path("data/fare_demo_cache.json")

# Default 8 High-Density Domestic Routes in India with DGCA Traffic Weights
DEFAULT_ROUTE_BASKET = [
    {
        "id": "DEL-BOM",
        "origin_iata": "DEL",
        "origin_city": "New Delhi",
        "destination_iata": "BOM",
        "destination_city": "Mumbai",
        "dgca_weight": 0.22,
        "daily_flights": 110,
    },
    {
        "id": "DEL-BLR",
        "origin_iata": "DEL",
        "origin_city": "New Delhi",
        "destination_iata": "BLR",
        "destination_city": "Bengaluru",
        "dgca_weight": 0.18,
        "daily_flights": 85,
    },
    {
        "id": "BOM-BLR",
        "origin_iata": "BOM",
        "origin_city": "Mumbai",
        "destination_iata": "BLR",
        "destination_city": "Bengaluru",
        "dgca_weight": 0.14,
        "daily_flights": 65,
    },
    {
        "id": "DEL-CCU",
        "origin_iata": "DEL",
        "origin_city": "New Delhi",
        "destination_iata": "CCU",
        "destination_city": "Kolkata",
        "dgca_weight": 0.12,
        "daily_flights": 50,
    },
    {
        "id": "BLR-HYD",
        "origin_iata": "BLR",
        "origin_city": "Bengaluru",
        "destination_iata": "HYD",
        "destination_city": "Hyderabad",
        "dgca_weight": 0.10,
        "daily_flights": 45,
    },
    {
        "id": "DEL-HYD",
        "origin_iata": "DEL",
        "origin_city": "New Delhi",
        "destination_iata": "HYD",
        "destination_city": "Hyderabad",
        "dgca_weight": 0.09,
        "daily_flights": 40,
    },
    {
        "id": "MAA-DEL",
        "origin_iata": "MAA",
        "origin_city": "Chennai",
        "destination_iata": "DEL",
        "destination_city": "New Delhi",
        "dgca_weight": 0.08,
        "daily_flights": 35,
    },
    {
        "id": "BOM-GOI",
        "origin_iata": "BOM",
        "origin_city": "Mumbai",
        "destination_iata": "GOI",
        "destination_city": "Goa",
        "dgca_weight": 0.07,
        "daily_flights": 30,
    },
]


def _load_json_sync(path: Path) -> Any:
    """Helper to read JSON file synchronously."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


async def seed_route_basket() -> int:
    """Seed configured city-pair routes into the database if empty."""
    async with async_session_maker() as session:
        count = (await session.execute(select(func.count()).select_from(RouteConfig))).scalar() or 0
        if count > 0:
            return count

        routes_data = DEFAULT_ROUTE_BASKET
        if ROUTE_BASKET_PATH.exists():
            try:
                routes_data = _load_json_sync(ROUTE_BASKET_PATH)
            except Exception as e:
                logger.warning("Could not read %s, using defaults: %s", ROUTE_BASKET_PATH, e)

        for item in routes_data:
            route = RouteConfig(
                id=item["id"],
                origin_iata=item["origin_iata"],
                origin_city=item["origin_city"],
                destination_iata=item["destination_iata"],
                destination_city=item["destination_city"],
                dgca_weight=item.get("dgca_weight", 0.1),
                daily_flights=item.get("daily_flights", 30),
                is_active=item.get("is_active", True),
            )
            session.add(route)

        await session.commit()
        logger.info("Seeded %d routes into RouteConfig.", len(routes_data))
        return len(routes_data)


async def seed_demo_fares() -> int:
    """Seed historical demo quotes cache if database has no quotes."""
    async with async_session_maker() as session:
        count = (await session.execute(select(func.count()).select_from(FareQuote))).scalar() or 0
        if count > 0:
            return count

        if not FARE_DEMO_CACHE_PATH.exists():
            logger.info("No fare demo cache file at %s to seed.", FARE_DEMO_CACHE_PATH)
            return 0

        try:
            quotes = _load_json_sync(FARE_DEMO_CACHE_PATH)
        except Exception as e:
            logger.warning("Failed to parse %s: %s", FARE_DEMO_CACHE_PATH, e)
            return 0

        added = 0
        for q in quotes:
            dep_date = (
                date.fromisoformat(q["departure_date"])
                if isinstance(q.get("departure_date"), str)
                else datetime.now(timezone.utc).date()
            )
            scrape_d = (
                date.fromisoformat(q["scrape_date"])
                if isinstance(q.get("scrape_date"), str)
                else datetime.now(timezone.utc).date()
            )

            db_quote = FareQuote(
                id=q.get("id"),
                route_id=q["route_id"],
                carrier_code=q.get("carrier_code", "6E"),
                carrier_name=q.get("carrier_name", "IndiGo"),
                flight_number=q.get("flight_number"),
                departure_date=dep_date,
                departure_time=q.get("departure_time"),
                arrival_time=q.get("arrival_time"),
                duration_minutes=q.get("duration_minutes", 120),
                scrape_date=scrape_d,
                advance_days=q.get("advance_days", 7),
                base_fare=q.get("base_fare", 4500.0),
                fuel_surcharge=q.get("fuel_surcharge", 600.0),
                udf=q.get("udf", 300.0),
                asf=q.get("asf", 200.0),
                gst=q.get("gst", 255.0),
                convenience_fee=q.get("convenience_fee", 350.0),
                total_fare=q.get("total_fare", 6205.0),
                fare_class=q.get("fare_class", "T"),
                cabin_class=q.get("cabin_class", "economy"),
                stops=q.get("stops", 0),
                source_platform=q.get("source_platform", "google_flights"),
                source_url=q.get("source_url", "https://www.google.com/travel/flights"),
                is_demo_data=True,
            )
            session.add(db_quote)
            added += 1

            if added % 500 == 0:
                await session.flush()

        await session.commit()
        logger.info("Seeded %d demo fare quotes into database.", added)
        return added


DGCA_BENCHMARK_PATH = Path("data/dgca_benchmark.json")


async def seed_dgca_benchmarks() -> int:
    """Seed official DGCA benchmark records into DgcaBenchmark table if empty."""
    from database import DgcaBenchmark

    async with async_session_maker() as session:
        count = (await session.execute(select(func.count()).select_from(DgcaBenchmark))).scalar() or 0
        if count > 0:
            return count

        if not DGCA_BENCHMARK_PATH.exists():
            return 0

        try:
            benchmarks = _load_json_sync(DGCA_BENCHMARK_PATH)
        except Exception as e:
            logger.warning("Failed to parse %s: %s", DGCA_BENCHMARK_PATH, e)
            return 0

        added = 0
        for b in benchmarks:
            rec = DgcaBenchmark(
                route_id=b["route_id"],
                year_month=b["year_month"],
                dgca_avg_fare=b["dgca_avg_fare"],
                passenger_load_factor_pct=b.get("passenger_load_factor_pct", 85.0),
                total_passengers_monthly=b.get("total_passengers_monthly", 0),
                source_bulletin=b.get("source_bulletin", "DGCA Domestic Air Transport Monthly Report"),
            )
            session.add(rec)
            added += 1

        await session.commit()
        logger.info("Seeded %d DGCA benchmarks into database.", added)
        return added


async def seed_airfare_database() -> dict[str, int]:
    """Main seeder entrypoint called during application startup."""
    routes_count = await seed_route_basket()
    fares_count = await seed_demo_fares()
    dgca_count = await seed_dgca_benchmarks()
    return {
        "routes": routes_count,
        "fare_quotes": fares_count,
        "dgca_benchmarks": dgca_count,
    }
