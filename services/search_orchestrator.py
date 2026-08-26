"""Airfare Survey Orchestrator for APIx.

Coordinates parallel fare collection across Google Flights (SerpAPI) and direct airline
booking engines, parses fare components, and saves quotes to the database with demo cache fallback.
"""

import json
import logging
import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from database import FareQuote, async_session_maker
from services.price_extractor import decompose_fare, extract_fares_from_content
from services.fetch_engine import run_fetch
from services.serpapi_service import search_google_flights

logger = logging.getLogger("apix.search_orchestrator")

DEMO_CACHE_PATH = Path(os.getenv("DEMO_CACHE_PATH", "data/fare_demo_cache.json"))
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in ("1", "true", "yes")


def _load_demo_cache() -> list[dict[str, Any]]:
    """Load pre-seeded 30-day realistic airfare quotes from disk."""
    if DEMO_CACHE_PATH.exists():
        try:
            with open(DEMO_CACHE_PATH, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load fare demo cache: %s", e)
    return []


def _find_cached_quotes(
    route: str,
    advance_days: int,
    target_date: date | None = None,
) -> list[dict[str, Any]]:
    """Look up cached fare quotes for a route and advance window."""
    cache = _load_demo_cache()
    if not cache:
        return []

    route_clean = route.upper().strip()
    matches = []

    for item in cache:
        if item.get("route_id") == route_clean and item.get("advance_days") == advance_days:
            if target_date:
                dep_date = item.get("departure_date")
                if dep_date == target_date.isoformat():
                    matches.append(item)
            else:
                matches.append(item)

    # Fallback to any quotes for that route if exact date/window is sparse
    if not matches:
        matches = [item for item in cache if item.get("route_id") == route_clean]

    return matches[:20]




async def _scrape_ota_fares(origin: str, dest: str, dep_date: str, advance_days: int, route_id: str) -> list[dict]:
    """Scrape fares from Ixigo OTA portal via Playwright headless browser."""
    try:
        import datetime
        date_obj = datetime.datetime.strptime(dep_date, "%Y-%m-%d")
        ixigo_date = date_obj.strftime("%d%m%Y")
        url = f"https://www.ixigo.com/search/result/flight/{origin}-{dest}-{ixigo_date}//1/0/0/e?source=Search%20Form"
        
        res = await run_fetch(
            url=url,
            render_js=True,
            output_format="markdown",
            stealth=True,
            timeout=15,
            wait_until="networkidle"
        )
        if res.get("content"):
            fares = extract_fares_from_content(res["content"], carrier="Ixigo OTA", route=route_id, source_platform="playwright_ota")
            for f in fares:
                f["advance_days"] = advance_days
                f["departure_date"] = date_obj.date()
                f["scrape_date"] = datetime.datetime.now(datetime.timezone.utc).date()
            return fares
    except Exception as e:
        logger.warning(f"OTA Playwright scrape failed for {route_id}: {e}")
    return []

async def _scrape_airline_fares(origin: str, dest: str, dep_date: str, advance_days: int, route_id: str) -> list[dict]:
    """Attempt direct airline portal scrape (SpiceJet) via Playwright (best-effort)."""
    try:
        import datetime
        date_obj = datetime.datetime.strptime(dep_date, "%Y-%m-%d")
        url = f"https://www.spicejet.com/search?from={origin}&to={dest}&date={dep_date}&adult=1"
        
        res = await run_fetch(
            url=url,
            render_js=True,
            output_format="markdown",
            stealth=True,
            timeout=15,
            wait_until="domcontentloaded"
        )
        if res.get("content"):
            fares = extract_fares_from_content(res["content"], carrier="SpiceJet", route=route_id, source_platform="playwright_airline")
            for f in fares:
                f["advance_days"] = advance_days
                f["departure_date"] = date_obj.date()
                f["scrape_date"] = datetime.datetime.now(datetime.timezone.utc).date()
            return fares
    except Exception as e:
        logger.warning(f"Airline Playwright scrape failed for {route_id}: {e}")
    return []

async def run_fare_survey(
    route: str,  # e.g., "DEL-BOM"
    advance_days: int = 7,  # T+1, T+7, T+15, T+30, T+45
    target_date: date | None = None,
    save_to_db: bool = True,
    force_live: bool = False,
) -> list[dict[str, Any]]:
    """Run an airfare survey for a specific city-pair and advance purchase window.

    1. Checks demo cache if DEMO_MODE=true and not force_live
    2. Queries Google Flights via SerpAPI for real-time fares
    3. Decomposes each fare into base tariff + fuel + UDF + ASF + GST + convenience
    4. Persists the FareQuote rows to the database
    5. Returns the structured fare quote list
    """
    route_upper = route.upper().strip()
    parts = route_upper.split("-")
    if len(parts) != 2:
        logger.error("Invalid route format '%s'. Expected 'ORIGIN-DEST' (e.g. DEL-BOM)", route)
        return []

    origin_iata, dest_iata = parts[0], parts[1]
    today = datetime.now(timezone.utc).date()
    dep_date = target_date or (today + timedelta(days=advance_days))

    # ── DEMO_MODE: Serve from curated cache if live fetch not forced ──
    if DEMO_MODE and not force_live:
        cached = _find_cached_quotes(route_upper, advance_days, dep_date)
        if cached:
            logger.info(
                "DEMO_MODE: serving %d cached fare quote(s) for %s (T+%d)",
                len(cached),
                route_upper,
                advance_days,
            )
            return cached

    # ── LIVE SCRAPING: Query Google Flights via SerpAPI ──
    quotes = await search_google_flights(
        origin_iata=origin_iata,
        destination_iata=dest_iata,
        departure_date=dep_date,
        advance_days=advance_days,
        max_results=15,
    )

    # 3. OTA Playwright Scrape (if SerpAPI returned few results, or just to supplement)
    ota_results = await _scrape_ota_fares(origin_iata, dest_iata, str(dep_date), advance_days, route_upper)
    
    # 4. Airline Playwright Scrape (best-effort probe)
    airline_results = await _scrape_airline_fares(origin_iata, dest_iata, str(dep_date), advance_days, route_upper)

    quotes.extend(ota_results)
    quotes.extend(airline_results)

    # ── Fallback to demo cache if live query yields no flights (or no API key) ──
    if not quotes:
        logger.info(
            "No live quotes returned for %s (T+%d). Falling back to demo cache.",
            route_upper,
            advance_days,
        )
        cached = _find_cached_quotes(route_upper, advance_days, dep_date)
        if cached:
            return cached

    # ── Statutory Fare Decomposition & DB Persistence ──
    enriched_quotes = []
    for q in quotes:
        total = q.get("total_fare", 0.0)
        breakdown = decompose_fare(total, origin_iata=origin_iata)

        enriched = {
            **q,
            "base_fare": breakdown["base_fare"],
            "fuel_surcharge": breakdown["fuel_surcharge"],
            "udf": breakdown["udf"],
            "asf": breakdown["asf"],
            "gst": breakdown["gst"],
            "convenience_fee": breakdown["convenience_fee"],
        }
        enriched_quotes.append(enriched)

    if save_to_db and enriched_quotes:
        try:
            async with async_session_maker() as session:
                for eq in enriched_quotes:
                    db_quote = FareQuote(
                        route_id=eq["route_id"],
                        carrier_code=eq["carrier_code"],
                        carrier_name=eq["carrier_name"],
                        flight_number=eq.get("flight_number"),
                        departure_date=date.fromisoformat(eq["departure_date"])
                        if isinstance(eq["departure_date"], str)
                        else eq["departure_date"],
                        departure_time=eq.get("departure_time"),
                        arrival_time=eq.get("arrival_time"),
                        duration_minutes=eq.get("duration_minutes"),
                        scrape_date=today,
                        advance_days=eq["advance_days"],
                        base_fare=eq["base_fare"],
                        fuel_surcharge=eq["fuel_surcharge"],
                        udf=eq["udf"],
                        asf=eq["asf"],
                        gst=eq["gst"],
                        convenience_fee=eq["convenience_fee"],
                        total_fare=eq["total_fare"],
                        fare_class=eq.get("fare_class"),
                        cabin_class=eq.get("cabin_class", "economy"),
                        stops=eq.get("stops", 0),
                        source_platform=eq.get("source_platform", "google_flights"),
                        source_url=eq.get("source_url"),
                        is_demo_data=eq.get("is_demo_data", False),
                    )
                    session.add(db_quote)
                await session.commit()
                logger.info("Saved %d fare quotes to database for %s", len(enriched_quotes), route_upper)
        except Exception as e:
            logger.warning("Could not persist fare quotes to DB: %s", e)

    return enriched_quotes


# Alias for backward compatibility
search_airfares = run_fare_survey
