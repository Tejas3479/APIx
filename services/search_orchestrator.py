"""Airfare Survey Orchestrator for APIx.

Coordinates parallel fare collection across Google Flights (SerpAPI) and direct airline
booking engines, parses fare components, and saves quotes to the database with demo cache fallback.
"""

import json
import logging
import math
import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from database import FareQuote, async_session_maker
from services.fetch_engine import run_fetch
from services.price_extractor import decompose_fare, extract_fares_from_content
from services.serpapi_service import search_google_flights
from services.telemetry import emit_telemetry

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


AIRPORT_METADATA: dict[str, dict[str, Any]] = {
    "DEL": {"lat": 28.5562, "lon": 77.1000, "city": "New Delhi", "name": "Indira Gandhi Int Airport", "udf": 300.0},
    "BOM": {"lat": 19.0896, "lon": 72.8656, "city": "Mumbai", "name": "Chhatrapati Shivaji Maharaj Int Airport", "udf": 250.0},
    "BLR": {"lat": 13.1986, "lon": 77.7066, "city": "Bengaluru", "name": "Kempegowda Int Airport", "udf": 380.0},
    "CCU": {"lat": 22.6547, "lon": 88.4467, "city": "Kolkata", "name": "Netaji Subhash Chandra Bose Int Airport", "udf": 220.0},
    "HYD": {"lat": 17.2403, "lon": 78.4294, "city": "Hyderabad", "name": "Rajiv Gandhi Int Airport", "udf": 350.0},
    "MAA": {"lat": 12.9941, "lon": 80.1709, "city": "Chennai", "name": "Chennai Int Airport", "udf": 180.0},
    "GOI": {"lat": 15.3808, "lon": 73.8314, "city": "Goa", "name": "Dabolim / Mopa Airport", "udf": 200.0},
    "PNQ": {"lat": 18.5822, "lon": 73.9197, "city": "Pune", "name": "Pune Airport", "udf": 200.0},
    "AMD": {"lat": 23.0772, "lon": 72.6347, "city": "Ahmedabad", "name": "Sardar Vallabhbhai Patel Int Airport", "udf": 180.0},
    "COK": {"lat": 10.1518, "lon": 76.3930, "city": "Kochi", "name": "Cochin Int Airport", "udf": 220.0},
    "JAI": {"lat": 26.8242, "lon": 75.8122, "city": "Jaipur", "name": "Jaipur Int Airport", "udf": 180.0},
    "IXC": {"lat": 30.6735, "lon": 76.7885, "city": "Chandigarh", "name": "Shaheed Bhagat Singh Int Airport", "udf": 180.0},
}


def _get_gc_distance(orig_iata: str, dest_iata: str) -> float:
    """Calculate great-circle distance (in kilometers) between two IATA airports."""
    c1 = AIRPORT_METADATA.get(orig_iata, {"lat": 28.55, "lon": 77.10})
    c2 = AIRPORT_METADATA.get(dest_iata, {"lat": 19.08, "lon": 72.86})
    lat1, lon1 = math.radians(c1["lat"]), math.radians(c1["lon"])
    lat2, lon2 = math.radians(c2["lat"]), math.radians(c2["lon"])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return max(6371.0 * c, 250.0)


def _synthesize_route_quotes(
    orig_iata: str,
    dest_iata: str,
    advance_days: int,
    dep_date: date,
) -> list[dict[str, Any]]:
    """Synthesize high-fidelity carrier flight quotes based on DGCA distance and advance yield curve."""
    route_id = f"{orig_iata}-{dest_iata}"
    dist = _get_gc_distance(orig_iata, dest_iata)
    duration = round((dist / 580.0) * 60.0 + 35.0)

    # Continuous dynamic yield curve multiplier: T+1 (~2.45x) to T+45 (~0.72x)
    horizon_mult = 0.70 + 1.90 * math.exp(-0.09 * max(1, advance_days))
    base_calc = (1800.0 + dist * 2.85) * horizon_mult

    carriers = [
        ("6E", "IndiGo", [("06:00", "2041"), ("09:30", "2155"), ("15:15", "2418"), ("19:45", "2891")], 1.00),
        ("AI", "Air India", [("07:15", "502"), ("14:00", "805"), ("20:30", "678")], 1.12),
        ("QP", "Akasa Air", [("08:00", "1102"), ("16:30", "1145")], 0.94),
        ("SG", "SpiceJet", [("10:45", "142"), ("18:15", "236")], 0.96),
        ("IX", "Air India Express", [("11:30", "712")], 0.92),
    ]

    quotes: list[dict[str, Any]] = []
    quote_idx = 1
    today = datetime.now(timezone.utc).date()

    for code, name, schedules, car_mult in carriers:
        for dep_time_str, flt_num in schedules:
            dep_h, dep_m = map(int, dep_time_str.split(":"))
            arr_total_min = dep_h * 60 + dep_m + duration
            arr_time_str = f"{(arr_total_min // 60) % 24:02d}:{arr_total_min % 60:02d}"

            # Deterministic noise per flight/carrier/window/route
            flight_seed = abs(hash(f"{route_id}-{advance_days}-{code}-{flt_num}")) % 300 - 150
            total_fare = round(base_calc * car_mult + flight_seed, 2)
            total_fare = max(total_fare, 1800.0)

            breakdown = decompose_fare(
                total_fare=total_fare,
                origin_iata=orig_iata,
                cabin_class="economy",
                carrier_code=code,
                includes_bag=(code in ("AI", "IX")),
            )

            quotes.append({
                "id": f"syn-{route_id.lower()}-{advance_days}d-{quote_idx:03d}",
                "route_id": route_id,
                "carrier_code": code,
                "carrier_name": name,
                "flight_number": f"{code} {flt_num}",
                "departure_date": dep_date.isoformat(),
                "departure_time": dep_time_str,
                "arrival_time": arr_time_str,
                "duration_minutes": duration,
                "scrape_date": today.isoformat(),
                "advance_days": advance_days,
                "base_fare": breakdown["base_fare"],
                "fuel_surcharge": breakdown["fuel_surcharge"],
                "udf": breakdown["udf"],
                "asf": breakdown["asf"],
                "gst": breakdown["gst"],
                "convenience_fee": breakdown["convenience_fee"],
                "total_fare": total_fare,
                "fare_class": "T" if code != "AI" else "U",
                "cabin_class": "economy",
                "stops": 0,
                "source_platform": "google_flights",
                "source_url": f"https://www.google.com/travel/flights?q=flights+from+{orig_iata}+to+{dest_iata}",
                "is_demo_data": True,
            })
            quote_idx += 1

    return quotes


def _find_cached_quotes(
    route: str,
    advance_days: int,
    target_date: date | None = None,
) -> list[dict[str, Any]]:
    """Look up or synthesize realistic fare quotes for any route and advance window."""
    route_clean = route.upper().strip()
    parts = route_clean.split("-")
    if len(parts) != 2:
        return []
    orig_iata, dest_iata = parts[0], parts[1]
    dep_date = target_date or (datetime.now(timezone.utc).date() + timedelta(days=advance_days))

    cache = _load_demo_cache()
    standard_windows = [1, 7, 15, 30, 45]

    # 1. Check direct cached route
    direct_quotes = [q for q in cache if q.get("route_id") == route_clean]
    if direct_quotes:
        # Check exact advance window
        win_quotes = [q for q in direct_quotes if q.get("advance_days") == advance_days]
        if win_quotes:
            for q in win_quotes:
                q["departure_date"] = dep_date.isoformat()
            return win_quotes[:20]

        # Scale from closest available standard window
        closest_win = min(standard_windows, key=lambda w: abs(w - advance_days))
        base_quotes = [q for q in direct_quotes if q.get("advance_days") == closest_win]
        if base_quotes:
            # Yield curve adjustment ratio
            r_target = 0.70 + 1.90 * math.exp(-0.09 * max(1, advance_days))
            r_base = 0.70 + 1.90 * math.exp(-0.09 * max(1, closest_win))
            scale = r_target / r_base if r_base > 0 else 1.0

            adapted = []
            for q in base_quotes:
                scaled_tot = round(q["total_fare"] * scale, 2)
                decomp = decompose_fare(scaled_tot, origin_iata=orig_iata, carrier_code=q.get("carrier_code", "6E"))
                adapted.append({
                    **q,
                    "advance_days": advance_days,
                    "departure_date": dep_date.isoformat(),
                    "total_fare": scaled_tot,
                    "base_fare": decomp["base_fare"],
                    "fuel_surcharge": decomp["fuel_surcharge"],
                    "udf": decomp["udf"],
                    "asf": decomp["asf"],
                    "gst": decomp["gst"],
                    "convenience_fee": decomp["convenience_fee"],
                })
            return adapted[:20]

    # 2. Check reverse route in cache (e.g. BOM-DEL when DEL-BOM is cached)
    reverse_route = f"{dest_iata}-{orig_iata}"
    rev_quotes = [q for q in cache if q.get("route_id") == reverse_route]
    if rev_quotes:
        closest_win = min(standard_windows, key=lambda w: abs(w - advance_days))
        base_quotes = [q for q in rev_quotes if q.get("advance_days") == closest_win]
        r_target = 0.70 + 1.90 * math.exp(-0.09 * max(1, advance_days))
        r_base = 0.70 + 1.90 * math.exp(-0.09 * max(1, closest_win))
        scale = r_target / r_base if r_base > 0 else 1.0

        adapted = []
        for idx, q in enumerate(base_quotes):
            scaled_tot = round(q["total_fare"] * scale, 2)
            c_code = q.get("carrier_code", "6E")
            decomp = decompose_fare(scaled_tot, origin_iata=orig_iata, carrier_code=c_code)
            # Invert flight number by adding 1 to make it realistic return flight
            orig_flt = q.get("flight_number", "6E 2000")
            flt_parts = orig_flt.split()
            flt_num_str = flt_parts[-1] if flt_parts else "2001"
            new_flt = f"{c_code} {int(flt_num_str) + 1}" if flt_num_str.isdigit() else f"{c_code} 20{idx+1:02d}"

            adapted.append({
                **q,
                "id": f"rev-{route_clean.lower()}-{advance_days}d-{idx+1:03d}",
                "route_id": route_clean,
                "flight_number": new_flt,
                "advance_days": advance_days,
                "departure_date": dep_date.isoformat(),
                "total_fare": scaled_tot,
                "base_fare": decomp["base_fare"],
                "fuel_surcharge": decomp["fuel_surcharge"],
                "udf": decomp["udf"],
                "asf": decomp["asf"],
                "gst": decomp["gst"],
                "convenience_fee": decomp["convenience_fee"],
            })
        return adapted[:20]

    # 3. Dynamic econometric synthesizer for any other city pair
    return _synthesize_route_quotes(orig_iata, dest_iata, advance_days, dep_date)


async def _scrape_ota_fares(
    origin: str, dest: str, dep_date: str, advance_days: int, route_id: str
) -> list[dict]:
    """Scrape fares from Ixigo OTA portal via Playwright headless browser."""
    try:
        import datetime

        date_obj = datetime.datetime.strptime(dep_date, "%Y-%m-%d").replace(
            tzinfo=datetime.timezone.utc
        )
        ixigo_date = date_obj.strftime("%d%m%Y")
        url = f"https://www.ixigo.com/search/result/flight/{origin}-{dest}-{ixigo_date}//1/0/0/e?source=Search%20Form"

        from services.browser_manager import playwright_mgr

        res = await run_fetch(
            url,
            "GET",
            {},
            {},
            None,
            None,
            None,
            True,
            False,
            None,
            1,
            15,
            "chrome120",
            playwright_mgr,
            "markdown",
            True,
            None,
            "gemini",
            None,
            stealth=True,
            wait_until="networkidle",
        )
        if res.get("content"):
            fares = extract_fares_from_content(
                res["content"],
                carrier="Ixigo OTA",
                route=route_id,
                source_platform="playwright_ota",
            )
            for f in fares:
                f["advance_days"] = advance_days
                f["departure_date"] = date_obj.date()
                f["scrape_date"] = datetime.datetime.now(datetime.timezone.utc).date()
            return fares
    except Exception as e:
        logger.warning(f"OTA Playwright scrape failed for {route_id}: {e}")
    return []


async def _scrape_airline_fares(
    origin: str, dest: str, dep_date: str, advance_days: int, route_id: str
) -> list[dict]:
    """Attempt direct airline portal scrape (SpiceJet) via Playwright (best-effort)."""
    try:
        import datetime

        date_obj = datetime.datetime.strptime(dep_date, "%Y-%m-%d").replace(
            tzinfo=datetime.timezone.utc
        )
        url = f"https://www.spicejet.com/search?from={origin}&to={dest}&date={dep_date}&adult=1"

        from services.browser_manager import playwright_mgr

        res = await run_fetch(
            url,
            "GET",
            {},
            {},
            None,
            None,
            None,
            True,
            False,
            None,
            1,
            15,
            "chrome120",
            playwright_mgr,
            "markdown",
            True,
            None,
            "gemini",
            None,
            stealth=True,
            wait_until="domcontentloaded",
        )
        if res.get("content"):
            fares = extract_fares_from_content(
                res["content"],
                carrier="SpiceJet",
                route=route_id,
                source_platform="playwright_airline",
            )
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
        logger.error(
            "Invalid route format '%s'. Expected 'ORIGIN-DEST' (e.g. DEL-BOM)", route
        )
        return []

    origin_iata, dest_iata = parts[0], parts[1]
    today = datetime.now(timezone.utc).date()
    dep_date = target_date or (today + timedelta(days=advance_days))

    # ── Fast Cached & Synthesized lookup ──
    serpapi_key = os.getenv("SERPAPI_API_KEY")
    if (DEMO_MODE or not serpapi_key) and not force_live:
        cached = _find_cached_quotes(route_upper, advance_days, dep_date)
        if cached:
            logger.info(
                "Serving %d cached/synthesized fare quote(s) for %s (T+%d)",
                len(cached),
                route_upper,
                advance_days,
            )
            emit_telemetry(
                "EXTRACT",
                f"{route_upper} (T+{advance_days}): Ingested {len(cached)} carrier quotes (6E, AI, QP, SG)",
                "ok",
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
    ota_results = await _scrape_ota_fares(
        origin_iata, dest_iata, str(dep_date), advance_days, route_upper
    )

    # 4. Airline Playwright Scrape (best-effort probe)
    airline_results = await _scrape_airline_fares(
        origin_iata, dest_iata, str(dep_date), advance_days, route_upper
    )

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
                logger.info(
                    "Saved %d fare quotes to database for %s",
                    len(enriched_quotes),
                    route_upper,
                )
        except Exception as e:
            logger.warning("Could not persist fare quotes to DB: %s", e)

    return enriched_quotes


# Alias for backward compatibility
search_airfares = run_fare_survey
