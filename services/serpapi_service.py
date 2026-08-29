"""SerpAPI Google Flights Price Discovery Service for APIx.

Fetches real-time Indian domestic airfares from Google Flights (engine=google_flights).
Supports one-way economy fares with carrier breakdown, duration, flight number, and stops.
Gracefully falls back if SERPAPI_KEY is not configured or in DEMO_MODE.
"""

import logging
import os
import re
import typing
from datetime import date, datetime, timezone

import httpx

logger = logging.getLogger("apix.serpapi")

SERPAPI_KEY = os.getenv("SERPAPI_KEY", "")
SERPAPI_ENDPOINT = "https://serpapi.com/search.json"


async def search_google_flights(
    origin_iata: str,
    destination_iata: str,
    departure_date: date | str,
    advance_days: int = 7,
    max_results: int = 15,
    timeout_sec: float = 12.0,
) -> list[dict[str, typing.Any]]:
    """Query Google Flights via SerpAPI for real-time one-way fares.

    Args:
        origin_iata: Origin airport code (e.g., "DEL")
        destination_iata: Destination airport code (e.g., "BOM")
        departure_date: Departure date (YYYY-MM-DD)
        advance_days: Advance purchase window (T+n)
        max_results: Maximum flights to return
        timeout_sec: Request timeout in seconds

    Returns:
        List of structured flight quote dictionaries
    """
    if not SERPAPI_KEY or SERPAPI_KEY.startswith("your_"):
        logger.debug(
            "SERPAPI_KEY not configured. Skipping SerpAPI live flights search."
        )
        return []

    date_str = (
        departure_date.isoformat()
        if isinstance(departure_date, date)
        else str(departure_date)
    )

    params = {
        "engine": "google_flights",
        "departure_id": origin_iata.upper(),
        "arrival_id": destination_iata.upper(),
        "outbound_date": date_str,
        "type": "2",  # One-way (documented scope decision)
        "currency": "INR",
        "gl": "in",
        "hl": "en",
        "api_key": SERPAPI_KEY,
    }

    try:
        async with httpx.AsyncClient(timeout=timeout_sec) as client:
            response = await client.get(SERPAPI_ENDPOINT, params=params)

            if response.status_code != 200:
                logger.warning(
                    "SerpAPI Google Flights request failed with status %d: %s",
                    response.status_code,
                    response.text[:200],
                )
                return []

            data = response.json()
            flight_bundles = []

            # Google Flights returns "best_flights" and "other_flights"
            if "best_flights" in data and isinstance(data["best_flights"], list):
                flight_bundles.extend(data["best_flights"])
            if "other_flights" in data and isinstance(data["other_flights"], list):
                flight_bundles.extend(data["other_flights"])

            results = []
            route_id = f"{origin_iata.upper()}-{destination_iata.upper()}"
            today = datetime.now(timezone.utc).date()

            for bundle in flight_bundles[:max_results]:
                price_val = bundle.get("price")
                if not price_val:
                    continue

                raw_price = None
                if isinstance(price_val, (int, float)):
                    raw_price = float(price_val)
                elif isinstance(price_val, str):
                    cleaned = re.sub(r"[^\d.]", "", price_val)
                    try:
                        raw_price = float(cleaned)
                    except ValueError:
                        continue

                if not raw_price or raw_price <= 0:
                    continue

                # Parse legs / segment info
                flights = bundle.get("flights", [])
                primary_flight = flights[0] if flights else {}
                carrier_name = primary_flight.get("airline", "IndiGo")
                flight_no = primary_flight.get("flight_number")
                dep_time = primary_flight.get("departure_airport", {}).get("time")
                arr_time = (
                    flights[-1].get("arrival_airport", {}).get("time")
                    if flights
                    else None
                )
                duration = bundle.get("total_duration") or primary_flight.get(
                    "duration"
                )
                stops = len(flights) - 1 if len(flights) > 1 else 0

                # Map carrier code
                carrier_code = "6E"
                c_lower = carrier_name.lower()
                if (
                    "air india express" in c_lower
                    or "ai express" in c_lower
                    or "express" in c_lower
                ):
                    carrier_code = "IX"
                    carrier_name = "Air India Express"
                elif "air india" in c_lower:
                    carrier_code = "AI"
                elif "akasa" in c_lower:
                    carrier_code = "QP"
                elif "spicejet" in c_lower:
                    carrier_code = "SG"
                elif "vistara" in c_lower:
                    carrier_code = "UK"

                results.append(
                    {
                        "route_id": route_id,
                        "carrier_code": carrier_code,
                        "carrier_name": carrier_name,
                        "flight_number": flight_no,
                        "departure_date": date_str,
                        "departure_time": dep_time,
                        "arrival_time": arr_time,
                        "duration_minutes": duration,
                        "scrape_date": today.isoformat(),
                        "advance_days": advance_days,
                        "total_fare": raw_price,
                        "stops": stops,
                        "source_platform": "google_flights",
                        "source_url": "https://www.google.com/travel/flights",
                        "is_demo_data": False,
                    }
                )

            logger.info(
                "SerpAPI returned %d valid flight quotes for route %s (date: %s, advance: T+%d)",
                len(results),
                route_id,
                date_str,
                advance_days,
            )
            return results

    except httpx.TimeoutException:
        logger.warning(
            "SerpAPI timeout for Google Flights route %s-%s on %s",
            origin_iata,
            destination_iata,
            date_str,
        )
        return []
    except Exception as e:
        logger.warning("SerpAPI Google Flights search failed: %s", e)
        return []
