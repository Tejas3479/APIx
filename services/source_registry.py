"""Airline & Aggregator Source Registry for APIx.

Defines target airline booking portals and aggregators, their scraping strategy,
carrier coverage, rendering requirements, and robots.txt policies.
"""

from typing import Any

AIRLINE_SOURCES: list[dict[str, Any]] = [
    {
        "id": "google_flights",
        "name": "Google Flights (SerpAPI)",
        "type": "api",
        "engine": "serpapi",
        "priority": 1,
        "is_active": True,
        "carrier_coverage": ["6E", "AI", "IX", "QP", "SG"],
        "description": "Multi-carrier aggregator via SerpAPI.",
    },
    {
        "id": "ixigo_ota",
        "name": "Ixigo",
        "type": "playwright",
        "base_url": "https://www.ixigo.com",
        "render_js": True,
        "priority": 2,
        "is_active": True,
        "carrier_coverage": ["6E", "AI", "QP", "SG"],
        "description": "OTA portal scrape via Playwright headless Chromium.",
    },
    {
        "id": "spicejet_direct",
        "name": "SpiceJet",
        "type": "playwright",
        "base_url": "https://www.spicejet.com",
        "render_js": True,
        "priority": 3,
        "carrier_code": "SG",
        "is_active": True,
        "description": "Direct airline portal attempt via Playwright (best-effort with graceful fallback).",
    },
]


def get_enabled_airline_sources() -> list[dict[str, Any]]:
    """Return list of currently active airline and aggregator scraping sources."""
    return [source for source in AIRLINE_SOURCES if source.get("is_active", True)]


def get_source_by_id(source_id: str) -> dict[str, Any] | None:
    """Find a source configuration by its identifier."""
    for source in AIRLINE_SOURCES:
        if source["id"] == source_id:
            return source
    return None
