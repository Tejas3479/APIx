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
        "description": "Direct airline portal attempt via Playwright.",
    },
    {
        "id": "indigo_direct",
        "name": "IndiGo",
        "type": "playwright",
        "base_url": "https://www.goindigo.in",
        "render_js": True,
        "priority": 4,
        "carrier_code": "6E",
        "is_active": True,
        "description": "Direct airline portal attempt via Playwright.",
    },
    {
        "id": "air_india_direct",
        "name": "Air India",
        "type": "playwright",
        "base_url": "https://www.airindia.com",
        "render_js": True,
        "priority": 5,
        "carrier_code": "AI",
        "is_active": True,
        "description": "Direct airline portal attempt via Playwright.",
    },
    {
        "id": "air_india_express_direct",
        "name": "Air India Express",
        "type": "playwright",
        "base_url": "https://www.airindiaexpress.com",
        "render_js": True,
        "priority": 6,
        "carrier_code": "IX",
        "is_active": True,
        "description": "Direct airline portal attempt via Playwright.",
    },
    {
        "id": "akasa_air_direct",
        "name": "Akasa Air",
        "type": "playwright",
        "base_url": "https://www.akasaair.com",
        "render_js": True,
        "priority": 7,
        "carrier_code": "QP",
        "is_active": True,
        "description": "Direct airline portal attempt via Playwright.",
    },
    {
        "id": "makemytrip_ota",
        "name": "MakeMyTrip",
        "type": "playwright",
        "base_url": "https://www.makemytrip.com",
        "render_js": True,
        "priority": 8,
        "is_active": True,
        "carrier_coverage": ["6E", "AI", "IX", "QP", "SG"],
        "description": "OTA portal scrape via Playwright headless Chromium.",
    },
    {
        "id": "yatra_ota",
        "name": "Yatra",
        "type": "playwright",
        "base_url": "https://www.yatra.com",
        "render_js": True,
        "priority": 9,
        "is_active": True,
        "carrier_coverage": ["6E", "AI", "IX", "QP", "SG"],
        "description": "OTA portal scrape via Playwright headless Chromium.",
    },
    {
        "id": "easemytrip_ota",
        "name": "EaseMyTrip",
        "type": "playwright",
        "base_url": "https://www.easemytrip.com",
        "render_js": True,
        "priority": 10,
        "is_active": True,
        "carrier_coverage": ["6E", "AI", "IX", "QP", "SG"],
        "description": "OTA portal scrape via Playwright headless Chromium.",
    },
    {
        "id": "cleartrip_ota",
        "name": "Cleartrip",
        "type": "playwright",
        "base_url": "https://www.cleartrip.com",
        "render_js": True,
        "priority": 11,
        "is_active": True,
        "carrier_coverage": ["6E", "AI", "IX", "QP", "SG"],
        "description": "OTA portal scrape via Playwright headless Chromium.",
    },
    {
        "id": "goibibo_ota",
        "name": "Goibibo",
        "type": "playwright",
        "base_url": "https://www.goibibo.com",
        "render_js": True,
        "priority": 12,
        "is_active": True,
        "carrier_coverage": ["6E", "AI", "IX", "QP", "SG"],
        "description": "OTA portal scrape via Playwright headless Chromium.",
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
