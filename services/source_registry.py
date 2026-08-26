"""Airline & Aggregator Source Registry for APIx.

Defines target airline booking portals and aggregators, their scraping strategy,
carrier coverage, rendering requirements, and robots.txt policies.
"""

from typing import Any

AIRLINE_SOURCES: list[dict[str, Any]] = [
    {
        "id": "google_flights",
        "name": "Google Flights",
        "type": "api",
        "engine": "serpapi",
        "priority": 1,
        "is_active": True,
        "carrier_coverage": ["6E", "AI", "IX", "QP", "SG", "UK"],
        "description": "Multi-carrier flight aggregator via SerpAPI (gl=in, currency=INR).",
        "robots_txt_url": "https://www.google.com/robots.txt",
    },
    {
        "id": "indigo_direct",
        "name": "IndiGo Airlines",
        "type": "playwright",
        "base_url": "https://www.goindigo.in",
        "render_js": True,
        "priority": 2,
        "carrier_code": "6E",
        "is_active": True,
        "description": "Direct IndiGo booking portal with standard headless rendering.",
        "robots_txt_url": "https://www.goindigo.in/robots.txt",
    },
    {
        "id": "air_india_express",
        "name": "Air India Express",
        "type": "playwright",
        "base_url": "https://www.airindiaexpress.com",
        "render_js": True,
        "priority": 3,
        "carrier_code": "IX",
        "is_active": True,
        "description": "Direct Air India Express portal with passive stealth headers.",
        "robots_txt_url": "https://www.airindiaexpress.com/robots.txt",
    },
    {
        "id": "akasa_air",
        "name": "Akasa Air",
        "type": "playwright",
        "base_url": "https://www.akasaair.com",
        "render_js": True,
        "priority": 4,
        "carrier_code": "QP",
        "is_active": True,
        "description": "Direct Akasa Air booking portal with AWS WAF passive stealth.",
        "robots_txt_url": "https://www.akasaair.com/robots.txt",
    },
    {
        "id": "spicejet",
        "name": "SpiceJet",
        "type": "playwright",
        "base_url": "https://www.spicejet.com",
        "render_js": True,
        "priority": 5,
        "carrier_code": "SG",
        "is_active": True,
        "description": "Direct SpiceJet booking portal with standard headless rendering.",
        "robots_txt_url": "https://www.spicejet.com/robots.txt",
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
