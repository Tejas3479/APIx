"""Async-safe Robots.txt Compliance Engine for APIx.

Validates outbound scraping requests against target website robots.txt rules
using standard Python urllib.robotparser with in-memory LRU caching.
"""

import asyncio
import logging
import os
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import httpx

logger = logging.getLogger("apix.robots")

RESPECT_ROBOTS_TXT = os.getenv("RESPECT_ROBOTS_TXT", "true").lower() == "true"
DEFAULT_USER_AGENT = "APIx-PriceStatisticsBot/1.0 (+https://mospi.gov.in/cpi)"

# Cache: origin -> (RobotFileParser, timestamp)
_ROBOTS_CACHE: dict[str, RobotFileParser] = {}
_CACHE_LOCK = asyncio.Lock()


class RobotsTxtChecker:
    """Checks URL accessibility according to domain robots.txt rules."""

    @classmethod
    async def is_allowed(
        cls,
        url: str,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout_sec: float = 4.0,
    ) -> bool:
        """Check if target URL path is permitted under site robots.txt policy."""
        if not RESPECT_ROBOTS_TXT:
            return True

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return True

        origin = f"{parsed.scheme}://{parsed.netloc}"
        robots_url = f"{origin}/robots.txt"

        parser = None
        async with _CACHE_LOCK:
            if origin in _ROBOTS_CACHE:
                parser = _ROBOTS_CACHE[origin]

        if parser is None:
            parser = RobotFileParser()
            try:
                async with httpx.AsyncClient(
                    timeout=timeout_sec, follow_redirects=True
                ) as client:
                    resp = await client.get(robots_url)
                    if resp.status_code == 200:
                        parser.parse(resp.text.splitlines())
                        logger.debug(
                            "Successfully loaded robots.txt for origin: %s", origin
                        )
                    elif resp.status_code in (401, 403):
                        # Site disallows all
                        parser.parse(["User-agent: *", "Disallow: /"])
                    else:
                        # 404 or other status means no restrictions
                        parser.parse(["User-agent: *", "Allow: /"])
            except Exception as e:
                logger.debug(
                    "Could not fetch robots.txt for %s (%s); defaulting to allow",
                    origin,
                    e,
                )
                parser.parse(["User-agent: *", "Allow: /"])

            async with _CACHE_LOCK:
                # Keep cache bounded to 100 domains
                if len(_ROBOTS_CACHE) > 100:
                    _ROBOTS_CACHE.clear()
                _ROBOTS_CACHE[origin] = parser

        can_fetch = parser.can_fetch(user_agent, url)
        if not can_fetch:
            logger.warning("Scrape blocked by robots.txt policy for URL: %s", url)
        return can_fetch
