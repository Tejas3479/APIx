"""Gemini AI Fare Intelligence & Anomaly Analysis Service for APIx.

Provides LLM-assisted fare decomposition, price surge anomaly diagnosis,
and structured parsing for complex airline booking layouts.
"""

import json
import logging
import os
import re
from typing import Any

import httpx

logger = logging.getLogger("apix.gemini")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.7-flash")
GEMINI_ENDPOINT = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"


async def analyze_fare_anomaly(
    route: str,
    advance_days: int,
    current_avg_fare: float,
    benchmark_fare: float,
    quotes_sample: list[dict[str, Any]],
    timeout_sec: float = 8.0,
) -> dict[str, Any] | None:
    """Diagnose why a route fare has spiked/dropped significantly vs benchmark."""
    if not GEMINI_API_KEY or GEMINI_API_KEY.startswith("your_"):
        logger.debug("GEMINI_API_KEY not configured. Skipping AI anomaly analysis.")
        return None

    surge_pct = (
        round(((current_avg_fare - benchmark_fare) / benchmark_fare) * 100, 1)
        if benchmark_fare > 0
        else 0.0
    )

    prompt = f"""
You are a senior aviation pricing economist at the Ministry of Statistics (MoSPI) analyzing price volatility for India's Consumer Price Index (CPI).
Diagnose this airfare pricing movement:

Route: {route}
Advance Booking Window: T+{advance_days} days
Observed Average Fare: ₹{current_avg_fare:,.2f}
Historical Benchmark Fare: ₹{benchmark_fare:,.2f}
Variation: {surge_pct:+}%
Recent Quotes Sample: {json.dumps(quotes_sample[:5], default=str)}

Provide your output ONLY as a valid JSON object with the following schema:
{{
  "is_anomaly": true | false,
  "surge_category": "FESTIVAL_SEASONAL" | "CAPACITY_MONOPOLY" | "LAST_MINUTE_YIELD" | "NORMAL_FLUCTUATION",
  "root_cause_explanation": "<concise 2-sentence explanation of economic factors>",
  "cpi_materiality_verdict": "HIGH_IMPACT" | "MODERATE" | "NEGLIGIBLE",
  "statistical_recommendation": "<recommendation for NSO index compiler>"
}}
"""

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json",
        },
    }

    try:
        url = f"{GEMINI_ENDPOINT}?key={GEMINI_API_KEY}"
        async with httpx.AsyncClient(timeout=timeout_sec) as client:
            res = await client.post(url, json=payload)
            if res.status_code != 200:
                logger.warning(
                    "Gemini API error (%d): %s", res.status_code, res.text[:200]
                )
                return None

            data = res.json()
            candidates = data.get("candidates", [])
            if not candidates:
                return None

            parts = candidates[0].get("content", {}).get("parts", [])
            if not parts:
                return None

            text = parts[0].get("text", "").strip()
            json_match = re.search(r"\{.*\}", text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(0))

    except Exception as e:
        logger.warning("Gemini anomaly analysis failed for '%s': %s", route, e)

    return None
