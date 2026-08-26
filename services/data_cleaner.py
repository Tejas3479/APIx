"""APIx Production Data Cleaning & Statistical Normalization Pipeline.

Implements a 6-stage statistical data cleaning engine aligned with Eurostat HICP
and ILO CPI Manual guidelines for high-frequency scanner/web-scraped data:
  1. Boundary & Schema Validation (Bounds: ₹500 to ₹200,000)
  2. Deterministic SHA-256 Deduplication (prevents repeat scrapes from skewing price relatives)
  3. Tukey's Fences Interquartile Range (IQR) Outlier Trimming
  4. Sold-Out & Zero-Inventory Flight Handling
  5. Missing Route Imputation (Eurostat carry-forward / median baseline fallback)
  6. Statutory Fee Isolation (Base Tariff vs. Fuel, UDF, ₹200 ASF, 5% GST)
"""

import hashlib
import logging
from typing import Any

import numpy as np

from services.price_extractor import decompose_fare

logger = logging.getLogger("apix.cleaner")

# Operational Boundaries for Domestic Indian Airfares
MIN_VALID_FARE = 500.0
MAX_VALID_FARE = 200000.0


class DataCleaner:
    """Production data cleaner for raw scraped domestic airfare quotes."""

    @staticmethod
    def generate_quote_fingerprint(quote: dict[str, Any]) -> str:
        """Compute a deterministic SHA-256 fingerprint for deduplication.

        Hash components: route_id, departure_date, carrier_code, flight_number,
        advance_days, and scrape_date.
        """
        route_id = str(quote.get("route_id", "")).upper().strip()
        dep_date = str(quote.get("departure_date", "")).strip()
        carrier = str(quote.get("carrier_code", "")).upper().strip()
        flight_no = str(quote.get("flight_number", "")).upper().strip()
        advance = str(quote.get("advance_days", 0))
        scrape_d = str(quote.get("scrape_date", "")).strip()

        key = f"{route_id}|{dep_date}|{carrier}|{flight_no}|{advance}|{scrape_d}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    @classmethod
    def clean_quote(cls, quote: dict[str, Any]) -> dict[str, Any] | None:
        """Sanitize, validate, and decompose an individual raw fare quote."""
        total_fare = float(quote.get("total_fare") or 0.0)

        # 1. Boundary & Sanity Filter
        if total_fare < MIN_VALID_FARE or total_fare > MAX_VALID_FARE:
            logger.debug(
                "Dropping quote outside valid fare bounds: ₹%.2f (Route: %s)",
                total_fare,
                quote.get("route_id"),
            )
            return None

        # 2. Check Required Dimensions
        route_id = str(quote.get("route_id", "")).upper().strip()
        if not route_id or "-" not in route_id:
            return None

        origin, dest = route_id.split("-", 1)
        origin = origin.strip()
        dest = dest.strip()

        # 3. Detect Sold Out / Zero Inventory
        is_sold_out = bool(quote.get("is_sold_out", False))
        if quote.get("seats_left") == 0:
            is_sold_out = True

        # 4. Statutory Decomposition
        cabin = str(quote.get("cabin_class", "economy")).lower()
        statutory = decompose_fare(total_fare, origin_iata=origin, cabin_class=cabin)

        cleaned = dict(quote)
        cleaned["route_id"] = route_id
        cleaned["origin_iata"] = origin
        cleaned["destination_iata"] = dest
        cleaned["total_fare"] = total_fare
        cleaned["base_fare"] = statutory["base_fare"]
        cleaned["fuel_surcharge"] = statutory["fuel_surcharge"]
        cleaned["udf"] = statutory["udf"]
        cleaned["asf"] = statutory["asf"]
        cleaned["gst"] = statutory["gst"]
        cleaned["convenience_fee"] = statutory["convenience_fee"]
        cleaned["is_sold_out"] = is_sold_out
        cleaned["fingerprint"] = cls.generate_quote_fingerprint(cleaned)

        return cleaned

    @classmethod
    def clean_batch(
        cls, quotes: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], dict[str, int]]:
        """Clean and deduplicate a batch of quotes, returning cleaned data and metrics."""
        cleaned_list: list[dict[str, Any]] = []
        seen_fingerprints: set[str] = set()

        metrics = {
            "total_input": len(quotes),
            "valid_quotes": 0,
            "duplicates_dropped": 0,
            "out_of_bounds_dropped": 0,
            "sold_out_flagged": 0,
        }

        for raw_q in quotes:
            cleaned = cls.clean_quote(raw_q)
            if cleaned is None:
                metrics["out_of_bounds_dropped"] += 1
                continue

            fp = cleaned.get("fingerprint", "")
            if fp in seen_fingerprints:
                metrics["duplicates_dropped"] += 1
                continue

            seen_fingerprints.add(fp)
            if cleaned.get("is_sold_out"):
                metrics["sold_out_flagged"] += 1

            cleaned_list.append(cleaned)

        metrics["valid_quotes"] = len(cleaned_list)
        return cleaned_list, metrics

    @staticmethod
    def filter_outliers_iqr(
        fares: list[float], multiplier: float = 1.5
    ) -> tuple[list[float], list[float]]:
        """Filter extreme fare outliers using standard Tukey's Interquartile Range (IQR) rule.

        Outlier boundaries:
          [Q1 - multiplier * IQR, Q3 + multiplier * IQR] with minimum floor ₹500.
        """
        if len(fares) < 4:
            return fares, []

        sorted_fares = sorted(fares)
        q1 = float(np.percentile(sorted_fares, 25))
        q3 = float(np.percentile(sorted_fares, 75))
        iqr = q3 - q1

        lower_bound = max(MIN_VALID_FARE, q1 - (multiplier * iqr))
        upper_bound = q3 + (multiplier * iqr)

        cleaned = [f for f in fares if lower_bound <= f <= upper_bound]
        outliers = [f for f in fares if f < lower_bound or f > upper_bound]

        return cleaned, outliers

    @staticmethod
    def impute_missing_route(
        missing_route_id: str,
        base_period_fares: dict[str, float] | None = None,
        all_active_fares: list[float] | None = None,
    ) -> float:
        """Eurostat HICP compliant missing price imputation.

        Falls back to:
          1. Historical baseline fare for that specific route.
          2. National median fare of current active quotes.
          3. Standard fallback baseline ₹5,500.
        """
        if base_period_fares and missing_route_id in base_period_fares:
            return float(base_period_fares[missing_route_id])

        if all_active_fares and len(all_active_fares) > 0:
            return float(np.median(all_active_fares))

        return 5500.0
