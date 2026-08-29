"""Airfare price extraction and statutory fare decomposition for APIx.

Extracts fare quotes from scraped airline/aggregator HTML/markdown content,
and decomposes total airfares into statutory components:
  - Base Fare (Dynamic airline tariff)
  - Fuel Surcharge (YQ / YR)
  - User Development Fee (UDF - Airport specific)
  - Aviation Security Fee (ASF - Statutory flat ₹200)
  - Goods & Services Tax (GST - 5% on Economy)
  - Convenience Fee / OTA platform charges
"""

import logging
import re
from typing import Any

logger = logging.getLogger("apix.price_extractor")

INR_PATTERN = re.compile(r"(?:₹|Rs\.?|INR)\s*([\d,]+(?:\.\d{1,2})?)", re.IGNORECASE)

# Standard Airport UDF Estimates (INR) per departing domestic passenger
AIRPORT_UDF_MAP: dict[str, float] = {
    "DEL": 300.0,
    "BOM": 250.0,
    "BLR": 380.0,
    "HYD": 350.0,
    "CCU": 220.0,
    "MAA": 180.0,
    "GOI": 200.0,
    "PNQ": 200.0,
    "AMD": 180.0,
}
DEFAULT_UDF = 250.0
STATUTORY_ASF = 200.0  # Aviation Security Fee flat rate
ECONOMY_GST_RATE = 0.05  # 5% GST on (base + fuel)

# Active Indian carrier standard 15kg checked baggage unbundled surcharges (INR)
CARRIER_BAG_SURCHARGES: dict[str, float] = {
    "6E": 599.0,  # IndiGo: Unbundled Lite/Saver
    "QP": 549.0,  # Akasa Air: Unbundled Saver
    "SG": 574.0,  # SpiceJet: Unbundled Saver
    "AI": 0.0,    # Air India: 15kg standard check-in included in base economy
    "IX": 0.0,    # Air India Express: 15kg standard check-in included
}
DEFAULT_UNBUNDLED_BAG_FEE = 550.0


def compute_quality_adjusted_fare(
    total_fare: float,
    carrier_code: str = "6E",
    includes_bag: bool = False,
) -> float:
    """Normalize retail fare to constant-quality 'all-in economy bundle' (15kg bag + standard seat).

    Addresses unbundling bias identified in official price collection: when carriers
    strip checked baggage to lower headline base fares, unadjusted indices show false deflation.
    """
    if total_fare <= 0:
        return 0.0
    if includes_bag:
        return total_fare
    surcharge = CARRIER_BAG_SURCHARGES.get(carrier_code.upper(), DEFAULT_UNBUNDLED_BAG_FEE)
    return round(total_fare + surcharge, 2)


def _parse_price(text: str) -> float | None:
    """Extract a numeric price from text, handling Indian number formatting."""
    cleaned = text.replace(",", "")
    try:
        val = float(cleaned)
        if 500 <= val <= 200_000:  # Reasonable domestic airfare range (₹500 - ₹2L)
            return val
    except ValueError:
        pass
    return None


def decompose_fare(
    total_fare: float,
    origin_iata: str = "DEL",
    cabin_class: str = "economy",
    carrier_code: str = "6E",
    includes_bag: bool = False,
) -> dict[str, float]:
    """Decompose total retail fare into economic, statutory, and quality-adjusted components.

    Formula:
      Total = (Base + Fuel) * (1 + GST) + UDF + ASF + Convenience
      Quality-Adjusted = Total + Baggage Surcharge (if unbundled)
    """
    if total_fare <= 0:
        return {
            "base_fare": 0.0,
            "fuel_surcharge": 0.0,
            "udf": 0.0,
            "asf": 0.0,
            "gst": 0.0,
            "convenience_fee": 0.0,
            "quality_adjusted_fare": 0.0,
            "total_fare": 0.0,
        }

    origin = origin_iata.upper()
    udf = AIRPORT_UDF_MAP.get(origin, DEFAULT_UDF)
    asf = STATUTORY_ASF
    convenience_fee = 350.0  # standard OTA / web booking convenience charge

    # Taxes and statutory fees non-dependent on base
    fixed_fees = udf + asf + convenience_fee

    if total_fare <= fixed_fees:
        # Minimum baseline fare handling
        udf = round(total_fare * 0.10, 2)
        asf = round(total_fare * 0.08, 2)
        convenience_fee = round(total_fare * 0.10, 2)
        fixed_fees = udf + asf + convenience_fee

    # Remainder represents taxable airfare (Base + Fuel) + GST
    taxable_plus_gst = total_fare - fixed_fees
    gst_rate = 0.12 if cabin_class == "business" else ECONOMY_GST_RATE

    base_plus_fuel = taxable_plus_gst / (1 + gst_rate)
    gst_amount = taxable_plus_gst - base_plus_fuel

    # Fuel surcharge is 12-15% of (Base + Fuel), capped at ₹800
    fuel_surcharge = round(min(800.0, base_plus_fuel * 0.12), 2)
    base_fare = round(base_plus_fuel - fuel_surcharge, 2)

    # Adjust rounding differences into base_fare so sum == total_fare exactly
    calculated_sum = base_fare + fuel_surcharge + udf + asf + gst_amount + convenience_fee
    rounding_diff = round(total_fare - calculated_sum, 2)
    base_fare = round(base_fare + rounding_diff, 2)

    quality_adj = compute_quality_adjusted_fare(
        total_fare=total_fare,
        carrier_code=carrier_code,
        includes_bag=includes_bag,
    )

    return {
        "base_fare": round(base_fare, 2),
        "fuel_surcharge": round(fuel_surcharge, 2),
        "udf": round(udf, 2),
        "asf": round(asf, 2),
        "gst": round(gst_amount, 2),
        "convenience_fee": round(convenience_fee, 2),
        "quality_adjusted_fare": quality_adj,
        "total_fare": round(total_fare, 2),
    }


def extract_fares_from_content(
    content: str,
    carrier: str,
    route: str,
    source_platform: str = "web_direct",
) -> list[dict[str, Any]]:
    """Extract individual fare rows from scraped airline HTML/markdown tables."""
    if not content or len(content.strip()) < 20:
        return []

    origin = route.split("-")[0] if "-" in route else "DEL"
    inr_matches = INR_PATTERN.findall(content)
    prices_found: list[float] = []

    for match in inr_matches:
        price = _parse_price(match)
        if price is not None and price >= 1500:  # Exclude baggage fees / add-ons < ₹1500
            prices_found.append(price)

    # Keep unique prices sorted
    unique_prices = sorted(set(prices_found))
    results = []

    for price in unique_prices[:15]:  # max 15 quotes per scrape
        breakdown = decompose_fare(price, origin_iata=origin)
        results.append(
            {
                "route_id": route,
                "carrier_name": carrier,
                "total_fare": price,
                "base_fare": breakdown["base_fare"],
                "fuel_surcharge": breakdown["fuel_surcharge"],
                "udf": breakdown["udf"],
                "asf": breakdown["asf"],
                "gst": breakdown["gst"],
                "convenience_fee": breakdown["convenience_fee"],
                "source_platform": source_platform,
            }
        )

    return results


def compute_statistics(fares: list[float]) -> dict[str, Any]:
    """Compute min/max/avg/median/count statistics from a list of airfares."""
    if not fares:
        return {}

    sorted_fares = sorted(fares)
    n = len(sorted_fares)
    return {
        "min": sorted_fares[0],
        "max": sorted_fares[-1],
        "avg": round(sum(sorted_fares) / n, 2),
        "median": round(
            sorted_fares[n // 2]
            if n % 2
            else (sorted_fares[n // 2 - 1] + sorted_fares[n // 2]) / 2,
            2,
        ),
        "count": n,
    }


# Alias for backward compatibility & service imports
extract_fare_statistics = compute_statistics
