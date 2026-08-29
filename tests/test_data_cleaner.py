"""Unit tests for APIx Data Cleaner and Statistical Normalization Pipeline."""

from services.data_cleaner import DataCleaner


def test_clean_quote_valid():
    """Valid quote within range should be sanitized with statutory decomposition."""
    raw = {
        "route_id": "DEL-BOM",
        "departure_date": "2026-08-30",
        "carrier_code": "6E",
        "carrier_name": "IndiGo",
        "flight_number": "6E-2045",
        "advance_days": 7,
        "total_fare": 6500.0,
        "scrape_date": "2026-08-23",
        "cabin_class": "economy",
    }
    cleaned = DataCleaner.clean_quote(raw)
    assert cleaned is not None
    assert cleaned["total_fare"] == 6500.0
    assert cleaned["asf"] == 200.0
    assert cleaned["base_fare"] > 0
    assert cleaned["fuel_surcharge"] >= 0
    assert cleaned["gst"] > 0
    assert "fingerprint" in cleaned


def test_clean_quote_out_of_bounds():
    """Fares under ₹500 or over ₹200,000 should be rejected as malformed."""
    too_low = {"route_id": "DEL-BOM", "total_fare": 150.0}
    too_high = {"route_id": "DEL-BOM", "total_fare": 500000.0}
    assert DataCleaner.clean_quote(too_low) is None
    assert DataCleaner.clean_quote(too_high) is None


def test_clean_batch_deduplication():
    """Duplicate quotes with identical flight keys should be dropped in batch."""
    q1 = {
        "route_id": "DEL-BLR",
        "departure_date": "2026-09-01",
        "carrier_code": "AI",
        "flight_number": "AI-506",
        "advance_days": 15,
        "total_fare": 7200.0,
        "scrape_date": "2026-08-20",
    }
    # Exact duplicate
    q2 = dict(q1)
    # Distinct flight
    q3 = dict(q1)
    q3["flight_number"] = "AI-805"

    cleaned_list, metrics = DataCleaner.clean_batch([q1, q2, q3])
    assert len(cleaned_list) == 2
    assert metrics["duplicates_dropped"] == 1
    assert metrics["valid_quotes"] == 2


def test_filter_outliers_iqr():
    """Tukey IQR filter must trim extreme pricing spikes."""
    normal_fares = [5200.0, 5400.0, 5600.0, 5800.0, 6000.0, 6200.0, 6500.0]
    outlier_fare = 45000.0  # Extreme anomaly
    fares = normal_fares + [outlier_fare]

    cleaned, outliers = DataCleaner.filter_outliers_iqr(fares)
    assert outlier_fare in outliers
    assert len(cleaned) == len(normal_fares)


def test_impute_missing_route():
    """Missing route imputation should return baseline or median fallback."""
    baseline = {"DEL-BOM": 5850.0}
    imputed = DataCleaner.impute_missing_route("DEL-BOM", base_period_fares=baseline)
    assert imputed == 5850.0

    fallback = DataCleaner.impute_missing_route(
        "UNKNOWN-ROUTE", base_period_fares=baseline, all_active_fares=[4000.0, 6000.0]
    )
    assert fallback == 5000.0
