"""Unit tests for the statutory price extractor and fare decomposition."""

from services.price_extractor import (
    AIRPORT_UDF_MAP,
    STATUTORY_ASF,
    compute_statistics,
    decompose_fare,
    extract_fares_from_content,
)


def test_statutory_fare_decomposition_sum():
    """All decomposed fare components must sum up exactly to the total fare."""
    test_fares = [1500.0, 3450.0, 6890.0, 12400.0, 28500.0, 75000.0]
    for fare in test_fares:
        d = decompose_fare(fare, origin_iata="DEL", cabin_class="economy")
        assert d["asf"] == STATUTORY_ASF, "Statutory ASF must equal flat ₹200"
        assert d["udf"] == AIRPORT_UDF_MAP["DEL"], "Delhi UDF must equal ₹300"
        assert d["base_fare"] > 0
        total_sum = round(
            d["base_fare"]
            + d["fuel_surcharge"]
            + d["udf"]
            + d["asf"]
            + d["gst"]
            + d["convenience_fee"],
            2,
        )
        assert abs(total_sum - fare) < 0.01, f"Decomposition mismatch for ₹{fare}"


def test_compute_statistics():
    """Summary statistics (min, max, median, avg) must be exact."""
    fares = [3000.0, 4500.0, 5500.0, 9000.0, 13000.0]
    stats = compute_statistics(fares)
    assert stats["min"] == 3000.0
    assert stats["max"] == 13000.0
    assert stats["median"] == 5500.0
    assert stats["count"] == 5
    assert stats["avg"] == 7000.0


def test_extract_fares_from_content():
    """Regex extractor must find INR currency amounts and filter out baggage fees."""
    sample_text = (
        "IndiGo flight 6E-2045: ₹5,420 (Economy Standard). "
        "Air India AI-805: ₹6,800. Excess baggage: ₹800."
    )
    results = extract_fares_from_content(sample_text, carrier="IndiGo", route="DEL-BOM")
    assert len(results) >= 2
    fares = [r["total_fare"] for r in results]
    assert 5420.0 in fares
    assert 6800.0 in fares
    assert 800.0 not in fares  # baggage fee below 1500 threshold
