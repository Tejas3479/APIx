"""Unit tests for the APIx Index Engine mathematical algorithms."""

from services.index_engine import (
    AirfareIndexEngine,
    compute_geks_tornqvist_matrix,
)


def test_jevons_index_identical_prices():
    """Identical current and base prices must yield index exactly 100.0."""
    prices = [4500.0, 6200.0, 7800.0]
    idx = AirfareIndexEngine.compute_jevons_index(prices, prices)
    assert idx == 100.0


def test_jevons_index_ten_percent_inflation():
    """10% increase across all price relatives must yield index exactly 110.0."""
    base = [5000.0, 6000.0, 8000.0]
    curr = [5500.0, 6600.0, 8800.0]
    idx = AirfareIndexEngine.compute_jevons_index(curr, base)
    assert idx == 110.0


def test_dutot_index():
    """Dutot index computes ratio of arithmetic means."""
    base = [4000.0, 6000.0]
    curr = [4400.0, 6600.0]
    idx = AirfareIndexEngine.compute_dutot_index(curr, base)
    assert idx == 110.0


def test_carli_upward_bias():
    """Carli index produces upward bias compared to Jevons on volatile price relatives."""
    base = [5000.0, 5000.0]
    curr = [10000.0, 2500.0]  # One doubled (2.0), one halved (0.5)

    jevons = AirfareIndexEngine.compute_jevons_index(curr, base)
    carli = AirfareIndexEngine.compute_carli_index(curr, base)

    # Jevons should be 100.0 (geometric mean of 2.0 and 0.5 is 1.0)
    assert jevons == 100.0
    # Carli is (2.0 + 0.5)/2 = 1.25 -> 125.0 (25% upward bias!)
    assert carli == 125.0
    assert carli > jevons


def test_methodology_comparison():
    """Methodology comparison helper must return valid bias metrics."""
    base = [5000.0, 6000.0, 8000.0]
    curr = [5500.0, 7200.0, 8800.0]
    diag = AirfareIndexEngine.compute_methodology_comparison(curr, base)
    assert "jevons_index" in diag
    assert "carli_index" in diag
    assert "dutot_index" in diag
    assert diag["recommended_standard"] == "jevons"


def test_geks_tornqvist_multilateral_consistency():
    """GEKS multilateral index must start at 100.0 on base date and be transitive."""
    matrix = {
        "2026-08-01": {"DEL-BOM-6E": 5000.0, "DEL-BLR-AI": 6000.0},
        "2026-08-02": {"DEL-BOM-6E": 5500.0, "DEL-BLR-AI": 6300.0},
        "2026-08-03": {"DEL-BOM-6E": 6000.0, "DEL-BLR-AI": 6600.0},
    }
    geks = compute_geks_tornqvist_matrix(matrix)
    assert geks["2026-08-01"] == 100.0
    assert geks["2026-08-02"] > 100.0
    assert geks["2026-08-03"] > geks["2026-08-02"]


def test_materiality_gap_static_vs_continuous():
    """Materiality gap must reflect positive distortion when snapshot misses peaks."""
    quotes = [
        {"total_fare": 4500.0, "advance_days": 30},
        {"total_fare": 5200.0, "advance_days": 15},
        {"total_fare": 12800.0, "advance_days": 1},
        {"total_fare": 16500.0, "advance_days": 1},
    ]
    res = AirfareIndexEngine.compute_materiality_gap(quotes)
    assert res["materiality_gap_pct"] > 0.0
    assert res["under_reporting_amount_inr"] > 0.0
