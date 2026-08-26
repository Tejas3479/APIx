"""Integration tests for dynamic dashboard, multi-frequency indices, and CSV microdata exports."""

import os
os.environ["AUTH_DISABLED"] = "true"

import pytest
from fastapi.testclient import TestClient

from app import app
from database import init_db
from services.airfare_seeder import seed_airfare_database

client = TestClient(app)


@pytest.fixture(autouse=True)
async def setup_env():
    await init_db()
    await seed_airfare_database()
    yield


def test_export_microdata_csv():
    """CSV microdata export must return valid CSV attachment with headers."""
    resp = client.get("/api/v1/export/csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "attachment; filename=" in resp.headers["content-disposition"]
    lines = resp.text.strip().split("\n")
    assert len(lines) >= 2  # Header + at least one data row
    assert "quote_id,route_id,carrier_code" in lines[0]


def test_export_index_series_csv():
    """CSV index series export must return valid CSV table."""
    resp = client.get("/api/v1/export/index-csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "index_date,frequency,apix_index_value" in resp.text


def test_get_weekly_index():
    """Weekly index endpoint must return 7-day rolling aggregates."""
    resp = client.get("/api/v1/index/weekly?limit=8")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert "week_label" in data[0]
    assert "index_value" in data[0]


def test_get_monthly_index():
    """Monthly index endpoint must return publication-ready monthly series."""
    resp = client.get("/api/v1/index/monthly?limit=6")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert "year_month" in data[0]
    assert "index_value" in data[0]


def test_get_methodology_comparison():
    """Methodology comparison must return Jevons vs Carli bias analysis."""
    resp = client.get("/api/v1/index/methodology-comparison?route_id=DEL-BOM")
    assert resp.status_code == 200
    data = resp.json()
    assert "jevons_index" in data
    assert "carli_index" in data
    assert "carli_upward_bias_pts" in data
    assert data["recommended_standard"] == "jevons"


def test_get_inflation_contribution():
    """Inflation contribution endpoint must decompose route contributions."""
    resp = client.get("/api/v1/index/inflation-contribution")
    assert resp.status_code == 200
    data = resp.json()
    assert "headline_national_inflation_pts" in data
    assert "route_contributions" in data


def test_dynamic_elasticity():
    """Lead-time elasticity must return dynamic curves across 5 horizons."""
    resp = client.get("/api/v1/dashboard/elasticity")
    assert resp.status_code == 200
    curves = resp.json()
    assert len(curves) >= 5
    first = curves[0]
    assert "route_id" in first
    assert "window_averages" in first
    assert "surge_multiplier" in first


def test_dynamic_carriers():
    """Carriers endpoint must return carrier breakdown with Air India Express."""
    resp = client.get("/api/v1/dashboard/carriers")
    assert resp.status_code == 200
    carriers = resp.json()
    assert len(carriers) >= 4
    codes = [c["carrier_code"] for c in carriers]
    assert "6E" in codes
    assert "AI" in codes


def test_scraper_live_logs():
    """Live telemetry endpoint must return list of in-memory logs."""
    resp = client.get("/api/v1/scraper/live-logs")
    assert resp.status_code == 200
    logs = resp.json()
    assert isinstance(logs, list)
    assert len(logs) > 0
