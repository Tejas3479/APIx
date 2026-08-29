"""APIx Integration and End-to-End API Test Suite."""

import os

os.environ["AUTH_DISABLED"] = "true"

import httpx
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


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == "APIx"
    assert data["apix_metrics"]["routes_configured"] >= 8


@pytest.mark.asyncio
async def test_routes_crud(async_client):
    # 1. Get routes (Public read)
    res = await async_client.get("/api/v1/routes")
    assert res.status_code == 200
    routes = res.json()
    assert len(routes) >= 8
    route_ids = [r["id"] for r in routes]
    assert "DEL-BOM" in route_ids

    # 2. Unauthenticated Add route (Must fail 401)
    new_route = {
        "origin_iata": "PNQ",
        "origin_city": "Pune",
        "destination_iata": "DEL",
        "destination_city": "New Delhi",
        "dgca_weight": 0.05,
        "daily_flights": 20,
    }
    unauth_res = await async_client.post("/api/v1/routes", json=new_route)
    assert unauth_res.status_code == 401

    # 3. Authenticated Add route (Must succeed 200/201)
    create_res = await async_client.post(
        "/api/v1/routes",
        json=new_route,
        headers={"x-api-key": "test-api-key"},
    )
    assert create_res.status_code in (200, 201)
    assert create_res.json()["id"] == "PNQ-DEL"


@pytest.mark.asyncio
async def test_dashboard_endpoints(async_client):
    for ep in [
        "/api/v1/dashboard/stats",
        "/api/v1/dashboard/heatmap",
        "/api/v1/dashboard/elasticity",
        "/api/v1/dashboard/carriers",
    ]:
        res = await async_client.get(ep)
        assert res.status_code == 200, f"Failed on endpoint {ep}"
        data = res.json()
        assert data is not None


@pytest.mark.asyncio
async def test_index_endpoints(async_client):
    # Daily index series
    res = await async_client.get("/api/v1/index/daily?limit=14")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)

    # Route sub-index
    r_res = await async_client.get("/api/v1/index/route/DEL-BOM")
    assert r_res.status_code == 200

    # Materiality gap
    m_res = await async_client.get("/api/v1/index/materiality")
    assert m_res.status_code == 200
    m_data = m_res.json()
    assert "materiality_gap_pct" in m_data
    assert m_data["materiality_gap_pct"] > 0


@pytest.mark.asyncio
async def test_scraper_endpoints(async_client):
    # Survey instant unauthenticated -> 401
    unauth_res = await async_client.post("/api/v1/scraper/survey-instant?route=DEL-BOM&advance_days=7")
    assert unauth_res.status_code == 401

    # Survey instant authenticated -> 200
    res = await async_client.post(
        "/api/v1/scraper/survey-instant?route=DEL-BOM&advance_days=7",
        headers={"x-api-key": "test-api-key"},
    )
    assert res.status_code == 200
    quotes = res.json()
    assert isinstance(quotes, list)
    if quotes:
        assert "base_fare" in quotes[0]
        assert "total_fare" in quotes[0]
        assert quotes[0]["asf"] == 200.0


@pytest.mark.asyncio
async def test_frontend_pages_served(async_client):
    pages = ["/", "/dashboard", "/benchmark", "/routes", "/scraper", "/profile"]
    for p in pages:
        res = await async_client.get(p)
        assert res.status_code == 200
        assert len(res.text) > 500


@pytest.mark.asyncio
async def test_statistical_bulletin_and_ai_diagnose(async_client):
    # 1. Bulletin (Public read)
    b_res = await async_client.get("/api/v1/index/bulletin?year_month=2026-08")
    assert b_res.status_code == 200
    b_data = b_res.json()
    assert b_data["reference_month"] == "2026-08"
    assert "headline_metrics" in b_data
    assert len(b_data["route_basket_weights"]) >= 8

    # 2. AI Diagnose (Authenticated)
    d_res = await async_client.post(
        "/api/v1/index/ai-diagnose?route=DEL-BOM&advance_days=1&current_avg_fare=16500&benchmark_fare=5850",
        headers={"x-api-key": "test-api-key"},
    )
    assert d_res.status_code == 200
    d_data = d_res.json()
    assert "diagnosis" in d_data
    diag = d_data["diagnosis"]
    assert "anomaly_detected" in diag
    assert "economic_explanation" in diag

