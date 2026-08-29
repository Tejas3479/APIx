"""Unit and integration tests for PPAC ATF benchmark validation and basket weights invariant."""

import pytest
from httpx import ASGITransport, AsyncClient

from app import app
from services.atf_validator import AtfValidator


@pytest.fixture
async def async_client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_atf_cross_validation_service():
    """AtfValidator must load benchmark data and compute positive correlation."""
    result = await AtfValidator.cross_validate_fuel_surcharges()
    assert result["total_months_evaluated"] >= 10
    assert result["correlation_coefficient"] > 0.70
    assert result["r_squared"] > 0.50
    assert result["tracking_verdict"] in ("STRONG_CONVERGENCE", "HIGH_CONVERGENCE")
    assert len(result["series_comparison"]) >= 10


@pytest.mark.asyncio
async def test_atf_cross_validation_endpoint(async_client):
    """GET /api/v1/index/atf-cross-validation must return valid correlation payload."""
    res = await async_client.get("/api/v1/index/atf-cross-validation")
    assert res.status_code == 200
    data = res.json()
    assert "correlation_coefficient" in data
    assert "r_squared" in data
    assert "economic_interpretation" in data


@pytest.mark.asyncio
async def test_route_weights_validation_endpoint(async_client):
    """GET /api/v1/routes/validation/weights must verify the basket sum invariant."""
    res = await async_client.get("/api/v1/routes/validation/weights")
    assert res.status_code == 200
    data = res.json()
    assert "total_active_weight" in data
    assert "is_balanced" in data
    assert data["target_sum"] == 1.000
