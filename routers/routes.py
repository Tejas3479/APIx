"""Route Basket Configuration Router for APIx.

CRUD endpoints to manage the city-pair basket, weights, and daily flight counts.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from auth import verify_api_key
from database import RouteConfig, async_session_maker
from models import RouteBasketConfig, RouteBasketCreate, RouteBasketUpdate

logger = logging.getLogger("apix.routers.routes")

router = APIRouter(prefix="/api/v1/routes", tags=["routes"])


@router.get("", response_model=list[RouteBasketConfig])
async def list_routes():
    """List all routes configured in the national basket with weights and flights."""
    async with async_session_maker() as session:
        stmt = select(RouteConfig).order_by(RouteConfig.dgca_weight.desc())
        routes = (await session.execute(stmt)).scalars().all()
        return routes


@router.get("/validation/weights")
async def validate_basket_weights():
    """Validate that active route basket weights satisfy the sum invariant (Σw_r = 1.000)."""
    async with async_session_maker() as session:
        stmt = select(RouteConfig).where(RouteConfig.is_active == True)
        routes = (await session.execute(stmt)).scalars().all()
        total_w = sum(r.dgca_weight for r in routes)
        is_balanced = abs(total_w - 1.0) <= 0.005
        return {
            "total_active_weight": round(total_w, 4),
            "is_balanced": is_balanced,
            "active_routes_count": len(routes),
            "target_sum": 1.000,
            "discrepancy": round(total_w - 1.0, 4),
            "status": "VALID" if is_balanced else "REBALANCE_REQUIRED",
        }


@router.post("", response_model=RouteBasketConfig, dependencies=[Depends(verify_api_key)])
async def create_route(req: RouteBasketCreate):
    """Add a new city-pair route to the basket with weight bounds validation."""
    if req.dgca_weight <= 0 or req.dgca_weight > 1.0:
        raise HTTPException(status_code=400, detail="Route weight must be between 0.001 and 1.0.")
    route_id = f"{req.origin_iata.upper()}-{req.destination_iata.upper()}"
    async with async_session_maker() as session:
        existing = (
            await session.execute(select(RouteConfig).where(RouteConfig.id == route_id))
        ).scalars().first()
        if existing:
            raise HTTPException(status_code=409, detail=f"Route {route_id} already exists.")

        # Check total active weight bounds
        active_routes = (
            await session.execute(select(RouteConfig).where(RouteConfig.is_active == True))
        ).scalars().all()
        current_sum = sum(r.dgca_weight for r in active_routes)
        if current_sum + req.dgca_weight > 1.5:
            raise HTTPException(
                status_code=422,
                detail=f"Total route basket weight ({current_sum + req.dgca_weight:.3f}) exceeds upper tolerance (1.50).",
            )

        route = RouteConfig(
            id=route_id,
            origin_iata=req.origin_iata.upper(),
            origin_city=req.origin_city,
            destination_iata=req.destination_iata.upper(),
            destination_city=req.destination_city,
            dgca_weight=req.dgca_weight,
            daily_flights=req.daily_flights,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        session.add(route)
        await session.commit()
        await session.refresh(route)
        return route


@router.put("/{route_id}", response_model=RouteBasketConfig, dependencies=[Depends(verify_api_key)])
async def update_route(route_id: str, req: RouteBasketUpdate):
    """Update route DGCA weight or toggle active tracking status."""
    if req.dgca_weight is not None and (req.dgca_weight <= 0 or req.dgca_weight > 1.0):
        raise HTTPException(status_code=400, detail="Route weight must be between 0.001 and 1.0.")
    async with async_session_maker() as session:
        route = (
            await session.execute(select(RouteConfig).where(RouteConfig.id == route_id.upper()))
        ).scalars().first()
        if not route:
            raise HTTPException(status_code=404, detail="Route not found.")

        if req.dgca_weight is not None:
            route.dgca_weight = req.dgca_weight
        if req.daily_flights is not None:
            route.daily_flights = req.daily_flights
        if req.is_active is not None:
            route.is_active = req.is_active

        session.add(route)
        await session.commit()
        await session.refresh(route)
        return route


@router.delete("/{route_id}", dependencies=[Depends(verify_api_key)])
async def delete_route(route_id: str):
    """Remove a route from the active basket."""
    async with async_session_maker() as session:
        route = (
            await session.execute(select(RouteConfig).where(RouteConfig.id == route_id.upper()))
        ).scalars().first()
        if not route:
            raise HTTPException(status_code=404, detail="Route not found.")

        await session.delete(route)
        await session.commit()
        return {"status": "deleted", "route_id": route_id.upper()}
