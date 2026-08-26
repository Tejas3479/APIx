"""Route Basket Configuration Router for APIx.

CRUD endpoints to manage the city-pair basket, weights, and daily flight counts.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

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


@router.post("", response_model=RouteBasketConfig)
async def create_route(req: RouteBasketCreate):
    """Add a new city-pair route to the basket."""
    route_id = f"{req.origin_iata.upper()}-{req.destination_iata.upper()}"
    async with async_session_maker() as session:
        existing = (
            await session.execute(select(RouteConfig).where(RouteConfig.id == route_id))
        ).scalars().first()
        if existing:
            raise HTTPException(status_code=409, detail=f"Route {route_id} already exists.")

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


@router.put("/{route_id}", response_model=RouteBasketConfig)
async def update_route(route_id: str, req: RouteBasketUpdate):
    """Update route DGCA weight or toggle active tracking status."""
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


@router.delete("/{route_id}")
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
