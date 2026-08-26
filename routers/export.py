"""Data Export Router for APIx — NSO / RBI microdata CSV and index series exports."""

import csv
import io
import logging
from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import Response
from sqlalchemy import desc, select

from database import DailyIndex, FareQuote, async_session_maker

logger = logging.getLogger("apix.routers.export")

router = APIRouter(prefix="/api/v1/export", tags=["export"])


@router.get("/csv")
async def export_microdata_csv(limit: int = 5000):
    """Export cleaned airfare quotes microdata as an audit-ready CSV for NSO statisticians."""
    async with async_session_maker() as session:
        stmt = (
            select(FareQuote)
            .where(FareQuote.total_fare > 0)
            .order_by(desc(FareQuote.scrape_date))
            .limit(limit)
        )
        quotes = (await session.execute(stmt)).scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)

    # Write Header
    writer.writerow(
        [
            "quote_id",
            "route_id",
            "carrier_code",
            "carrier_name",
            "flight_number",
            "departure_date",
            "advance_window",
            "base_fare_inr",
            "fuel_surcharge_inr",
            "udf_inr",
            "asf_inr",
            "gst_inr",
            "convenience_fee_inr",
            "total_fare_inr",
            "cabin_class",
            "stops",
            "source_platform",
            "scrape_date",
            "is_sold_out",
        ]
    )

    for q in quotes:
        writer.writerow(
            [
                q.id,
                q.route_id,
                q.carrier_code,
                q.carrier_name,
                q.flight_number or "N/A",
                q.departure_date.isoformat(),
                f"T+{q.advance_days}",
                q.base_fare,
                q.fuel_surcharge,
                q.udf,
                q.asf,
                q.gst,
                q.convenience_fee,
                q.total_fare,
                q.cabin_class,
                q.stops,
                q.source_platform,
                q.scrape_date.isoformat(),
                q.is_sold_out,
            ]
        )

    today_str = datetime.now(timezone.utc).date().isoformat()
    csv_content = output.getvalue()
    filename = f"APIx_NSO_Airfare_Microdata_{today_str}.csv"

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/index-csv")
async def export_index_series_csv(limit: int = 365):
    """Export national APIx time series as a CSV table for RBI monetary policy modeling."""
    async with async_session_maker() as session:
        stmt = (
            select(DailyIndex)
            .order_by(DailyIndex.index_date)
            .limit(limit)
        )
        indices = (await session.execute(stmt)).scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(
        [
            "index_date",
            "frequency",
            "apix_index_value",
            "base_period_value",
            "methodology",
            "active_routes_count",
            "quotes_aggregated",
            "computed_at",
        ]
    )

    for idx in indices:
        writer.writerow(
            [
                idx.index_date.isoformat(),
                idx.frequency,
                idx.index_value,
                idx.base_period_value,
                idx.methodology,
                idx.route_coverage,
                idx.quote_count,
                idx.computed_at.isoformat() if idx.computed_at else "",
            ]
        )

    today_str = datetime.now(timezone.utc).date().isoformat()
    csv_content = output.getvalue()
    filename = f"APIx_National_Index_Series_{today_str}.csv"

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
