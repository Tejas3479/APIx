import logging
import os
import time
from urllib.parse import parse_qs, urlparse

from fastapi import APIRouter, Depends, HTTPException
from rapidfuzz import fuzz

from auth import verify_api_key
from fetcher import playwright_mgr, run_fetch, session_manager
from models import FetchRequest, FetchResponse
from services.search_orchestrator import _load_demo_cache

logger = logging.getLogger("apix.fetch")

router = APIRouter(tags=["fetch"])

DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in ("1", "true", "yes")


def _demo_snapshot_content(req: FetchRequest) -> str:
    """Build a clean structured airfare/portal snapshot for DEMO_MODE (no network)."""
    url = str(req.url)
    query = ""
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        query = (qs.get("q") or qs.get("k") or qs.get("route") or [""])[0]
    except Exception:
        pass
    query = query.strip()

    netloc = urlparse(url).netloc or "airline-portal"
    lines = [
        f"# APIx Demo Snapshot — {netloc}",
        "",
        "> **DEMO MODE:** live network fetch disabled in demo environment. Showing verified airfare observation snapshot from the reference dataset.",
        "",
    ]

    cache = _load_demo_cache()
    matches: list[tuple[float, dict]] = []

    if isinstance(cache, list):
        for item in cache:
            if not isinstance(item, dict):
                continue
            item_text = f"{item.get('route_id', '')} {item.get('carrier_name', '')} {item.get('carrier_code', '')} {item.get('flight_number', '')}"
            score = fuzz.token_set_ratio(query.lower(), item_text.lower()) if query else 100
            if score >= 50 or not query:
                matches.append((score, item))
    elif isinstance(cache, dict):
        for key, results in cache.items():
            if isinstance(results, list):
                for item in results:
                    score = fuzz.token_set_ratio(query.lower(), key.lower()) if query else 100
                    if score >= 50:
                        matches.append((score, item))

    matches.sort(key=lambda m: m[0], reverse=True)

    rows = []
    for _score, item in matches[:12]:
        carrier = item.get("carrier_name") or item.get("carrier_code") or "Airline"
        flight_no = item.get("flight_number") or "Direct"
        route = item.get("route_id", "DEL-BOM")
        price = item.get("total_fare") or item.get("price")
        price_s = f"₹{price:,.2f}" if isinstance(price, (int, float)) else str(price or "—")
        adv = f"T+{item.get('advance_days', 7)}"
        source = item.get("source_platform", "google_flights")
        evidence = item.get("source_url", url)

        rows.append(
            {
                "carrier": carrier,
                "flight": flight_no,
                "route": route,
                "advance": adv,
                "fare": price_s,
                "source": source,
                "evidence": evidence,
            }
        )

    if rows:
        lines.append("| # | Carrier | Flight | Sector | Horizon | Fare (Total) | Platform | Source |")
        lines.append("|---|---------|--------|--------|---------|--------------|----------|--------|")
        for idx, r in enumerate(rows, start=1):
            evidence_host = urlparse(r["evidence"]).netloc or "flights"
            lines.append(
                f"| {idx} | {r['carrier']} | {r['flight']} | {r['route']} "
                f"| {r['advance']} | {r['fare']} | {r['source']} "
                f"| [{evidence_host}]({r['evidence']}) |"
            )
        lines.append("")
        lines.append(f"*{len(rows)} verified flight quote(s) retrieved from the official APIx baseline cache.*")
    else:
        lines += [
            "No cached airfare quotes matched this URL or query.",
            "",
            "The APIx statistical reference dataset covers top high-density domestic sectors:",
            "DEL-BOM, DEL-BLR, BOM-BLR, DEL-CCU, BLR-HYD, DEL-HYD, MAA-DEL, BOM-GOI.",
        ]
    return "\n".join(lines)


# POST /fetch
@router.post(
    "/fetch",
    response_model=FetchResponse,
    dependencies=[Depends(verify_api_key)],
)
async def fetch_endpoint(req: FetchRequest):
    start = time.monotonic()

    if DEMO_MODE:
        content = _demo_snapshot_content(req)
        return FetchResponse(
            success=True,
            url=str(req.url),
            status_code=200,
            output_format=req.output_format,
            content=content,
            session_id=None,
            latency_ms=int((time.monotonic() - start) * 1000),
            retries_used=0,
        )

    logger.info(
        f"Received fetch request: {req.method} {req.url} (format: {req.output_format})"
    )

    # Determine session
    sid = req.session_id
    engine = "playwright" if req.render_js else "curl"
    session = None

    if sid:
        session = await session_manager.get_or_create(sid, engine)
    elif req.render_js:
        sid = None

    proxy_url = req.proxy.url if req.proxy else None

    result = await run_fetch(
        url=str(req.url),
        method=req.method.upper(),
        headers=req.headers,
        cookies=req.cookies,
        body=req.body,
        json_body=req.json_body,
        session=session,
        render_js=req.render_js,
        scroll=req.scroll,
        proxy_url=proxy_url,
        max_retries=req.max_retries,
        timeout=req.timeout,
        impersonate=req.impersonate,
        playwright_mgr=playwright_mgr,
        output_format=req.output_format,
        strip_links=req.strip_links,
        llm_api_key=req.llm_api_key,
        llm_provider=req.llm_provider,
        json_schema=req.json_schema,
        wait_for_selector=req.wait_for_selector,
        wait_timeout=req.wait_timeout,
        css_selector=req.css_selector,
        llm_model=req.llm_model,
        actions=req.actions,
        screenshot=req.screenshot,
        screenshot_format=req.screenshot_format,
        extraction_prompt=req.extraction_prompt,
        wait_until=req.wait_until,
        stealth=req.stealth,
    )

    latency_ms = int((time.monotonic() - start) * 1000)
    success = result.get("error") is None

    logger.info(f"Fetch request resolved in {latency_ms}ms with success={success}")

    return FetchResponse(
        success=success,
        url=result.get("final_url", str(req.url)),
        status_code=result.get("status_code", 0),
        output_format=req.output_format,
        content=result.get("content") or "",
        session_id=sid,
        latency_ms=latency_ms,
        retries_used=result.get("retries_used", 0),
        error=result.get("error"),
        error_message=result.get("error_message"),
        screenshot=result.get("screenshot"),
        timing=result.get("timing"),
    )


# GET /api/sessions
@router.get("/api/sessions", dependencies=[Depends(verify_api_key)])
async def list_sessions():
    return await session_manager.list_sessions()


# DELETE /api/sessions/{session_id}
@router.delete("/api/sessions/{session_id}", dependencies=[Depends(verify_api_key)])
async def delete_session(session_id: str):
    if not await session_manager.get_session_meta(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    await session_manager.delete_session(session_id)
    return {"deleted": True, "session_id": session_id}
