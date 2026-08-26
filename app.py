import asyncio
import os
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from database import init_db
from fetcher import (
    SensitiveDataFilter,
    playwright_mgr,
    session_manager,
)
from routers import (
    auth_router,
    dashboard_router,
    export_router,
    fetch_router,
    health_router,
    index_router,
    routes_router,
    scraper_router,
)
from services.scrape_scheduler import run_scheduler_loop
from services.session_manager import redis_client

# Set up logging configuration with SensitiveDataFilter
logger = logging.getLogger("apix.app")
logger.addFilter(SensitiveDataFilter())

log_handler = logging.StreamHandler()
log_handler.addFilter(SensitiveDataFilter())
log_handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
)
logging.basicConfig(level=logging.INFO, handlers=[log_handler])

# RATE LIMITER & RESOURCE LIMIT CONSTANTS
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
MAX_BODY_SIZE_BYTES = int(
    os.getenv("MAX_REQUEST_BODY_SIZE", str(10 * 1024 * 1024))
)  # 10MB


class RateLimiter:
    """
    In-memory sliding window rate limiter per client IP or API key.
    """

    def __init__(
        self,
        requests_per_minute: int = RATE_LIMIT_PER_MINUTE,
        window_seconds: int = 60,
    ):
        self.rpm = requests_per_minute
        self.window = window_seconds

    async def check(self, key: str) -> tuple[bool, int, int]:
        if self.rpm <= 0:
            return False, 9999, 0

        now = time.time()
        cutoff = now - self.window
        redis_key = f"rate_limit:{key}"

        try:
            async with redis_client.pipeline(transaction=True) as pipe:
                pipe.zremrangebyscore(redis_key, 0, cutoff)
                pipe.zadd(redis_key, {str(now): now})
                pipe.zcard(redis_key)
                pipe.expire(redis_key, self.window)
                results = await pipe.execute()
        except Exception as e:
            logger.warning(f"Redis rate limiter failed: {e}")
            return False, 9999, 0

        count = results[2]
        if count > self.rpm:
            return True, 0, self.window

        remaining = self.rpm - count
        return False, remaining, self.window

    async def cleanup_loop(self):
        try:
            while True:
                await asyncio.sleep(86400)
        except asyncio.CancelledError:
            pass


rate_limiter = RateLimiter()

# LIFESPAN
_cleanup_task: asyncio.Task | None = None
_rate_limit_task: asyncio.Task | None = None
_scheduler_task: asyncio.Task | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _cleanup_task, _rate_limit_task, _scheduler_task
    # STARTUP
    try:
        await init_db()

        # Seed initial route basket and demo historical fare data
        from services.airfare_seeder import seed_airfare_database

        await seed_airfare_database()

        await playwright_mgr.initialize()
    except Exception as e:
        logger.warning(
            f"Playwright pre-initialization skipped on startup ({e}). Will initialize lazily when JS rendering is requested."
        )

    _cleanup_task = asyncio.create_task(session_manager.cleanup_loop())
    _rate_limit_task = asyncio.create_task(rate_limiter.cleanup_loop())
    _scheduler_task = asyncio.create_task(run_scheduler_loop())
    logger.info(
        "APIx application started, engine initialized, rate limiter and automated scheduler active."
    )
    yield
    # SHUTDOWN
    if _cleanup_task:
        _cleanup_task.cancel()
    if _rate_limit_task:
        _rate_limit_task.cancel()
    if _scheduler_task:
        _scheduler_task.cancel()
    await session_manager.close_all()
    await playwright_mgr.close()
    logger.info("APIx application shutdown complete.")


# APP INIT
app_kwargs = {
    "title": "APIx — Real-Time Airfare Price Index API",
    "description": (
        "National Statistical Office (NSO) / MoSPI Real-Time Airfare Price Index Platform. "
        "Aggregates high-frequency multi-carrier domestic fares, decomposes statutory base tariffs "
        "from airport taxes, and constructs multilateral GEKS-Törnqvist price indices."
    ),
    "version": "1.0.0",
    "lifespan": lifespan,
}
if os.getenv("ENV", "development") == "production":
    app_kwargs["docs_url"] = None
    app_kwargs["redoc_url"] = None
    app_kwargs["openapi_url"] = None

app = FastAPI(**app_kwargs)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:8000,http://localhost:3000,http://127.0.0.1:8000").split(","),
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    allow_credentials=False,
)


# Security headers middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)

    # Prevent MIME-type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Clickjacking protection
    response.headers["X-Frame-Options"] = "DENY"

    # Disable legacy XSS filter (modern CSP is the proper defense)
    response.headers["X-XSS-Protection"] = "0"

    # Limit referrer information leaked to external sites
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Cross-Origin isolation headers
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

    # Restrict browser features the dashboard does not need
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=()"
    )

    # Content Security Policy — allows only the exact CDN origins the dashboard uses
    # Plus any deploy origin(s) the operator allows for API calls via CSP_CONNECT_SRC.
    connect_extra = os.getenv("CSP_CONNECT_SRC", "")
    connect_src = "connect-src 'self'" + (
        " " + " ".join(x.strip() for x in connect_extra.split(",") if x.strip())
        if connect_extra
        else ""
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        f"{connect_src}; "
        "frame-src 'self'; "
        "frame-ancestors 'self'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    # HSTS — enforce HTTPS in production only (avoids breaking local dev over HTTP)
    if os.getenv("ENV", "development") == "production":
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )

    return response


@app.middleware("http")
async def resource_limits_middleware(request: Request, call_next):
    # Payload size limit check
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_BODY_SIZE_BYTES:
                client_ip = request.client.host if request.client else "127.0.0.1"
                logger.warning(
                    f"Rejected oversized payload ({content_length} bytes) from {client_ip}"
                )
                return JSONResponse(
                    status_code=413,
                    content={
                        "detail": f"Request payload size exceeds maximum server limit of {MAX_BODY_SIZE_BYTES // (1024 * 1024)}MB."
                    },
                )
        except ValueError:
            pass

    path = request.url.path
    # Exempt health check and static asset requests from rate limiting
    if (
        path == "/api/health"
        or path.startswith("/static")
        or ("." in path.split("/")[-1] and not path.startswith("/api"))
    ):
        return await call_next(request)

    forwarded = request.headers.get("x-forwarded-for")
    client_ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "127.0.0.1")
    )
    api_key = request.headers.get("x-api-key") or ""
    client_key = f"key:{api_key}" if api_key else f"ip:{client_ip}"

    is_limited, remaining, reset_sec = await rate_limiter.check(client_key)
    if is_limited:
        logger.warning(f"Rate limit exceeded for client: {client_key} on path {path}")
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests. Rate limit exceeded."},
            headers={
                "X-RateLimit-Limit": str(rate_limiter.rpm),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset_sec),
                "Retry-After": str(reset_sec),
            },
        )

    response = await call_next(request)
    if rate_limiter.rpm > 0:
        response.headers["X-RateLimit-Limit"] = str(rate_limiter.rpm)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_sec)
    return response


# Include Routers
app.include_router(health_router)
app.include_router(fetch_router)
app.include_router(auth_router)
app.include_router(scraper_router)
app.include_router(routes_router)
app.include_router(index_router)
app.include_router(dashboard_router)
app.include_router(export_router)


# Flagship Root Route: National Statutory Portal Landing Page
@app.get("/", response_class=FileResponse, include_in_schema=False)
async def serve_root():
    return FileResponse("static/landing.html")


@app.get("/benchmark", response_class=FileResponse, include_in_schema=False)
async def serve_benchmark():
    return FileResponse("static/benchmark.html")


@app.get("/dashboard", response_class=FileResponse, include_in_schema=False)
async def serve_dashboard():
    return FileResponse("static/dashboard.html")


@app.get("/routes", response_class=FileResponse, include_in_schema=False)
async def serve_routes():
    return FileResponse("static/routes.html")


@app.get("/scraper", response_class=FileResponse, include_in_schema=False)
async def serve_scraper():
    return FileResponse("static/index.html")


@app.get("/profile", response_class=FileResponse, include_in_schema=False)
async def serve_profile():
    return FileResponse("static/profile.html")


# Mount static files
if os.path.isdir("static"):
    app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
