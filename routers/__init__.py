from .auth_routes import router as auth_router
from .dashboard_api import router as dashboard_router
from .export import router as export_router
from .fetch import router as fetch_router
from .health import router as health_router
from .index import router as index_router
from .routes import router as routes_router
from .scraper import router as scraper_router

__all__ = [
    "auth_router",
    "dashboard_router",
    "export_router",
    "fetch_router",
    "health_router",
    "index_router",
    "routes_router",
    "scraper_router",
]
