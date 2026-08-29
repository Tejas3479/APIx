"""Official Python Client for the APIx Real-Time Airfare Price Index & Analytics Engine."""

from typing import Any

import httpx


class APIxError(Exception):
    """Base exception for APIx client errors."""


class APIxClient:
    """Synchronous client for the APIx Real-Time Airfare Price Index API."""

    def __init__(
        self,
        api_key: str | None = None,
        bearer_token: str | None = None,
        base_url: str = "http://localhost:8000",
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = {}
        if api_key:
            self.headers["x-api-key"] = api_key
        if bearer_token:
            self.headers["Authorization"] = f"Bearer {bearer_token}"
        self.client = httpx.Client(
            base_url=self.base_url, headers=self.headers, timeout=60.0
        )

    def get_health(self) -> dict[str, Any]:
        """Check API and worker cluster health."""
        res = self.client.get("/api/health")
        self._check_response(res)
        return res.json()

    def get_daily_index(
        self, limit: int = 30, from_date: str | None = None, to_date: str | None = None
    ) -> list[dict[str, Any]]:
        """Retrieve national daily APIx price index time series."""
        params: dict[str, Any] = {"limit": limit}
        if from_date:
            params["from_date"] = from_date
        if to_date:
            params["to_date"] = to_date
        res = self.client.get("/api/v1/index/daily", params=params)
        self._check_response(res)
        return res.json()

    def get_route_index(self, route_id: str, limit: int = 30) -> list[dict[str, Any]]:
        """Retrieve per-sector daily sub-index time series."""
        res = self.client.get(
            f"/api/v1/index/route/{route_id.upper()}", params={"limit": limit}
        )
        self._check_response(res)
        return res.json()

    def get_materiality_gap(self) -> dict[str, Any]:
        """Retrieve econometric materiality gap between static monthly snapshot and continuous index."""
        res = self.client.get("/api/v1/index/materiality")
        self._check_response(res)
        return res.json()

    def get_dashboard_stats(self) -> dict[str, Any]:
        """Retrieve headline index KPI metrics and 24h trajectory."""
        res = self.client.get("/api/v1/dashboard/stats")
        self._check_response(res)
        return res.json()

    def survey_route(
        self, route_id: str = "DEL-BOM", advance_days: int = 7, force_live: bool = False
    ) -> list[dict[str, Any]]:
        """Survey real-time airfares for a city-pair and booking window with statutory breakdown."""
        res = self.client.post(
            "/api/v1/scraper/survey-instant",
            params={
                "route": route_id.upper(),
                "advance_days": advance_days,
                "force_live": force_live,
            },
        )
        self._check_response(res)
        return res.json()

    def list_routes(self) -> list[dict[str, Any]]:
        """List all city-pairs and DGCA passenger volume weights."""
        res = self.client.get("/api/v1/routes")
        self._check_response(res)
        return res.json()

    def fetch(self, url: str, **kwargs) -> dict[str, Any]:
        """Send a raw scrape request through the headless browser engine."""
        payload = {"url": url, **kwargs}
        res = self.client.post("/fetch", json=payload)
        self._check_response(res)
        return res.json()

    def _check_response(self, response: httpx.Response):
        if not response.is_success:
            try:
                detail = response.json().get("detail", response.text)
            except Exception:
                detail = response.text
            raise APIxError(f"HTTP {response.status_code}: {detail}")


class AsyncAPIxClient:
    """Asynchronous client for the APIx Real-Time Airfare Price Index API."""

    def __init__(
        self,
        api_key: str | None = None,
        bearer_token: str | None = None,
        base_url: str = "http://localhost:8000",
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = {}
        if api_key:
            self.headers["x-api-key"] = api_key
        if bearer_token:
            self.headers["Authorization"] = f"Bearer {bearer_token}"
        self.client = httpx.AsyncClient(
            base_url=self.base_url, headers=self.headers, timeout=60.0
        )

    async def get_daily_index(self, limit: int = 30) -> list[dict[str, Any]]:
        res = await self.client.get("/api/v1/index/daily", params={"limit": limit})
        self._check_response(res)
        return res.json()

    async def survey_route(
        self, route_id: str = "DEL-BOM", advance_days: int = 7
    ) -> list[dict[str, Any]]:
        res = await self.client.post(
            "/api/v1/scraper/survey-instant",
            params={"route": route_id.upper(), "advance_days": advance_days},
        )
        self._check_response(res)
        return res.json()

    def _check_response(self, response: httpx.Response):
        if not response.is_success:
            try:
                detail = response.json().get("detail", response.text)
            except Exception:
                detail = response.text
            raise APIxError(f"HTTP {response.status_code}: {detail}")
