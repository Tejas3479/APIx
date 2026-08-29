"""APIx Pydantic schemas and request/response models.

Defines strict type models, JSON schema examples, and validation rules
for Route Basket Management, Scraper Jobs, Econometric Indices, and AI Diagnostics.
"""

from datetime import date, datetime
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

# ALLOWED LLM MODELS ALLOWLIST
ALLOWED_LLM_MODELS = {
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.7-flash",
    "gemini-3.6-flash",
    "gemini-3.1-pro-preview",
    "gpt-4o",
    "gpt-4o-mini",
    "claude-3-5-sonnet-20241022",
}


# ===== INFRASTRUCTURE & FETCH SCHEMAS =====


class ProxyConfig(BaseModel):
    url: str = Field(
        ...,
        max_length=2000,
        description="Full proxy URL e.g. http://user:pass@host:port",
    )
    country_code: str | None = Field(None, max_length=10)

    @field_validator("url")
    @classmethod
    def validate_proxy_url(cls, v: str) -> str:
        v_str = v.strip()
        parsed = urlparse(v_str)
        if parsed.scheme.lower() not in (
            "http",
            "https",
            "socks5",
            "socks4",
            "socks5h",
        ):
            raise ValueError("Proxy URL scheme must be http, https, socks5, or socks4")
        if not parsed.netloc:
            raise ValueError("Invalid proxy URL format")
        return v_str


class ActionConfig(BaseModel):
    type: Literal["click", "wait", "scroll", "fill", "hover", "press"]
    selector: str | None = Field(None, max_length=500)
    value: str | None = Field(None, max_length=2000)
    duration: int | None = Field(None, ge=0, le=60)


class FetchRequest(BaseModel):
    url: HttpUrl
    method: str = Field("GET", max_length=10)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    body: str | None = Field(None, max_length=10_000_000)
    json_body: dict | None = None
    session_id: str | None = Field(None, max_length=100)
    render_js: bool = False
    scroll: bool = False
    output_format: Literal["html", "markdown", "structured"] = "html"
    strip_links: bool = False
    proxy: ProxyConfig | None = None
    max_retries: int = Field(2, ge=0, le=5)
    timeout: int = Field(30, ge=1, le=120)
    impersonate: str = Field("chrome120", max_length=50)
    llm_api_key: str | None = Field(None, max_length=500)
    llm_provider: Literal["openai", "anthropic", "gemini"] = "gemini"
    json_schema: dict | None = None
    wait_for_selector: str | None = Field(None, max_length=500)
    wait_timeout: int = Field(30, ge=1, le=120)
    css_selector: str | None = Field(None, max_length=500)
    llm_model: str | None = Field(None, max_length=100)
    actions: list[ActionConfig] | None = Field(None, max_length=20)
    screenshot: bool = False
    screenshot_format: Literal["png", "jpeg"] = "png"
    extraction_prompt: str | None = Field(None, max_length=5000)
    wait_until: Literal["domcontentloaded", "load", "networkidle"] = "networkidle"
    stealth: bool = True

    @field_validator("url")
    @classmethod
    def validate_url_scheme(cls, v: HttpUrl) -> HttpUrl:
        scheme = v.scheme.lower() if v.scheme else ""
        if scheme not in ("http", "https"):
            raise ValueError("Target URL scheme must be http or https")
        return v

    @field_validator("llm_model")
    @classmethod
    def validate_llm_model(cls, v: str | None) -> str | None:
        if v is not None and v.strip():
            model_clean = v.strip().lower()
            if model_clean not in ALLOWED_LLM_MODELS:
                raise ValueError(
                    f"Model '{v}' is not in the allowed models list: {sorted(ALLOWED_LLM_MODELS)}"
                )
            return model_clean
        return None


class FetchResponse(BaseModel):
    success: bool
    url: str
    status_code: int
    output_format: str
    content: str | dict
    session_id: str | None
    latency_ms: int
    retries_used: int
    error: str | None = None
    error_message: str | None = None
    screenshot: str | None = None
    timing: dict | None = None


class ProxyCreate(BaseModel):
    url: str


# ===== AUTH & USER SCHEMAS =====


class UserCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., max_length=200)
    password: str = Field(..., min_length=8, max_length=100)
    department: str | None = Field(None, max_length=200)
    organization: str | None = Field(None, max_length=200)


class UserLogin(BaseModel):
    email: str
    password: str


class DemoLoginRequest(BaseModel):
    """One-click simulated statistical officer profile for MoSPI/RBI demonstration."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "name": "Dr. S. K. Mukherjee",
                    "email": "sk.mukherjee@mospi.gov.in",
                    "department": "National Statistical Office (Price Statistics)",
                    "role": "senior_officer",
                }
            ]
        }
    )

    name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., max_length=200)
    department: str | None = Field(None, max_length=200)
    role: str = Field(default="senior_officer")


class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    department: str | None
    organization: str | None
    role: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ===== APIx: ROUTE BASKET SCHEMAS =====


class RouteBasketConfig(BaseModel):
    id: str  # "DEL-BOM"
    origin_iata: str
    origin_city: str
    destination_iata: str
    destination_city: str
    dgca_weight: float
    daily_flights: int | None = None
    is_active: bool = True
    created_at: datetime


class RouteBasketCreate(BaseModel):
    origin_iata: str = Field(..., min_length=3, max_length=3, description="Origin 3-letter IATA (e.g. DEL)")
    origin_city: str = Field(..., min_length=2, max_length=100, description="City name (e.g. New Delhi)")
    destination_iata: str = Field(..., min_length=3, max_length=3, description="Destination 3-letter IATA (e.g. BOM)")
    destination_city: str = Field(..., min_length=2, max_length=100, description="City name (e.g. Mumbai)")
    dgca_weight: float = Field(..., ge=0.0, le=1.0, description="Official DGCA passenger volume weight (0.0 to 1.0)")
    daily_flights: int | None = Field(None, ge=0, description="Daily scheduled direct flights")

    @field_validator("origin_iata", "destination_iata")
    @classmethod
    def uppercase_iata(cls, v: str) -> str:
        return v.strip().upper()


class RouteBasketUpdate(BaseModel):
    dgca_weight: float | None = Field(None, ge=0.0, le=1.0)
    daily_flights: int | None = Field(None, ge=0)
    is_active: bool | None = None


# ===== APIx: FARE QUOTE SCHEMAS =====


class FareQuoteResponse(BaseModel):
    id: str
    route_id: str
    carrier_code: str
    carrier_name: str
    flight_number: str | None = None
    departure_date: date
    departure_time: str | None = None
    arrival_time: str | None = None
    duration_minutes: int | None = None
    scrape_date: date
    advance_days: int
    base_fare: float
    fuel_surcharge: float = 0.0
    udf: float = 0.0
    asf: float = 200.0
    gst: float = 0.0
    convenience_fee: float = 0.0
    total_fare: float
    fare_class: str | None = None
    cabin_class: str = "economy"
    stops: int = 0
    source_platform: str
    source_url: str | None = None
    is_sold_out: bool = False
    is_demo_data: bool = False
    scraped_at: datetime


# ===== APIx: SCRAPER & SCHEDULER SCHEMAS =====


class ScrapeRequest(BaseModel):
    """Trigger an on-demand scrape survey for specific routes and advance purchase windows."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "routes": ["DEL-BOM", "DEL-BLR"],
                    "advance_days": [1, 7, 15, 30],
                    "cabin_class": "economy",
                }
            ]
        }
    )

    routes: list[str] = Field(default=["DEL-BOM"])
    advance_days: list[int] = Field(default=[1, 7, 15, 30, 45])
    cabin_class: str = "economy"
    force_live: bool = False


class ScrapeJobResponse(BaseModel):
    id: str
    job_type: str
    status: str
    routes_targeted: int
    routes_completed: int
    quotes_collected: int
    errors: list[dict[str, Any]] = []
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime


# ===== APIx: INDEX ENGINE & STATISTICAL SCHEMAS =====


class IndexQueryParams(BaseModel):
    from_date: date | None = None
    to_date: date | None = None
    route_id: str | None = None
    frequency: Literal["daily", "weekly", "monthly"] = "daily"
    methodology: Literal["jevons", "geks_tornqvist"] = "jevons"


class DailyIndexResponse(BaseModel):
    id: str
    index_date: date
    frequency: str
    index_value: float
    base_period_value: float
    methodology: str
    route_coverage: int
    quote_count: int
    missing_routes: list[str] = []
    std_error: float | None = None
    ci_lower_95: float | None = None
    ci_upper_95: float | None = None
    quality_tier: str = "HIGH"
    is_demo_data: bool = False
    computed_at: datetime


class RouteHeatmapPoint(BaseModel):
    route_id: str
    date: date
    avg_fare: float
    median_fare: float
    min_fare: float
    max_fare: float
    quote_count: int
    intensity_level: Literal["low", "mid", "high", "surge"]


class LeadTimeElasticityCurve(BaseModel):
    route_id: str
    route_name: str
    window_averages: dict[int, float]
    surge_multiplier: float


class MaterialityGapResponse(BaseModel):
    month: str
    single_snapshot_fare: float
    daily_index_avg_fare: float
    materiality_gap_pct: float
    under_reporting_amount_inr: float
    analysis: str
    nso_snapshot_day: int | None = None
    nso_snapshot_index: float | None = None
    continuous_index: float | None = None
    materiality_gap_pts: float | None = None


class AtfCrossValidationResponse(BaseModel):
    correlation_coefficient: float
    r_squared: float
    tracking_verdict: str
    total_months_evaluated: int
    latest_atf_inr_per_kl: float
    latest_extracted_fuel_surcharge_avg: float
    economic_interpretation: str
    series_comparison: list[dict[str, Any]]


class CarrierMarketShareItem(BaseModel):
    carrier_code: str
    carrier_name: str
    market_share_pct: float
    avg_fare_inr: float
    brand_color: str
    active_fleet_count: int | None = None


class DgcaBenchmarkResponse(BaseModel):
    id: str
    route_id: str
    year_month: str
    dgca_avg_fare: float
    passenger_load_factor_pct: float
    total_passengers_monthly: int
    source_bulletin: str
    created_at: datetime


class AiDiagnoseRequest(BaseModel):
    route_id: str | None = None
    days: int | None = None
    current_avg_fare: float | None = None
    benchmark_fare: float | None = None


class FareAnomalyReportCreate(BaseModel):
    route_id: str
    survey_date: date
    advance_days: int
    surge_multiplier: float
    diagnosis_text: str
    ai_model: str = "gemini-3.7-flash"


class FareAnomalyReportResponse(BaseModel):
    id: str
    route_id: str
    survey_date: date
    advance_days: int
    surge_multiplier: float
    diagnosis_text: str
    ai_model: str
    flagged_by: str
    is_verified: bool
    created_at: datetime


class DashboardStatsResponse(BaseModel):
    today_index: float
    index_change_pct_24h: float
    active_routes_count: int
    total_quotes_count: int
    avg_fare_today: float
    lead_time_spread_ratio: float
    last_scrape_time: datetime | None = None
    playwright_pool_status: str
