# Changelog

All notable changes to APIx are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Changed
- **UX & Spatial Layout Overhaul** — standardized design tokens across `base.css` (`--space-*`, `--card-*`, `--btn-*`), unified page content width to 1280px with responsive padding, rescaled KPI metrics to 28px, decluttered hero and heatmap headers, separated Carrier Market Share and Statistical Materiality Gap into distinct focused cards, widened route columns in sector inflation breakdown, and improved cross-page input/button touch targets.

### Removed
- **Orphaned `static/index.html`** — deleted redundant legacy clone of `scraper.html` and updated all documentation references.
- **Multi-page crawl pipeline** — removed `routers/crawl.py`, `services/crawl_manager.py`, `worker.py` (ARQ background worker), the `CrawlJob`/`BatchJob`/`Destination`/`ScheduledCrawl` tables, `arq`/`croniter`/`pinecone-client`/`weaviate-client`/`supabase` dependencies, the Docker `worker` service, and the dead front-end bundles. The single-URL anti-bot fetch engine (`/fetch`) that powers background batch scraping is retained. Migration `9bdeb31f1488` drops the crawl tables.
- **Legacy branding** — remaining legacy references scrubbed from UI and docs.

### Fixed
- JWT secret handling: missing/whitespace `JWT_SECRET_KEY` now fails fast instead of silently falling back to an insecure default.

### Security
- JWT enforcement on core endpoints. When `AUTH_DISABLED=true` (dev/demo) requests pass through anonymously; otherwise a valid Bearer JWT is mandatory.

---

## [2.0.0] — 2026-08-14

### Major Release
Transformed APIx into a specialized Airfare Price Index engine.

### Added
- **Airfare Price Index engine** with Jevons + GEKS-Törnqvist multilateral index computation
- **8-route DGCA-weighted basket** with CRUD management
- **SerpAPI Google Flights integration** with demo cache fallback
- **Statutory fare decomposition** (Base, Fuel YQ, UDF, ASF, GST)
- **Real-time dashboard** with index time series, heatmaps, elasticity curves
- **Statistical materiality gap analysis**
- **Gemini AI fare anomaly diagnosis**
- **NSO statistical bulletin generator**
- **Premium custom frontend** with dark theme, animations, interactive pipeline
- **JWT + API key dual authentication** with demo bypass
- **Background batch scraping** with job tracking
- **SSRF protection**, security headers, rate limiting, sensitive log filtering
- **Docker + docker-compose deployment**
- **Python and Node.js SDKs**

---

## [1.2.0] — 2026-07-28

### Added
- **AI Vector Pipelines** — Push embeddings natively to Pinecone, Weaviate, and Supabase via new `Destination` configurations.
- **Scheduled Crawls** — Schedule recurring extractions using `croniter` and the ARQ background worker.
- **Client SDKs** — Official Python and Node.js (TypeScript) SDKs for easy integration.
- **Captcha Solving** — Integration with 2Captcha and CapSolver for bypassing complex anti-bot challenges during scraping.
- **Database Backend** — Shifted core states (Jobs, API Keys, Proxies, Destinations) to SQLite via SQLModel/SQLAlchemy.
- **API Key DB Support** — `verify_api_key` now checks both `VALID_KEYS` environment variable and SQLite `ApiKey` table.
- **Docker Image CI** — Automated Docker build testing in GitHub Actions.

### Changed
- Replaced legacy `SESSIONS_FILE` and `CRAWLS_FILE` disk writes with proper SQLite database backend.
- Updated `worker.py` and `app.py` with Python 3.9+ type annotations (`dict` instead of `Dict`) for `ruff` compliance.
- Dockerfile now runs `apt-get` update prior to `playwright install-deps` to fix broken package cache.

---

## [1.1.0] — 2026-07-22

### Added
- **Environment Variables Panel** — Save named API keys (Production, Test, Staging) in sidebar. Chip UI for instant switching. Masked display (`myke••••3x9a`). Persisted in `localStorage`.
- **Request Timing Waterfall** — Real server-side timing breakdown below meta bar: Security / Connect / TTFB / Processing phases. Proportional colored segments with hover tooltips and ms legend.
- **Request History** — Last 20 requests stored in `localStorage`. Sidebar panel with click-to-replay. Keyboard accessible (Enter/Space to replay). Clear button with confirmation.
- **Keyboard Shortcuts** — `Ctrl+Enter` / `Cmd+Enter` sends request. `Ctrl+K` / `Cmd+K` focuses URL bar. Works cross-platform.
- **Preview Theme Toggle** — Light/dark background switcher above iframe preview. State persists within session.
- **Visibility-aware Polling** — Health checks and session refresh pause when the browser tab is hidden. Resumes on tab focus.
- **Crawl extraction prompt** — Separate `<textarea>` for the crawl section, no longer shared with request builder.
- **XSS-safe JSON tree** — `renderJsonTree()` now HTML-escapes all keys and values via `escapeHtml()` before `innerHTML`.
- **SEO/A11y improvements** — `<title>`, `<meta name="description">`, SVG favicon, `<h1 class="sr-only">`, `prefers-reduced-motion` media query, `focus-visible` rings on all interactive elements.
- **JetBrains Mono font** — Code and monospace elements now use JetBrains Mono.
- **Timing fields in API response** — `FetchResponse` now includes a `timing` object with `security_ms`, `connect_ms`, `ttfb_ms`, `transfer_ms`, `total_ms`.

### Fixed
- **CRITICAL** — CORS misconfiguration: `allow_origins=["*"]` + `allow_credentials=True` is invalid per spec. Fixed to `allow_credentials=False`.
- **CRITICAL** — `is_ssrf_safe()` was synchronous DNS resolution inside an async route, blocking the event loop. Converted to `async def` using `loop.run_in_executor()`.
- **CRITICAL** — Race condition on `playwright_mgr.slots_free` counter. Added `asyncio.Lock` (`_slots_lock`) to guard all read-modify-write operations.
- **CRITICAL** — `import uuid` and `import base64` were mid-file (line 856+). Moved to top-of-file import block.
- **CRITICAL** — Duplicate `logging.basicConfig()` call in `fetcher.py`. Removed — `app.py` is the single source of truth.
- **CRITICAL** — `datetime.utcnow()` deprecated in Python 3.12+. All instances replaced with `datetime.now(timezone.utc)`.
- **HIGH** — Anthropic model `claude-3-haiku-20240307` deprecated. Updated to `claude-3-5-haiku-20241022`.
- **HIGH** — `cleanup_loop` did not handle `asyncio.CancelledError` on shutdown. Wrapped in `try/except asyncio.CancelledError`.
- **HIGH** — `MAX_SESSIONS` eviction used `>` instead of `>=`, allowing one extra session beyond the limit.
- **HIGH** — Crawl section shared `#extraction-prompt-textarea` with the request builder. Now uses dedicated `#crawl-extraction-prompt`.
