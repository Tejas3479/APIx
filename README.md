<div align="center">

<h1>✈️ APIx — Real-Time Airfare Price Index</h1>
<p><strong>Automated High-Frequency Airfare Intelligence & Multilateral Index Platform for National Price Statistics</strong></p>
<p><em>Aligned with the CPI 2024=100 Base Revision, ILO/IMF CPI Manual (Ch. 10), and Eurostat Scanner Data Standards</em></p>

[![License: MIT](https://img.shields.io/badge/License-MIT-fa5d19.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-60a5fa.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-34d399.svg)](https://fastapi.tiangolo.com/)
[![Target: MoSPI / NSO](https://img.shields.io/badge/Agency-MoSPI%20%2F%20NSO-059669.svg)](https://mospi.gov.in)
[![Mathematical Index: GEKS-Törnqvist](https://img.shields.io/badge/Methodology-GEKS--T%C3%B6rnqvist-blueviolet.svg)](#-mathematical-methodology)
[![SIH 2026](https://img.shields.io/badge/Smart%20India%20Hackathon-2026-f59e0b.svg)](#)

</div>

---

## 🏆 Smart India Hackathon (SIH 2026)

**Problem Statement:** India's CPI 2024=100 base revision requires modernizing airfare price collection from manual mid-month snapshots to automated, continuous digital scraping — eliminating the **+18% to +25% statistical distortion** caused by airline yield management algorithms.

**Our Solution:** APIx automates multi-carrier fare collection across 8 high-density domestic routes and 5 advance-booking windows (T+1, T+7, T+15, T+30, T+45), computing chained **Jevons / GEKS-Törnqvist multilateral price indices** that meet international econometric standards.

---

## 🏛️ What is APIx?

**APIx (Airfare Price Index)** is an automated high-frequency data collection and index computation engine designed for the **Ministry of Statistics & Programme Implementation (MoSPI)** and the **National Statistical Office (NSO)**.

### The Real Statistical Gap
Under the new CPI 2024=100 base revision, statistical investigators collect airfare observations online. However, airlines employ hyper-dynamic yield algorithms where ticket prices fluctuate by **200%–500%** based on lead time, carrier market power, and booking dates. 

Sampling once a month on a single mid-month date fails to capture intra-month dynamic pricing, creating a **materiality distortion of +18% to +25%** in transport inflation metrics.

APIx solves this by implementing **continuous, multi-carrier digital scraping** across **5 advance booking horizons (T+1, T+7, T+15, T+30, T+45)** and computing a chained **GEKS-Törnqvist / Jevons multilateral index**.

---

### International Precedents for Automated Web Scraping in CPI
Global statistical agencies have already transitioned to automated web scraping and scanner data for volatile components like airfare:
- **Istat (Italy):** Automated scraping for transport and accommodation.
- **INE (Portugal) & IBGE (Brazil):** Web scraping pipelines for airfare indices.
- **Eurostat:** Scanner data and web scraping integration guidelines.
- **MIT Billion Prices Project:** Demonstrated the validity of high-frequency digital price collection over traditional manual sampling.
- **US BLS (Bureau of Labor Statistics):** Established statutory data feeds for passenger revenue. See our [Production Readiness Note](docs/PRODUCTION_READINESS.md) for India's path to Phase 2.

## ✨ Key Capabilities

| Module | Purpose | Method / Standard |
|:---|:---|:---|
| **GEKS-Törnqvist Index** | Chained multilateral price index | Eliminates chain drift; Eurostat / IMF CPI standard |
| **Jevons Elementary Aggregates** | Geometric mean of price relatives | ILO CPI Manual Ch. 10 |
| **Lead-Time Yield Curves** | Dynamic pricing measurement | Compares T+1, T+7, T+15, T+30, T+45 booking spreads |
| **Statutory Decomposition** | Isolates airline tariffs from fees | Decomposes Base Tariff, Fuel (YQ), UDF, ASF (₹200), GST |
| **Materiality Gap Analysis** | Quantifies legacy snapshot distortion | Compares mid-month static price vs continuous weighted index |
| **Sector Fare Heatmaps** | Festival & surge pricing detection | Color-intensity grid across top domestic city-pairs |
| **Gemini AI Anomaly Diagnosis** | LLM-powered fare spike analysis | Classifies surge as FESTIVAL_SEASONAL / CAPACITY_MONOPOLY / YIELD |
| **NSO Statistical Bulletin** | Official publication output | Formal bulletin JSON with methodology notes |

---

## ⚡ Solution Architecture

```mermaid
flowchart TD
    subgraph DataCollection["1. High-Frequency Scraping Layer"]
        GF["Google Flights via SerpAPI<br/>100% Domestic Coverage"]
        IX["Ixigo OTA<br/>Playwright Chromium"]
        SG["SpiceJet Direct<br/>Playwright Chromium (Probe)"]
        DGCA["DGCA Traffic Benchmarks<br/>Official Sector Volumes"]
    end

    subgraph Normalization["2. Normalization & Decomposition Engine"]
        DEC["Statutory Fare Decomposer<br/>Base Tariff vs Fuel, UDF, ASF, 5% GST"]
        WIN["Advance Window Tagging<br/>T+1 Emergency · T+7 Business · T+30 Planned"]
        DB[("SQLite / PostgreSQL<br/>FareQuote Table")]
    end

    subgraph MathematicalEngine["3. Econometric Index Construction"]
        JEV["Jevons Elementary Aggregates<br/>Geometric Mean of Relatives"]
        GEKS["Multilateral GEKS-Törnqvist<br/>Rolling Window Chaining"]
        DGCA_W["DGCA Traffic Weighting<br/>Sector Passenger Weights"]
    end

    subgraph Dashboards["4. Institutional Intelligence Outputs"]
        DASH["MoSPI / RBI National CPI Dashboard"]
        HEAT["Route x Date Price Surge Heatmaps"]
        ELAS["Lead-Time Elasticity Yield Curves"]
        GAP["Statistical Materiality Gap Diagnostic"]
    end

    DataCollection --> Normalization
    DEC --> DB
    WIN --> DB
    DB --> MathematicalEngine
    JEV --> DGCA_W
    GEKS --> DGCA_W
    DGCA_W --> Dashboards
```

---

## 🛤️ Route Basket (DGCA-Weighted)

APIx tracks India's **8 highest-density domestic air corridors**, weighted by DGCA monthly traffic data:

| Route | City Pair | DGCA Weight | Daily Flights |
|:---|:---|:---:|:---:|
| DEL-BOM | New Delhi ⇄ Mumbai | 22% | 110 |
| DEL-BLR | New Delhi ⇄ Bengaluru | 18% | 85 |
| BOM-BLR | Mumbai ⇄ Bengaluru | 14% | 65 |
| DEL-CCU | New Delhi ⇄ Kolkata | 12% | 50 |
| BLR-HYD | Bengaluru ⇄ Hyderabad | 10% | 45 |
| DEL-HYD | New Delhi ⇄ Hyderabad | 9% | 40 |
| MAA-DEL | Chennai ⇄ New Delhi | 8% | 35 |
| BOM-GOI | Mumbai ⇄ Goa | 7% | 30 |

---

## 📐 Mathematical Methodology

### Jevons Elementary Aggregate
Elementary price relatives within each city-pair are aggregated using the **geometric mean** (Jevons formula):

$$I_{\text{Jevons}} = \prod_{i=1}^{n} \left(\frac{p_i^t}{p_i^0}\right)^{1/n}$$

### GEKS-Törnqvist Multilateral Index
To eliminate chain drift across time windows, APIx constructs a **GEKS-Törnqvist matrix** across a rolling window of periods:

$$\text{GEKS}^{t/0} = \prod_{k=1}^{T} \left( P_T^{t/k} \cdot P_T^{k/0} \right)^{1/T}$$

Where $P_T^{t/k}$ is the bilateral Törnqvist index between periods $t$ and $k$, computed with DGCA traffic share weights.

---

## 🚀 Quickstart

### Prerequisites
- Python 3.11+
- Git

### Installation
```bash
# Clone the repository
git clone https://github.com/Tejas3479/APIx.git APIx
cd APIx

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers (if needed for JS rendering)
playwright install chromium
```

### Configuration
```bash
# Copy the example environment file
cp .env.example .env
# Edit .env with your API keys (optional — DEMO_MODE works without them)
```

### Run the Server
```bash
python -m uvicorn app:app --host 0.0.0.0 --port 8000
```

### Access the Application
| Page | URL |
|:---|:---|
| 🏠 Landing Portal | `http://localhost:8000/` |
| 📊 Analytics Dashboard | `http://localhost:8000/dashboard` |
| 🔍 Route Fare Survey | `http://localhost:8000/benchmark` |
| ⚙️ Route Basket Config | `http://localhost:8000/routes` |
| 🖥️ Scraper Telemetry | `http://localhost:8000/scraper` |
| 📚 Interactive API Docs | `http://localhost:8000/docs` |

> **Demo Mode:** APIx ships with `DEMO_MODE=true` and a pre-seeded dataset of ~4,800 realistic fare quotes across 30 days. All dashboards and indices work immediately — no API keys required.

### Docker Deployment
```bash
docker compose up --build
# App available at http://localhost:8000
```

---

## 📡 API Endpoints Reference

### Index & Analytics
| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/v1/index/daily` | Retrieve daily APIx time series |
| `GET` | `/api/v1/index/route/{id}` | Sub-index history for a specific city-pair |
| `GET` | `/api/v1/index/materiality` | Statistical materiality gap analysis |
| `POST` | `/api/v1/index/compute` | Trigger on-demand index recomputation |
| `GET` | `/api/v1/index/bulletin` | Generate NSO statistical bulletin |
| `POST` | `/api/v1/index/ai-diagnose` | Gemini AI fare anomaly analysis |

### Dashboard Visualizations
| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/v1/dashboard/stats` | Headline KPI cards (index, delta, quotes) |
| `GET` | `/api/v1/dashboard/heatmap` | Route × Date fare matrix (14 days) |
| `GET` | `/api/v1/dashboard/elasticity` | Lead-time yield curve data |
| `GET` | `/api/v1/dashboard/carriers` | Carrier pricing comparison |

### Scraper & Survey
| Method | Endpoint | Description |
|:---|:---|:---|
| `POST` | `/api/v1/scraper/run` | Dispatch async batch scrape job |
| `POST` | `/api/v1/scraper/survey-instant` | Synchronous single-route live survey |
| `GET` | `/api/v1/scraper/jobs` | Batch scrape execution history |

### Route Basket Configuration
| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/v1/routes` | List all active city-pairs with DGCA weights |
| `POST` | `/api/v1/routes` | Add new sector to the index basket |
| `PUT` | `/api/v1/routes/{id}` | Update sector weight or active status |
| `DELETE` | `/api/v1/routes/{id}` | Remove route from basket |

### Authentication
| Method | Endpoint | Description |
|:---|:---|:---|
| `POST` | `/auth/register` | Register new officer account |
| `POST` | `/auth/login` | JWT token authentication |
| `POST` | `/auth/demo-login` | One-click demo access |
| `GET` | `/auth/me` | Current user profile |

---

## 🔧 Tech Stack

| Layer | Technology |
|:---|:---|
| **Backend** | Python 3.11+ · FastAPI · Uvicorn |
| **Database** | SQLite (aiosqlite) / PostgreSQL |
| **ORM** | SQLModel · SQLAlchemy 2.0 |
| **Scraping** | Playwright (Chromium) · curl-cffi · SerpAPI |
| **Caching** | Redis (with fakeredis fallback) |
| **AI/ML** | Google Gemini 2.0 Flash |
| **Math** | NumPy · SciPy (Jevons + GEKS-Törnqvist) |
| **Auth** | PyJWT · Argon2 (pwdlib) |
| **Frontend** | Vanilla HTML/CSS/JS · Chart.js |
| **Deployment** | Docker · docker-compose |

---

## ⚖️ Ethical Scraping Policy
APIx adheres strictly to ethical statistical data acquisition standards:
1. **Passive Stealth Only**: Standard headless browser configuration, TLS finger-printing matching modern Chrome, and standard viewport headers.
2. **Zero CAPTCHA Defeat**: Active challenge bypassing is explicitly disabled (`CAPTCHA_SOLVING_ENABLED=false`).
3. **Rate Limiting & Politeness**: Requests to carrier portals observe polite intervals to avoid server load.

---

## 📁 Project Structure

```
APIx/
├── app.py                     # FastAPI application entry point
├── auth.py                    # JWT + API key verification
├── database.py                # SQLModel tables + async engine
├── models.py                  # Pydantic request/response schemas
├── routers/                   # API route handlers
│   ├── auth_routes.py         # Authentication endpoints
│   ├── dashboard_api.py       # Dashboard KPI endpoints
│   ├── fetch.py               # Web fetch endpoint
│   ├── health.py              # Health check
│   ├── index.py               # Index computation endpoints
│   ├── routes.py              # Route basket CRUD
│   └── scraper.py             # Scrape job triggers
├── services/                  # Business logic layer
│   ├── index_engine.py        # Jevons + GEKS-Törnqvist math
│   ├── search_orchestrator.py # Fare survey coordination
│   ├── price_extractor.py     # Statutory fare decomposition
│   ├── bulletin_generator.py  # NSO bulletin generation
│   ├── gemini_grounding.py    # AI anomaly analysis
│   ├── fetch_engine.py        # Core fetch engine
│   └── ...                    # Browser, session, SSRF, etc.
├── static/                    # Frontend pages
│   ├── landing.html           # Marketing landing page
│   ├── dashboard.html         # Analytics dashboard
│   ├── benchmark.html         # Route fare survey
│   ├── routes.html            # Route basket config
│   └── base.css               # Design system
├── data/                      # Seed data files
│   ├── fare_demo_cache.json   # Pre-seeded 30-day fare quotes
│   ├── route_basket.json      # 8-route DGCA basket
│   └── dgca_benchmark.json    # Official DGCA benchmarks
├── sdks/                      # Client SDKs
│   ├── node/                  # Node.js/TypeScript SDK
│   └── python/                # Python SDK
├── Dockerfile                 # Container build
├── docker-compose.yml         # Multi-service deployment
└── requirements.txt           # Python dependencies
```

---

<div align="center">
  <sub>Developed for <strong>Smart India Hackathon (SIH 2026)</strong> | National Statistical Office (NSO) / MoSPI</sub>
</div>
