# 🔌 APIx Integration & Developer Guide for NSO / RBI Economists

**Document Purpose:** Technical specification for integrating APIx real-time airfare index feeds into automated CPI compilation pipelines and macroeconomic forecasting models at MoSPI, NSO, and RBI.

---

## 1. Quick Connection Reference

- **Base URL (Local/Demo):** `http://localhost:8000`
- **Swagger Interactive Documentation:** `http://localhost:8000/docs`
- **OpenAPI JSON Spec:** `http://localhost:8000/openapi.json`
- **Authentication:** `Bearer <JWT_TOKEN>` or `x-api-key: <API_KEY>` header (in demo mode, `AUTH_DISABLED=true` allows direct queries).

---

## 2. Core Economic Data Endpoints

### 2.1 National Daily Index Series
```http
GET /api/v1/index/daily?from_date=2026-08-01&limit=30
```
**Response Format (JSON):**
```json
[
  {
    "id": "auto-2026-08-25",
    "index_date": "2026-08-25",
    "frequency": "daily",
    "index_value": 103.7,
    "base_period_value": 100.0,
    "methodology": "jevons_dgca_weighted",
    "route_coverage": 8,
    "quote_count": 160,
    "missing_routes": [],
    "is_demo_data": false,
    "computed_at": "2026-08-25T18:30:00Z"
  }
]
```

### 2.2 Weekly 7-Day Rolling Multilateral Index
```http
GET /api/v1/index/weekly?limit=12
```
*Purpose:* Smoothed trend eliminating day-of-week demand surges.

### 2.3 Official Monthly CPI Series
```http
GET /api/v1/index/monthly?limit=6
```
*Purpose:* Monthly chained indices matching NSO CPI release calendar.

### 2.4 Inflation Contribution Decomposition
```http
GET /api/v1/index/inflation-contribution
```
*Purpose:* Decomposes each route's percentage point contribution ($\Delta I_r \times w_r$) to national airfare inflation for RBI Monetary Policy analysis.

### 2.5 NSO Microdata Audit CSV Export
```http
GET /api/v1/export/csv
```
*Purpose:* Direct CSV stream containing individual flight price observations with statutory fee breakdown.

---

## 3. Statistical Software Integration Snippets

### 3.1 Python (Pandas / Statsmodels)
```python
import pandas as pd
import requests

# Fetch daily index series
url = "http://localhost:8000/api/v1/index/daily?limit=30"
response = requests.get(url, headers={"Accept": "application/json"})
data = response.json()

# Convert to DataFrame
df = pd.DataFrame(data)
df["index_date"] = pd.to_datetime(df["index_date"])
df.set_index("index_date", inplace=True)

# Calculate 7-day rolling inflation rate
df["inflation_pct_7d"] = df["index_value"].pct_change(7) * 100.0
print(df[["index_value", "inflation_pct_7d"]].tail(5))
```

### 3.2 R (Tidyverse / Tsibble)
```r
library(httr)
library(jsonlite)
library(dplyr)

res <- GET("http://localhost:8000/api/v1/index/daily?limit=30")
data <- fromJSON(content(res, as = "text"))

df <- as_tibble(data) %>%
  mutate(index_date = as.Date(index_date)) %>%
  arrange(index_date)

head(df)
```
