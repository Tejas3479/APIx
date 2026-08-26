# APIx Python Client

Official Python client for the **APIx Real-Time Airfare Price Index & Econometric Analytics Engine**.

## Installation

```bash
pip install apix-client
```

## Quickstart

```python
from apix_client import APIxClient

# Initialize client
client = APIxClient(base_url="http://localhost:8000")

# 1. Retrieve headline index statistics
stats = client.get_dashboard_stats()
print("National APIx Index:", stats["today_index"])

# 2. Retrieve national daily price index time series
series = client.get_daily_index(limit=30)
for point in series:
    print(f"{point['date']}: {point['index_value']} pts")

# 3. Calculate statistical materiality gap (under-reporting measurement)
materiality = client.get_materiality_gap()
print("Materiality Gap:", materiality["materiality_gap_pct"], "%")

# 4. Instant sector airfare survey & statutory decomposition
quotes = client.survey_route(route_id="DEL-BOM", advance_days=7)
for q in quotes:
    print(f"{q['carrier']}: Total ₹{q['total_fare']} | Base ₹{q['base_fare']} | Taxes ₹{q['taxes']}")
```
