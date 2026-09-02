# Contributing to APIx

Thank you for your interest in contributing! Here's how to get started.

---

## Development Setup

```bash
git clone https://github.com/Tejas3479/APIx.git
cd APIx

python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/Mac

pip install -r requirements.txt
playwright install chromium

# Run with SSRF disabled for local testing
$env:DISABLE_SSRF_CHECK = "true"
$env:API_KEYS = "devkey"
uvicorn app:app --reload
```

---

## Project Structure

```
APIx/
├── app.py              # FastAPI lifespan, routing, and middleware setup
├── database.py         # SQLAlchemy ORM models (SQLite/PostgreSQL)
├── models.py           # Pydantic data schemas & request/response validation
├── routers/            # Modular FastAPI endpoints (/index, /scraper, /routes, /export, /auth)
├── services/           # Econometric index engine, scrapers, and sanitization
├── requirements.txt    # Python dependencies
├── static/
│   ├── base.css        # Shared institutional design foundation
│   ├── scraper.html    # Scraper operations & browser pool telemetry
│   ├── landing.html    # MoSPI / NSO landing portal
│   ├── dashboard.html  # National airfare price index executive telemetry
│   ├── benchmark.html  # Route discovery & statutory tariff decomposition
│   ├── routes.html     # DGCA route basket studio & traffic weights
│   └── profile.html    # Statistical analyst profile & API bearer keys
└── docs/
    ├── API.md          # Full API endpoints reference
    ├── BACKTEST_REPORT.md # 30-day directional baseline validation
    └── SELF_HOSTING.md # Production self-hosting & security guide
```

---

## Code Style

- **Python**: Follow PEP 8. Use `async/await` for all I/O. No blocking calls in async context.
- **JavaScript**: Vanilla ES2022+. No frameworks. Keep functions small and focused.
- **CSS**: CSS variables for all colors/spacing. No inline styles in HTML (except dynamic values).

---

## Pull Request Guidelines

1. Fork the repo and create a branch: `git checkout -b feat/your-feature`
2. Keep commits atomic — one logical change per commit
3. Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`
4. Test your change manually before submitting
5. Update `CHANGELOG.md` under `[Unreleased]`
6. Open a PR with a clear description of what and why

---

## Reporting Issues

Please include:
- OS and Python version
- Steps to reproduce
- Expected vs actual behaviour
- Relevant logs (from `uvicorn` terminal output)
