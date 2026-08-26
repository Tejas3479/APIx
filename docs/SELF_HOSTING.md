# Self-Hosting Guide

This guide covers running APIx on your own infrastructure — locally or on a cloud VPS.

---

## 🏗️ Deployment Architecture

```mermaid
flowchart LR
    subgraph Public["Public Network"]
        CLIENT["Web Browser / Statistical Officer / Macroeconomic Pipeline"]
        NGINX["Nginx Reverse Proxy (HTTPS 443)"]
    end

    subgraph Host["Server Environment (VPS / Container)"]
        CONTAINER["APIx Engine Process (:8000)"]
        
        subgraph Inside["Internal Components"]
            FASTAPI["FastAPI Application"]
            INDEX["Jevons & GEKS-Törnqvist Engine"]
            DECOMP["Statutory Fare Decomposer"]
            SEEDER["Route & Quote Database Seeder"]
            PW["Playwright Chromium Stealth Pool"]
            SESSIONS["Redis Session & Cache Store"]
        end
    end

    CLIENT -->|HTTPS| NGINX
    NGINX -->|Proxy Pass :8000| CONTAINER
    CONTAINER --> FASTAPI
    FASTAPI --> INDEX
    FASTAPI --> DECOMP
    FASTAPI --> SEEDER
    FASTAPI --> PW
    FASTAPI --> SESSIONS
```

---

## Option 1: Local Python

### Prerequisites
- Python 3.11+
- pip

### Steps

```bash
# 1. Clone
git clone https://github.com/Tejas3479/APIx.git
cd APIx

# 2. Create virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / Mac
# source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install Playwright browser
playwright install chromium
# Linux only:
# playwright install-deps chromium

# 5. Set environment variables and run the API
# Windows PowerShell:
$env:API_KEYS = "your-secret-key"
# Linux/Mac:
# export API_KEYS="your-secret-key"

# 6. Launch the server (reference data seeds automatically on first run)
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

---

## Option 2: VPS / Cloud VM (Ubuntu 22.04 / 24.04)

### Recommended specs
- 2 CPU, 4 GB RAM minimum for production workloads (Playwright & parallel multi-source querying)

### Setup

```bash
# Install Python 3.11 and Redis
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip git redis-server

# Clone and install
git clone https://github.com/Tejas3479/APIx.git
cd APIx
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
playwright install-deps chromium

# Run API with systemd (persistent)
sudo tee /etc/systemd/system/APIx-api.service << EOF
[Unit]
Description=APIx Airfare Price Index & Analytics Platform
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$PWD
Environment=API_KEYS=your-secret-key
Environment=MAX_PLAYWRIGHT_INSTANCES=3
ExecStart=$PWD/.venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable APIx-api
sudo systemctl start APIx-api
```

---

## Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `API_KEYS` | *(required)* | Comma-separated API keys, e.g. `key1,key2` |
| `JWT_SECRET_KEY` | *(required)* | Secret key used for signing authentication JWT tokens (must be set in env) |
| `JWT_EXPIRE_MINUTES` | `480` (8 hours) | Token validity duration |
| `RATE_LIMIT_PER_MINUTE` | `60` | Max requests per minute per IP / API key (set to `0` to disable) |
| `MAX_PLAYWRIGHT_INSTANCES` | `3` | Max concurrent headless browser instances |
| `SESSION_TTL_MINUTES` | `30` | How long an idle browser session lives before cleanup |
| `MAX_SESSIONS` | `100` | Total max concurrent persistent sessions |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins, e.g. `https://myapp.com` |
| `DISABLE_SSRF_CHECK` | `false` | Allow requests to private IPs (⚠️ dev only) |

---

## Security Considerations

### API Keys & JWT Secrets
- In production, configure a cryptographic random string for `JWT_SECRET_KEY`:
  ```bash
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
- Store secrets using environment files or cloud secret managers (AWS Secrets Manager, HashiCorp Vault).

### SSRF Protection
- APIx inspects target URLs with asynchronous DNS resolution before executing any fetch.
- Private IP spaces (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`) are blocked by default.
