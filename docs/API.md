# APIx — Real-Time Airfare Price Index API Reference

**Base URL:** `http://localhost:8001`  
**Target Agency / Standard:** Ministry of Statistics & Programme Implementation (MoSPI) / National Statistical Office (NSO) — CPI (Base 2024=100) Revision  
**Authentication:** 
- **Institutional & Analytical Endpoints:** Header `x-api-key: <api-key>` or `Authorization: Bearer <jwt-token>`
- **Demo Officer Sessions:** `POST /auth/demo-login` (when `DEMO_MODE=true` or `AUTH_DISABLED=true`)
- **Health Check (`/api/health`):** Public, unauthenticated

---

## 📑 API Endpoints Overview

- [Index & Econometrics](#1-index--econometrics)
  - [GET /api/v1/index/daily](#get-apiv1indexdaily)
  - [GET /api/v1/index/weekly](#get-apiv1indexweekly)
  - [GET /api/v1/index/monthly](#get-apiv1indexmonthly)
  - [GET /api/v1/index/methodology-comparison](#get-apiv1indexmethodology-comparison)
  - [GET /api/v1/index/inflation-contribution](#get-apiv1indexinflation-contribution)
  - [GET /api/v1/index/route/{id}](#get-apiv1indexrouteid)
  - [GET /api/v1/index/materiality](#get-apiv1indexmateriality)
  - [POST /api/v1/index/compute](#post-apiv1indexcompute)
  - [GET /api/v1/index/bulletin](#get-apiv1indexbulletin)
  - [POST /api/v1/index/ai-diagnose](#post-apiv1indexai-diagnose)
- [Data Export & NSO Microdata](#2-data-export--nso-microdata)
  - [GET /api/v1/export/csv](#get-apiv1exportcsv)
  - [GET /api/v1/export/index-csv](#get-apiv1exportindex-csv)
- [Dashboard & Analytics](#3-dashboard--analytics)
  - [GET /api/v1/dashboard/stats](#get-apiv1dashboardstats)
  - [GET /api/v1/dashboard/heatmap](#get-apiv1dashboardheatmap)
  - [GET /api/v1/dashboard/elasticity](#get-apiv1dashboardelasticity)
  - [GET /api/v1/dashboard/carriers](#get-apiv1dashboardcarriers)
- [Route Basket Configuration](#4-route-basket-configuration)
  - [GET /api/v1/routes](#get-apiv1routes)
  - [POST /api/v1/routes](#post-apiv1routes)
  - [PUT /api/v1/routes/{id}](#put-apiv1routesid)
  - [DELETE /api/v1/routes/{id}](#delete-apiv1routesid)
- [Scraper Operations & Ingestion](#5-scraper-operations--ingestion)
  - [POST /api/v1/scraper/run](#post-apiv1scraperrun)
  - [POST /api/v1/scraper/survey-instant](#post-apiv1scrapersurvey-instant)
  - [GET /api/v1/scraper/jobs](#get-apiv1scraperjobs)
  - [GET /api/v1/scraper/live-logs](#get-apiv1scraperlive-logs)
- [Authentication & Profiles](#6-authentication--profiles)
  - [POST /auth/register](#post-authregister)
  - [POST /auth/login](#post-authlogin)
  - [POST /auth/demo-login](#post-authdemo-login)
  - [GET /auth/me](#get-authme)
- [System & Health](#7-system--health)
  - [GET /api/health](#get-apihealth)

---

## 1. Index & Econometrics

### GET /api/v1/index/daily
Retrieve national daily APIx price index time series aggregated across the domestic route basket using the Jevons geometric mean and DGCA passenger traffic weights.

### GET /api/v1/index/weekly
Retrieve 7-day rolling multilateral weekly APIx series smoothing out weekday vs weekend demand surges.

### GET /api/v1/index/monthly
Retrieve calendar-month chained publication index series aligned with MoSPI CPI monthly release schedules.

### GET /api/v1/index/methodology-comparison
Compare Jevons vs Dutot vs Carli formulas on live route fare quotes with upward bias metrics (ILO CPI Manual Ch. 10).

### GET /api/v1/index/inflation-contribution
Decompose percentage point contribution of each domestic corridor ($\Delta I_r \times w_r$) to headline national airfare inflation.

### GET /api/v1/index/route/{id}
Retrieve route sub-index history and advance purchase window breakdown for a specific corridor (e.g. `DEL-BOM`).

### GET /api/v1/index/materiality
Retrieve statistical materiality gap between single monthly snapshot and continuous APIx.

### POST /api/v1/index/compute
Trigger on-demand index calculation for a given date applying Tukey IQR outlier filtering.

### GET /api/v1/index/bulletin
Generate the official MoSPI/NSO Airfare Price Index Monthly Statistical Bulletin.

### POST /api/v1/index/ai-diagnose
Diagnose price surge or capacity shocks using Gemini AI or econometric heuristics.

---

## 2. Data Export & NSO Microdata

### GET /api/v1/export/csv
Download cleaned, deduplicated fare quotes microdata as an audit-ready CSV for NSO price statisticians.

### GET /api/v1/export/index-csv
Download national APIx index time series as a CSV table for RBI monetary policy modeling.

---

## 3. Dashboard & Analytics

### GET /api/v1/dashboard/stats
Retrieve headline KPI metrics for dashboard cards.

### GET /api/v1/dashboard/heatmap
Retrieve Route × Date fare heatmap matrix with color intensity rankings.

### GET /api/v1/dashboard/elasticity
Retrieve dynamic yield curve data grouped by advance booking horizon ($T+1, T+7, T+15, T+30, T+45$).

### GET /api/v1/dashboard/carriers
Compare market share, average fares, and tracked quote counts across domestic carriers (6E, AI, IX, QP, SG).

---

## 4. Scraper Operations

### POST /api/v1/scraper/run
Dispatches asynchronous multi-route matrix batch survey.

### POST /api/v1/scraper/survey-instant
Synchronous single-route live survey.

### GET /api/v1/scraper/jobs
List execution history and quote counts of batch scraping jobs.

### GET /api/v1/scraper/live-logs
Retrieve live in-memory telemetry logs for the scraper operations stream.
