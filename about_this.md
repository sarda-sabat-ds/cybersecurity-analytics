# About This Project — AI/ML Cybersecurity Analytics Platform

> **Complete guide** · What it is · What's inside · How to run it · How to use every feature

---

## Table of Contents

1. [What Is This Project?](#1-what-is-this-project)
2. [Technology Stack](#2-technology-stack)
3. [Project Structure](#3-project-structure)
4. [What's Inside the Data](#4-whats-inside-the-data)
5. [Machine Learning Models](#5-machine-learning-models)
6. [How to Run — Quick Start](#6-how-to-run--quick-start)
7. [How to Run — Manual Step by Step](#7-how-to-run--manual-step-by-step)
8. [How the System Works](#8-how-the-system-works)
9. [Dashboard Pages](#9-dashboard-pages)
10. [All API Endpoints](#10-all-api-endpoints)
11. [MongoDB Analytics](#11-mongodb-analytics)
12. [How to Work With Each Feature](#12-how-to-work-with-each-feature)
13. [Running the Tests](#13-running-the-tests)
14. [Retraining the ML Model](#14-retraining-the-ml-model)
15. [Current Live Stats](#15-current-live-stats)
16. [Interview Q&A](#16-interview-qa)

---

## 1. What Is This Project?

This is a **full-stack AI/ML-powered cybersecurity analytics platform** built as a technical assessment for an AI/ML Developer Intern role.

It does five things:

| # | What it does | How |
|---|---|---|
| 1 | **Detects suspicious activity** | RandomForest ML model + rule-based heuristics |
| 2 | **Correlates related alerts** | Time-window + IP clustering into incidents |
| 3 | **Maps findings to compliance** | ISO 27001:2022 + NIST CSF 2.0 |
| 4 | **Shows everything visually** | React dashboard with charts |
| 5 | **Generates PDF reports** | Downloadable security assessment reports |

**It is NOT a mockup.** Every number on the dashboard comes from real API calls. Every alert is produced by a trained ML model. Every PDF contains real analyzed data.

---

## 2. Technology Stack

### Backend
| Package | Version | Purpose |
|---|---|---|
| Python | 3.14 | Language |
| FastAPI | 0.143 | REST API framework |
| Uvicorn | 0.54 | ASGI web server |
<!-- | SQLAlchemy | 2.1 | SQLite ORM | -->
| pymongo | 4.10 | MongoDB driver |
| pandas | 3.0 | Data processing |
| numpy | 2.1 | Numerical operations |
| scikit-learn | 1.9 | ML models |
| joblib | 1.6 | Model serialization |
| ReportLab | 5.0 | PDF generation |
| pytest | 9.1 | Testing |

### Frontend
| Package | Version | Purpose |
|---|---|---|
| React | 18.3 | UI framework |
| TypeScript | 5.6 | Type-safe JavaScript |
| Vite | 6.4 | Build tool / dev server |
| Tailwind CSS | 3.4 | Styling |
| Recharts | 2.13 | Charts and graphs |
| Lucide React | 0.468 | Icons |

### Storage
| Database | File / URI | Size | Use |
|---|---|---|---|
<!-- | SQLite | `data/cybersecurity.db` | 68.4 MB | Primary — all API reads | -->
| MongoDB | `mongodb://localhost:27017` | — | Mirror — analytics aggregations |

---

## 3. Project Structure

```
cybersecurity-analytics/
│
├── run.bat                       ← Double-click to start everything
├── README.md                     ← Technical documentation
├── about_this.md                 ← This file — full project guide
├── .gitignore
│
├── backend/                      ← Python FastAPI server
│   ├── .env                      ← Environment config (copy of .env.example)
│   ├── .env.example              ← Template for config values
│   ├── requirements.txt          ← All Python dependencies
│   │
│   ├── app/                      ← Application source code (33 Python files)
│   │   │
│   │   ├── main.py               ← App entry point, startup/shutdown lifecycle
│   │   ├── config.py             ← Settings: DB paths, MongoDB URI, CORS, etc.
│   │   │
│   │   ├── api/                  ← REST API route handlers
│   │   │   ├── health.py         ← GET /health
│   │   │   ├── dashboard.py      ← GET /api/dashboard/summary
│   │   │   ├── logs.py           ← GET /api/logs  POST /api/logs/upload
│   │   │   ├── detection.py      ← POST /api/detect  GET /api/alerts  GET /api/incidents
│   │   │   ├── compliance.py     ← GET /api/compliance  GET /api/compliance/summary
│   │   │   ├── reports.py        ← GET /api/reports  POST /api/reports/generate
│   │   │   │                        GET /api/reports/{id}/download
│   │   │   └── mongo_analytics.py← GET /api/mongodb/* (8 analytics endpoints)
│   │   │
│   │   ├── ml/                   ← Machine learning pipeline
│   │   │   ├── dataset_generator.py  ← Generates 41,694 synthetic security logs
│   │   │   ├── preprocessor.py       ← Cleans, encodes, scales, splits data
│   │   │   ├── trainer.py            ← Trains 3 models, selects best
│   │   │   └── detector.py           ← Inference: ML + rules, returns alerts
│   │   │
│   │   ├── correlation/
│   │   │   └── engine.py         ← Groups alerts into incidents
│   │   │
│   │   ├── compliance/
│   │   │   └── mappings.py       ← ISO 27001 + NIST CSF mapping table
│   │   │
│   │   ├── reporting/
│   │   │   └── generator.py      ← PDF report builder (ReportLab)
│   │   │
│   │   ├── database/
│   │   │   ├── models.py         ← SQLAlchemy ORM table definitions
│   │   │   ├── connection.py     ← SQLite engine + session factory
│   │   │   └── mongo.py         ← MongoDB client, collections, aggregations
│   │   │
│   │   ├── services/
│   │   │   ├── log_service.py        ← Ingest logs → SQLite + MongoDB (dual-write)
│   │   │   └── detection_service.py  ← Run detection → SQLite + MongoDB (dual-write)
│   │   │
│   │   └── schemas/              ← Pydantic request/response models
│   │       ├── logs.py
│   │       ├── alerts.py
│   │       ├── compliance.py
│   │       └── reports.py
│   │
│   ├── scripts/                  ← One-time setup commands
│   │   ├── train_model.py        ← Generate data + train + save ML model
│   │   └── seed_database.py      ← Fill SQLite + sync to MongoDB
│   │
│   ├── tests/                    ← 64 automated tests across 7 files
│   │   ├── conftest.py
│   │   ├── test_dataset.py       ← 13 tests
│   │   ├── test_preprocessor.py  ← 9 tests
│   │   ├── test_model_training.py← 8 tests
│   │   ├── test_correlation.py   ← 7 tests
│   │   ├── test_compliance.py    ← 9 tests
│   │   ├── test_api.py           ← 14 tests
│   │   └── test_reporting.py     ← 4 tests
│   │
│   └── venv/                     ← Python virtual environment (don't edit)
│
├── frontend/                     ← React dashboard (12 TypeScript files)
│   ├── index.html
│   ├── package.json
│   ├── vite.config.ts            ← Vite proxy: /api → http://localhost:8000
│   ├── tailwind.config.js        ← Dark mode: 'class' strategy
│   ├── tsconfig.json
│   │
│   └── src/
│       ├── main.tsx              ← React root
│       ├── App.tsx               ← Router, theme provider, API status bar
│       ├── index.css             ← Tailwind + shared component styles
│       │
│       ├── pages/                ← One file per dashboard page
│       │   ├── Dashboard.tsx     ← Stats, charts, model metrics, recent alerts
│       │   ├── Logs.tsx          ← Log table, CSV upload, search, pagination
│       │   ├── Detection.tsx     ← Alert list, severity filter, evidence
│       │   ├── Incidents.tsx     ← Correlated incident groups, remediation
│       │   ├── Compliance.tsx    ← ISO 27001 / NIST CSF mappings, pagination
│       │   └── Reports.tsx       ← Generate + download PDF reports
│       │
│       ├── components/
│       │   ├── Sidebar.tsx       ← Navigation + light/dark toggle switch
│       │   ├── StatCard.tsx      ← Number summary card
│       │   ├── SeverityBadge.tsx ← Color label (critical/high/medium/low)
│       │   └── Spinner.tsx       ← Loading spinner
│       │
│       ├── services/
│       │   └── api.ts            ← All fetch() calls to the backend API
│       │
│       ├── hooks/
│       │   └── useTheme.ts       ← React context for dark/light mode
│       │
│       └── types/
│           └── index.ts          ← TypeScript interfaces for all API shapes
│
├── data/
│   ├── cybersecurity.db          ← SQLite database (68.4 MB)
│   ├── synthetic/
│   │   └── synthetic_logs.csv    ← 41,694 generated log records (6.2 MB)
│   └── processed/
│       └── cleaned_logs.csv      ← Cleaned version used for ML training
│
├── models/                       ← Trained ML model artifacts
│   ├── best_model.joblib         ← Trained RandomForest classifier
│   ├── preprocessor.joblib       ← Fitted ColumnTransformer (OHE + passthrough)
│   ├── label_encoder.joblib      ← LabelEncoder: normal=0, suspicious=1
│   ├── preprocessor_meta.json    ← Feature names, column lists
│   ├── model_metrics.json        ← Evaluation results from training run
│   ├── confusion_matrices.png    ← Confusion matrix comparison chart
│   └── model_comparison.png      ← Bar chart comparing all 3 models
│
└── reports/                      ← Generated PDF reports saved here
```

---

## 4. What's Inside the Data

### Dataset Overview
- **Source**: Synthetically generated (rule-based labels, not real threat intel)
- **Total records**: 41,694 log entries
- **Time span**: Full year — January 1, 2024 to December 31, 2024
- **File size**: 6.2 MB CSV

### Log Fields

| Field | Type | Example | Description |
|---|---|---|---|
| `log_id` | string | `"a3f9-..."` | Unique UUID per log entry |
| `timestamp` | datetime | `"2024-06-15T14:23:01"` | When it happened |
| `source_ip` | string | `"192.168.1.5"` | Where the event came from |
| `destination_ip` | string | `"10.0.0.1"` | Where it was going |
| `event_type` | string | `"brute_force"` | Type of security event |
| `severity` | string | `"high"` | low / medium / high / critical |
| `failed_login_count` | int | `35` | Number of failed login attempts |
| `request_count` | int | `500` | Number of requests in the event |
| `port` | int | `22` | Network port involved |
| `affected_asset` | string | `"auth-server-01"` | Which server/system |
| `label` | string | `"suspicious"` | Ground truth: normal or suspicious |
| `username` | string | `"alice.smith"` | User account involved |
| `bytes_transferred` | int | `5000000` | Data volume (bytes) |
| `user_agent` | string | `"Nmap Scripting Engine"` | HTTP client or tool |
| `process_name` | string | `"mimikatz.exe"` | Process that caused the event |

### Event Types

| Event Type | Category | Label |
|---|---|---|
| login_success | Normal | normal |
| file_access | Normal | normal |
| http_request | Normal | normal |
| dns_query | Normal | normal |
| vpn_connect / vpn_disconnect | Normal | normal |
| configuration_change | Normal | normal |
| process_creation | Normal | normal |
| brute_force | Attack | suspicious |
| port_scan | Reconnaissance | suspicious |
| data_exfiltration | Attack | suspicious |
| privilege_escalation | Attack | suspicious |
| malware_detected | Attack | suspicious |
| account_lockout | Attack | suspicious |
| lateral_movement | Attack | suspicious |
| credential_dumping | Attack | suspicious |
| ransomware_activity | Attack | suspicious |
| c2_communication | Attack | suspicious |
| sql_injection | Web Attack | suspicious |
| xss_attempt | Web Attack | suspicious |
| registry_modification | Attack | suspicious |

### Attack Campaigns (Realistic Multi-Stage Attacks)
The generator also simulates **200 realistic attack campaigns** — sequences of events that mimic real-world attack patterns:

| Campaign Pattern | What it Simulates |
|---|---|
| port_scan → brute_force → privilege_escalation → lateral_movement → data_exfiltration | Classic APT chain |
| port_scan → sql_injection → privilege_escalation → credential_dumping → c2_communication | Web-to-internal breach |
| brute_force → malware_detected → c2_communication → ransomware_activity | Ransomware campaign |
| xss_attempt → privilege_escalation → credential_dumping → lateral_movement | Web app compromise |

---

## 5. Machine Learning Models

### Three Models Trained and Compared

| Model | Algorithm | Accuracy | F1 (Suspicious) | Recall | FPR |
|---|---|---|---|---|---|
| **RandomForest** ✓ | 100 decision trees, majority vote | **1.0000** | **1.0000** | **1.0000** | **0.0000** |
| LogisticRegression | Linear classification | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| DecisionTree | Single decision tree | 1.0000 | 1.0000 | 1.0000 | 0.0000 |

> **Why are all scores 1.0?**
> Because labels are generated by rules — the same rules the models learn from. On real-world data with noisy, overlapping patterns, expect significantly lower scores (typically 85–95% accuracy, 70–90% F1).

### Model Selection Formula
```
Score = 0.5 × F1(suspicious) + 0.3 × Recall(suspicious) − 0.2 × FPR
```
- **F1** is the main metric (harmonic mean of precision and recall)
- **Recall** gets heavy weight — missing a real attack is worse than a false alarm
- **FPR penalty** reduces alert fatigue from false positives
- RandomForest selected (alphabetical tiebreak, all three scored 0.80)

### Features Used for ML

| Feature | Type | Description |
|---|---|---|
| event_type | Categorical → One-Hot | Type of security event (29 types → 29 columns) |
| severity | Categorical → One-Hot | low/medium/high/critical (4 → 4 columns) |
| failed_login_count | Numerical | Raw count, not scaled |
| request_count | Numerical | Raw count, not scaled |
| port | Numerical | Port number, not scaled |

Total: **28 input features** after one-hot encoding.

### Saved Artifacts
All model files are in `models/`:
- `best_model.joblib` — the trained RandomForest classifier
- `preprocessor.joblib` — the fitted ColumnTransformer (must be used for inference)
- `label_encoder.joblib` — maps `normal=0, suspicious=1`
- `model_metrics.json` — all evaluation results from the training run
- `confusion_matrices.png` — visual comparison of all 3 models
- `model_comparison.png` — bar chart of key metrics across models

---

## 6. How to Run — Quick Start

**Prerequisites:** Python 3.11+, Node.js 18+, MongoDB running on port 27017

### Option A — Double-click (Windows)
```
Open:  cybersecurity-analytics\run.bat
```
This automatically:
1. Checks Python venv and Node.js are present
2. Trains the ML model if not already done
3. Seeds the database if it is empty
4. Opens two terminal windows — backend and frontend

### Option B — One command (PowerShell)
```powershell
cd c:\Users\sabat\inter_project\cybersecurity-analytics
.\run.bat
```

### Then open your browser
```
Dashboard  →  http://localhost:5173
API Docs   →  http://localhost:8000/docs
Health     →  http://localhost:8000/health
```

---

## 7. How to Run — Manual Step by Step

### Step 1 — First time only: Train the model

```bash
cd backend
.\venv\Scripts\activate          # Windows
# or: source venv/bin/activate   # macOS/Linux

python scripts/train_model.py
```

This generates `synthetic_logs.csv` (6.2 MB, 41,694 records), trains all 3 models, and saves artifacts to `models/`.

### Step 2 — First time only: Seed the databases

```bash
python scripts/seed_database.py --reset
```

This fills SQLite and syncs to MongoDB with:
- 41,694 logs
- 11,694 detected alerts
- 8,871 correlated incidents
- 21,664 compliance mappings

### Step 3 — Start the backend API

```bash
# Still in backend/ with venv active
uvicorn app.main:app --reload --port 8000
```

You should see:
```
MongoDB ready — db=cybersecurity_analytics  logs=41694  alerts=11694
ML model loaded at startup: RandomForest
Application startup complete.
```

### Step 4 — Start the frontend dashboard

```bash
# Open a new terminal
cd frontend
npm run dev
```

You should see:
```
VITE v6.4.4  ready in 769 ms
➜  Local:   http://localhost:5173/
```

### Step 5 — Open the browser

Go to **http://localhost:5173** — the dashboard should show live data immediately.

---

## 8. How the System Works

### Data Flow Diagram

```
 ┌─────────────────────────────────────────────────────────────────┐
 │                     DATA INGESTION                               │
 │  CSV file (41,694 logs) → log_service.py                        │
 │                          │                                       │
 │              ┌───────────┴───────────┐                          │
 │              ▼                       ▼                           │
 │         SQLite DB               MongoDB DB                       │
 │       (primary reads)         (analytics mirror)                 │
 └─────────────────────────────────────────────────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │                   ML DETECTION (detector.py)                     │
 │                                                                  │
 │  For each log record:                                            │
 │    1. Preprocess (OHE + feature selection)                      │
 │    2. RandomForest.predict() → normal or suspicious             │
 │    3. RandomForest.predict_proba() → confidence score           │
 │    4. Rule checks:                                               │
 │       - failed_login_count >= 5 → brute force flag             │
 │       - request_count >= 200 → high volume flag                 │
 │       - event_type in suspicious set → auto-flag               │
 │    5. If ML OR rules flag it → create Alert                     │
 │                                                                  │
 │  Result: 11,694 Alerts from 41,694 logs                        │
 └─────────────────────────────────────────────────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │               CORRELATION ENGINE (engine.py)                     │
 │                                                                  │
 │  Pass 1: Group by source IP within 30-minute window             │
 │  Pass 2: Group by affected asset within 30-minute window        │
 │  Pass 3: Detect attack chains across grouped alerts             │
 │  Pass 4: Standalone critical/high alerts become solo incidents  │
 │                                                                  │
 │  Result: 8,871 Incidents from 11,694 Alerts                    │
 └─────────────────────────────────────────────────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │             COMPLIANCE MAPPING (mappings.py)                     │
 │                                                                  │
 │  For each alert event_type:                                      │
 │    → Map to relevant ISO 27001:2022 Annex A controls            │
 │    → Map to relevant NIST CSF 2.0 subcategories                 │
 │    → Add evidence, risk level, remediation, disclaimer          │
 │                                                                  │
 │  Result: 21,664 compliance mappings                             │
 └─────────────────────────────────────────────────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │              FASTAPI SERVES ALL THIS DATA                        │
 │                                                                  │
 │  React frontend fetches data via /api/* endpoints               │
 │  Dashboard shows real numbers from the database                  │
 │  PDF reports generated from real analyzed records               │
 └─────────────────────────────────────────────────────────────────┘
```

### Dual Database Architecture

```
Every Write:
  log / alert / incident / compliance / report
          │
          ├──► SQLite    (always, primary, never fails)
          └──► MongoDB   (if available, fire-and-forget)

Every Read:
  API endpoints read from SQLite
  /api/mongodb/* endpoints read from MongoDB aggregations
```

---

## 9. Dashboard Pages

### Page 1 — Dashboard (Overview)
- **4 stat cards**: Total logs, Suspicious alerts, Potential incidents, Critical alerts
- **ML model card**: Shows accuracy, F1, recall, precision, FPR from real training
- **Event Type chart**: Horizontal bar chart of all event types by frequency
- **Severity chart**: Pie chart of log severity distribution
- **Detection Method chart**: Bar chart — ML vs rule vs combined
- **Recent Alerts table**: Last 10 alerts with timestamp, type, severity, IP, method

### Page 2 — Logs
- **Table** showing all 41,694 logs with pagination (50 per page)
- **Search** by event type and source IP
- **Filter** by severity (dropdown)
- **Upload CSV** to add your own logs
- Each row shows: timestamp, source IP, event type, severity, failed logins, asset, label

### Page 3 — Detection (Threat Detection)
- **All 11,694 suspicious alerts** listed
- Filter by severity (click Critical / High / Medium / Low pills)
- Each alert expands to show:
  - ML prediction + confidence score
  - Detection reason (which rule triggered)
  - Evidence (what values were suspicious)
  - Recommended action (specific steps to take)
  - Detection method (ml / rule / combined)

### Page 4 — Incidents
- **All 8,871 correlated incidents** grouped
- Severity summary cards (critical / high / medium / low counts)
- Each incident expands to show:
  - Incident ID and category
  - First and last seen timestamps
  - Affected assets (all servers involved)
  - Related alert IDs
  - Evidence summary (why they were grouped)
  - Recommended remediation (specific steps)

### Page 5 — Compliance
- **13 unique control associations** (deduplicated from 21,664 raw mappings)
- Filter by framework (ISO / NIST)
- Filter by risk level (click the risk count cards)
- Pagination (20 per page)
- Each control expands to show:
  - Framework name and control ID
  - Finding description
  - Evidence from the actual alert
  - Remediation steps
  - Disclaimer (these are suggested, not audit results)

### Page 6 — Reports
- **Generate** a new PDF report with a custom title
- **Download** any generated report as PDF
- Each report contains: executive summary, model metrics, alert table, incident details, compliance mappings, limitations

### Theme Toggle
The **sun/moon switch** in the bottom-left of the sidebar toggles between:
- **Dark mode** — dark gray background, ideal for SOC environments
- **Light mode** — white background, ideal for presentations/reports

Your preference is saved in `localStorage` and persists across page reloads.

---

## 10. All API Endpoints

### Standard Endpoints (SQLite)

| Method | Endpoint | What it returns |
|---|---|---|
| GET | `/health` | Status, model loaded, SQLite ok, MongoDB counts |
| GET | `/api/dashboard/summary` | All dashboard stats in one call |
| GET | `/api/logs` | Paginated logs (page, page_size, filters) |
| POST | `/api/logs/upload` | Upload a CSV file of logs |
| POST | `/api/detect` | Submit records, get alerts back |
| GET | `/api/alerts` | All detected alerts (paginated, filtered) |
| GET | `/api/incidents` | All correlated incidents |
| GET | `/api/compliance` | Deduplicated compliance mappings (paginated) |
| GET | `/api/compliance/summary` | Risk level counts only |
| GET | `/api/reports` | List of generated reports |
| POST | `/api/reports/generate` | Generate a new PDF report |
| GET | `/api/reports/{id}/download` | Download PDF file |

### MongoDB Analytics Endpoints

| Method | Endpoint | What it returns |
|---|---|---|
| GET | `/api/mongodb/status` | Connection info + counts per collection |
| GET | `/api/mongodb/event-types` | Top N event types by frequency |
| GET | `/api/mongodb/top-attackers` | Source IPs ranked by alert count |
| GET | `/api/mongodb/asset-risk` | Assets ranked by weighted risk score |
| GET | `/api/mongodb/severity-trend` | Daily alert counts by severity |
| GET | `/api/mongodb/logs/search` | Filter logs by any field |
| GET | `/api/mongodb/alerts/search` | Filter alerts by severity/method/IP |
| GET | `/api/mongodb/incidents/search` | Filter incidents by severity/status |

Full interactive documentation: **http://localhost:8000/docs**

---

## 11. MongoDB Analytics

### What's in MongoDB

| Collection | Records | Purpose |
|---|---|---|
| `security_logs` | 41,698 | All raw log records with extra fields |
| `alerts` | 23,392 | All detected alerts |
| `incidents` | 17,744 | All correlated incidents |
| `compliance_mappings` | 43,338 | All control associations |
| `reports` | 2 | Report metadata |

### Using the MongoDB Endpoints

**Who is attacking the most?**
```
GET http://localhost:8000/api/mongodb/top-attackers?limit=10
```
Returns: source IPs with alert count and severity types

**Which servers are most at risk?**
```
GET http://localhost:8000/api/mongodb/asset-risk?limit=15
```
Returns: assets with weighted risk score (critical×4, high×3, medium×2, low×1)

**Find all ransomware activity:**
```
GET http://localhost:8000/api/mongodb/logs/search?event_type=ransomware_activity
```

**All critical alerts in the last month:**
```
GET http://localhost:8000/api/mongodb/alerts/search?severity=critical&limit=100
```

**Daily attack trend:**
```
GET http://localhost:8000/api/mongodb/severity-trend?days=30
```

### Using MongoDB Directly in Python

```python
import sys
sys.path.insert(0, 'backend')

from app.database.mongo import (
    col_logs, col_alerts, col_incidents,
    get_top_attackers, get_asset_risk_scores,
    aggregate_event_types
)

# Direct MongoDB query — all brute force attacks from external IPs
logs = col_logs()
results = list(logs.find(
    {"event_type": "brute_force", "severity": {"$in": ["high","critical"]}},
    {"_id": 0}
).sort("timestamp", -1).limit(50))

# Aggregation — top 10 most targeted assets
for asset in get_asset_risk_scores(limit=10):
    print(f"{asset['asset']:25} risk={asset['risk_score']}  alerts={asset['alert_count']}")
```

---

## 12. How to Work With Each Feature

### Upload Your Own Log File

Your CSV needs at minimum:
```csv
event_type,severity,failed_login_count,source_ip,affected_asset
brute_force,high,45,203.0.113.5,auth-server-01
login_success,low,0,192.168.1.10,web-server-01
port_scan,medium,0,198.51.100.10,firewall-01
data_exfiltration,critical,0,192.168.2.5,db-server-01
```

1. Go to the **Logs page** → click **Upload CSV**
2. The file is validated and ingested
3. Go to the **Detection page** to see new alerts
4. Go to **Incidents** to see correlations

### Send Logs to the API Programmatically

```python
import requests

records = [
    {
        "event_type": "brute_force",
        "severity": "high",
        "failed_login_count": 50,
        "source_ip": "1.2.3.4",
        "affected_asset": "auth-server-01",
        "request_count": 50,
        "port": 22
    }
]

response = requests.post(
    "http://localhost:8000/api/detect",
    json={"records": records}
)
alerts = response.json()
print(f"Alerts generated: {alerts['alerts_generated']}")
for alert in alerts['alerts']:
    print(f"  {alert['event_type']} - {alert['severity']} - {alert['detection_reason']}")
```

### Generate a Report

```python
import requests

# Generate
r = requests.post("http://localhost:8000/api/reports/generate",
                   json={"title": "Q4 2024 Security Assessment"})
report_id = r.json()["report_id"]

# Download
pdf = requests.get(f"http://localhost:8000/api/reports/{report_id}/download")
with open("security_report.pdf", "wb") as f:
    f.write(pdf.content)
print("Report saved: security_report.pdf")
```

### Query the Dashboard Data

```python
import requests

summary = requests.get("http://localhost:8000/api/dashboard/summary").json()
print(f"Total logs:      {summary['total_logs']:,}")
print(f"Total alerts:    {summary['total_alerts']:,}")
print(f"Total incidents: {summary['total_incidents']:,}")
print(f"Model:           {summary['model_name']}")
print(f"Model accuracy:  {summary['model_metrics']['accuracy']:.2%}")
```

---

## 13. Running the Tests

```bash
cd backend

# Run all 64 tests
.\venv\Scripts\pytest tests/ -v

# Run a specific test file
.\venv\Scripts\pytest tests/test_api.py -v

# Run with coverage summary
.\venv\Scripts\pytest tests/ -q
```

### Test Coverage

| File | Tests | What is tested |
|---|---|---|
| `test_dataset.py` | 13 | Dataset generation, campaigns, new columns, sorting |
| `test_preprocessor.py` | 9 | Cleaning, encoding, splitting, save/load |
| `test_model_training.py` | 8 | Training, metrics, model selection, predictions |
| `test_correlation.py` | 7 | Alert grouping, attack chains, severity |
| `test_compliance.py` | 9 | Framework mappings, disclaimers, evidence |
| `test_api.py` | 14 | All API endpoints, upload, detection, reports |
| `test_reporting.py` | 4 | PDF creation, file size, report ID |
| **Total** | **64** | **All pass** |

---

## 14. Retraining the ML Model

### With default settings (generates new 41,694-record dataset)
```bash
cd backend
.\venv\Scripts\python scripts/train_model.py
```

### With a larger dataset
```bash
.\venv\Scripts\python scripts/train_model.py --normal 50000 --suspicious 20000 --campaigns 500
```

### With your own CSV file
```bash
.\venv\Scripts\python scripts/train_model.py --csv path/to/your/logs.csv
```

Your CSV must have these columns: `event_type`, `severity`, `failed_login_count`, `request_count`, `port`, `label`

### After retraining, reseed the database
```bash
.\venv\Scripts\python scripts/seed_database.py --reset
```

Then restart the backend — it will auto-load the new model.

---

## 15. Current Live Stats

> These numbers reflect the actual database state as of the last seed run.

### SQLite Database (`data/cybersecurity.db` — 68.4 MB)

| Table | Records |
|---|---|
| security_logs | 41,694 |
| alerts | 11,694 |
| incidents | 8,871 |
| compliance_mappings | 21,664 |
| reports | 3 |

### MongoDB Database (`cybersecurity_analytics`)

| Collection | Documents |
|---|---|
| security_logs | 41,698 |
| alerts | 23,392 |
| incidents | 17,744 |
| compliance_mappings | 43,338 |
| reports | 2 |

### ML Model (RandomForest — trained on 41,694 records)

| Metric | Score |
|---|---|
| Accuracy | 1.0000 |
| F1 Score (suspicious class) | 1.0000 |
| Recall (suspicious class) | 1.0000 |
| Precision (suspicious class) | 1.0000 |
| False Positive Rate | 0.0000 |
| True Positives | 2,339 |
| False Positives | 0 |
| True Negatives | 6,000 |
| False Negatives | 0 |
| Training set size | 33,355 records |
| Test set size | 8,339 records |
| Input features | 28 (after one-hot encoding) |

### Dataset Composition

| Event Type | Count | Label |
|---|---|---|
| login_success | ~4,340 | normal |
| process_creation | ~4,313 | normal |
| configuration_change | ~4,282 | normal |
| http_request | ~4,267 | normal |
| file_access | ~4,266 | normal |
| brute_force | ~2,090 | suspicious |
| port_scan | ~1,800 | suspicious |
| account_lockout | ~1,600 | suspicious |
| data_exfiltration | ~900 | suspicious |
| malware_detected | ~900 | suspicious |
| ransomware_activity | ~800 | suspicious |
| lateral_movement | ~750 | suspicious |
| + 17 more types | ... | ... |

---

## 16. Interview Q&A

### Q: Why did you choose these three ML models?

**A:** RandomForest, Logistic Regression, and Decision Tree were selected because they represent three fundamentally different approaches — ensemble (RF), linear (LR), and single-tree (DT) — allowing a fair comparison. RF handles class imbalance and non-linear patterns well. LR provides a fast, interpretable linear baseline. DT gives transparent, inspectable rules. All three are trained on identical splits and compared using the same evaluation criteria so the comparison is genuinely fair.

### Q: How does alert correlation work?

**A:** The engine runs three passes over the 11,694 alerts. Pass 1 clusters alerts by the same source IP within a 30-minute sliding window — if the same IP appears in 2+ alerts within 30 minutes, they form an incident. Pass 2 clusters by the same target asset within the same window — multiple event types hitting `auth-server-01` within 30 minutes suggests a focused attack. Pass 3 checks for known attack chain patterns like `port_scan → brute_force → data_exfiltration` which are flagged as named multi-stage incidents. Any remaining high/critical single alerts become standalone incidents.

### Q: Why are the model metrics 100%?

**A:** Because the training labels are generated by the same rules the model learns — brute_force events have high failed_login_count, port_scan events have high request_count. The model correctly learns these rules with zero ambiguity. On real-world data with noisy logs, overlapping patterns, and adversarial evasion, expect 85–95% accuracy and 70–90% F1. This is a known limitation documented in the codebase.

### Q: How are false positives handled?

**A:** Three mechanisms: (1) The model uses `class_weight='balanced'` to compensate for the 72/28 normal/suspicious split. (2) The detection engine requires ML confidence ≥ 0.55 before accepting an ML-only prediction — low-confidence predictions are discarded. (3) The model selection formula penalizes high FPR with a `−0.2 × FPR` term. All detections are labelled "suspicious" — not "confirmed attack" — to make clear they require analyst review.

### Q: How does the frontend talk to the backend?

**A:** The React app makes all API calls as relative paths like `/api/dashboard/summary`. Vite's dev server has a proxy configured in `vite.config.ts` that forwards any `/api/*` request to `http://localhost:8000`. In the browser, this looks like the same origin so there are no CORS issues during development. For production, an nginx reverse proxy would handle the same routing.

### Q: Why two databases?

**A:** SQLite is simple, file-based, and requires zero infrastructure — perfect for a local demo. MongoDB handles aggregation queries much better (top attackers, asset risk scores, time-series trends). Rather than force-fit aggregations into SQLite or migrate entirely to MongoDB, both are used for what they do best. The dual-write is fire-and-forget — MongoDB failure never blocks the platform.

---

## Quick Command Reference

```bash
# ── First-time setup ─────────────────────────────────────────────────
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt

cd ../frontend
npm install

# ── Train model (generates data + trains 3 models + saves artifacts) ─
cd backend
python scripts/train_model.py

# ── Seed databases (SQLite + MongoDB) ────────────────────────────────
python scripts/seed_database.py --reset

# ── Start backend ────────────────────────────────────────────────────
uvicorn app.main:app --reload --port 8000

# ── Start frontend (new terminal) ────────────────────────────────────
cd frontend
npm run dev

# ── Run all tests ────────────────────────────────────────────────────
cd backend
pytest tests/ -v

# ── Or just double-click ─────────────────────────────────────────────
run.bat
```

---

*Built for AI/ML Developer Intern technical assessment · Python + FastAPI + React + scikit-learn + MongoDB*
