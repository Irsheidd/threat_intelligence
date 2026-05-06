# Threat Intelligence System

A complete multi-agent threat detection pipeline that combines machine learning anomaly detection, CrewAI orchestration, Flask API, and an interactive dashboard for network security monitoring.

## Project Overview

This system detects suspicious network activity by:
1. **Detector Agent** — scores incoming network logs using an Isolation Forest model
2. **Analyzer Agent** — explains the suspicious behavior in plain language
3. **Reporter Agent** — formats structured, actionable alerts
4. **Dashboard** — visualizes detections, alerts, and threat severity in real-time

## Project Structure

```
├── sources/                          # Raw data
│   └── network_logs.csv
├── data_prep/                        # Feature engineering pipeline
│   ├── feature_engineering.py        # Parse logs → feature matrix
│   ├── model.py                      # Train & save Isolation Forest
│   ├── outputs/
│   │   ├── features_dataset.csv
│   │   ├── anomaly_scores.csv
│   │   └── models/isolation_forest.joblib
│   └── schemas/create_table.sql
├── threat_intel/                     # Shared detection logic
│   ├── pipeline.py                   # Run model, score sessions, analyze
│   └── alerts.py                     # Store and retrieve alerts
├── api/                              # Flask API & Dashboard
│   ├── app.py                        # REST endpoints + dashboard routes
│   ├── test_api.py                   # Smoke tests
│   ├── feature_extractor.py          # Normalize incoming logs
│   └── templates/dashboard.html      # Interactive threat dashboard
├── test_crew/                        # CrewAI multi-agent orchestration
│   └── src/test_crew/
│       ├── main.py                   # Local runner (no LLM needed)
│       ├── crew.py                   # Agent/task definitions
│       ├── workflow.py               # Deterministic workflow
│       ├── config/agents.yaml        # Detector/Analyzer/Reporter configs
│       ├── config/tasks.yaml         # Detection/Analysis/Reporting tasks
│       └── tools/threat_tools.py     # CrewAI-compatible tools
├── sample_logs.txt                   # Example network logs
├── requirements.txt                  # Root dependencies
└── venv/                             # Python virtual environment
```

## Installation & Setup

### 1. Create and activate virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. (Optional) Setup database

```bash
export DATABASE_URL="postgresql://user:pass@host:5432/dbname"
```

## Running the Project

### Feature Engineering (One-time setup)

Prepare raw logs into a feature-engineered dataset and train the model:

```bash
venv/bin/python -m data_prep.feature_engineering
venv/bin/python -m data_prep.model
```

Outputs:
- `data_prep/outputs/features_dataset.csv` — cleaned feature matrix
- `data_prep/outputs/models/isolation_forest.joblib` — trained model
- `data_prep/outputs/anomaly_scores.csv` — detection results

### Option A: Run Multi-Agent Workflow (No LLM Required)

Run the deterministic threat workflow on sample logs:

```bash
venv/bin/python test_crew/src/test_crew/main.py
```

This displays structured JSON with detections, analyses, and generated alerts.

### Option B: Start the Flask API & Dashboard

Launch the interactive web interface:

```bash
venv/bin/python api/app.py
```

Then open `http://localhost:5002/dashboard` in your browser.

**Available endpoints:**
- `GET /dashboard` — interactive threat dashboard
- `POST /detect` — analyze logs and return detections + alerts
- `GET /api/alerts` — retrieve stored alerts with severity summary
- `GET /api/summary` — get alert statistics (critical, high, medium, low)

### Option C: Run API Tests

Verify the detection pipeline and alert generation:

```bash
venv/bin/python api/test_api.py
```

## Core Components

### Shared Threat Pipeline (`threat_intel/`)

Both the API and CrewAI runner use the same deterministic pipeline:

```python
from threat_intel.pipeline import run_threat_pipeline

result = run_threat_pipeline(logs)
# Returns: {
#   'count': int,
#   'suspicious_count': int,
#   'detections': [...],
#   'analyses': [...],
#   'alerts': [...]
# }
```

**Pipeline steps:**
1. Parse and normalize log entries
2. Extract features (IP frequency, failed logins, data transfer volume, etc.)
3. Score sessions with Isolation Forest model
4. Classify anomalies based on score thresholds
5. Generate threat level and recommendations
6. Store structured alerts

### CrewAI Agents

Three specialized agents handle threat intelligence:

- **Detector Agent** — identifies suspicious sessions and anomaly scores
- **Analyzer Agent** — contextualizes findings (failed logins, unusual countries, data movement)
- **Reporter Agent** — formats alerts with severity levels and recommended actions

All three are integrated into `test_crew/src/test_crew/crew.py` and use the shared threat pipeline for reproducible results.

### Flask API & Dashboard

- **`/dashboard`** — responsive web UI showing alert history, severity breakdown, and a log submission form
- **`/detect`** — JSON API for programmatic threat analysis
- **`/api/alerts`** — retrieve alert history with statistics
- Real-time alert generation stored in memory (resets on restart)

### Alert Schema

Every generated alert includes:

```json
{
  "id": "alert-1",
  "session_id": "sess_025",
  "src_ip": "192.168.1.65",
  "dst_ip": "10.0.0.2",
  "timestamp": "2026-05-06T11:47:06.759086+00:00",
  "threat_level": "critical",
  "issue": "Suspicious network behavior",
  "description": "Clear explanation of detected activity",
  "recommended_action": "Specific steps for incident responders",
  "anomaly_score": -0.0998,
  "evidence": ["List", "of", "detection", "signals"]
}
```

## Threat Levels

- **Critical** — Multiple high-risk signals (failed logins + large transfer + unusual country)
- **High** — One or more high-risk signals
- **Medium** — Anomaly detected but low-confidence signals
- **Low** — Routine activity

## Development Notes

- The project uses an in-memory alert store. Restarting the Flask app clears alert history.
- For persistent storage, connect to PostgreSQL via `DATABASE_URL`.
- The CrewAI definitions are pre-configured for the detector/analyzer/reporter workflow but do not require an LLM (running deterministically).
- All timestamps are ISO 8601 UTC.
- Feature engineering preserves source/destination IPs per session so alerts are grounded in actual network data.
