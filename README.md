# Network Intrusion Detection System (IDS) Simulation

A **defensive**, beginner-friendly hybrid IDS: synthetic network-flow records → feature engineering →
**signature rules + statistical anomaly detection + machine learning** → weighted risk score → alerts →
SQLite → live SOC dashboard with investigation workflow.

> **Safety:** the project is 100% data. It never sends, scans, floods or probes anything. Only RFC 5737
> documentation IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are used, and the simulator refuses
> any non-localhost URL.

## 1. Quick start (about 3 minutes)

Requires **Python 3.10+**. Open a terminal **inside the `Network-IDS-Simulation` folder**.

**Windows (PowerShell)**
```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python run.py
```
**macOS / Linux**
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```
Open **http://127.0.0.1:5000**. `run.py` automatically creates `data/network_traffic.csv` (5,000 rows)
and trains the ML models the first time.

## 2. Step-by-step simulation (matches the course spec)

| Step | Action (use separate terminals, venv activated) |
|---|---|
| 1 | `python -m simulator.generate_dataset` → creates `data/network_traffic.csv` |
| 1b | `python -m ml.train_model` → trains models, prints **real** metrics, saves `models/metrics.json` |
| 2 | `python -m backend.app` → backend + dashboard on port 5000 (frontend is `frontend/index.html`, served by Flask) |
| 3 | Open http://127.0.0.1:5000 in the browser |
| 4 | New terminal: `python -m simulator.traffic_simulator --mode mixed --speed slow` |
| 5 | Dashboard dropdown → **NORMAL_WEB** → *Inject synthetic flow* → expect `NORMAL`, no alert |
| 6 | Inject **REPEATED_FAILED_CONNECTIONS** / **HIGH_CONNECTION_RATE** → expect POTENTIAL INTRUSION |
| 7 | Inject **MULTI_PORT_PROBING_PATTERN** → rule IDS-003 triggers |
| 8 | New alert appears in *Recent alerts* (auto-refresh every 3 s) |
| 9 | Click the alert row → investigation panel |
| 10 | Click **INVESTIGATING** (status NEW → INVESTIGATING) |
| 11 | Type an analyst note → **Add note** |
| 12 | Click **RESOLVED** or **FALSE_POSITIVE** (timeline records every change) |

Simulator options: `--mode normal|mixed`, `--speed slow|fast`, `--count N`, `--dry-run`.
Run tests: `python -m unittest discover -s tests -v` (33 tests; run `python -m ml.train_model` first for the ML test).

## 3. Folder guide

| Path | Purpose |
|---|---|
| `simulator/generate_dataset.py` | Creates the 5,000-row labelled CSV and the `make_flow()` scenario generator |
| `simulator/traffic_simulator.py` | Continuous synthetic flow generator → POSTs to localhost API |
| `ids/feature_extractor.py` | Validation + 15 features (division-by-zero, bad IP/port/protocol handling) |
| `ids/rule_engine.py` | 6 configurable signature rules (`analyze_flow`) |
| `ids/anomaly_detector.py` | Baseline, Z-score, IQR, moving average → `calculate_anomaly_score` (0-100) |
| `ids/risk_engine.py` | Hybrid weighted score (`calculate_risk_score`), bands and severities |
| `ids/alert_engine.py` | `generate_alert` + recommended investigation steps |
| `ids/correlation.py` | `correlate_alerts` (source IP + alert type + 60 s window) → incidents |
| `ids/pipeline.py` | Glue: features → rules + anomaly + ML → risk |
| `ml/train_model.py, predict.py, evaluate.py` | Logistic Regression, Random Forest, Isolation Forest; metrics computed on a held-out 25 % test set |
| `backend/app.py` | Flask REST API, rate limiting, optional API-key auth, serves the dashboard |
| `backend/db.py` | SQLite schema (5 tables + indexes) and queries (parameterised) |
| `backend/service.py` | Validate → analyze → store flow → create alert |
| `frontend/index.html` | SOC dashboard (cards, 8 charts, filters, investigation modal), polling every 3 s |
| `tests/test_ids.py` | 33 automated tests |
| `data/ models/ screenshots/ docs/ reports/` | Generated data, saved models, your screenshots, your docs and report |
| `run.py` | One-command launcher |

*Simplification vs. the long spec:* the backend is a flat package (`app/db/service`) and the frontend is a single
HTML file (no Node/React build) so a beginner can run it in minutes. Polling was chosen over SSE/WebSockets
because it is the simplest and robust.

## 4. How detection works

```
flow → validate/features → [Rules | Anomaly | ML] → weighted risk → alert (if rule hit or risk > 40) → DB → dashboard
```
* **Rules:** IDS-001 connection rate, -002 failed connections, -003 many ports, -004 SYN-heavy, -005 unusual port, -006 volume. Thresholds live in the `rules` table and can be changed via `PUT /api/rules/{id}`. A match means *investigate*, not *proven attack*.
* **Anomaly:** baseline (mean/std/quartiles) is learned from the NORMAL rows; each metric gets a Z-score + IQR-fence score; result 0-100. Finds unseen patterns but can cause false positives.
* **ML:** Random Forest probability (if `models/random_forest.joblib` exists).
* **Risk:** with ML 40 % rule + 30 % anomaly + 30 % ML; without ML 60 % / 40 %. Bands: 0-20 NORMAL, 21-40 LOW, 41-60 SUSPICIOUS, 61-80 HIGH, 81-100 CRITICAL. These are **project assumptions** - calibrate in a real SOC.
* **Why accuracy alone is not enough:** with 70 % normal traffic a model that says "NORMAL" always is 70 % accurate yet misses every attack. Check recall (missed attacks), precision (false alarms) and F1.

## 5. Scenario results (measured on 200 generated flows each)

| Scenario | Rule triggered | Typical risk | Result |
|---|---|---|---|
| A Normal HTTPS | none | 0-22 | NORMAL, no alert |
| B Normal DNS | none | 1-14 | NORMAL, no alert |
| C Repeated failed connections | IDS-002 | ≈75-80 | POTENTIAL INTRUSION, HIGH alert |
| D High connection rate | IDS-001 | ≈76-85 | POTENTIAL INTRUSION |
| E Multi-port probing-like | IDS-003 (+IDS-005) | ≈80-83 | POTENTIAL INTRUSION |
| F SYN-heavy | IDS-004 | ≈60-72 | SUSPICIOUS / POTENTIAL INTRUSION |
| G High traffic volume | IDS-006 | ≈80 | POTENTIAL INTRUSION |

Your numbers can differ slightly because of random generation. The ML metrics are printed by `python -m ml.train_model`
(in our run the Random Forest scored accuracy 0.984, recall 0.952; the Isolation Forest was clearly weaker - this is expected for unsupervised models).

## 6. REST API

| Method | Endpoint | Notes |
|---|---|---|
| POST | `/api/flows` | JSON flow → 201 created, 200 duplicate, 422 invalid, 400 bad body |
| GET | `/api/flows`, `/api/flows/{id}` | 404 if missing |
| GET | `/api/alerts` | filters: `severity, protocol, status, alert_type, minutes, limit` |
| GET | `/api/alerts/{id}` | includes notes/timeline |
| PUT | `/api/alerts/{id}/status` | body `{"status":"INVESTIGATING","note":"..."}` |
| POST | `/api/alerts/{id}/notes` | body `{"note":"..."}` |
| GET | `/api/dashboard/stats`, `/traffic`, `/alerts` | dashboard data |
| GET | `/api/rules`; PUT `/api/rules/{id}` | tune thresholds / enable / severity |
| GET | `/api/incidents` | correlated alerts |
| POST | `/api/simulate` | `{"scenario":"SYN_HEAVY_PATTERN"}` generates one synthetic record |

Authentication: set `API_KEY` in `.env`/environment → all POST/PUT calls need header `X-API-Key`. (Default empty = open, for local demo only.) Rate limit: `RATE_LIMIT_PER_MIN`.

## 7. Security & privacy notes
Synthetic data only; no payload storage; SQL parameter binding; dashboard output escaped; request size limit; rate limit; secrets via environment; in production add real analyst login/RBAC, HTTPS, audit logs, least privilege. IDS data itself is sensitive (it reveals network layout and weaknesses).

## 8. False positives / negatives
FP: a nightly backup triggers the volume rule. FN: a slow, low-rate scan stays under thresholds. Reduce both with better baselines, combining methods, threshold tuning, analyst feedback (FALSE_POSITIVE statuses) and context (asset inventory, scan schedules).

## 9. GitHub & LinkedIn
1. `git init && git add . && git commit -m "Network IDS simulation"` → create a repo → push.
2. Add 4-5 screenshots to `screenshots/` (dashboard, alert investigation, test run, ML metrics) and link them here.
3. Pin the repo; LinkedIn post: *"Built a hybrid Network IDS simulation (rules + statistical anomaly + ML) with SOC dashboard, alert correlation and incident workflow - Python, Flask, SQLite, scikit-learn, 33 automated tests."*
4. Resume bullet: *Designed and implemented a hybrid network IDS processing 5,000 synthetic flows with 6 signature rules, Z-score/IQR anomaly scoring and a Random Forest model (computed F1 reported in README); built REST API, SQLite store and analyst triage dashboard.*

## 10. Interview prep (short)
IDS vs IPS (detects vs blocks) · NIDS vs HIDS · signature vs anomaly · why hybrid · flow vs packet · why precision/recall matter · how you would reduce false positives · what is an incident vs alert · why synthetic data (safety/legal) and its limitation (not real-world traffic, labels derive from the generator, so ML scores are optimistic).

## 11. Troubleshooting
* `python` not found → try `python3` / `py`.
* Port busy → `PORT=5050 python run.py` (Windows PowerShell: `$env:PORT=5050; python run.py`); pass `--url http://127.0.0.1:5050/api/flows` to the simulator.
* Reset everything → stop the server and delete `ids.db`.
