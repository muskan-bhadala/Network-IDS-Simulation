"""Business logic: validate -> analyze -> store flow -> create alert."""
import os
import threading
import uuid

from backend import db
from ids.alert_engine import generate_alert
from ids.anomaly_detector import build_baseline
from ids.feature_extractor import extract_network_features
from ids.pipeline import IDSPipeline
from ml.predict import load_model

_lock = threading.Lock()


def build_pipeline(csv_path="data/network_traffic.csv", use_ml=True):
    import csv
    rows = []
    if os.path.exists(csv_path):
        with open(csv_path) as fh:
            rows = [extract_network_features(r) for r in csv.DictReader(fh) if r["label"] == "NORMAL"]
    baseline = build_baseline(rows)
    return IDSPipeline(baseline, load_model() if use_ml else None)


def process_flow(con, pipeline, flow):
    """Returns result dict. Raises FlowValidationError for bad input."""
    result = pipeline.analyze(flow, db.get_rules(con))
    f, risk = result["features"], result["risk"]
    flow_id = str(flow.get("flow_id") or f"FLW-{uuid.uuid4().hex[:12]}")
    ts = str(flow.get("timestamp") or db.now())[:19]
    with _lock:
        inserted = db.insert_flow(con, flow_id, ts, f, risk["risk_score"], risk["classification"])
        alert = None
        if inserted and (result["rule_matches"] or risk["risk_score"] > 40):
            alert = generate_alert(db.next_alert_id(con), flow_id, f, result["rule_matches"],
                                   result["anomaly_score"], result["ml_probability"], risk)
            db.insert_alert(con, alert)
    return {"flow_id": flow_id, "duplicate": not inserted, "classification": risk["classification"],
            "risk_score": risk["risk_score"], "severity": risk["severity"],
            "signature_risk": result["signature_risk"], "anomaly_score": result["anomaly_score"],
            "ml_probability": result["ml_probability"],
            "rules_triggered": [m["rule_id"] for m in result["rule_matches"]],
            "alert_id": alert["alert_id"] if alert else None}
