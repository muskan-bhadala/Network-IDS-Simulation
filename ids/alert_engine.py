"""Alert creation with recommended (defensive) investigation steps."""
from datetime import datetime, timezone

STEPS = {
    "IDS-001": ["Check whether the source is a known scanner/monitoring host",
                "Compare connection rate with the historical baseline", "Review firewall records for this source"],
    "IDS-002": ["Review authentication logs on the destination", "Check if the account is locked/expected",
                "Confirm whether the source is a legitimate user or service"],
    "IDS-003": ["Check whether an authorised vulnerability scan was scheduled", "Review firewall logs for the source",
                "Verify which of the contacted ports are actually exposed"],
    "IDS-004": ["Check destination server load and half-open connections", "Review firewall/SYN-cookie statistics"],
    "IDS-005": ["Identify the service listening on that port", "Check change tickets for new services",
                "Review endpoint telemetry where authorised"],
    "IDS-006": ["Check for scheduled backups/transfers", "Identify the data owner of the destination",
                "Review DLP/proxy logs where authorised"],
    "ANOMALY": ["Compare with the historical baseline", "Check whether the activity is expected (new app, event)"],
}


def generate_alert(alert_id, flow_id, features, rule_matches, anomaly_score, ml_probability, risk):
    top = max(rule_matches, key=lambda m: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(m["severity"]),
              default=None)
    if top:
        rule_id, alert_type, desc = top["rule_id"], top["name"], top["description"]
        reason = "; ".join(f"{m['rule_id']}: {m['evidence']}" for m in rule_matches)
    else:
        rule_id, alert_type = "ANOMALY", "Anomalous Traffic Pattern"
        desc = "Traffic deviated significantly from the learned baseline."
        reason = f"anomaly_score={anomaly_score}"
    severity = risk["severity"]
    if rule_matches and severity == "INFO":
        severity = "LOW"
    steps = []
    for m in rule_matches or [{"rule_id": "ANOMALY"}]:
        steps += [s for s in STEPS.get(m["rule_id"], []) if s not in steps]
    steps.append("Determine whether the activity is expected before escalating")
    return {
        "alert_id": alert_id, "flow_id": flow_id,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
        "source_ip": features["source_ip"], "destination_ip": features["destination_ip"],
        "protocol": features["protocol"], "source_port": features["source_port"],
        "destination_port": features["destination_port"], "rule_id": rule_id,
        "alert_type": alert_type, "severity": severity, "risk_score": risk["risk_score"],
        "description": desc, "status": "NEW", "anomaly_score": anomaly_score,
        "ml_score": None if ml_probability is None else round(ml_probability * 100, 2),
        "details": {"reason": reason, "matched_rules": rule_matches, "recommended_steps": steps,
                    "stats": {k: features[k] for k in ("packet_count", "byte_count", "duration",
                              "connection_count", "failed_connection_count", "syn_count",
                              "unique_destination_ports", "connection_rate", "bytes_per_second")}},
    }
