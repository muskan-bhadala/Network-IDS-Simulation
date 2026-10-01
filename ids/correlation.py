"""Alert correlation. EVENT = one observation; ALERT = needs attention; INCIDENT = related alerts."""
from datetime import datetime

SEV = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _t(s):
    return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")


def correlate_alerts(alerts, window_seconds=60):
    """Group alerts with the same (source_ip, alert_type) that occur within the time window."""
    groups = {}
    for a in sorted(alerts, key=lambda x: x["timestamp"]):
        key = (a["source_ip"], a["alert_type"])
        bucket = groups.setdefault(key, [])
        if bucket and (_t(a["timestamp"]) - _t(bucket[-1][-1]["timestamp"])).total_seconds() <= window_seconds:
            bucket[-1].append(a)
        else:
            bucket.append([a])
    incidents = []
    for (src, typ), buckets in groups.items():
        for b in buckets:
            incidents.append({"source_ip": src, "alert_type": typ, "alert_count": len(b),
                              "first_seen": b[0]["timestamp"], "last_seen": b[-1]["timestamp"],
                              "max_risk": max(x["risk_score"] for x in b),
                              "max_severity": max((x["severity"] for x in b), key=SEV.index),
                              "alert_ids": [x["alert_id"] for x in b]})
    return sorted(incidents, key=lambda i: i["last_seen"], reverse=True)
