"""Signature / rule-based detection. A match means "investigate", NOT "proven attack"."""

SEVERITY_POINTS = {"INFO": 5, "LOW": 25, "MEDIUM": 45, "HIGH": 70, "CRITICAL": 90}
COMMON_PORTS = [20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995,
                3306, 5432, 8080, 8443]

DEFAULT_RULES = [
    {"rule_id": "IDS-001", "name": "High Connection Rate", "severity": "HIGH", "enabled": 1,
     "description": "Connection rate exceeded configured baseline.",
     "threshold": {"max_connection_rate": 10}},
    {"rule_id": "IDS-002", "name": "Repeated Failed Connections", "severity": "HIGH", "enabled": 1,
     "description": "Many failed connection attempts from one source.",
     "threshold": {"min_failed": 10, "min_failure_ratio": 0.5}},
    {"rule_id": "IDS-003", "name": "Many Destination Ports", "severity": "HIGH", "enabled": 1,
     "description": "One source contacted an unusually large number of destination ports.",
     "threshold": {"max_unique_ports": 20}},
    {"rule_id": "IDS-004", "name": "SYN-Heavy Behavior", "severity": "MEDIUM", "enabled": 1,
     "description": "Unusually high share of SYN packets in the flow.",
     "threshold": {"min_syn": 50, "min_syn_ratio": 0.8}},
    {"rule_id": "IDS-005", "name": "Unusual Service Port", "severity": "MEDIUM", "enabled": 1,
     "description": "Traffic to a port outside the approved service list.",
     "threshold": {"allowed_ports": COMMON_PORTS}},
    {"rule_id": "IDS-006", "name": "Abnormally High Traffic Volume", "severity": "HIGH", "enabled": 1,
     "description": "Byte volume or byte rate exceeded configured limits.",
     "threshold": {"max_bytes": 50_000_000, "max_bytes_per_second": 5_000_000}},
]


def _check(rule_id, f, t):
    """Return evidence string if the rule matches, else None."""
    if rule_id == "IDS-001" and f["connection_rate"] > t["max_connection_rate"]:
        return f"connection_rate={f['connection_rate']:.1f}/s > {t['max_connection_rate']}"
    if rule_id == "IDS-002" and f["failed_connection_count"] >= t["min_failed"] \
            and f["failure_ratio"] > t["min_failure_ratio"]:
        return f"failed={int(f['failed_connection_count'])}, ratio={f['failure_ratio']:.2f}"
    if rule_id == "IDS-003" and f["unique_destination_ports"] > t["max_unique_ports"]:
        return f"unique_destination_ports={int(f['unique_destination_ports'])} > {t['max_unique_ports']}"
    if rule_id == "IDS-004" and f["syn_count"] >= t["min_syn"] and f["syn_ratio"] > t["min_syn_ratio"]:
        return f"syn_count={int(f['syn_count'])}, syn_ratio={f['syn_ratio']:.2f}"
    if rule_id == "IDS-005" and f["protocol"] in ("TCP", "UDP") \
            and f["destination_port"] not in t["allowed_ports"]:
        return f"destination_port={f['destination_port']} not in approved list"
    if rule_id == "IDS-006" and (f["byte_count"] > t["max_bytes"]
                                 or f["bytes_per_second"] > t["max_bytes_per_second"]):
        return f"byte_count={int(f['byte_count'])}, bytes/s={int(f['bytes_per_second'])}"
    return None


def analyze_flow(features, rules=None):
    """Run every enabled rule against a feature dict. Returns list of matches."""
    matches = []
    for r in (rules or DEFAULT_RULES):
        if not r.get("enabled", 1):
            continue
        evidence = _check(r["rule_id"], features, r["threshold"])
        if evidence:
            matches.append({"rule_id": r["rule_id"], "name": r["name"], "severity": r["severity"],
                            "description": r["description"], "evidence": evidence})
    return matches


def signature_risk(matches):
    """0-100: strongest match + 5 points per extra match."""
    if not matches:
        return 0.0
    pts = sorted((SEVERITY_POINTS[m["severity"]] for m in matches), reverse=True)
    return float(min(100, pts[0] + 5 * (len(pts) - 1)))
