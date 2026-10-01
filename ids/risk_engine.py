"""Hybrid risk scoring. Thresholds are PROJECT ASSUMPTIONS - calibrate them in a real SOC."""
WEIGHTS_WITH_ML = {"rule": 0.4, "anomaly": 0.3, "ml": 0.3}
WEIGHTS_NO_ML = {"rule": 0.6, "anomaly": 0.4}

BANDS = [(20, "NORMAL", "INFO"), (40, "LOW RISK", "LOW"), (60, "SUSPICIOUS", "MEDIUM"),
         (80, "HIGH RISK", "HIGH"), (100, "CRITICAL INVESTIGATION", "CRITICAL")]


def calculate_risk_score(signature_score, anomaly_score, ml_probability=None, weights=None):
    """Weighted blend -> dict with score (0-100), band, severity, flow classification."""
    if ml_probability is None:
        w = weights or WEIGHTS_NO_ML
        score = w["rule"] * signature_score + w["anomaly"] * anomaly_score
    else:
        w = weights or WEIGHTS_WITH_ML
        score = w["rule"] * signature_score + w["anomaly"] * anomaly_score + w["ml"] * ml_probability * 100
    score = round(max(0.0, min(100.0, score)), 2)
    band, severity = next((b, s) for limit, b, s in BANDS if score <= limit)
    classification = "NORMAL" if score <= 40 else "SUSPICIOUS" if score <= 60 else "POTENTIAL INTRUSION"
    return {"risk_score": score, "band": band, "severity": severity, "classification": classification}
