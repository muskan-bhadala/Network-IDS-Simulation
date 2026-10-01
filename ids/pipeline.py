"""Glue: features -> rules + anomaly + ML -> risk."""
from ids.feature_extractor import extract_network_features
from ids.rule_engine import analyze_flow, signature_risk
from ids.anomaly_detector import calculate_anomaly_score
from ids.risk_engine import calculate_risk_score


class IDSPipeline:
    def __init__(self, baseline, ml_model=None, weights=None):
        self.baseline, self.ml_model, self.weights = baseline, ml_model, weights

    def analyze(self, flow, rules=None):
        features = extract_network_features(flow)          # may raise FlowValidationError
        matches = analyze_flow(features, rules)
        sig = signature_risk(matches)
        anomaly = calculate_anomaly_score(features, self.baseline)
        ml_prob = None
        if self.ml_model is not None:
            from ml.predict import predict_probability
            ml_prob = predict_probability(self.ml_model, features)
        risk = calculate_risk_score(sig, anomaly, ml_prob, self.weights)
        if matches and risk["classification"] == "NORMAL":
            risk["classification"] = "SUSPICIOUS"   # a rule hit always deserves analyst attention
        return {"features": features, "rule_matches": matches, "signature_risk": sig,
                "anomaly_score": anomaly, "ml_probability": ml_prob, "risk": risk}
