"""Flask REST API + dashboard host.   Run:  python -m backend.app"""
import os
import time
from collections import defaultdict

from flask import Flask, jsonify, request, send_from_directory

from backend import db, service
from ids.correlation import correlate_alerts
from ids.feature_extractor import FlowValidationError
from simulator.generate_dataset import NORMAL_SCENARIOS, SUSPICIOUS_SCENARIOS, make_flow

FRONTEND = os.path.join(os.path.dirname(__file__), "..", "frontend")
SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def create_app(db_path=None, use_ml=True, csv_path="data/network_traffic.csv"):
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    con = db.connect(db_path or os.getenv("DATABASE_PATH", "ids.db"))
    db.init_db(con)
    pipeline = service.build_pipeline(csv_path, use_ml)
    api_key = os.getenv("API_KEY", "")           # empty = auth disabled (local demo)
    hits = defaultdict(list)
    limit = int(os.getenv("RATE_LIMIT_PER_MIN", "1200"))

    def err(msg, code):
        return jsonify({"error": msg}), code

    @app.before_request
    def guard():
        if not request.path.startswith("/api/"):
            return None
        now = time.time()
        h = hits[request.remote_addr] = [t for t in hits[request.remote_addr] if now - t < 60]
        if len(h) >= limit:
            return err("Rate limit exceeded", 429)
        h.append(now)
        if api_key and request.method != "GET" and request.headers.get("X-API-Key") != api_key:
            return err("Unauthorized: missing or invalid X-API-Key", 401)
        return None

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        return resp

    # ---------- dashboard ----------
    @app.get("/")
    def index():
        return send_from_directory(FRONTEND, "index.html")

    # ---------- flows ----------
    @app.post("/api/flows")
    def post_flow():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return err("Body must be a JSON object", 400)
        try:
            res = service.process_flow(con, pipeline, body)
        except FlowValidationError as e:
            return err(str(e), 422)
        return jsonify(res), 200 if res["duplicate"] else 201

    @app.get("/api/flows")
    def flows():
        return jsonify(db.list_flows(con, min(int(request.args.get("limit", 100)), 1000)))

    @app.get("/api/flows/<flow_id>")
    def flow(flow_id):
        f = db.get_flow(con, flow_id)
        return jsonify(f) if f else err("Flow not found", 404)

    @app.post("/api/simulate")
    def simulate():
        """Generate ONE synthetic flow record for a scenario (no packets are sent)."""
        sc = (request.get_json(silent=True) or {}).get("scenario", "NORMAL_WEB")
        if sc not in NORMAL_SCENARIOS + SUSPICIOUS_SCENARIOS:
            return err("Unknown scenario", 400)
        f = make_flow(sc)
        f.pop("label"), f.pop("scenario_type")
        res = service.process_flow(con, pipeline, f)
        res["scenario"] = sc
        return jsonify(res), 201

    # ---------- alerts ----------
    @app.get("/api/alerts")
    def alerts():
        a = request.args
        return jsonify(db.list_alerts(con, a.get("severity"), a.get("protocol"), a.get("status"),
                                      a.get("alert_type"), a.get("minutes"), min(int(a.get("limit", 200)), 1000)))

    @app.get("/api/alerts/<alert_id>")
    def alert(alert_id):
        a = db.get_alert(con, alert_id)
        return jsonify(a) if a else err("Alert not found", 404)

    @app.put("/api/alerts/<alert_id>/status")
    def alert_status(alert_id):
        body = request.get_json(silent=True) or {}
        if body.get("status") not in db.STATUSES:
            return err(f"status must be one of {db.STATUSES}", 400)
        if not db.set_status(con, alert_id, body["status"], str(body.get("note", ""))[:1000] or None):
            return err("Alert not found", 404)
        return jsonify(db.get_alert(con, alert_id))

    @app.post("/api/alerts/<alert_id>/notes")
    def alert_note(alert_id):
        note = str((request.get_json(silent=True) or {}).get("note", "")).strip()
        if not note or len(note) > 1000:
            return err("note is required (max 1000 chars)", 400)
        if not db.get_alert(con, alert_id):
            return err("Alert not found", 404)
        db.add_note(con, alert_id, note)
        return jsonify(db.get_alert(con, alert_id)), 201

    @app.get("/api/incidents")
    def incidents():
        return jsonify(correlate_alerts(db.list_alerts(con, limit=1000), int(request.args.get("window", 60))))

    # ---------- dashboard data ----------
    @app.get("/api/dashboard/stats")
    def d_stats():
        return jsonify(db.stats(con))

    @app.get("/api/dashboard/traffic")
    def d_traffic():
        return jsonify(db.traffic(con))

    @app.get("/api/dashboard/alerts")
    def d_alerts():
        return jsonify(db.alert_dist(con))

    # ---------- rules ----------
    @app.get("/api/rules")
    def rules():
        return jsonify(db.get_rules(con))

    @app.put("/api/rules/<rule_id>")
    def rule(rule_id):
        b = request.get_json(silent=True) or {}
        if "severity" in b and b["severity"] not in SEVERITIES:
            return err("Invalid severity", 400)
        if "threshold" in b and not isinstance(b["threshold"], dict):
            return err("threshold must be an object", 400)
        r = db.update_rule(con, rule_id, b.get("enabled"), b.get("severity"), b.get("threshold"))
        return jsonify(r) if r else err("Rule not found", 404)

    app.db = con
    return app


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    create_app().run(host="127.0.0.1", port=port, debug=False)
