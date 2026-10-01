"""30+ automated tests. Run:  python -m unittest discover -s tests -v   (or: pytest)"""
import os
import random
import tempfile
import unittest

from backend.app import create_app
from ids.alert_engine import generate_alert
from ids.anomaly_detector import build_baseline, calculate_anomaly_score, moving_average
from ids.correlation import correlate_alerts
from ids.feature_extractor import FlowValidationError, extract_network_features
from ids.risk_engine import calculate_risk_score
from ids.rule_engine import DEFAULT_RULES, analyze_flow
from simulator.generate_dataset import generate_dataset, make_flow

RNG = random.Random(7)


def base(**kw):
    f = dict(source_ip="192.0.2.15", destination_ip="198.51.100.20", source_port=50000, destination_port=443,
             protocol="TCP", packet_count=20, byte_count=12000, duration_seconds=5, connection_count=2,
             failed_connection_count=0, syn_count=2, rst_count=0)
    f.update(kw)
    return f


def feats(**kw):
    return extract_network_features(base(**kw))


def rule_ids(**kw):
    return {m["rule_id"] for m in analyze_flow(feats(**kw), DEFAULT_RULES)}


APP = create_app(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), use_ml=True)
CLIENT = APP.test_client()
BASELINE = build_baseline(extract_network_features(make_flow("NORMAL_WEB", RNG)) and
                          [extract_network_features(r) for r in generate_dataset(800) if r["label"] == "NORMAL"])


class T(unittest.TestCase):
    # ---- normal traffic (T01-T04)
    def test01_normal_tcp(self): self.assertEqual(rule_ids(), set())
    def test02_normal_udp(self): self.assertEqual(rule_ids(protocol="UDP", destination_port=123), set())
    def test03_normal_dns(self): self.assertEqual(rule_ids(protocol="UDP", destination_port=53, packet_count=2), set())
    def test04_normal_https(self): self.assertEqual(rule_ids(destination_port=443), set())
    # ---- suspicious patterns (T05-T09)
    def test05_high_conn_rate(self): self.assertIn("IDS-001", rule_ids(connection_count=300, duration_seconds=5))
    def test06_failed_conns(self): self.assertIn("IDS-002", rule_ids(connection_count=50, failed_connection_count=45))
    def test07_multi_port(self): self.assertIn("IDS-003", rule_ids(unique_destination_ports=80))
    def test08_syn_heavy(self): self.assertIn("IDS-004", rule_ids(packet_count=500, syn_count=480))
    def test09_high_volume(self): self.assertIn("IDS-006", rule_ids(byte_count=200_000_000, duration_seconds=60))
    # ---- invalid input (T10-T16)
    def test10_bad_src_ip(self):
        with self.assertRaises(FlowValidationError): feats(source_ip="999.1.1.1")
    def test11_bad_dst_ip(self):
        with self.assertRaises(FlowValidationError): feats(destination_ip="not-an-ip")
    def test12_bad_src_port(self):
        with self.assertRaises(FlowValidationError): feats(source_port=-5)
    def test13_bad_dst_port(self):
        with self.assertRaises(FlowValidationError): feats(destination_port=70000)
    def test14_bad_protocol(self):
        with self.assertRaises(FlowValidationError): feats(protocol="XYZ")
    def test15_missing_packets(self):
        f = base(); del f["packet_count"]
        r = extract_network_features(f)
        self.assertEqual(r["packet_count"], 0)
        self.assertTrue(r["warnings"])
    def test16_zero_duration(self):
        r = feats(duration_seconds=0)
        self.assertEqual(r["bytes_per_second"], 12000)          # floored to 1 second, no crash

    # ---- engines (T17-T21)
    def test17_feature_extraction(self):
        r = feats(packet_count=20, byte_count=10000, duration_seconds=10, connection_count=4, failed_connection_count=2)
        self.assertEqual(r["average_packet_size"], 500)
        self.assertAlmostEqual(r["failure_ratio"], 0.5)
        self.assertAlmostEqual(r["packets_per_second"], 2)
    def test18_rule_detection_disabled_rule(self):
        rules = [dict(r, enabled=0) for r in DEFAULT_RULES]
        self.assertEqual(analyze_flow(feats(connection_count=999, duration_seconds=1), rules), [])
    def test19_anomaly_score(self):
        normal = calculate_anomaly_score(feats(), BASELINE)
        wild = calculate_anomaly_score(feats(connection_count=500, duration_seconds=2, unique_destination_ports=300), BASELINE)
        self.assertLess(normal, 25)
        self.assertGreater(wild, 50)
        self.assertTrue(0 <= wild <= 100)
    def test20_risk_score(self):
        no_ml = calculate_risk_score(70, 60)
        self.assertAlmostEqual(no_ml["risk_score"], 0.6 * 70 + 0.4 * 60)
        with_ml = calculate_risk_score(70, 60, 0.78)
        self.assertAlmostEqual(with_ml["risk_score"], 0.4 * 70 + 0.3 * 60 + 0.3 * 78)
        self.assertEqual(calculate_risk_score(0, 0)["classification"], "NORMAL")
        self.assertEqual(calculate_risk_score(100, 100, 1)["severity"], "CRITICAL")
    def test21_alert_creation(self):
        f = feats(connection_count=300, duration_seconds=5)
        m = analyze_flow(f, DEFAULT_RULES)
        a = generate_alert("ALT-10001", "F1", f, m, 50, None, calculate_risk_score(70, 50))
        self.assertEqual(a["status"], "NEW")
        self.assertEqual(a["rule_id"], "IDS-001")
        self.assertTrue(a["details"]["recommended_steps"])

    # ---- correlation / workflow / database (T22-T26)
    def test22_correlation(self):
        al = [dict(alert_id=f"A{i}", source_ip="203.0.113.5", alert_type="X", timestamp=f"2026-10-01T10:00:{i:02d}",
                   risk_score=50 + i, severity="HIGH") for i in range(5)]
        al.append(dict(alert_id="Z", source_ip="203.0.113.5", alert_type="X", timestamp="2026-10-01T11:00:00",
                       risk_score=10, severity="LOW"))
        inc = correlate_alerts(al, 60)
        self.assertEqual(len(inc), 2)
        self.assertEqual(max(i["alert_count"] for i in inc), 5)
    def _suspicious_alert(self):
        r = CLIENT.post("/api/simulate", json={"scenario": "MULTI_PORT_PROBING_PATTERN"}).get_json()
        return r["alert_id"]
    def test23_status_update(self):
        aid = self._suspicious_alert()
        r = CLIENT.put(f"/api/alerts/{aid}/status", json={"status": "INVESTIGATING"})
        self.assertEqual(r.get_json()["status"], "INVESTIGATING")
        self.assertIsNotNone(r.get_json()["investigated_at"])
        CLIENT.put(f"/api/alerts/{aid}/status", json={"status": "FALSE_POSITIVE"})
        self.assertEqual(CLIENT.get(f"/api/alerts/{aid}").get_json()["status"], "FALSE_POSITIVE")
    def test24_analyst_note(self):
        aid = self._suspicious_alert()
        r = CLIENT.post(f"/api/alerts/{aid}/notes", json={"note": "Checked firewall"})
        self.assertEqual(r.status_code, 201)
        self.assertIn("Checked firewall", [n["note"] for n in r.get_json()["notes"]])
    def test25_database_storage(self):
        r = CLIENT.post("/api/flows", json=base(flow_id="DB-TEST-1"))
        self.assertEqual(r.status_code, 201)
        self.assertEqual(CLIENT.get("/api/flows/DB-TEST-1").get_json()["destination_port"], 443)
        self.assertEqual(CLIENT.get("/api/flows/NOPE").status_code, 404)
    def test26_dashboard_stats(self):
        CLIENT.post("/api/simulate", json={"scenario": "NORMAL_WEB"})
        s = CLIENT.get("/api/dashboard/stats").get_json()
        self.assertGreaterEqual(s["total_flows"], 1)
        self.assertEqual(s["total_flows"], s["normal_flows"] + s["suspicious_flows"])

    # ---- ML / API / edge cases (T27-T30)
    def test27_ml_prediction(self):
        from ml.predict import load_model, predict_probability
        m = load_model()
        self.assertIsNotNone(m, "run: python -m ml.train_model first")
        bad = predict_probability(m, extract_network_features(make_flow("HIGH_TRAFFIC_VOLUME", RNG)))
        good = predict_probability(m, extract_network_features(make_flow("NORMAL_WEB", RNG)))
        self.assertGreater(bad, 0.5)
        self.assertLess(good, 0.5)
    def test28_api_validation(self):
        self.assertEqual(CLIENT.post("/api/flows", json=base(protocol="BAD")).status_code, 422)
        self.assertEqual(CLIENT.post("/api/flows", data="nope", content_type="text/plain").status_code, 400)
        self.assertEqual(CLIENT.put("/api/alerts/ALT-1/status", json={"status": "WHATEVER"}).status_code, 400)
        self.assertEqual(CLIENT.put("/api/alerts/ALT-NOPE/status", json={"status": "RESOLVED"}).status_code, 404)
        self.assertEqual(CLIENT.post("/api/simulate", json={"scenario": "ATTACK_REAL_HOST"}).status_code, 400)
    def test29_empty_dataset(self):
        b = build_baseline([])
        self.assertEqual(calculate_anomaly_score(feats(), b) >= 0, True)
        a = create_app(db_path=os.path.join(tempfile.mkdtemp(), "e.db"), use_ml=False, csv_path="missing.csv")
        self.assertEqual(a.test_client().get("/api/dashboard/stats").get_json()["total_flows"], 0)
        self.assertEqual(a.test_client().get("/api/alerts").get_json(), [])
    def test30_duplicate_event(self):
        first = CLIENT.post("/api/flows", json=base(flow_id="DUP-1"))
        second = CLIENT.post("/api/flows", json=base(flow_id="DUP-1"))
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 200)
        self.assertTrue(second.get_json()["duplicate"])
    # ---- bonus
    def test31_dataset_size_and_ranges(self):
        rows = generate_dataset(5000)
        self.assertEqual(len(rows), 5000)
        self.assertTrue(all(r["source_ip"].split(".")[0:3] in (["192", "0", "2"], ["203", "0", "113"]) for r in rows))
    def test32_moving_average(self):
        self.assertEqual(moving_average([2, 4, 6], 2), [2, 3, 5])
    def test33_rule_update_api(self):
        r = CLIENT.put("/api/rules/IDS-001", json={"threshold": {"max_connection_rate": 15}})
        self.assertEqual(r.get_json()["threshold"]["max_connection_rate"], 15)
        CLIENT.put("/api/rules/IDS-001", json={"threshold": {"max_connection_rate": 10}})
        self.assertEqual(CLIENT.put("/api/rules/NOPE", json={}).status_code, 404)


if __name__ == "__main__":
    unittest.main()
