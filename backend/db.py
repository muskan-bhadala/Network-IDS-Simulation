"""SQLite storage. Parameterised queries only (prevents SQL injection)."""
import json
import sqlite3
from datetime import datetime, timezone

from ids.rule_engine import DEFAULT_RULES

SCHEMA = """
CREATE TABLE IF NOT EXISTS network_flows(
  flow_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source_ip TEXT, destination_ip TEXT,
  source_port INTEGER, destination_port INTEGER, protocol TEXT, packet_count REAL, byte_count REAL,
  duration REAL, connection_count REAL, failed_connection_count REAL, syn_count REAL, rst_count REAL,
  risk_score REAL, classification TEXT);
CREATE TABLE IF NOT EXISTS alerts(
  alert_id TEXT PRIMARY KEY, flow_id TEXT REFERENCES network_flows(flow_id), rule_id TEXT, alert_type TEXT,
  severity TEXT, description TEXT, risk_score REAL, status TEXT DEFAULT 'NEW', created_at TEXT,
  source_ip TEXT, destination_ip TEXT, protocol TEXT, source_port INTEGER, destination_port INTEGER,
  anomaly_score REAL, ml_score REAL, details_json TEXT, investigated_at TEXT, resolved_at TEXT);
CREATE TABLE IF NOT EXISTS rules(
  rule_id TEXT PRIMARY KEY, rule_name TEXT, description TEXT, severity TEXT, threshold TEXT, enabled INTEGER);
CREATE TABLE IF NOT EXISTS incident_notes(
  note_id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT REFERENCES alerts(alert_id),
  note TEXT, kind TEXT DEFAULT 'NOTE', created_at TEXT);
CREATE TABLE IF NOT EXISTS model_results(
  result_id INTEGER PRIMARY KEY AUTOINCREMENT, flow_id TEXT REFERENCES network_flows(flow_id),
  model_name TEXT, prediction TEXT, score REAL);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON network_flows(timestamp);
CREATE INDEX IF NOT EXISTS idx_flows_src ON network_flows(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_notes_alert ON incident_notes(alert_id);
"""
STATUSES = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def connect(path):
    con = sqlite3.connect(path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def init_db(con):
    con.executescript(SCHEMA)
    for r in DEFAULT_RULES:
        con.execute("INSERT OR IGNORE INTO rules VALUES(?,?,?,?,?,?)",
                    (r["rule_id"], r["name"], r["description"], r["severity"],
                     json.dumps(r["threshold"]), r["enabled"]))
    con.commit()


def get_rules(con):
    return [{"rule_id": r["rule_id"], "name": r["rule_name"], "description": r["description"],
             "severity": r["severity"], "threshold": json.loads(r["threshold"]), "enabled": r["enabled"]}
            for r in con.execute("SELECT * FROM rules ORDER BY rule_id")]


def update_rule(con, rule_id, enabled=None, severity=None, threshold=None):
    cur = get_rules(con)
    rule = next((r for r in cur if r["rule_id"] == rule_id), None)
    if not rule:
        return None
    if enabled is not None:
        rule["enabled"] = 1 if enabled else 0
    if severity:
        rule["severity"] = severity
    if threshold:
        rule["threshold"].update(threshold)
    con.execute("UPDATE rules SET enabled=?, severity=?, threshold=? WHERE rule_id=?",
                (rule["enabled"], rule["severity"], json.dumps(rule["threshold"]), rule_id))
    con.commit()
    return rule


def insert_flow(con, flow_id, ts, f, risk, classification):
    cur = con.execute("INSERT OR IGNORE INTO network_flows VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (flow_id, ts, f["source_ip"], f["destination_ip"], f["source_port"], f["destination_port"],
                       f["protocol"], f["packet_count"], f["byte_count"], f["duration"], f["connection_count"],
                       f["failed_connection_count"], f["syn_count"], f["rst_count"], risk, classification))
    con.commit()
    return cur.rowcount == 1          # False => duplicate flow_id ignored


def next_alert_id(con):
    return f"ALT-{10001 + con.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]}"


def insert_alert(con, a):
    con.execute("INSERT INTO alerts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (a["alert_id"], a["flow_id"], a["rule_id"], a["alert_type"], a["severity"], a["description"],
                 a["risk_score"], "NEW", a["timestamp"], a["source_ip"], a["destination_ip"], a["protocol"],
                 a["source_port"], a["destination_port"], a["anomaly_score"], a["ml_score"],
                 json.dumps(a["details"]), None, None))
    con.commit()


def alert_row(r):
    d = dict(r)
    d["details"] = json.loads(d.pop("details_json") or "{}")
    return d


def list_alerts(con, severity=None, protocol=None, status=None, alert_type=None, minutes=None, limit=200):
    q, p = "SELECT * FROM alerts WHERE 1=1", []
    for col, val in (("severity", severity), ("protocol", protocol), ("status", status), ("alert_type", alert_type)):
        if val:
            q += f" AND {col}=?"      # column names are fixed above, values are bound
            p.append(val)
    if minutes:
        q += " AND created_at >= datetime('now', ?)"
        p.append(f"-{int(minutes)} minutes")
    q += " ORDER BY created_at DESC, alert_id DESC LIMIT ?"
    p.append(int(limit))
    return [alert_row(r) for r in con.execute(q, p)]


def get_alert(con, alert_id):
    r = con.execute("SELECT * FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
    if not r:
        return None
    d = alert_row(r)
    d["notes"] = [dict(n) for n in con.execute(
        "SELECT * FROM incident_notes WHERE alert_id=? ORDER BY note_id", (alert_id,))]
    return d


def set_status(con, alert_id, status, note=None):
    a = con.execute("SELECT status FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
    if not a:
        return False
    t = now()
    con.execute("UPDATE alerts SET status=?, investigated_at=COALESCE(investigated_at, ?), resolved_at=? "
                "WHERE alert_id=?",
                (status, t if status != "NEW" else None, t if status in ("RESOLVED", "FALSE_POSITIVE") else None,
                 alert_id))
    add_note(con, alert_id, f"Status {a['status']} -> {status}" + (f": {note}" if note else ""), "STATUS")
    return True


def add_note(con, alert_id, note, kind="NOTE"):
    con.execute("INSERT INTO incident_notes(alert_id,note,kind,created_at) VALUES(?,?,?,?)",
                (alert_id, note, kind, now()))
    con.commit()


def list_flows(con, limit=100):
    return [dict(r) for r in con.execute("SELECT * FROM network_flows ORDER BY timestamp DESC LIMIT ?", (limit,))]


def get_flow(con, flow_id):
    r = con.execute("SELECT * FROM network_flows WHERE flow_id=?", (flow_id,)).fetchone()
    return dict(r) if r else None


def _groups(con, sql, p=()):
    return [dict(r) for r in con.execute(sql, p)]


def stats(con):
    one = lambda s: con.execute(s).fetchone()[0] or 0
    return {"total_flows": one("SELECT COUNT(*) FROM network_flows"),
            "normal_flows": one("SELECT COUNT(*) FROM network_flows WHERE classification='NORMAL'"),
            "suspicious_flows": one("SELECT COUNT(*) FROM network_flows WHERE classification!='NORMAL'"),
            "open_alerts": one("SELECT COUNT(*) FROM alerts WHERE status IN ('NEW','INVESTIGATING')"),
            "critical_alerts": one("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'"),
            "avg_risk": round(one("SELECT AVG(risk_score) FROM network_flows"), 2)}


def traffic(con):
    series = _groups(con, """SELECT substr(timestamp,1,16) AS minute, COUNT(*) AS flows, SUM(packet_count) AS packets,
        SUM(byte_count) AS bytes, SUM(failed_connection_count) AS failed, SUM(connection_count) AS connections
        FROM (SELECT * FROM network_flows ORDER BY timestamp DESC LIMIT 3000) GROUP BY minute ORDER BY minute""")
    return {"series": series[-60:],
            "protocols": _groups(con, "SELECT protocol AS label, COUNT(*) AS value FROM network_flows GROUP BY protocol"),
            "ports": _groups(con, "SELECT CAST(destination_port AS TEXT) AS label, COUNT(*) AS value FROM network_flows "
                                  "GROUP BY destination_port ORDER BY value DESC LIMIT 10"),
            "risk_hist": _groups(con, "SELECT CAST(MIN(risk_score/10,9) AS INT)*10 AS label, COUNT(*) AS value "
                                      "FROM network_flows GROUP BY label ORDER BY label"),
            "classes": _groups(con, "SELECT classification AS label, COUNT(*) AS value FROM network_flows "
                                    "GROUP BY classification")}


def alert_dist(con):
    return {"severity": _groups(con, "SELECT severity AS label, COUNT(*) AS value FROM alerts GROUP BY severity"),
            "types": _groups(con, "SELECT alert_type AS label, COUNT(*) AS value FROM alerts GROUP BY alert_type "
                                  "ORDER BY value DESC LIMIT 6"),
            "sources": _groups(con, "SELECT source_ip AS label, COUNT(*) AS value FROM alerts GROUP BY source_ip "
                                    "ORDER BY value DESC LIMIT 6")}
