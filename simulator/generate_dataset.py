"""Synthetic flow-record generator (DATA ONLY - no packets are ever sent).

Run:  python -m simulator.generate_dataset
Output: data/network_traffic.csv  (5,000 rows)

Only RFC 5737 documentation IP ranges are used:
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
"""
import csv
import os
import random
from datetime import datetime, timedelta, timezone

NORMAL_SCENARIOS = ["NORMAL_WEB", "NORMAL_DNS", "NORMAL_SSH", "NORMAL_EMAIL", "NORMAL_DATABASE"]
SUSPICIOUS_SCENARIOS = ["HIGH_CONNECTION_RATE", "REPEATED_FAILED_CONNECTIONS",
                        "MULTI_PORT_PROBING_PATTERN", "SYN_HEAVY_PATTERN",
                        "UNUSUAL_PORT_ACTIVITY", "HIGH_TRAFFIC_VOLUME"]
UNUSUAL_PORTS = [4444, 6667, 31337, 1337, 9001, 12345, 5555, 8888]

COLUMNS = ["flow_id", "timestamp", "source_ip", "destination_ip", "source_port",
           "destination_port", "protocol", "packet_count", "byte_count",
           "duration_seconds", "connection_count", "failed_connection_count",
           "syn_count", "rst_count", "average_packet_size", "label", "scenario_type",
           "unique_destination_ports", "unique_destination_ips"]


def _ip(rng, net):
    return f"{net}.{rng.randint(1, 254)}"


def make_flow(scenario, rng=None, ts=None, flow_id=None):
    """Return ONE synthetic flow record (dict) for the given scenario."""
    rng = rng or random.Random()
    ts = ts or datetime.now(timezone.utc)
    f = dict(flow_id=flow_id or f"FLW-{rng.randint(0, 10**9):09d}",
             timestamp=ts.strftime("%Y-%m-%dT%H:%M:%S"),
             source_port=rng.randint(49152, 65535), protocol="TCP",
             failed_connection_count=0, rst_count=0,
             unique_destination_ports=1, unique_destination_ips=1,
             scenario_type=scenario, label="NORMAL")
    src_net, dst_net = "192.0.2", "198.51.100"
    size = 500
    if scenario == "NORMAL_WEB":
        f.update(destination_port=rng.choice([443] * 8 + [80] * 2), packet_count=rng.randint(8, 80),
                 duration_seconds=rng.uniform(1, 30), connection_count=rng.randint(1, 6),
                 syn_count=rng.randint(1, 3), rst_count=rng.choice([0, 0, 0, 1]),
                 unique_destination_ips=rng.randint(1, 2))
        size = rng.randint(200, 1200)
    elif scenario == "NORMAL_DNS":
        f.update(protocol="UDP", destination_port=53, packet_count=rng.randint(2, 4),
                 duration_seconds=rng.uniform(0.01, 0.5), connection_count=rng.randint(1, 3), syn_count=0)
        size = rng.randint(60, 120)
    elif scenario == "NORMAL_SSH":
        f.update(destination_port=22, packet_count=rng.randint(20, 300),
                 duration_seconds=rng.uniform(20, 600), connection_count=rng.randint(1, 2),
                 failed_connection_count=rng.choice([0, 0, 0, 1]), syn_count=rng.randint(1, 2))
        size = rng.randint(80, 300)
    elif scenario == "NORMAL_EMAIL":
        f.update(destination_port=rng.choice([25, 587, 993, 143, 465]), packet_count=rng.randint(10, 100),
                 duration_seconds=rng.uniform(2, 40), connection_count=rng.randint(1, 4),
                 syn_count=rng.randint(1, 3))
        size = rng.randint(300, 1400)
    elif scenario == "NORMAL_DATABASE":
        f.update(destination_port=rng.choice([3306, 5432]), packet_count=rng.randint(50, 1000),
                 duration_seconds=rng.uniform(5, 120), connection_count=rng.randint(1, 8),
                 syn_count=rng.randint(1, 3))
        size = rng.randint(200, 1400)
    else:  # suspicious patterns come from the documentation range 203.0.113.0/24
        src_net = "203.0.113"
        f["label"] = "SUSPICIOUS"
        if scenario == "HIGH_CONNECTION_RATE":
            conn = rng.randint(200, 600)
            f.update(destination_port=rng.choice([443, 80, 22]), connection_count=conn,
                     duration_seconds=rng.uniform(2, 15), packet_count=conn * rng.randint(4, 8),
                     failed_connection_count=int(conn * rng.uniform(0, 0.2)),
                     syn_count=int(conn * rng.uniform(0.3, 0.6)), rst_count=rng.randint(0, 10))
            size = rng.randint(60, 200)
        elif scenario == "REPEATED_FAILED_CONNECTIONS":
            conn = rng.randint(30, 120)
            failed = int(conn * rng.uniform(0.75, 0.95))
            f.update(destination_port=22, connection_count=conn, failed_connection_count=failed,
                     duration_seconds=rng.uniform(20, 120), packet_count=conn * 3,
                     syn_count=conn, rst_count=failed)
            size = rng.randint(50, 100)
        elif scenario == "MULTI_PORT_PROBING_PATTERN":
            ports = rng.randint(25, 200)
            conn = ports
            f.update(destination_port=rng.randint(1, 1023), unique_destination_ports=ports,
                     connection_count=conn, failed_connection_count=int(conn * rng.uniform(0.2, 0.45)),
                     duration_seconds=rng.uniform(60, 300), packet_count=conn * 2,
                     syn_count=conn, rst_count=int(conn * 0.3))
            size = rng.randint(40, 80)
        elif scenario == "SYN_HEAVY_PATTERN":
            pk = rng.randint(200, 1500)
            conn = rng.randint(20, 60)
            f.update(destination_port=rng.choice([80, 443]), packet_count=pk,
                     syn_count=int(pk * rng.uniform(0.85, 0.98)), connection_count=conn,
                     failed_connection_count=int(conn * 0.2), duration_seconds=rng.uniform(10, 60),
                     rst_count=rng.randint(0, 5))
            size = rng.randint(40, 60)
        elif scenario == "UNUSUAL_PORT_ACTIVITY":
            f.update(destination_port=rng.choice(UNUSUAL_PORTS), packet_count=rng.randint(20, 200),
                     duration_seconds=rng.uniform(10, 300), connection_count=rng.randint(1, 4),
                     syn_count=rng.randint(1, 3))
            size = rng.randint(100, 800)
        elif scenario == "HIGH_TRAFFIC_VOLUME":
            total = rng.randint(80_000_000, 600_000_000)
            size = rng.randint(1200, 1500)
            f.update(destination_port=443, packet_count=total // size,
                     duration_seconds=rng.uniform(20, 120), connection_count=rng.randint(1, 4),
                     syn_count=rng.randint(1, 3))
        else:
            raise ValueError(f"Unknown scenario: {scenario}")
    f["source_ip"] = _ip(rng, src_net)
    f["destination_ip"] = _ip(rng, dst_net)
    f["duration_seconds"] = round(f["duration_seconds"], 3)
    f["byte_count"] = f["packet_count"] * size
    f["average_packet_size"] = round(f["byte_count"] / max(f["packet_count"], 1), 2)
    return f


def generate_dataset(n=5000, seed=42, suspicious_fraction=0.3):
    rng = random.Random(seed)
    start = datetime.now(timezone.utc) - timedelta(hours=24)
    rows = []
    for i in range(n):
        pool = SUSPICIOUS_SCENARIOS if rng.random() < suspicious_fraction else NORMAL_SCENARIOS
        ts = start + timedelta(seconds=i * 86400 / n)
        rows.append(make_flow(rng.choice(pool), rng, ts, f"FLW-{i + 1:06d}"))
    return rows


def main(path="data/network_traffic.csv", n=5000):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rows = generate_dataset(n)
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {len(rows)} synthetic flow records to {path}")


if __name__ == "__main__":
    main()
