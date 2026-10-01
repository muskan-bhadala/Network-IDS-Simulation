"""Continuous synthetic flow generator.  DATA ONLY - sends no network packets.

It POSTs JSON flow records to the IDS backend running on THIS computer.

Examples:
  python -m simulator.traffic_simulator --mode mixed --speed slow
  python -m simulator.traffic_simulator --mode normal --speed fast --count 50
  python -m simulator.traffic_simulator --dry-run --count 3      (just print)
"""
import argparse
import json
import random
import time
import urllib.request
from urllib.parse import urlparse

from simulator.generate_dataset import NORMAL_SCENARIOS, SUSPICIOUS_SCENARIOS, make_flow

SPEEDS = {"slow": 2.0, "fast": 0.3}  # seconds between records
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def pick_scenario(mode, rng):
    if mode == "mixed" and rng.random() < 0.25:
        return rng.choice(SUSPICIOUS_SCENARIOS)
    return rng.choice(NORMAL_SCENARIOS)


def post_flow(url, flow):
    data = json.dumps(flow).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["normal", "mixed"], default="mixed")
    p.add_argument("--speed", choices=list(SPEEDS), default="slow")
    p.add_argument("--url", default="http://127.0.0.1:5000/api/flows")
    p.add_argument("--count", type=int, default=0, help="0 = run until Ctrl+C")
    p.add_argument("--dry-run", action="store_true", help="print records instead of sending")
    a = p.parse_args()

    # Safety guard: only the local machine is allowed as a target.
    if not a.dry_run and urlparse(a.url).hostname not in LOCAL_HOSTS:
        raise SystemExit("Refusing to send: this lab tool only talks to localhost.")

    rng = random.Random()
    sent = 0
    print(f"Simulator started (mode={a.mode}, speed={a.speed}). Ctrl+C to stop.")
    try:
        while a.count == 0 or sent < a.count:
            flow = make_flow(pick_scenario(a.mode, rng), rng)
            flow.pop("label")  # the IDS must decide by itself
            sc = flow.pop("scenario_type")
            if a.dry_run:
                print(sc, json.dumps(flow))
            else:
                try:
                    res = post_flow(a.url, flow)
                    print(f"[{sent + 1}] {sc:<28} -> {res.get('classification')} risk={res.get('risk_score')}")
                except Exception as exc:  # backend not running etc.
                    print("Could not reach backend:", exc)
                    time.sleep(2)
                    continue
            sent += 1
            time.sleep(SPEEDS[a.speed])
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
