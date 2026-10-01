"""Statistical anomaly detection: Z-score + IQR + moving average, scored 0-100."""
import numpy as np

METRICS = ["packets_per_second", "bytes_per_second", "connection_rate",
           "failure_ratio", "unique_destination_ports"]


def build_baseline(feature_rows):
    """feature_rows: iterable of feature dicts from NORMAL traffic -> baseline dict."""
    rows = list(feature_rows)
    base = {}
    for m in METRICS:
        v = np.array([r[m] for r in rows], dtype=float) if rows else np.array([0.0])
        q1, q3 = np.percentile(v, [25, 75])
        base[m] = {"mean": float(v.mean()), "std": float(v.std()), "q1": float(q1),
                   "q3": float(q3), "iqr": float(q3 - q1)}
    return base


def moving_average(values, window=5):
    """Simple moving average - useful for smoothing a live stream of one metric."""
    out, buf = [], []
    for v in values:
        buf.append(v)
        buf = buf[-window:]
        out.append(sum(buf) / len(buf))
    return out


def metric_score(x, b):
    """Deviation of one metric from baseline -> 0-100 (only upward deviation counts)."""
    std = max(b["std"], 1e-9)
    z = (x - b["mean"]) / std
    z_part = min(1.0, max(0.0, z) / 6.0)                      # 6 sigma = max
    scale = max(b["iqr"], 0.1 * std, 1e-9)
    iqr_part = min(1.0, max(0.0, x - (b["q3"] + 1.5 * b["iqr"])) / (3 * scale))
    return 100.0 * (0.5 * z_part + 0.5 * iqr_part)


def calculate_anomaly_score(features, baseline):
    """0-100 anomaly score: 60% worst metric + 40% average of all metrics."""
    scores = [metric_score(features[m], baseline[m]) for m in METRICS]
    return round(0.6 * max(scores) + 0.4 * (sum(scores) / len(scores)), 2)
