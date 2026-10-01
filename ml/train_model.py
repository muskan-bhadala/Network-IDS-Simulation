"""Train Logistic Regression, Random Forest (supervised) and Isolation Forest (unsupervised).

Run:  python -m ml.train_model
"""
import csv
import json
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from ids.feature_extractor import extract_network_features
from ml.evaluate import evaluate

FEATURES = ["packet_count", "byte_count", "duration", "bytes_per_second", "packets_per_second",
            "connection_count", "failed_connection_count", "syn_count", "rst_count", "average_packet_size"]


def load_xy(path="data/network_traffic.csv"):
    X, y = [], []
    with open(path) as fh:
        for row in csv.DictReader(fh):
            f = extract_network_features(row)
            X.append([f[k] for k in FEATURES])
            y.append(1 if row["label"] == "SUSPICIOUS" else 0)
    return np.array(X), np.array(y)


def main():
    X, y = load_xy()
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=42)
    os.makedirs("models", exist_ok=True)
    results = {}

    lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, class_weight="balanced"))
    lr.fit(Xtr, ytr)
    results["logistic_regression"] = evaluate(yte, lr.predict(Xte))

    rf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")
    rf.fit(Xtr, ytr)
    results["random_forest"] = evaluate(yte, rf.predict(Xte))

    iso = make_pipeline(StandardScaler(), IsolationForest(n_estimators=100, contamination=0.1, random_state=42))
    iso.fit(Xtr[ytr == 0])                       # unsupervised: learns NORMAL only, no labels used
    results["isolation_forest"] = evaluate(yte, (iso.predict(Xte) == -1).astype(int))

    joblib.dump(lr, "models/logistic_regression.joblib")
    joblib.dump(rf, "models/random_forest.joblib")
    joblib.dump(iso, "models/isolation_forest.joblib")
    results["_info"] = {"train_rows": int(len(Xtr)), "test_rows": int(len(Xte)), "features": FEATURES}
    with open("models/metrics.json", "w") as fh:
        json.dump(results, fh, indent=2)
    for name, m in results.items():
        if name != "_info":
            print(f"{name:<22} acc={m['accuracy']} prec={m['precision']} rec={m['recall']} "
                  f"f1={m['f1']} cm={m['confusion_matrix']}")
    print("Saved models/ and models/metrics.json")


if __name__ == "__main__":
    main()
