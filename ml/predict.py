"""Load the Random Forest and return P(suspicious) for a feature dict."""
import os

import joblib

from ml.train_model import FEATURES

MODEL_PATH = "models/random_forest.joblib"


def load_model(path=MODEL_PATH):
    return joblib.load(path) if os.path.exists(path) else None


def predict_probability(model, features):
    return float(model.predict_proba([[features[k] for k in FEATURES]])[0][1])
