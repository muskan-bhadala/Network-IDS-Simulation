"""One-command launcher:  python run.py
Creates the dataset and trains the ML models if they are missing, then starts the dashboard."""
import os

from simulator.generate_dataset import main as make_data

if not os.path.exists("data/network_traffic.csv"):
    make_data()
if not os.path.exists("models/random_forest.joblib"):
    from ml.train_model import main as train
    train()

from backend.app import create_app

port = int(os.getenv("PORT", "5000"))
print(f"\nDashboard: http://127.0.0.1:{port}   (Ctrl+C to stop)\n")
create_app().run(host="127.0.0.1", port=port, debug=False)
