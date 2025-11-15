import os
import json
import numpy as np
from sklearn.ensemble import IsolationForest
from joblib import dump, load
from datetime import datetime, timedelta

# === PATHS ===
BASE = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(BASE, ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
CORR_DIR = os.path.join(DATA_DIR, "correlations")
ANOM_DIR = os.path.join(DATA_DIR, "anomalies")
WEIGHT_FILE = os.path.join(DATA_DIR, "adaptive_weights.json")
FEEDBACK_FILE = os.path.join(DATA_DIR, "feedback_store.json")

RETRAIN_DIR = os.path.join(PROJECT_ROOT, "retrained_model")
os.makedirs(RETRAIN_DIR, exist_ok=True)

# === UTILITIES ===
def load_latest_json(folder):
    if not os.path.exists(folder):
        return None
    json_files = [f for f in os.listdir(folder) if f.endswith(".json")]
    if not json_files:
        return None
    latest_file = max([os.path.join(folder, f) for f in json_files], key=os.path.getmtime)
    with open(latest_file, "r") as f:
        return json.load(f)

def load_json(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)

def extract_features(correlated_data, weights):
    features = []
    for item in correlated_data:
        event_count = len(item.get("events", []))
        score = item.get("score", 0.0)
        cid = str(item.get("incident_id", ""))
        weight = weights.get(cid, 0.0)
        features.append([event_count, score, weight])
    return np.array(features)


# === ADAPTIVE WEIGHT UPDATE ===
def update_weights(weights, feedback_data, decay=0.98):
    """
    Update adaptive weights using feedback:
    - FP (false positive): decrease weight
    - TP (true positive): increase weight
    Also apply a decay factor to slowly reduce old weight influence.
    """
    for cid, fb in feedback_data.items():
        old_weight = weights.get(cid, 0.0) * decay
        if fb.get("label") == "TP":
            new_weight = old_weight + 0.2  # reward
        elif fb.get("label") == "FP":
            new_weight = old_weight - 0.3  # penalize
        else:
            new_weight = old_weight
        weights[cid] = float(np.clip(new_weight, -1.0, 1.0))
    return weights


# === MAIN LOGIC ===
if __name__ == "__main__":
    print("🔁 Starting Adaptive Global Model Retraining...")

    correlation_data = load_latest_json(CORR_DIR)
    anomaly_data = load_latest_json(ANOM_DIR)
    weights = load_json(WEIGHT_FILE)
    feedback_data = load_json(FEEDBACK_FILE)

    if not correlation_data or not anomaly_data:
        print("⚠️ Missing correlation or anomaly data. Retraining aborted.")
        exit()

    if not feedback_data:
        print("⚠️ No new feedback available. Retraining skipped.")
        exit()

    # Update adaptive weights using feedback
    weights = update_weights(weights, feedback_data)
    save_json(WEIGHT_FILE, weights)

    # Combine both anomaly and correlation datasets
    X_corr = extract_features(correlation_data, weights)
    X_anom = extract_features(anomaly_data, weights)
    X = np.vstack([X_corr, X_anom])

    # === Retrain Adaptive IsolationForest ===
    model = IsolationForest(
        n_estimators=250,
        contamination=0.08,
        random_state=42
    )
    model.fit(X)

    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
    model_path = os.path.join(RETRAIN_DIR, f"adaptive_model_{timestamp}.joblib")
    dump(model, model_path)

    print(f"✅ Adaptive model retrained and saved at:\n➡️ {model_path}")
    print("📈 Feedback integrated. Adaptive weights updated.")