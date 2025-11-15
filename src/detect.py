import os
import joblib
import json
from datetime import datetime
from ingest import ingest_all
from features import auth_features, process_features, firewall_features
from sklearn.ensemble import IsolationForest
import numpy as np

# === Base Directories ===
BASE = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BASE, ".."))
DATA_DIR = os.path.join(ROOT_DIR, "data")
MODEL_DIR = os.path.join(ROOT_DIR, "models")
RETRAINED_DIR = os.path.join(ROOT_DIR, "retrained_model")  # match retrain.py folder
ANOMALY_DIR = os.path.join(DATA_DIR, "anomalies")

os.makedirs(ANOMALY_DIR, exist_ok=True)


# === Helper: Load Model ===
def load_model(path):
    try:
        return joblib.load(path)
    except Exception:
        return None


# === Helper: Get Latest Adaptive Model ===
def get_latest_retrained_model():
    """Return the latest adaptive model path if exists."""
    if not os.path.exists(RETRAINED_DIR):
        return None
    retrained_files = [f for f in os.listdir(RETRAINED_DIR) if f.endswith(".joblib")]
    if not retrained_files:
        return None
    latest = max(
        [os.path.join(RETRAINED_DIR, f) for f in retrained_files],
        key=os.path.getmtime
    )
    return latest


# === Load Models ===
def load_models():
    latest_adaptive = get_latest_retrained_model()

    if latest_adaptive:
        print(f"🧠 Using Adaptive Correlation-Aware Model Influence: {latest_adaptive}")
        try:
            adaptive_model = joblib.load(latest_adaptive)
            return {"adaptive": adaptive_model}
        except Exception as e:
            print(f"⚠️ Failed to load adaptive model ({e}). Falling back to baseline models.")

    print("⚙️ Using baseline models (no adaptive model found).")
    return {
        "auth": load_model(os.path.join(MODEL_DIR, "iforest_auth.pkl")),
        "process": load_model(os.path.join(MODEL_DIR, "iforest_proc.pkl")),
        "firewall": load_model(os.path.join(MODEL_DIR, "iforest_fw.pkl")),
    }


# === Save Detected Anomalies ===
def save_anomalies(anomalies):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"anomalies_{timestamp}.json"
    path = os.path.join(ANOMALY_DIR, filename)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(anomalies, f, indent=4, default=str)
        print(f"[INFO] Saved anomalies → {path}")
        return path
    except Exception as e:
        print(f"[ERROR] Failed to save anomalies: {e}")
        return None


# === Detection Logic ===
def detect(mapping):
    events = ingest_all(mapping)
    models = load_models()
    anomalies = []

    # === Adaptive Sensitivity Influence ===
    adaptive_model = models.get("adaptive")
    if adaptive_model:
        try:
            # probe the adaptive model’s internal behavior on a neutral input
            dummy_features = np.ones((1, adaptive_model.n_features_in_))
            adaptive_score = abs(adaptive_model.decision_function(dummy_features)[0])
            contamination_level = float(min(0.5, max(0.05, adaptive_score)))
            print(f"🧩 Adaptive sensitivity calibrated → contamination={contamination_level:.3f}")
        except Exception as e:
            print(f"⚠️ Adaptive sensitivity fallback ({e})")
            contamination_level = 0.1
    else:
        contamination_level = 0.1

    # === Use baseline models with adaptive sensitivity ===
    for ev_type, feature_fn, key in [
        ("auth", auth_features, "username"),
        ("process", process_features, "host"),
        ("firewall", firewall_features, "src_ip")
    ]:
        evs = [e for e in events if e.get("source") == ev_type]
        if not evs:
            continue

        df = feature_fn(evs)
        if df.empty:
            continue

        X = df.drop(columns=[key], errors="ignore").select_dtypes(include=[float, int]).values
        baseline_model = load_model(os.path.join(MODEL_DIR, f"iforest_{ev_type[:4]}.pkl"))

        # If baseline model missing, train a temporary one dynamically
        if baseline_model is None:
            print(f"⚠️ No baseline model for {ev_type}, training quick adaptive baseline...")
            baseline_model = IsolationForest(
                contamination=contamination_level,
                random_state=42
            ).fit(X)

        preds = baseline_model.predict(X)
        scores = baseline_model.decision_function(X)

        for i, p in enumerate(preds):
            if p == -1:
                anomalies.append({
                    "source": ev_type,
                    "entity": df.iloc[i].get(key),
                    "score": float(-scores[i]),
                    "event": evs[i],
                    "timestamp": evs[i].get("timestamp", "N/A")
                })

    anomalies.sort(key=lambda x: x["score"], reverse=True)
    saved_path = save_anomalies(anomalies)
    return anomalies, saved_path


# === Main Run ===
if __name__ == "__main__":
    mapping = {
        "auth": os.path.join(DATA_DIR, "train_auth.csv"),
        "process": os.path.join(DATA_DIR, "train_process.csv"),
        "firewall": os.path.join(DATA_DIR, "train_firewall.csv"),
    }

    anomalies, saved_path = detect(mapping)

    print("\n=== Detection Summary ===")
    print(f"✅ Total anomalies detected: {len(anomalies)}")
    if saved_path:
        print(f"📁 Saved anomaly report: {saved_path}")

    if anomalies:
        print("\n=== Sample Anomalies ===")
        for a in anomalies[:3]:
            print(f"- Source: {a['source']} | Entity: {a['entity']} | Score: {a['score']:.3f}")
    else:
        print("No anomalies detected.")