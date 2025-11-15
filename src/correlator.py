import os
import json
from datetime import datetime, timedelta
from collections import defaultdict
import uuid

# === CONFIG ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(os.path.dirname(BASE_DIR), "data")
ANOMALY_DIR = os.path.join(DATA_DIR, "anomalies")
CORR_DIR = os.path.join(DATA_DIR, "correlations")

# Ensure correlation folder exists
os.makedirs(CORR_DIR, exist_ok=True)


# === HELPER: Extract correlation keys ===
def extract_key_fields(anomaly):
    """
    Extract key fields (username, host, src_ip) from anomaly data safely.
    Works across 'auth', 'process', 'firewall', etc.
    """
    event = anomaly.get("event", {})
    attrs = event.get("attributes", {})

    username = (
        attrs.get("username")
        or attrs.get("user")
        or (anomaly.get("entity") if "user" in str(anomaly.get("entity", "")).lower() else None)
    )

    host = (
        attrs.get("host")
        or attrs.get("hostname")
        or (anomaly.get("entity") if "host" in str(anomaly.get("entity", "")).lower() else None)
    )

    src_ip = (
        attrs.get("src_ip")
        or (anomaly.get("entity") if "ip" in str(anomaly.get("entity", "")).lower() else None)
    )

    return username, host, src_ip


# === MAIN CORRELATION LOGIC ===
def correlate(anomalies, window_minutes=30):
    """
    Correlate anomalies that share the same username, host, or src_ip
    within a given time window.
    """
    window = timedelta(minutes=window_minutes)
    correlated = []
    grouped = defaultdict(list)

    # Sort by timestamp
    anomalies = sorted(anomalies, key=lambda x: x.get("timestamp") or datetime.min)

    for a in anomalies:
        user, host, ip = extract_key_fields(a)
        key = f"{user or ''}|{host or ''}|{ip or ''}"
        grouped[key].append(a)

    # Build correlated incidents
    for key, events in grouped.items():
        if not events:
            continue

        start = events[0].get("timestamp")
        end = events[-1].get("timestamp")
        duration = (end - start).total_seconds() / 60 if start and end else 0

        score = min(1.0, 0.2 * len(events) + (duration / 60) * 0.05)

        correlated.append({
            "incident_id": str(uuid.uuid4()),
            "key": key,
            "events": events,
            "score": score,
            "start_time": start.isoformat() if start else None,
            "end_time": end.isoformat() if end else None,
            "duration_mins": duration,
        })

    return correlated


# === LOAD ALL ANOMALIES ===
def load_all_anomalies():
    """Load and combine all anomalies from JSON files."""
    all_anomalies = []
    for file in os.listdir(ANOMALY_DIR):
        if file.endswith(".json"):
            path = os.path.join(ANOMALY_DIR, file)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for a in data:
                        ts = a.get("timestamp") or a.get("event", {}).get("timestamp")
                        if isinstance(ts, str):
                            try:
                                a["timestamp"] = datetime.fromisoformat(ts.replace(" ", "T"))
                            except Exception:
                                a["timestamp"] = None
                        all_anomalies.append(a)
            except Exception as e:
                print(f"[WARN] Failed to load {file}: {e}")
    print(f"[INFO] Loaded total anomalies: {len(all_anomalies)}")
    return all_anomalies


# === SAVE CORRELATED DATA TO JSON ===
def save_correlations(correlated_data):
    """Save correlated incidents to a JSON file under data/correlations/."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"correlation_{timestamp}.json"
    path = os.path.join(CORR_DIR, filename)

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(correlated_data, f, indent=4, default=str)
        print(f"[INFO] Correlation results saved → {path}")
    except Exception as e:
        print(f"[ERROR] Failed to save correlation file: {e}")


# === MAIN RUNNER ===
if __name__ == "__main__":
    anomalies = load_all_anomalies()

    if not anomalies:
        print("[INFO] No anomalies found — nothing to correlate.")
    else:
        correlated_groups = correlate(anomalies, window_minutes=30)
        print(f"\n[INFO] Correlated into {len(correlated_groups)} incidents.\n")

        # Save correlation results
        save_correlations(correlated_groups)

        print("Correlation completed ✅")
