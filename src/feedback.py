import os
import json
from datetime import datetime
import numpy as np
import faiss
from joblib import dump, load
from sentence_transformers import SentenceTransformer

# === PATH SETUP ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)

FEEDBACK_PATH = os.path.join(DATA_DIR, "feedback_store.json")
FAISS_INDEX_PATH = os.path.join(DATA_DIR, "feedback_index.faiss")
META_PATH = os.path.join(DATA_DIR, "feedback_meta.json")
ADAPTIVE_WEIGHTS_PATH = os.path.join(DATA_DIR, "adaptive_weights.json")
MODEL_PATH = os.path.join(DATA_DIR, "sentence_model.joblib")  # optional if caching

# === EMBEDDING MODEL (Semantic) ===
# Use a lightweight, CPU-friendly model
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
MODEL = SentenceTransformer(MODEL_NAME)

def encode_text(text):
    """Generate semantic embeddings for the given text."""
    emb = MODEL.encode([text], convert_to_numpy=True, normalize_embeddings=True)[0]
    return emb.astype("float32")

# === HELPER FUNCTIONS ===
def load_json(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}

def save_json(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

# === FEEDBACK STORAGE ===
def store_feedback(incident_id, label, comment):
    """Store analyst feedback (TP/FP) and create/update embeddings."""
    feedback_data = load_json(FEEDBACK_PATH)
    entry = {
        "incident_id": incident_id,
        "label": label,
        "comment": comment,
        "timestamp": datetime.utcnow().isoformat()
    }
    feedback_data[str(incident_id)] = entry
    save_json(feedback_data, FEEDBACK_PATH)
    upsert_embedding(comment, incident_id, label)

# === VECTOR EMBEDDINGS (FAISS) ===
def upsert_embedding(text, incident_id, label):
    """Create or update FAISS index and metadata for semantic similarity search."""
    vec = encode_text(text)
    dim = vec.shape[0]

    if os.path.exists(FAISS_INDEX_PATH):
        index = faiss.read_index(FAISS_INDEX_PATH)
        meta = load_json(META_PATH).get("data", [])
    else:
        index = faiss.IndexFlatIP(dim)  # IP = cosine similarity for normalized vectors
        meta = []

    index.add(np.expand_dims(vec, axis=0))
    meta.append({
        "incident_id": incident_id,
        "label": label,
        "comment": text
    })

    faiss.write_index(index, FAISS_INDEX_PATH)
    save_json({"data": meta}, META_PATH)

def search_similar(text, k=3):
    """Find semantically similar feedback comments."""
    if not os.path.exists(FAISS_INDEX_PATH):
        return []

    vec = encode_text(text)
    index = faiss.read_index(FAISS_INDEX_PATH)
    D, I = index.search(np.expand_dims(vec, axis=0), k)
    meta = load_json(META_PATH).get("data", [])

    results = []
    for idx, score in zip(I[0], D[0]):
        if idx < len(meta):
            results.append({**meta[idx], "similarity": float(score)})
    return results

# === ADAPTIVE LEARNING ===
def adapt_weights(explanation_text, label):
    """Adjust adaptive weights based on semantically similar feedback."""
    weights = load_json(ADAPTIVE_WEIGHTS_PATH)
    similar = search_similar(explanation_text, k=5)
    adjust = 1 if label.upper() == "TP" else -1

    for item in similar:
        key = item["incident_id"]
        weights[key] = weights.get(key, 0.0) + adjust * 0.1

    save_json(weights, ADAPTIVE_WEIGHTS_PATH)

def get_adaptive_score(incident_id):
    weights = load_json(ADAPTIVE_WEIGHTS_PATH)
    return weights.get(str(incident_id), 0.0)

# === FEEDBACK INTERFACE ===
def give_feedback(incident_id, explanation_text, label, comment):
    """Analyst provides feedback (TP/FP)."""
    store_feedback(incident_id, label, comment)
    adapt_weights(explanation_text, label)

# === DEMO ===
if __name__ == "__main__":
    explanation = "Multiple failed logins followed by a successful one from the same host."
    give_feedback("INC123", explanation, "TP", "Confirmed brute-force pattern")

    print("Feedback stored and adaptive weights updated ✅")
    sim = search_similar("Brute-force attack with repeated authentication failures", k=2)
    print("Similar feedback found:", sim)
    print("Adaptive score for INC123:", get_adaptive_score("INC123"))