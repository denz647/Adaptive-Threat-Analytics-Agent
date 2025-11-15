# ingest.py
import pandas as pd
from normalize import normalize_row
from typing import Dict, List

def ingest_csv(filepath: str, source_label: str):
    df = pd.read_csv(filepath)
    events = []
    for _, r in df.iterrows():
        events.append(normalize_row(r.to_dict(), source_label))
    # sort by timestamp where present
    events.sort(key=lambda e: e["timestamp"] or 0)
    return events

def ingest_all(mapping: Dict[str, str]):
    """
    mapping: { "auth": "data/train_auth.csv", ... }
    returns combined list of canonical events
    """
    all_events = []
    for label, path in mapping.items():
        all_events.extend(ingest_csv(path, label))
    all_events.sort(key=lambda e: e["timestamp"] or 0)
    return all_events
