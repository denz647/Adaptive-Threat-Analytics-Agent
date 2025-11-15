# features.py
from collections import defaultdict
import pandas as pd
import numpy as np

def auth_features(events):
    # aggregated per user
    per_user = defaultdict(list)
    for e in events:
        user = e["attributes"].get("username") or "unknown"
        per_user[user].append(e)
    rows = []
    for user, evs in per_user.items():
        ts = [e["timestamp"] for e in evs if e["timestamp"]]
        hours = [t.hour for t in ts] if ts else []
        src_ips = [e["attributes"].get("src_ip") for e in evs if e["attributes"].get("src_ip")]
        failed = sum(1 for e in evs if str(e["attributes"].get("outcome") or "").lower().startswith("fail"))
        total = len(evs)
        days_span = 1
        if ts:
            days_span = (max(ts).date() - min(ts).date()).days + 1
        rows.append({
            "username": user,
            "avg_logins_per_day": total / max(1, days_span),
            "unique_ips": len(set(src_ips)),
            "hour_mode": max(set(hours), key=hours.count) if hours else 0,
            "failed_ratio": failed / total if total > 0 else 0.0
        })
    return pd.DataFrame(rows).fillna(0)

def process_features(events):
    per_host = defaultdict(list)
    for e in events:
        host = e["attributes"].get("host") or "unknown"
        per_host[host].append(e)
    rows=[]
    for host, evs in per_host.items():
        procs = [ev["attributes"].get("process_name") for ev in evs if ev["attributes"].get("process_name")]
        unique_procs = len(set(procs))
        rows.append({
            "host": host,
            "unique_procs": unique_procs,
            "proc_count": len(procs)
        })
    return pd.DataFrame(rows).fillna(0)

def firewall_features(events):
    per_ip = defaultdict(list)
    for e in events:
        ip = e["attributes"].get("src_ip") or "unknown"
        per_ip[ip].append(e)
    rows=[]
    for ip, evs in per_ip.items():
        dsts = set(e["attributes"].get("dst_ip") for e in evs if e["attributes"].get("dst_ip"))
        bytes_count = sum(float(e["attributes"].get("bytes") or 0) for e in evs)
        rows.append({
            "src_ip": ip,
            "unique_dsts": len(dsts),
            "bytes": bytes_count
        })
    return pd.DataFrame(rows).fillna(0)
