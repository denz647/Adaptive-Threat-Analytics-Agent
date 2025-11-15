# src/parsers.py
import json, os

def load_json(path):
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

# --- ANOMALIES ---
def parse_anomalies(json_path):
    data = load_json(json_path)
    parsed = []

    for item in data:
        ev = item.get("event", {})
        attrs = ev.get("attributes", {})
        event_type = ev.get("event_type", "")

        # --- intelligent summary depending on event type ---
        if event_type == "net_flow":
            summary = f"{attrs.get('src_ip', '?')} → {attrs.get('dst_ip', '?')}:{attrs.get('dst_port', '?')} ({attrs.get('protocol', '?')})"

        elif event_type == "process_create":
            summary = f"{attrs.get('username', '?')} ran {attrs.get('process_name', '?')} (parent: {attrs.get('parent_process', '?')})"

        elif event_type == "login":
            summary = f"{attrs.get('username', '?')} logged in from {attrs.get('src_ip', '?')} via {attrs.get('auth_method', '?')} ({attrs.get('outcome', '?')})"

        else:
            summary = str(attrs)[:200]  # fallback

        parsed.append({
            "source": item.get("source"),
            "entity": item.get("entity"),
            "score": round(item.get("score", 0), 4),
            "timestamp": item.get("timestamp"),
            "event_type": event_type,
            "summary": summary
        })

    return parsed[:10]

# --- CORRELATIONS ---

def parse_correlations(path):
    data = load_json(path)
    parsed = []

    for inc in data:
        events_summary = []
        seen = set()  # to track unique events

        for e in inc.get("events", []):
            evt = e.get("event", {})
            attrs = evt.get("attributes", {})
            src = e.get("source") or evt.get("source")

            summary = {
                "source": src,
                "event_type": evt.get("event_type"),
                "timestamp": e.get("timestamp"),
            }

            # Context-aware extraction
            if src == "auth":
                summary.update({
                    "username": attrs.get("username"),
                    "src_ip": attrs.get("src_ip"),
                    "auth_method": attrs.get("auth_method"),
                    "outcome": attrs.get("outcome"),
                })
            elif src == "process":
                summary.update({
                    "username": attrs.get("username"),
                    "process_name": attrs.get("process_name"),
                    "parent_process": attrs.get("parent_process"),
                    "cmdline": attrs.get("cmdline"),
                })
            elif src == "firewall":
                summary.update({
                    "src_ip": attrs.get("src_ip"),
                    "dst_ip": attrs.get("dst_ip"),
                    "protocol": attrs.get("protocol"),
                    "dst_port": attrs.get("dst_port"),
                    "action": attrs.get("action"),
                })

            # Create a unique key (string) for de-duplication
            key = "|".join(str(v) for v in summary.values() if v is not None)

            if key not in seen:
                seen.add(key)
                events_summary.append(summary)

        parsed.append({
            "incident_id": inc.get("incident_id"),
            "key": inc.get("key"),
            "score": round(inc.get("score", 0), 4),
            "duration": inc.get("duration_mins", 0),
            "events": events_summary,
        })

    return parsed[:5]



# --- EXPLANATIONS ---
def parse_explanations(path):
    data = load_json(path)
    if not isinstance(data, dict):
        return {}
    return {
        "num_incidents": data.get("num_incidents"),
        "correlation_file": data.get("correlation_file"),
        "summary_text": data.get("combined_summary"),
        "attack_chain": data.get("explanation", "")[:2500]
    }

