# normalize.py
from utils import parse_ts, new_id

def normalize_row(row: dict, source: str):
    """
    Normalize a dict row (from pandas row.to_dict()) into canonical event.
    Handles the exact column names you provided.
    """
    ts = parse_ts(row.get("timestamp") or row.get("time") or None)
    attrs = {}
    if source == "auth":
        # expected columns: timestamp, username, src_ip, auth_method, outcome
        attrs["username"] = row.get("username")
        attrs["src_ip"] = row.get("src_ip")
        attrs["auth_method"] = row.get("auth_method")
        attrs["outcome"] = row.get("outcome")
        event_type = "login"
        entity = f"user:{attrs.get('username') or 'unknown'}"
    elif source == "process":
        # expected: timestamp, host, username, process_name, parent_process, cmdline, event_type
        attrs["host"] = row.get("host")
        attrs["username"] = row.get("username")
        attrs["process_name"] = row.get("process_name")
        attrs["parent_process"] = row.get("parent_process")
        attrs["cmdline"] = row.get("cmdline")
        attrs["event_type"] = row.get("event_type") or "process_create"
        event_type = attrs["event_type"]
        entity = f"host:{attrs.get('host') or 'unknown'}"
    elif source == "firewall":
        # expected: timestamp, src_ip, dst_ip, dst_port, protocol, action, bytes
        attrs["src_ip"] = row.get("src_ip")
        attrs["dst_ip"] = row.get("dst_ip")
        attrs["dst_port"] = row.get("dst_port")
        attrs["protocol"] = row.get("protocol")
        attrs["action"] = row.get("action")
        try:
            attrs["bytes"] = float(row.get("bytes") or 0)
        except:
            attrs["bytes"] = 0.0
        event_type = "net_flow"
        entity = f"ip:{attrs.get('src_ip') or 'unknown'}"
    else:
        # generic mapping
        attrs.update(row)
        event_type = row.get("event_type") or "unknown"
        entity = "unknown"

    return {
        "event_id": new_id("evt"),
        "timestamp": ts,
        "source": source,
        "entity": entity,
        "event_type": event_type,
        "attributes": attrs,
        "raw": row
    }
