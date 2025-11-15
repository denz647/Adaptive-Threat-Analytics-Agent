# utils.py
import dateutil.parser as dp
import uuid, datetime

def parse_ts(ts):
    if not ts:
        return None
    try:
        return dp.parse(str(ts))
    except Exception:
        try:
            return datetime.datetime.fromtimestamp(float(ts))
        except:
            return None

def now_iso():
    return datetime.datetime.utcnow().isoformat() + "Z"

def new_id(prefix="evt"):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"
