import os
import json
import requests
from dotenv import load_dotenv
from datetime import datetime

# === CONFIG ===
load_dotenv()

CORR_DIR = "data/correlations"
OUTPUT_DIR = "data/explanations"

LLM_API_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
LLM_API_KEY = os.getenv("OPENROUTER_API_KEY")
MODEL_NAME = "nvidia/nemotron-nano-12b-v2-vl:free"

os.makedirs(OUTPUT_DIR, exist_ok=True)


def summarize_incident(incident):
    """Convert incident JSON into a readable summary with timestamps."""
    summary_lines = [
        f"Incident ID: {incident.get('incident_id')}",
        f"Correlation Key: {incident.get('key')}",
        f"Correlation Score: {incident.get('score')}",
        f"Duration: {incident.get('duration_mins')} minutes",
        "Events (chronological):"
    ]

    events_sorted = sorted(incident.get("events", []), key=lambda e: e.get("timestamp", ""))

    for e in events_sorted:
        ts = e.get("timestamp", "Unknown time")
        src = e.get("source", "unknown")
        attrs = e.get("event", {}).get("attributes", {})

        if src == "auth":
            summary_lines.append(
                f"- 🕓 [{ts}] User {attrs.get('username')} login {attrs.get('outcome')} "
                f"from {attrs.get('src_ip')} ({attrs.get('auth_method')})"
            )
        elif src == "process":
            summary_lines.append(
                f"- 🕓 [{ts}] Process {attrs.get('process_name')} executed by {attrs.get('username')} "
                f"on host {attrs.get('host')} (parent: {attrs.get('parent_process')})"
            )
        elif src == "firewall":
            summary_lines.append(
                f"- 🕓 [{ts}] Network flow {attrs.get('src_ip')} → {attrs.get('dst_ip')}:{attrs.get('dst_port')} "
                f"({attrs.get('protocol')}, {attrs.get('action')})"
            )
        else:
            summary_lines.append(f"- 🕓 [{ts}] Event from {src}: {attrs}")

    return "\n".join(summary_lines)


def call_llm(prompt):
    """Send the incident summary to OpenRouter and get an explanation."""
    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "HTTP-Referer": "https://your-app-or-demo-url.com/",
        "X-Title": "Detectify Hackathon Demo",
        "Content-Type": "application/json",
    }

    data = {
        "model": MODEL_NAME,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity SOC analyst. Given correlated incident timelines, "
                    "analyze and describe the likely attack chain, objective, and root cause."
                )
            },
            {
                "role": "user",
                "content": f"""
Analyze the following correlated incidents:

{prompt}

Please explain:
1️⃣ The chronological attack flow.
2️⃣ Attacker’s objective and behavior.
3️⃣ Detection gaps and mitigation suggestions.
"""
            }
        ],
        "max_tokens": 800
    }

    try:
        print("📡 Calling LLM API for explanation...")
        resp = requests.post(LLM_API_ENDPOINT, headers=headers, json=data, timeout=60)
        resp.raise_for_status()
        result = resp.json()
        if "choices" in result:
            return result["choices"][0]["message"]["content"].strip()
        return "No explanation returned."
    except Exception as e:
        print("❌ LLM call failed:", e)
        return "Explanation not available (LLM error)."


def get_latest_correlation_file():
    """Return the path of the latest JSON file in the correlations folder."""
    files = [
        os.path.join(CORR_DIR, f)
        for f in os.listdir(CORR_DIR)
        if f.endswith(".json")
    ]
    if not files:
        return None
    latest_file = max(files, key=os.path.getmtime)
    return latest_file


def explain_latest_correlation():
    """Generate explanation only for the latest correlation JSON file."""
    latest_file = get_latest_correlation_file()

    if not latest_file:
        print("⚠️ No correlation files found in folder.")
        return

    print(f"🕵️ Processing latest correlation file → {latest_file}")
    with open(latest_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        print("[WARN] Unexpected JSON format — skipping.")
        return

    combined_text = "\n\n".join([summarize_incident(i) for i in data])
    explanation = call_llm(combined_text)

    output = {
        "correlation_file": os.path.basename(latest_file),
        "num_incidents": len(data),
        "explanation": explanation,
        "combined_summary": combined_text,
        "generated_at": datetime.now().isoformat()
    }

    out_filename = os.path.basename(latest_file).replace(".json", "_explanation.json")
    out_path = os.path.join(OUTPUT_DIR, out_filename)

    with open(out_path, "w", encoding="utf-8") as out_f:
        json.dump(output, out_f, indent=4)

    print(f"✅ Explanation saved → {out_path}")
    print("🏁 Completed successfully.")


if __name__ == "__main__":
    explain_latest_correlation()
