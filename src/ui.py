from flask import Flask, render_template, request, redirect, url_for, session
import json, os, sys, subprocess
from datetime import datetime
from feedback import give_feedback, get_adaptive_score, load_json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
TEMPLATES_DIR = os.path.join(PROJECT_ROOT, "templates")

app = Flask(__name__, template_folder=TEMPLATES_DIR)
app.secret_key = "supersecretkey"


def get_latest_json_file(folder_path):
    """Find the most recent JSON output file."""
    if not os.path.exists(folder_path):
        print(f"[WARN] Folder not found: {folder_path}")
        return None
    files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith(".json")]
    if not files:
        print(f"[WARN] No JSON files in: {folder_path}")
        return None
    latest = max(files, key=os.path.getmtime)
    print(f"[INFO] Latest JSON file selected: {latest}")
    return latest


@app.route("/", methods=["GET"])
def index():
    """Render dashboard view."""
    last_action = session.get("last_action")
    latest_data = session.get("latest_data")
    feedback_history = load_json(os.path.join(PROJECT_ROOT, "data", "feedback_store.json"))
    print(f"[INFO] Rendering dashboard for: {last_action or 'None'}")

    return render_template(
        "index.html",
        latest_action=last_action,
        latest_data=latest_data,
        feedback_submitted=session.pop("feedback_submitted", False),
        feedback_incident=session.pop("feedback_incident", None),
        adaptive_score=session.pop("adaptive_score", None),
        feedback_history=feedback_history.values() if feedback_history else [],
        last_refresh=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )


@app.route("/run/<action>", methods=["POST"])
def run_action(action):
    """
    Execute selected analysis step:
    - anomaly → detect.py
    - correlate → correlator.py
    - explain → explain.py
    - retrain → retrain.py
    """
    script_map = {
        "anomaly": ("detect.py", "anomalies", "parse_anomalies"),
        "correlate": ("correlator.py", "correlations", "parse_correlations"),
        "explain": ("explain.py", "explanations", "parse_explanations"),
        # retrained model stored directly under project root, not data/
        "retrain": ("retrain.py", None, None),
    }

    if action not in script_map:
        return "Invalid Action", 400

    script_file, folder, parser_name = script_map[action]
    script_path = os.path.join(BASE_DIR, script_file)

    # Prevent re-triggering the same action repeatedly
    if session.get("last_action") == action:
        print(f"[WARN] Action '{action}' recently executed — skipping.")
        return redirect(url_for("index"))

    print(f"[INFO] Executing: {script_path} using {sys.executable}")

    try:
        subprocess.run(
            [sys.executable, script_path],
            check=True,
            env=os.environ.copy()
        )
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Script failed: {e}")
        session["last_action"] = action
        session["latest_data"] = {"error": f"Execution failed: {e}"}
        return redirect(url_for("index"))

    # ✅ Handle retrain — always display "Model retrained"
    if action == "retrain":
        session["latest_data"] = {
            "status": "Model retrained"
        }
        session["last_action"] = action
        session.modified = True
        print("[INFO] Model retrained")
        return redirect(url_for("index"))

    # ✅ Handle normal actions (anomaly, correlate, explain)
    folder_path = os.path.join(PROJECT_ROOT, "data", folder)
    latest_json = get_latest_json_file(folder_path)
    if not latest_json:
        session["latest_data"] = {"error": "No output JSON found"}
        return redirect(url_for("index"))

    try:
        if parser_name:
            from parsers import parse_anomalies, parse_correlations, parse_explanations
            parser_func = locals()[parser_name]
            parsed = parser_func(latest_json)
        else:
            parsed = json.load(open(latest_json))

        session["last_action"] = action
        session["latest_data"] = parsed
        session.modified = True
        print(f"[INFO] Dashboard updated for action: {action}")

    except Exception as e:
        print(f"[ERROR] Parsing failed for {action}: {e}")
        session["latest_data"] = {"error": str(e)}

    return redirect(url_for("index"))


@app.route("/submit_feedback", methods=["POST"])
def submit_feedback():
    """Store analyst feedback (TP/FP)."""
    incident_id = request.form.get("incident_id")
    label = request.form.get("label")
    comment = request.form.get("comment")

    if not incident_id or not label:
        print("[ERROR] Missing feedback input")
        return redirect(url_for("index"))

    explanation_text = comment or ""
    give_feedback(incident_id, explanation_text, label, comment)
    adaptive_score = get_adaptive_score(incident_id)

    session["feedback_submitted"] = True
    session["feedback_incident"] = incident_id
    session["adaptive_score"] = round(adaptive_score, 4)
    print(f"[INFO] Feedback stored for {incident_id} — label={label}, adaptive={adaptive_score}")

    return redirect(url_for("index"))


@app.route("/clear", methods=["GET"])
def clear_session():
    """Clear dashboard session."""
    session.clear()
    print("[INFO] Session cleared")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)