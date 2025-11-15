# Adaptive Threat Analytics Agent (Local Demo)

## Overview
Local prototype that:
- trains baselines from CSV logs (auth, process, firewall),
- detects anomalies using IsolationForest,
- correlates anomalies across sources,
- explains the correlated events picturing a storyline using a LLM API
- stores analyst feedback in FAISS vector memory and uses it in future reasoning. Feedback influence adaptive weights for Retraining the isolation forest model .

## Setup
1. Create and activate venv:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
2. Install:
   ```bash
   pip install -r requirements.txt
   ```

## Place your CSVs
For customized training other than sample data Replace and Put your CSVs in `data/`:
- train_auth.csv (cols: timestamp, username, src_ip, auth_method, outcome)
- train_firewall.csv (cols: timestamp, src_ip, dst_ip, dst_port, protocol, action, bytes)
- train_process.csv (cols: timestamp, host, username, process_name, parent_process, cmdline, event_type)
- test_auth.csv, test_process.csv, test_attack.csv

## Environment variables for LLM API
- Placed in the env file

## Run (local)
1. Run the Flask app:
   ```bash
   python src/ui.py
   Flask app will run on the local host port 5000
   ```
2. Interact with the Dashboard :
   ```bash
   FLow :: Detect Anomalies ==>Correlate events==>Explain Results==>Give Feedback in the analyst Feedback form (ID , verdict(True positive / False positive) , Comments) ==>Retrain model.
   Clear session to clear the current session
   ```

## Notes

- Data stored for anomalies , correlations and explanations are in json form .
- Feedback stored in `feedback_store.db`. Analyst notes are embedded and indexed in FAISS (`feedback_faiss.index`) for semantic recall.