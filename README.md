# Adaptive Threat Analytics Agent (Local Demo)

## Overview
Adaptive Threat Analytics Agent (ATA) is an AI-driven security analysis system designed to support SOC operations by automatically detecting suspicious activity, correlating related events into attack storylines, and continuously improving through analyst feedback.

The system analyzes security logs to identify abnormal behavior patterns, correlates anomalies across multiple data sources, and generates clear, human-readable explanations of potential attacks using an LLM. Analysts can review the generated incident narrative and provide feedback (TP/FP with notes), which the system stores and uses to improve future detection accuracy through adaptive learning.

ATA evolves over time by learning from real analyst decisions, reducing false positives, improving prioritization, and enabling faster security investigations.

## Setup
### **Prerequisites**

* **Python 3.10 / 3.11 recommended**
* **pip** and **virtual environment** support enabled

---

### **1. Clone the repository**

```bash
git clone https://github.com/denz647/Adaptive-Threat-Analytics-Agent.git
cd Adaptive-Threat-Analytics-Agent
```

### **2. Create and activate a virtual environment**

**Windows**

```bash
python -m venv venv
venv\Scripts\activate
```

**Mac / Linux**

```bash
python3 -m venv venv
source venv/bin/activate
```

---

### **3. Install required dependencies**

```bash
pip install -r requirements.txt
```

---

### **4. Run the application**

```bash
python src/ui.py
```

---


## Place your CSVs
For customized training other than sample data Replace and Put your CSVs in `data/`:
- train_auth.csv (cols: timestamp, username, src_ip, auth_method, outcome)
- train_firewall.csv (cols: timestamp, src_ip, dst_ip, dst_port, protocol, action, bytes)
- train_process.csv (cols: timestamp, host, username, process_name, parent_process, cmdline, event_type)
- test_auth.csv, test_process.csv, test_attack.csv

## Environment variables for LLM API
- Place your own API key for Open Router model : nvidia/nemotron-nano-12b-v2-vl:free

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
