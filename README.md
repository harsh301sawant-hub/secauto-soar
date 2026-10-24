# SecAuto SOAR: Automated Cyber Attack Detector & Response System

An enterprise-grade Security Orchestration, Automation, and Response (SOAR) web application that detects incoming cyber attacks in real-time and executes automated mitigation playbooks.

---

## 🌟 Key Features

1. **Real-Time Threat Ingestion**:
   - WebSocket pipeline for zero-latency alert streaming to the SOC console.
   - Brute-Force & Credential Stuffing detection engine.
   - Web application exploit detection (SQL Injection & Malicious Payloads).
   - Phishing & Typosquatting URL scanner with multi-heuristic scoring (0-100).

2. **Automated Incident Response Engine (SOAR Playbooks)**:
   - **Step 1: IOC Enrichment** (extracts IPs, target accounts, and signatures).
   - **Step 2: Threat Intelligence OSINT** (AbuseIPDB reputation lookup).
   - **Step 3: Network Firewall Drop** (automatic IP quarantine).
   - **Step 4: Identity Session Quarantine** (session token revocation).
   - **Step 5: Automated Alert Dispatch** (Slack / SOC notification).

3. **Database & Storage**:
   - SQLite persistence for incident history, attack payloads, and active firewall blocklists.

---

## 🚀 How to Run Locally

### 1. Install Dependencies
```bash
pip install fastapi uvicorn requests python-dotenv pydantic
```

### 2. Start the Server
```bash
cd backend
python -m uvicorn main:app --reload --port 8000
```

### 3. Open the SOC Analyst Console
Open your browser and navigate to:
```
http://127.0.0.1:8000
```

---

## 🎓 Viva / Presentation Demonstration Guide (150 Marks)

1. Open `http://127.0.0.1:8000` on your screen.
2. In a separate terminal, run the attack simulator:
   ```bash
   python test_attacks/simulate_attack.py
   ```
3. Choose option `1` to launch a simulated brute-force attack.
4. Watch the web dashboard instantly catch the attack live over WebSockets, flag it as **CRITICAL**, and allow you to execute the automated remediation pipeline!
