import uuid
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os

from database import (
    init_db, log_incident, get_recent_incidents, 
    get_blocked_ips, is_ip_blocked, clear_all_incidents
)
from detector import analyze_login_attempt, analyze_web_payload, analyze_url_or_domain
from responder import execute_playbook
from intel import enrich_ip_intelligence, get_real_client_ip, generate_analyst_mitre_report

init_db()

app = FastAPI(
    title="SecAuto SOAR - Enterprise SOC Cyber Defense Platform",
    description="Real-Time Threat Detection & Response Engine",
    version="2.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

# --- Request Models ---
class LoginAttempt(BaseModel):
    username: str
    password: str

class WebRequest(BaseModel):
    path: str
    payload: str

class PhishingCheck(BaseModel):
    url: str

class PlaybookRequest(BaseModel):
    incident_id: str
    playbook_name: str
    source_ip: str
    target_user: str

class ReportRequest(BaseModel):
    incident_id: str

# --- Endpoints ---

@app.get("/api/health")
def health():
    return {"status": "ONLINE", "engine": "SecAuto SOAR v2.2.0"}

@app.get("/api/whoami")
def whoami(request: Request):
    client_ip = get_real_client_ip(dict(request.headers), request.client.host if request.client else "127.0.0.1")
    return enrich_ip_intelligence(client_ip)

@app.get("/api/incidents")
def list_incidents():
    return get_recent_incidents()

@app.get("/api/blocked-ips")
def list_blocked():
    return get_blocked_ips()

@app.delete("/api/incidents/clear")
def clear_queue():
    clear_all_incidents()
    return {"status": "CLEARED", "message": "All incidents and blocklists have been reset."}

@app.get("/api/intel/{ip}")
def get_ip_intel(ip: str):
    return enrich_ip_intelligence(ip)

@app.post("/api/report/generate")
def get_incident_report(req: ReportRequest):
    incidents = get_recent_incidents(100)
    inc = next((i for i in incidents if i["incident_id"] == req.incident_id), None)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    intel = enrich_ip_intelligence(inc["source_ip"])
    return generate_analyst_mitre_report(inc, intel)

@app.post("/api/simulate/login")
async def simulate_login(req: LoginAttempt, request: Request):
    client_ip = get_real_client_ip(dict(request.headers), request.client.host if request.client else "127.0.0.1")
    real_intel = enrich_ip_intelligence(client_ip)
    actual_ip = real_intel.get("ip", client_ip)

    if is_ip_blocked(actual_ip):
        return {
            "status": "BLOCKED",
            "message": f"Connection terminated: Your IP {actual_ip} is blocked by the Firewall."
        }

    is_success = (req.password == "secret123")
    detection = analyze_login_attempt(actual_ip, req.username, is_success)

    if detection:
        inc_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
        log_incident(
            incident_id=inc_id,
            attack_type=detection["attack_type"],
            severity=detection["severity"],
            source_ip=actual_ip,
            target_user=detection["target_user"],
            details=detection["details"]
        )
        
        payload = {
            "type": "NEW_INCIDENT",
            "incident": {
                "incident_id": inc_id,
                **detection,
                "intel": real_intel
            }
        }
        await manager.broadcast(payload)
        
        return {
            "status": "ATTACK_TRIGGERED",
            "incident_id": inc_id,
            "detection": detection,
            "intel": real_intel
        }

    return {"status": "SUCCESS" if is_success else "FAILED", "client_ip": actual_ip}

@app.post("/api/simulate/web-attack")
async def simulate_web_attack(req: WebRequest, request: Request):
    client_ip = get_real_client_ip(dict(request.headers), request.client.host if request.client else "127.0.0.1")
    real_intel = enrich_ip_intelligence(client_ip)
    actual_ip = real_intel.get("ip", client_ip)

    if is_ip_blocked(actual_ip):
        return {"status": "BLOCKED", "message": f"IP {actual_ip} is blocked."}

    detection = analyze_web_payload(actual_ip, req.path, req.payload)
    if detection:
        inc_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
        log_incident(
            incident_id=inc_id,
            attack_type=detection["attack_type"],
            severity=detection["severity"],
            source_ip=actual_ip,
            target_user=detection["target_user"],
            details=detection["details"]
        )
        await manager.broadcast({
            "type": "NEW_INCIDENT",
            "incident": {
                "incident_id": inc_id,
                **detection,
                "intel": real_intel
            }
        })
        return {"status": "ATTACK_DETECTED", "incident_id": inc_id, "detection": detection, "intel": real_intel}
    
    return {"status": "SAFE", "message": "Payload passed WAF checks."}

@app.post("/api/scan/phishing")
async def scan_phishing(req: PhishingCheck, request: Request):
    """
    Scans URL for phishing. If verdict is MALICIOUS, automatically creates 
    a high-priority incident in the Ingested Threat Queue!
    """
    result = analyze_url_or_domain(req.url)
    
    # If malicious or high-risk, log it into the SOAR Threat Queue!
    if result["verdict"] in ["MALICIOUS", "SUSPICIOUS"]:
        client_ip = get_real_client_ip(dict(request.headers), request.client.host if request.client else "127.0.0.1")
        real_intel = enrich_ip_intelligence(client_ip)
        actual_ip = real_intel.get("ip", client_ip)

        inc_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
        reasons_summary = "; ".join(result["reasons"])
        
        log_incident(
            incident_id=inc_id,
            attack_type="Phishing & Deceptive URL Detected",
            severity="HIGH" if result["verdict"] == "MALICIOUS" else "MEDIUM",
            source_ip=actual_ip,
            target_user=f"Target Link: {req.url[:40]}...",
            details=f"URL: {req.url} | Risk Score: {result['risk_score']}/100 | Reasons: {reasons_summary}"
        )

        # Broadcast live to the dashboard queue!
        await manager.broadcast({
            "type": "NEW_INCIDENT",
            "incident": {
                "incident_id": inc_id,
                "attack_type": "Phishing & Deceptive URL Detected",
                "severity": "HIGH" if result["verdict"] == "MALICIOUS" else "MEDIUM",
                "source_ip": actual_ip,
                "target_user": req.url,
                "details": f"Deceptive Link Detected: {req.url} (Score {result['risk_score']}/100). Flags: {reasons_summary}",
                "auto_playbook": "Playbook_Phishing_Sinkhole.yaml",
                "status": "ACTIVE",
                "intel": real_intel
            }
        })
        result["incident_id"] = inc_id

    return result

@app.post("/api/playbook/run")
async def run_playbook(req: PlaybookRequest):
    result = execute_playbook(
        incident_id=req.incident_id,
        playbook_name=req.playbook_name,
        source_ip=req.source_ip,
        target_user=req.target_user
    )
    await manager.broadcast({
        "type": "PLAYBOOK_EXECUTED",
        "result": result
    })
    return result

# --- WebSockets ---
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Serve Frontend static directory
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    def serve_index():
        return FileResponse(os.path.join(frontend_dir, "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
