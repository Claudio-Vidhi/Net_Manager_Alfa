import os
import sys
import time
import json
import threading
import webbrowser
import requests
from typing import Optional, List
from datetime import timedelta

from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, BackgroundTasks, Security
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
from pydantic import BaseModel, Field

import inventory_manager
import core_engine
from security_manager import create_access_token, verify_access_token

PORT = 8765
BASE_URL = "https://euvdservices.enisa.europa.eu"

app = FastAPI(title="Net Manager Alfa Enterprise API", version="2.0")

# Abilita CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security_scheme = HTTPBearer(auto_error=False)

def get_resource_path(relative_path):
    """Restituisce il percorso assoluto della risorsa, funzionando sia in dev che bundled."""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# --- DIPENDENZE DI AUTENTICAZIONE ---

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme)):
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Autenticazione richiesta. Token mancante."
        )
    token = credentials.credentials
    payload = verify_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Token non valido o scaduto."
        )
    return payload

# --- MODELLI PYDANTIC ---

class LoginRequest(BaseModel):
    username: str
    password: str

class DeviceCreate(BaseModel):
    ip: str = Field(..., pattern=r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    vendor: str
    profile: str
    username: Optional[str] = ""
    password: Optional[str] = ""
    enable_secret: Optional[str] = ""
    group: Optional[str] = "Generale"

class DeviceDelete(BaseModel):
    ip: str

class CSVImportRequest(BaseModel):
    csv_data: str

class CommandRequest(BaseModel):
    ip: str
    command: str

class GroupCreate(BaseModel):
    group_name: str

class GroupUpdate(BaseModel):
    new_name: str

# --- STATO DEI JOB IN BACKGROUND ---

triage_job = {
    "status": "idle",       # "idle", "running", "complete"
    "progress": 0,
    "total": 0,
    "current_device": "",
    "results": []
}

def run_triage_background():
    global triage_job
    devices = inventory_manager.get_all_devices()
    triage_job["status"] = "running"
    triage_job["total"] = len(devices)
    triage_job["progress"] = 0
    triage_job["results"] = []
    
    for d in devices:
        triage_job["current_device"] = d['IP']
        res = core_engine.run_backup_and_triage(d)
        triage_job["results"].append({"ip": d['IP'], "result": res})
        triage_job["progress"] += 1
        
    triage_job["status"] = "complete"
    triage_job["current_device"] = ""

# --- ROTTE STATICHE ---

@app.get("/", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
def serve_dashboard():
    template_path = get_resource_path(os.path.join("templates", "dashboard.html"))
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Errore: dashboard.html non trovato nella cartella templates</h1>", status_code=404)

# --- ROTTE DI AUTENTICAZIONE ---

@app.post("/api/auth/login")
def login(payload: LoginRequest):
    # Credenziali di default per Net Manager Alfa Enterprise
    if payload.username == "admin" and payload.password == "admin":
        access_token = create_access_token(data={"sub": payload.username})
        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="Credenziali amministratore non valide."
    )

# --- ROTTE DISPOSITIVI (INVENTARIO) ---

@app.get("/api/local-devices")
def get_local_devices(current_user = Depends(get_current_user)):
    devices = inventory_manager.get_all_devices()
    versions = inventory_manager.get_detected_versions()
    return {"devices": devices, "detected_versions": versions}

@app.post("/api/add-device")
def add_device(payload: DeviceCreate, current_user = Depends(get_current_user)):
    inventory_manager.add_or_update_device(
        payload.ip, payload.vendor, payload.profile,
        payload.username, payload.password, payload.enable_secret,
        payload.group
    )
    return {"status": "success"}

@app.post("/api/delete-device")
def delete_device(payload: DeviceDelete, current_user = Depends(get_current_user)):
    inventory_manager.delete_device(payload.ip)
    return {"status": "success"}

@app.post("/api/import-csv")
def import_csv(payload: CSVImportRequest, current_user = Depends(get_current_user)):
    lines = payload.csv_data.split('\n')
    import csv as csv_parser
    reader = csv_parser.DictReader(lines)
    for row in reader:
        if row.get('IP'):
            inventory_manager.add_or_update_device(
                row['IP'], row.get('Vendor', 'cisco'), row.get('Profile', 'default'),
                row.get('Username', 'Admin'), row.get('Password', 'admin'), row.get('Enable Secret', 'admin'),
                row.get('Group', 'Generale')
            )
    return {"status": "success", "message": "CSV Importato"}

# --- ROTTE AUTOMAZIONE & COMANDI ---

@app.post("/api/run-triage")
def run_triage(background_tasks: BackgroundTasks, current_user = Depends(get_current_user)):
    global triage_job
    if triage_job["status"] == "running":
        return {"status": "running", "message": "Scansione già in corso"}
    
    triage_job["status"] = "running"
    triage_job["progress"] = 0
    triage_job["total"] = 0
    triage_job["current_device"] = "Inizializzazione..."
    
    background_tasks.add_task(run_triage_background)
    return {"status": "running", "message": "Scansione avviata in background"}

@app.get("/api/triage-status")
def get_triage_status(current_user = Depends(get_current_user)):
    return triage_job

@app.post("/api/send-command")
def send_command(payload: CommandRequest, current_user = Depends(get_current_user)):
    devices = inventory_manager.get_all_devices()
    target_device = next((d for d in devices if d['IP'] == payload.ip), None)
    if target_device:
        res = core_engine.send_custom_command(target_device, payload.command)
        return res
    raise HTTPException(status_code=404, detail="Dispositivo non presente in inventario")

@app.get("/api/download-backup/{ip_or_filename}")
def download_backup(ip_or_filename: str, current_user = Depends(get_current_user)):
    # 1. Verifica se il file esiste esattamente in backup-config
    filepath = os.path.join("backup-config", ip_or_filename)
    if os.path.exists(filepath):
        return FileResponse(filepath, media_type="application/octet-stream", filename=ip_or_filename)
        
    # 2. Se è stato passato un IP o un formato con vendor, cerchiamo in modo euristico il file corrispondente
    ip = ip_or_filename
    if ip_or_filename.endswith(".txt"):
        # Estrae l'IP dall'eventuale nome file (es. cisco_10.0.0.1.txt o Switch-10.0.0.1.txt)
        for sep in ["_", "-"]:
            parts = ip_or_filename[:-4].split(sep)
            if len(parts) >= 2:
                ip = parts[-1]
                break

    if os.path.exists("backup-config"):
        for f in os.listdir("backup-config"):
            if f.endswith(f"-{ip}.txt") or f.endswith(f"_{ip}.txt") or f == f"{ip}.txt" or f == ip_or_filename:
                target_path = os.path.join("backup-config", f)
                return FileResponse(target_path, media_type="application/octet-stream", filename=f)
                
    raise HTTPException(status_code=404, detail="File di backup non trovato per questo dispositivo.")

# --- ROTTE GRUPPI (CRUD) ---

@app.get("/api/groups")
def get_groups(current_user = Depends(get_current_user)):
    return inventory_manager.get_all_groups()

@app.post("/api/groups")
def create_group(payload: GroupCreate, current_user = Depends(get_current_user)):
    success = inventory_manager.add_group(payload.group_name)
    if success:
        return {"status": "success"}
    raise HTTPException(status_code=400, detail="Gruppo già esistente o nome non valido")

@app.put("/api/groups/{group_name}")
def rename_group(group_name: str, payload: GroupUpdate, current_user = Depends(get_current_user)):
    success = inventory_manager.update_group(group_name, payload.new_name)
    if success:
        return {"status": "success"}
    raise HTTPException(status_code=400, detail="Impossibile rinominare il gruppo (es. Generale non è rinominabile)")

@app.delete("/api/groups/{group_name}")
def delete_group(group_name: str, current_user = Depends(get_current_user)):
    success = inventory_manager.delete_group(group_name)
    if success:
        return {"status": "success"}
    raise HTTPException(status_code=400, detail="Impossibile eliminare il gruppo richiesto")

# --- ROTTA MAPPA DI RETE ---

@app.get("/api/network-map")
def get_network_map(current_user = Depends(get_current_user)):
    return core_engine.generate_network_map()

# --- PROXY TRASPARENTE VERSO ENISA EUVD ---

@app.api_route("/api/{path:path}", methods=["GET", "POST", "OPTIONS"])
async def proxy_enisa(path: str, request: Request, current_user = Depends(get_current_user)):
    target = f"{BASE_URL}/api/{path}"
    query = request.url.query
    if query:
        target += f"?{query}"
        
    try:
        headers = {"User-Agent": "ThreatIntelDashboard/3.0"}
        method = request.method
        
        if method == "GET":
            from fastapi.concurrency import run_in_threadpool
            r = await run_in_threadpool(requests.get, target, headers=headers, timeout=15)
        elif method == "POST":
            body = await request.body()
            from fastapi.concurrency import run_in_threadpool
            r = await run_in_threadpool(requests.post, target, headers=headers, data=body, timeout=15)
        else:
            return Response(status_code=200)
            
        return Response(
            content=r.content, 
            status_code=r.status_code, 
            headers={"Content-Type": r.headers.get("Content-Type", "application/json")}
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

# --- AVVIO E BROWSER AUTOMATICO ---

def open_browser():
    time.sleep(1.5)
    webbrowser.open(f"http://localhost:{PORT}/")

def main():
    if not os.path.exists("templates"): 
        os.makedirs("templates")
        
    # Avvia l'apertura del browser in background
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Avvia uvicorn
    uvicorn.run("app_server:app", host="localhost", port=PORT, log_level="info")

if __name__ == "__main__":
    main()
