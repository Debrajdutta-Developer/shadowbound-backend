import os
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client, Client
from crypto_guard import jit_engine, behavioral_guard

app = FastAPI(title="ShadowBound Core")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SUPABASE_URL = os.getenv("https://mvihbwrseuswexaazmmj.supabase.co")
SUPABASE_KEY = os.getenv("sb_publishable_6AdO_fSdknVdeQJKo2BrDA_BjtZxo5H")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

class TokenRequest(BaseModel):
    workload_id: str
    service_type: str

async def log_event(source: str, message: str, severity: str):
    try: supabase.table("security_logs").insert({"source": source, "message": message, "severity": severity}).execute()
    except: pass

@app.middleware("http")
async def recon_shield(request: Request, call_next):
    path = request.url.path.lower()
    if any(ind in path for ind in ["/latest/meta-data", "/computemetadata/v1", "/var/run/secrets"]):
        await log_event("SHIELD", f"Intercepted metadata probe on: {path}", "CRITICAL")
        return JSONResponse(status_code=403, content={"error": "Trust Boundary Drift Intercepted."})
    return await call_next(request)

@app.get("/api/v1/telemetry/workloads")
async def get_workloads():
    res = supabase.table("workloads").select("*").order("id").execute()
    return res.data

@app.get("/api/v1/telemetry/logs")
async def get_logs():
    res = supabase.table("security_logs").select("*").order("timestamp", desc=True).limit(15).execute()
    return res.data

@app.post("/api/v1/identity/issue")
async def issue_token(payload: TokenRequest):
    if payload.workload_id in behavioral_guard.isolated_workloads:
        raise HTTPException(status_code=403, detail="Workload isolated.")
    token = jit_engine.issue_workload_token(payload.workload_id, payload.service_type)
    return {"token": token, "expires_in": "30s"}

@app.post("/api/v1/operator/reinstate/{workload_id}")
async def reinstate(workload_id: str):
    behavioral_guard.isolated_workloads.discard(workload_id)
    supabase.table("workloads").update({"status": "active"}).eq("id", workload_id).execute()
    await log_event("OPERATOR", f"Reinstated identity boundary for {workload_id}", "INFO")
    return {"status": "reinstated"}
  
