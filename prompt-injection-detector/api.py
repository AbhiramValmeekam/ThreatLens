# ============================================================
# FastAPI REST API — Backend for Next.js Frontend
# ============================================================
"""
Exposes the ThreatLens ML detection engine, explainability,
analytics, and scan history as a REST API. Includes user
registration and login capabilities.

Run with:
    uvicorn api:app --reload --port 8000
"""

import os
import sys
import json
import csv
import io
from typing import Optional, List
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Query, UploadFile, File, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

# Ensure project root is in path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.database import (
    init_db, save_scan, get_scan_history, get_total_scan_count,
    create_user, get_user_by_email, save_firewall_log, get_firewall_logs,
    get_total_firewall_log_count, get_firewall_stats
)
from src.auth_utils import (
    hash_password, verify_password, create_access_token, verify_access_token
)
from src.analytics import (
    get_dashboard_stats,
    get_daily_attacks,
    get_attack_category_data,
    get_risk_distribution_data,
    get_severity_data,
    get_top_attack_patterns,
    get_owasp_mapping_data,
    get_hourly_distribution,
)

# ─── App Setup ────────────────────────────────────────────────

app = FastAPI(
    title="ThreatLens API",
    description="LLM Security Monitoring REST API with Authentication",
    version="2.0.0",
)

ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# ─── Initialize on startup ───────────────────────────────────

_detector = None
_explainer = None
_firewall = None


def _get_detector():
    global _detector
    if _detector is None:
        from src.ensemble import EnsembleDetector
        _detector = EnsembleDetector()
    return _detector


def _get_explainer():
    global _explainer
    if _explainer is None:
        from src.explain import ExplainabilityEngine
        _explainer = ExplainabilityEngine()
    return _explainer


def _get_firewall():
    global _firewall
    if _firewall is None:
        from src.firewall import PromptSentinelFirewall
        _firewall = PromptSentinelFirewall()
    return _firewall


@app.on_event("startup")
async def startup():
    init_db()
    # Eagerly load models so first request isn't slow
    _get_detector()
    _get_explainer()
    _get_firewall()


# ─── Auth Dependency ─────────────────────────────────────────

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verifies the bearer token in authorization header."""
    token = credentials.credentials
    payload = verify_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired session token"
        )
    email = payload.get("sub")
    user = get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=401, detail="User account not found")
    return user


# ─── Request / Response Models ────────────────────────────────

class ScanRequest(BaseModel):
    prompt: str


class BatchScanRequest(BaseModel):
    prompts: List[str]


class AuthRequest(BaseModel):
    email: str
    password: str


class GoogleAuthRequest(BaseModel):
    id_token: str


# ─── Google OAuth Verification ───────────────────────────────

import urllib.request
import urllib.parse

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")


def verify_google_token(id_token: str) -> Optional[dict]:
    """Verify Google token via Google OAuth2 API."""
    try:
        url = f"https://oauth2.googleapis.com/tokeninfo?id_token={urllib.parse.quote(id_token)}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
            aud = data.get("aud")
            if GOOGLE_CLIENT_ID and aud != GOOGLE_CLIENT_ID:
                print("Warning: Google token aud does not match GOOGLE_CLIENT_ID")
            if "email" in data:
                return data
    except Exception as e:
        print(f"Google token verification failed: {e}")
    return None


# ─── Authentication Endpoints ─────────────────────────────────

@app.post("/api/auth/register")
async def register(req: AuthRequest):
    """Register a new user account."""
    if not req.email.strip() or not req.password.strip():
        raise HTTPException(status_code=400, detail="Email and password cannot be empty")
    
    if "@" not in req.email:
        raise HTTPException(status_code=400, detail="Invalid email format")
        
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    existing = get_user_by_email(req.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email is already registered")

    pwd_hash = hash_password(req.password)
    user = create_user(req.email, pwd_hash)

    token = create_access_token({"sub": user.email, "id": user.id})
    return {
        "token": token,
        "user": {"id": user.id, "email": user.email}
    }


@app.post("/api/auth/login")
async def login(req: AuthRequest):
    """Authenticate and obtain a session token."""
    if not req.email.strip() or not req.password.strip():
        raise HTTPException(status_code=400, detail="Email and password required")

    user = get_user_by_email(req.email)
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    token = create_access_token({"sub": user.email, "id": user.id})
    return {
        "token": token,
        "user": {"id": user.id, "email": user.email}
    }


@app.post("/api/auth/google")
async def auth_google(req: GoogleAuthRequest):
    """Authenticate with a Google ID Token."""
    if not req.id_token.strip():
        raise HTTPException(status_code=400, detail="Token cannot be empty")
        
    payload = verify_google_token(req.id_token)
    if not payload:
        raise HTTPException(status_code=400, detail="Invalid Google authentication token")
        
    email = payload.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email not provided by Google")
        
    # Check if user exists
    user = get_user_by_email(email)
    if not user:
        # Create a new user with placeholder password hash
        placeholder_hash = hash_password(os.urandom(16).hex())
        user = create_user(email, placeholder_hash)
        
    # Generate session token
    token = create_access_token({"sub": user.email, "id": user.id})
    return {
        "token": token,
        "user": {"id": user.id, "email": user.email}
    }


@app.get("/api/auth/me")
async def get_me(current_user=Depends(get_current_user)):
    """Fetch profile details for the authenticated user."""
    return {"id": current_user.id, "email": current_user.email}


# ─── Scan Endpoints (Protected) ──────────────────────────────

@app.post("/api/scan")
async def scan_prompt(req: ScanRequest, user=Depends(get_current_user)):
    """Analyze a single prompt for injection attacks."""
    if not req.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")

    detector = _get_detector()
    result = detector.predict(req.prompt)

    # Get explanations
    try:
        explainer = _get_explainer()
        explanation = explainer.explain(req.prompt, result.to_dict())
    except Exception:
        explanation = {
            "keywords": [],
            "shap_values": [],
            "highlighted_segments": [],
            "reasons": result.reasons,
            "risk_factors": [],
        }

    # Save to database
    save_scan(
        prompt=req.prompt,
        risk_score=result.risk_score,
        attack_type=result.attack_type,
        attack_category_id=result.attack_category_id,
        severity=result.severity,
        confidence=result.confidence,
        explanation="; ".join(result.reasons) if result.reasons else None,
        matched_patterns=json.dumps(result.matched_patterns, default=str) if result.matched_patterns else None,
        model_scores=json.dumps(result.model_scores, default=str),
    )

    return {
        "risk_score": result.risk_score,
        "attack_type": result.attack_type,
        "attack_category_id": result.attack_category_id,
        "severity": result.severity,
        "confidence": result.confidence,
        "is_injection": result.is_injection,
        "model_scores": result.model_scores,
        "matched_patterns": result.matched_patterns,
        "reasons": result.reasons,
        "explanation": explanation,
    }


# ─── LLM Firewall & Heatmap Endpoints (Protected) ─────────────

@app.post("/api/firewall/simulate")
async def simulate_firewall(req: ScanRequest, user=Depends(get_current_user)):
    """Simulate prompt passing through the LLM Firewall."""
    if not req.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")
    
    firewall = _get_firewall()
    result = firewall.process_prompt(req.prompt)
    return result


@app.get("/api/firewall/logs")
async def firewall_logs(
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    user=Depends(get_current_user),
):
    """Get paginated firewall action logs."""
    action_filter = action.split(",") if action else None
    logs = get_firewall_logs(limit=limit, offset=offset, search_query=search, action_filter=action_filter)
    total = get_total_firewall_log_count(search_query=search, action_filter=action_filter)
    return {"data": logs, "total": total}


@app.get("/api/firewall/stats")
async def firewall_stats(user=Depends(get_current_user)):
    """Get aggregated firewall analytics statistics."""
    return get_firewall_stats()


@app.post("/api/heatmap")
async def generate_prompt_heatmap(req: ScanRequest, user=Depends(get_current_user)):
    """Generate visual risk heatmap segments for a prompt."""
    if not req.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")
    
    detector = _get_detector()
    result = detector.predict(req.prompt)
    
    try:
        explainer = _get_explainer()
        explanation = explainer.explain(req.prompt, result.to_dict())
    except Exception:
        explanation = {
            "keywords": [],
            "shap_values": [],
            "highlighted_segments": [],
            "reasons": result.reasons,
            "risk_factors": [],
        }
        
    from src.heatmap import generate_heatmap
    heatmap = generate_heatmap(req.prompt, explanation, result)
    return heatmap


@app.post("/api/batch-scan")
async def batch_scan(req: BatchScanRequest, user=Depends(get_current_user)):
    """Analyze multiple prompts for injection attacks."""
    if not req.prompts:
        raise HTTPException(status_code=400, detail="Prompts list cannot be empty")

    detector = _get_detector()
    results = []

    for prompt in req.prompts:
        if not prompt.strip():
            continue

        result = detector.predict(prompt)

        save_scan(
            prompt=prompt,
            risk_score=result.risk_score,
            attack_type=result.attack_type,
            attack_category_id=result.attack_category_id,
            severity=result.severity,
            confidence=result.confidence,
            explanation="; ".join(result.reasons) if result.reasons else None,
            matched_patterns=json.dumps(result.matched_patterns, default=str) if result.matched_patterns else None,
            model_scores=json.dumps(result.model_scores, default=str),
        )

        results.append({
            "prompt": prompt,
            "risk_score": result.risk_score,
            "attack_type": result.attack_type,
            "severity": result.severity,
            "confidence": result.confidence,
            "is_injection": result.is_injection,
            "reasons": "; ".join(result.reasons) if result.reasons else "",
        })

    return {"results": results, "total": len(results)}


@app.post("/api/batch-scan/upload")
async def batch_scan_upload(file: UploadFile = File(...), user=Depends(get_current_user)):
    """Upload a CSV/TXT file and scan all prompts."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file uploaded")

    content = await file.read()
    text = content.decode("utf-8")
    prompts = []

    if file.filename.endswith(".csv"):
        import pandas as pd
        df = pd.read_csv(io.StringIO(text))
        text_col = None
        for col_name in ["prompt", "text", "input", "content", "query", "message"]:
            if col_name in df.columns:
                text_col = col_name
                break
        if text_col is None:
            text_col = df.columns[0]
        prompts = df[text_col].dropna().astype(str).tolist()
    else:
        prompts = [line.strip() for line in text.splitlines() if line.strip()]

    if not prompts:
        raise HTTPException(status_code=400, detail="No valid prompts found in file")

    # Reuse batch scan logic
    req = BatchScanRequest(prompts=prompts)
    return await batch_scan(req, user=user)


# ─── Analytics Endpoints (Protected) ──────────────────────────

@app.get("/api/stats")
async def dashboard_stats(user=Depends(get_current_user)):
    """Get dashboard summary statistics."""
    return get_dashboard_stats()


@app.get("/api/analytics/daily")
async def daily_attacks(days: int = Query(30, ge=1, le=365), user=Depends(get_current_user)):
    """Get daily attack time series data."""
    df = get_daily_attacks(days=days)
    if df.empty:
        return {"data": []}
    # Convert timestamps to strings for JSON
    df["date"] = df["date"].astype(str)
    return {"data": df.to_dict(orient="records")}


@app.get("/api/analytics/categories")
async def attack_categories(user=Depends(get_current_user)):
    """Get attack category breakdown."""
    df = get_attack_category_data()
    if df.empty:
        return {"data": []}
    return {"data": df.to_dict(orient="records")}


@app.get("/api/analytics/risk-distribution")
async def risk_distribution(user=Depends(get_current_user)):
    """Get risk score distribution for histogram."""
    df = get_risk_distribution_data()
    if df.empty:
        return {"data": []}
    return {"data": df.to_dict(orient="records")}


@app.get("/api/analytics/severity")
async def severity_breakdown(user=Depends(get_current_user)):
    """Get severity level breakdown."""
    df = get_severity_data()
    if df.empty:
        return {"data": []}
    return {"data": df.to_dict(orient="records")}


@app.get("/api/analytics/patterns")
async def top_patterns(limit: int = Query(10, ge=1, le=50), user=Depends(get_current_user)):
    """Get top attack patterns."""
    data = get_top_attack_patterns(limit=limit)
    return {"data": data}


@app.get("/api/analytics/owasp")
async def owasp_mapping(user=Depends(get_current_user)):
    """Get OWASP LLM Top 10 mapping data."""
    data = get_owasp_mapping_data()
    return {"data": data}


@app.get("/api/analytics/hourly")
async def hourly_distribution(user=Depends(get_current_user)):
    """Get hourly scan distribution."""
    df = get_hourly_distribution()
    if df.empty:
        return {"data": []}
    return {"data": df.to_dict(orient="records")}


# ─── History Endpoints (Protected) ────────────────────────────

@app.get("/api/history")
async def scan_history(
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc"),
    user=Depends(get_current_user),
):
    """Get paginated scan history with filters."""
    category_filter = category.split(",") if category else None
    severity_filter = severity.split(",") if severity else None

    records = get_scan_history(
        limit=limit,
        offset=offset,
        search_query=search,
        category_filter=category_filter,
        severity_filter=severity_filter,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return {"data": records}


@app.get("/api/history/count")
async def scan_count(
    search: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    user=Depends(get_current_user),
):
    """Get total scan count with filters."""
    category_filter = category.split(",") if category else None
    severity_filter = severity.split(",") if severity else None

    count = get_total_scan_count(
        search_query=search,
        category_filter=category_filter,
        severity_filter=severity_filter,
    )
    return {"count": count}


@app.get("/api/history/export")
async def export_history(
    search: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc"),
    user=Depends(get_current_user),
):
    """Export scan history as CSV."""
    category_filter = category.split(",") if category else None
    severity_filter = severity.split(",") if severity else None

    records = get_scan_history(
        limit=10000,
        offset=0,
        search_query=search,
        category_filter=category_filter,
        severity_filter=severity_filter,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    output = io.StringIO()
    if records:
        cols = ["timestamp", "prompt", "risk_score", "attack_type", "severity", "confidence", "explanation"]
        writer = csv.DictWriter(output, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)

    output.seek(0)
    filename = f"scan_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ─── Health Check (Open) ──────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "2.0.0"}
