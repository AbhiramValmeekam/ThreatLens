# ============================================================
# FastAPI REST API — Backend for Next.js Frontend
# ============================================================
"""
Exposes the ThreatLens ML detection engine, explainability,
analytics, and scan history as a REST API.

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

from fastapi import FastAPI, Query, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# Ensure project root is in path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.database import init_db, save_scan, get_scan_history, get_total_scan_count
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
    description="LLM Security Monitoring REST API",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Initialize on startup ───────────────────────────────────

_detector = None
_explainer = None


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


@app.on_event("startup")
async def startup():
    init_db()
    # Eagerly load models so first request isn't slow
    _get_detector()
    _get_explainer()


# ─── Request / Response Models ────────────────────────────────

class ScanRequest(BaseModel):
    prompt: str


class BatchScanRequest(BaseModel):
    prompts: List[str]


# ─── Scan Endpoints ──────────────────────────────────────────

@app.post("/api/scan")
async def scan_prompt(req: ScanRequest):
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


@app.post("/api/batch-scan")
async def batch_scan(req: BatchScanRequest):
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
async def batch_scan_upload(file: UploadFile = File(...)):
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
    return await batch_scan(req)


# ─── Analytics Endpoints ─────────────────────────────────────

@app.get("/api/stats")
async def dashboard_stats():
    """Get dashboard summary statistics."""
    return get_dashboard_stats()


@app.get("/api/analytics/daily")
async def daily_attacks(days: int = Query(30, ge=1, le=365)):
    """Get daily attack time series data."""
    df = get_daily_attacks(days=days)
    if df.empty:
        return {"data": []}
    # Convert timestamps to strings for JSON
    df["date"] = df["date"].astype(str)
    return {"data": df.to_dict(orient="records")}


@app.get("/api/analytics/categories")
async def attack_categories():
    """Get attack category breakdown."""
    df = get_attack_category_data()
    if df.empty:
        return {"data": []}
    return {"data": df.to_dict(orient="records")}


@app.get("/api/analytics/risk-distribution")
async def risk_distribution():
    """Get risk score distribution for histogram."""
    df = get_risk_distribution_data()
    if df.empty:
        return {"data": []}
    return {"data": df.to_dict(orient="records")}


@app.get("/api/analytics/severity")
async def severity_breakdown():
    """Get severity level breakdown."""
    df = get_severity_data()
    if df.empty:
        return {"data": []}
    return {"data": df.to_dict(orient="records")}


@app.get("/api/analytics/patterns")
async def top_patterns(limit: int = Query(10, ge=1, le=50)):
    """Get top attack patterns."""
    data = get_top_attack_patterns(limit=limit)
    return {"data": data}


@app.get("/api/analytics/owasp")
async def owasp_mapping():
    """Get OWASP LLM Top 10 mapping data."""
    data = get_owasp_mapping_data()
    return {"data": data}


@app.get("/api/analytics/hourly")
async def hourly_distribution():
    """Get hourly scan distribution."""
    df = get_hourly_distribution()
    if df.empty:
        return {"data": []}
    return {"data": df.to_dict(orient="records")}


# ─── History Endpoints ───────────────────────────────────────

@app.get("/api/history")
async def scan_history(
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc"),
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


# ─── Health Check ─────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "2.0.0"}
