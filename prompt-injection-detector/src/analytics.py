# ============================================================
# Analytics — Dashboard Analytics & Aggregation Queries
# ============================================================
"""
Provides analytics functions for the Streamlit dashboard:

- Summary statistics (total scans, detection rate, etc.)
- Daily attack time series
- Risk score distributions
- Attack category breakdowns
- Top attack patterns
- OWASP LLM Top 10 mapping

All functions query the SQLite database via the database module.

Usage:
    from src.analytics import get_dashboard_stats, get_daily_attacks
    stats = get_dashboard_stats()
    daily = get_daily_attacks(days=30)
"""

import os
from datetime import date, timedelta
from typing import Dict, Any, List, Optional

import pandas as pd

from src.database import (
    get_session,
    get_analytics_summary,
    get_daily_analytics,
    get_category_breakdown,
    get_risk_score_distribution,
    get_severity_breakdown,
    ScanHistory,
    Analytics,
)
from sqlalchemy import func, desc

# ─── OWASP LLM Top 10 Mapping ────────────────────────────────
OWASP_LLM_MAPPING = {
    "Safe": None,
    "Prompt Injection": {
        "id": "LLM01",
        "name": "Prompt Injection",
        "description": "Manipulating LLMs via crafted inputs to cause unintended actions",
        "severity": "Critical",
    },
    "Jailbreak": {
        "id": "LLM01",
        "name": "Prompt Injection",
        "description": "Bypassing model safety filters through creative prompting",
        "severity": "Critical",
    },
    "Role Hijacking": {
        "id": "LLM01",
        "name": "Prompt Injection",
        "description": "Reassigning the model's persona to bypass restrictions",
        "severity": "High",
    },
    "System Prompt Extraction": {
        "id": "LLM06",
        "name": "Sensitive Information Disclosure",
        "description": "Extracting hidden system prompts and configuration",
        "severity": "High",
    },
    "Data Exfiltration": {
        "id": "LLM06",
        "name": "Sensitive Information Disclosure",
        "description": "Attempting to extract sensitive data through the model",
        "severity": "Critical",
    },
    "Indirect Prompt Injection": {
        "id": "LLM01",
        "name": "Prompt Injection",
        "description": "Hidden instructions embedded in external content",
        "severity": "High",
    },
    "Tool Abuse Attempt": {
        "id": "LLM07",
        "name": "Insecure Plugin Design",
        "description": "Attempting to abuse tool/plugin access through the model",
        "severity": "Critical",
    },
}


def get_dashboard_stats() -> Dict[str, Any]:
    """
    Get all summary statistics for the dashboard home page.
    
    Returns:
        Dict with total_scans, attacks_detected, high_risk_count,
        detection_rate, avg_risk_score, recent_trend
    """
    summary = get_analytics_summary()

    # Calculate recent trend (last 7 days vs previous 7 days)
    daily = get_daily_analytics(days=14)
    trend = _calculate_trend(daily)

    summary["trend"] = trend
    return summary


def get_daily_attacks(days: int = 30) -> pd.DataFrame:
    """
    Get daily attack data for time-series chart.
    
    Args:
        days: Number of days to look back
    
    Returns:
        DataFrame with date, total_scans, attacks_detected, high_risk_count columns
    """
    data = get_daily_analytics(days=days)

    if not data:
        # Return empty DataFrame with correct columns
        return pd.DataFrame(
            columns=["date", "total_scans", "attacks_detected", "high_risk_count", "avg_risk_score"]
        )

    df = pd.DataFrame(data)
    df["date"] = pd.to_datetime(df["date"])
    return df


def get_attack_category_data() -> pd.DataFrame:
    """
    Get attack category distribution for pie/donut chart.
    
    Returns:
        DataFrame with attack_type and count columns
    """
    data = get_category_breakdown()
    if not data:
        return pd.DataFrame(columns=["attack_type", "count"])
    return pd.DataFrame(data)


def get_risk_distribution_data() -> pd.DataFrame:
    """
    Get risk score distribution for histogram.
    
    Returns:
        DataFrame with risk_score column
    """
    data = get_risk_score_distribution()
    if not data:
        return pd.DataFrame(columns=["risk_score"])
    return pd.DataFrame(data)


def get_severity_data() -> pd.DataFrame:
    """
    Get severity level distribution for chart.
    
    Returns:
        DataFrame with severity and count columns
    """
    data = get_severity_breakdown()
    if not data:
        return pd.DataFrame(columns=["severity", "count"])
    return pd.DataFrame(data)


def get_top_attack_patterns(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Get the most frequently matched attack patterns.
    
    Analyzes the matched_patterns field from scan history
    to find the most common attack signatures.
    
    Args:
        limit: Max number of patterns to return
    
    Returns:
        List of dicts with pattern, count, and category
    """
    import json

    session = get_session()
    try:
        records = (
            session.query(ScanHistory.matched_patterns)
            .filter(ScanHistory.matched_patterns.isnot(None))
            .filter(ScanHistory.matched_patterns != "")
            .filter(ScanHistory.matched_patterns != "[]")
            .all()
        )

        pattern_counts: Dict[str, int] = {}
        pattern_details: Dict[str, Dict] = {}

        for (patterns_json,) in records:
            try:
                patterns = json.loads(patterns_json)
                for p in patterns:
                    desc = p.get("description", "Unknown")
                    pattern_counts[desc] = pattern_counts.get(desc, 0) + 1
                    if desc not in pattern_details:
                        pattern_details[desc] = {
                            "category": p.get("category_name", "Unknown"),
                            "pattern": p.get("pattern", ""),
                        }
            except (json.JSONDecodeError, TypeError):
                continue

        # Sort by count and take top N
        sorted_patterns = sorted(
            pattern_counts.items(), key=lambda x: x[1], reverse=True
        )[:limit]

        return [
            {
                "description": desc,
                "count": count,
                "category": pattern_details.get(desc, {}).get("category", "Unknown"),
                "pattern": pattern_details.get(desc, {}).get("pattern", ""),
            }
            for desc, count in sorted_patterns
        ]
    finally:
        session.close()


def get_owasp_mapping_data() -> List[Dict[str, Any]]:
    """
    Get attack category to OWASP LLM Top 10 mapping with counts.
    
    Returns:
        List of dicts with attack_type, owasp_id, owasp_name, count
    """
    categories = get_category_breakdown()
    owasp_data = []

    for cat_data in categories:
        attack_type = cat_data["attack_type"]
        mapping = OWASP_LLM_MAPPING.get(attack_type)

        if mapping:
            owasp_data.append({
                "attack_type": attack_type,
                "owasp_id": mapping["id"],
                "owasp_name": mapping["name"],
                "owasp_description": mapping["description"],
                "owasp_severity": mapping["severity"],
                "count": cat_data["count"],
            })

    return owasp_data


def _calculate_trend(daily_data: List[Dict]) -> Dict[str, Any]:
    """
    Calculate the trend by comparing the last 7 days to the previous 7 days.
    
    Args:
        daily_data: List of daily analytics dicts (last 14 days)
    
    Returns:
        Dict with direction, percentage change, and description
    """
    if len(daily_data) < 2:
        return {"direction": "stable", "change": 0.0, "description": "Not enough data"}

    # Split into recent and previous periods
    midpoint = len(daily_data) // 2
    recent = daily_data[midpoint:]
    previous = daily_data[:midpoint]

    recent_attacks = sum(d.get("attacks_detected", 0) for d in recent)
    previous_attacks = sum(d.get("attacks_detected", 0) for d in previous)

    if previous_attacks == 0:
        if recent_attacks > 0:
            return {"direction": "up", "change": 100.0, "description": "New attacks detected"}
        return {"direction": "stable", "change": 0.0, "description": "No attacks in period"}

    change_pct = ((recent_attacks - previous_attacks) / previous_attacks) * 100

    if change_pct > 10:
        direction = "up"
        desc = f"Attacks increased {abs(change_pct):.0f}% from previous period"
    elif change_pct < -10:
        direction = "down"
        desc = f"Attacks decreased {abs(change_pct):.0f}% from previous period"
    else:
        direction = "stable"
        desc = "Attack rate stable compared to previous period"

    return {
        "direction": direction,
        "change": round(change_pct, 1),
        "description": desc,
    }


def get_hourly_distribution() -> pd.DataFrame:
    """
    Get the distribution of scans by hour of day.
    
    Returns:
        DataFrame with hour and count columns
    """
    session = get_session()
    try:
        results = (
            session.query(
                func.strftime("%H", ScanHistory.timestamp).label("hour"),
                func.count(ScanHistory.id).label("count"),
            )
            .group_by("hour")
            .order_by("hour")
            .all()
        )

        if not results:
            return pd.DataFrame(columns=["hour", "count"])

        return pd.DataFrame([{"hour": int(r[0]), "count": r[1]} for r in results])
    finally:
        session.close()
