# ============================================================
# Database Layer — SQLAlchemy ORM Models & CRUD Operations
# ============================================================
"""
Provides the database schema and operations for the prompt
injection detection platform.

Tables:
    User         — Registered users
    ScanHistory  — Individual prompt scan records
    Analytics    — Daily aggregated detection metrics

Usage:
    from src.database import init_db, save_scan, get_scan_history
    init_db()
    save_scan(prompt="...", risk_score=85.0, ...)
"""

import os
from datetime import datetime, date
from typing import Optional, List, Dict, Any
from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, DateTime,
    Date, Text, Boolean, func, desc, asc
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# ─── Configuration ────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "prompt_injection.db")

# Allow database override via environment variables or Streamlit Secrets (useful for cloud hosting)
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    try:
        import streamlit as st
        if hasattr(st, "secrets") and "database" in st.secrets and "url" in st.secrets["database"]:
            DATABASE_URL = st.secrets["database"]["url"]
        elif hasattr(st, "secrets") and "database_url" in st.secrets:
            DATABASE_URL = st.secrets["database_url"]
    except Exception:
        pass

if not DATABASE_URL:
    DATABASE_URL = f"sqlite:///{DB_PATH}"

Base = declarative_base()
engine = None
SessionLocal = None


# ============================================================
# ORM Models
# ============================================================

class User(Base):
    """Registered user accounts."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}')>"


class ScanHistory(Base):
    """Individual prompt scan records with detection results."""
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    prompt = Column(Text, nullable=False)
    risk_score = Column(Float, nullable=False, default=0.0)
    attack_type = Column(String(100), nullable=False, default="Safe")
    attack_category_id = Column(Integer, nullable=False, default=0)
    severity = Column(String(20), nullable=False, default="Low")
    confidence = Column(Float, nullable=False, default=0.0)
    explanation = Column(Text, nullable=True)
    matched_patterns = Column(Text, nullable=True)  # JSON string of matched patterns
    model_scores = Column(Text, nullable=True)       # JSON string of individual model scores
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self):
        return f"<ScanHistory(id={self.id}, risk={self.risk_score}, type='{self.attack_type}')>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary for DataFrame/JSON use."""
        return {
            "id": self.id,
            "prompt": self.prompt,
            "risk_score": self.risk_score,
            "attack_type": self.attack_type,
            "attack_category_id": self.attack_category_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "matched_patterns": self.matched_patterns,
            "model_scores": self.model_scores,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class Analytics(Base):
    """Daily aggregated detection metrics for dashboard analytics."""
    __tablename__ = "analytics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(Date, unique=True, nullable=False, index=True)
    total_scans = Column(Integer, default=0, nullable=False)
    attacks_detected = Column(Integer, default=0, nullable=False)
    high_risk_count = Column(Integer, default=0, nullable=False)
    avg_risk_score = Column(Float, default=0.0, nullable=False)

    def __repr__(self):
        return f"<Analytics(date={self.date}, scans={self.total_scans}, attacks={self.attacks_detected})>"


class FirewallLog(Base):
    """Logs of LLM Firewall actions."""
    __tablename__ = "firewall_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    original_prompt = Column(Text, nullable=False)
    sanitized_prompt = Column(Text, nullable=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    threat_category = Column(String(100), nullable=True)
    firewall_action = Column(String(50), nullable=False) # ALLOW, SANITIZE, BLOCK
    heatmap_data = Column(Text, nullable=True) # JSON string of segments
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self):
        return f"<FirewallLog(id={self.id}, action='{self.firewall_action}', risk={self.risk_score})>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary for DataFrame/JSON use."""
        return {
            "id": self.id,
            "original_prompt": self.original_prompt,
            "sanitized_prompt": self.sanitized_prompt,
            "risk_score": self.risk_score,
            "threat_category": self.threat_category,
            "firewall_action": self.firewall_action,
            "heatmap_data": self.heatmap_data,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }



# ============================================================
# Database Initialization
# ============================================================

def init_db(db_url: Optional[str] = None) -> None:
    """
    Initialize the database engine and create all tables.
    
    Args:
        db_url: Optional custom database URL. Defaults to SQLite file.
    """
    global engine, SessionLocal

    url = db_url or DATABASE_URL

    # Ensure the data directory exists
    db_dir = os.path.dirname(DB_PATH)
    os.makedirs(db_dir, exist_ok=True)

    engine = create_engine(url, echo=False, future=True)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    # Create all tables if they don't exist
    Base.metadata.create_all(engine)

    # Simple migration: ensure users table has password_hash column
    try:
        from sqlalchemy import text
        with engine.begin() as conn:
            result = conn.execute(text("PRAGMA table_info(users)"))
            columns = [row[1] for row in result.fetchall()]
            if "password_hash" not in columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN password_hash VARCHAR(255)"))
    except Exception as e:
        pass


def get_session() -> Session:
    """Get a new database session. Caller must close it."""
    if SessionLocal is None:
        init_db()
    return SessionLocal()


# ============================================================
# CRUD Operations — Scan History
# ============================================================

def save_scan(
    prompt: str,
    risk_score: float,
    attack_type: str,
    attack_category_id: int,
    severity: str,
    confidence: float,
    explanation: Optional[str] = None,
    matched_patterns: Optional[str] = None,
    model_scores: Optional[str] = None,
) -> ScanHistory:
    """
    Save a new scan result to the database and update daily analytics.
    
    Args:
        prompt: The scanned prompt text
        risk_score: Ensemble risk score (0-100)
        attack_type: Human-readable attack category name
        attack_category_id: Numeric category (0-7)
        severity: Low/Medium/High/Critical
        confidence: Model confidence (0-100)
        explanation: Human-readable detection explanation
        matched_patterns: JSON string of matched rule patterns
        model_scores: JSON string of individual model scores
    
    Returns:
        The created ScanHistory record
    """
    session = get_session()
    try:
        # Create scan record
        scan = ScanHistory(
            prompt=prompt,
            risk_score=risk_score,
            attack_type=attack_type,
            attack_category_id=attack_category_id,
            severity=severity,
            confidence=confidence,
            explanation=explanation,
            matched_patterns=matched_patterns,
            model_scores=model_scores,
        )
        session.add(scan)

        # Update daily analytics
        _update_daily_analytics(
            session, risk_score, attack_category_id, severity
        )

        session.commit()
        return scan
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def get_scan_history(
    limit: int = 100,
    offset: int = 0,
    search_query: Optional[str] = None,
    category_filter: Optional[List[str]] = None,
    severity_filter: Optional[List[str]] = None,
    sort_by: str = "timestamp",
    sort_order: str = "desc",
) -> List[Dict[str, Any]]:
    """
    Retrieve scan history with optional filtering and pagination.
    
    Args:
        limit: Max records to return
        offset: Number of records to skip
        search_query: Text search in prompt field
        category_filter: List of attack type names to filter by
        severity_filter: List of severity levels to filter by
        sort_by: Column to sort by (timestamp, risk_score, attack_type)
        sort_order: 'asc' or 'desc'
    
    Returns:
        List of scan record dictionaries
    """
    session = get_session()
    try:
        query = session.query(ScanHistory)

        # Apply search filter
        if search_query:
            query = query.filter(
                ScanHistory.prompt.ilike(f"%{search_query}%")
            )

        # Apply category filter
        if category_filter:
            query = query.filter(
                ScanHistory.attack_type.in_(category_filter)
            )

        # Apply severity filter
        if severity_filter:
            query = query.filter(
                ScanHistory.severity.in_(severity_filter)
            )

        # Apply sorting
        sort_column = getattr(ScanHistory, sort_by, ScanHistory.timestamp)
        if sort_order == "desc":
            query = query.order_by(desc(sort_column))
        else:
            query = query.order_by(asc(sort_column))

        # Apply pagination
        results = query.offset(offset).limit(limit).all()
        return [r.to_dict() for r in results]
    finally:
        session.close()


def get_total_scan_count(
    search_query: Optional[str] = None,
    category_filter: Optional[List[str]] = None,
    severity_filter: Optional[List[str]] = None,
) -> int:
    """Get total number of scans matching the given filters."""
    session = get_session()
    try:
        query = session.query(func.count(ScanHistory.id))

        if search_query:
            query = query.filter(
                ScanHistory.prompt.ilike(f"%{search_query}%")
            )
        if category_filter:
            query = query.filter(
                ScanHistory.attack_type.in_(category_filter)
            )
        if severity_filter:
            query = query.filter(
                ScanHistory.severity.in_(severity_filter)
            )

        return query.scalar() or 0
    finally:
        session.close()


# ============================================================
# CRUD Operations — Analytics
# ============================================================

def _update_daily_analytics(
    session: Session,
    risk_score: float,
    attack_category_id: int,
    severity: str,
) -> None:
    """
    Update daily analytics aggregation (called within save_scan transaction).
    
    Args:
        session: Active database session
        risk_score: The scan's risk score
        attack_category_id: The attack category ID
        severity: The severity level string
    """
    today = date.today()
    record = session.query(Analytics).filter(Analytics.date == today).first()

    is_attack = attack_category_id > 0
    is_high_risk = severity in ("High", "Critical")

    if record:
        record.total_scans += 1
        if is_attack:
            record.attacks_detected += 1
        if is_high_risk:
            record.high_risk_count += 1
        # Running average of risk scores
        total = record.avg_risk_score * (record.total_scans - 1) + risk_score
        record.avg_risk_score = total / record.total_scans
    else:
        record = Analytics(
            date=today,
            total_scans=1,
            attacks_detected=1 if is_attack else 0,
            high_risk_count=1 if is_high_risk else 0,
            avg_risk_score=risk_score,
        )
        session.add(record)


def get_analytics_summary() -> Dict[str, Any]:
    """
    Get overall analytics summary for the dashboard home page.
    
    Returns:
        Dict with total_scans, attacks_detected, high_risk_count,
        detection_rate, avg_risk_score
    """
    session = get_session()
    try:
        total_scans = session.query(
            func.sum(Analytics.total_scans)
        ).scalar() or 0

        attacks_detected = session.query(
            func.sum(Analytics.attacks_detected)
        ).scalar() or 0

        high_risk_count = session.query(
            func.sum(Analytics.high_risk_count)
        ).scalar() or 0

        avg_risk = session.query(
            func.avg(Analytics.avg_risk_score)
        ).scalar() or 0.0

        detection_rate = (
            (attacks_detected / total_scans * 100)
            if total_scans > 0
            else 0.0
        )

        return {
            "total_scans": int(total_scans),
            "attacks_detected": int(attacks_detected),
            "high_risk_count": int(high_risk_count),
            "detection_rate": round(detection_rate, 1),
            "avg_risk_score": round(float(avg_risk), 1),
        }
    finally:
        session.close()


def get_daily_analytics(days: int = 30) -> List[Dict[str, Any]]:
    """
    Get daily analytics for the last N days.
    
    Args:
        days: Number of days to look back
    
    Returns:
        List of daily analytics dictionaries sorted by date
    """
    session = get_session()
    try:
        from datetime import timedelta
        cutoff = date.today() - timedelta(days=days)

        records = (
            session.query(Analytics)
            .filter(Analytics.date >= cutoff)
            .order_by(asc(Analytics.date))
            .all()
        )

        return [
            {
                "date": r.date.isoformat(),
                "total_scans": r.total_scans,
                "attacks_detected": r.attacks_detected,
                "high_risk_count": r.high_risk_count,
                "avg_risk_score": round(r.avg_risk_score, 1),
            }
            for r in records
        ]
    finally:
        session.close()


def get_category_breakdown() -> List[Dict[str, Any]]:
    """Get attack category distribution from scan history."""
    session = get_session()
    try:
        results = (
            session.query(
                ScanHistory.attack_type,
                func.count(ScanHistory.id).label("count")
            )
            .group_by(ScanHistory.attack_type)
            .order_by(desc("count"))
            .all()
        )

        return [
            {"attack_type": r[0], "count": r[1]}
            for r in results
        ]
    finally:
        session.close()


def get_risk_score_distribution() -> List[Dict[str, Any]]:
    """Get risk score distribution for histogram chart."""
    session = get_session()
    try:
        results = (
            session.query(ScanHistory.risk_score)
            .order_by(ScanHistory.risk_score)
            .all()
        )
        return [{"risk_score": r[0]} for r in results]
    finally:
        session.close()


def get_severity_breakdown() -> List[Dict[str, Any]]:
    """Get severity level distribution."""
    session = get_session()
    try:
        results = (
            session.query(
                ScanHistory.severity,
                func.count(ScanHistory.id).label("count")
            )
            .group_by(ScanHistory.severity)
            .all()
        )
        return [{"severity": r[0], "count": r[1]} for r in results]
    finally:
        session.close()


def create_user(email: str, password_hash: str) -> User:
    """Create a new user in the database."""
    session = get_session()
    try:
        user = User(email=email.strip().lower(), password_hash=password_hash)
        session.add(user)
        session.commit()
        return user
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def get_user_by_email(email: str) -> Optional[User]:
    """Retrieve a user by their email address."""
    session = get_session()
    try:
        return session.query(User).filter(User.email == email.strip().lower()).first()
    finally:
        session.close()


# ============================================================
# CRUD Operations — Firewall Logs
# ============================================================

def save_firewall_log(
    original_prompt: str,
    sanitized_prompt: Optional[str],
    risk_score: float,
    threat_category: Optional[str],
    firewall_action: str,
    heatmap_data: Optional[str] = None,
) -> FirewallLog:
    """Save a new firewall log entry to the database."""
    session = get_session()
    try:
        log = FirewallLog(
            original_prompt=original_prompt,
            sanitized_prompt=sanitized_prompt,
            risk_score=risk_score,
            threat_category=threat_category,
            firewall_action=firewall_action,
            heatmap_data=heatmap_data,
        )
        session.add(log)
        session.commit()
        return log
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def get_firewall_logs(
    limit: int = 100,
    offset: int = 0,
    search_query: Optional[str] = None,
    action_filter: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Retrieve firewall logs with optional filtering and pagination."""
    session = get_session()
    try:
        query = session.query(FirewallLog)
        if search_query:
            query = query.filter(
                FirewallLog.original_prompt.ilike(f"%{search_query}%") |
                FirewallLog.sanitized_prompt.ilike(f"%{search_query}%")
            )
        if action_filter:
            query = query.filter(FirewallLog.firewall_action.in_(action_filter))
        query = query.order_by(desc(FirewallLog.timestamp))
        results = query.offset(offset).limit(limit).all()
        return [r.to_dict() for r in results]
    finally:
        session.close()


def get_total_firewall_log_count(
    search_query: Optional[str] = None,
    action_filter: Optional[List[str]] = None,
) -> int:
    """Get total count of firewall logs matching filters."""
    session = get_session()
    try:
        query = session.query(func.count(FirewallLog.id))
        if search_query:
            query = query.filter(
                FirewallLog.original_prompt.ilike(f"%{search_query}%") |
                FirewallLog.sanitized_prompt.ilike(f"%{search_query}%")
            )
        if action_filter:
            query = query.filter(FirewallLog.firewall_action.in_(action_filter))
        return query.scalar() or 0
    finally:
        session.close()


def get_firewall_stats() -> Dict[str, Any]:
    """Calculate and return LLM Firewall metrics."""
    session = get_session()
    try:
        allowed = session.query(func.count(FirewallLog.id)).filter(FirewallLog.firewall_action == "ALLOW").scalar() or 0
        sanitized = session.query(func.count(FirewallLog.id)).filter(FirewallLog.firewall_action == "SANITIZE").scalar() or 0
        blocked = session.query(func.count(FirewallLog.id)).filter(FirewallLog.firewall_action == "BLOCK").scalar() or 0
        total = allowed + sanitized + blocked
        
        success_denominator = sanitized + blocked
        success_rate = (sanitized / success_denominator * 100.0) if success_denominator > 0 else 100.0
        
        return {
            "allowed_count": allowed,
            "sanitized_count": sanitized,
            "blocked_count": blocked,
            "total_count": total,
            "success_rate": round(success_rate, 1)
        }
    finally:
        session.close()

