# ============================================================
# AI Prompt Injection Detection & LLM Security Monitoring System
# ============================================================
"""
Core source package for the prompt injection detection platform.

Modules:
    database    — SQLAlchemy ORM models and CRUD operations
    rule_engine — Regex-based pattern detection engine
    detector    — Individual ML model inference wrappers
    ensemble    — Weighted ensemble combining all detectors
    data_loader — Dataset loading from HuggingFace
    preprocess  — Text cleaning and data splitting
    train       — Model training pipeline
    explain     — SHAP and keyword-based explainability
    analytics   — Dashboard analytics and aggregation queries
"""

__version__ = "1.0.0"
__author__ = "AI Security Team"
