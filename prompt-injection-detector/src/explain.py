# ============================================================
# Explain — Explainability Engine for Prompt Injection Detection
# ============================================================
"""
Provides multi-layered explanations for why a prompt was flagged:

1. Important Keywords — TF-IDF feature weights from SVM/LogReg
2. SHAP Explanations — LinearExplainer on TF-IDF models for fast SHAP
3. Suspicious Segment Highlighting — Rule engine match locations
4. Reason Generation — Human-readable detection explanations

Usage:
    from src.explain import ExplainabilityEngine
    explainer = ExplainabilityEngine()
    explanation = explainer.explain("Ignore all previous instructions")
"""

import os
import pickle
import re
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
import streamlit as st

# ─── Paths ────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")


class ExplainabilityEngine:
    """
    Multi-layered explanation engine for prompt injection detection.
    
    Combines keyword analysis, SHAP values, segment highlighting,
    and rule-based reason generation to provide comprehensive
    explanations of why a prompt was flagged.
    """

    def __init__(
        self,
        svm_path: Optional[str] = None,
        logreg_path: Optional[str] = None,
    ):
        """
        Initialize the explainability engine.
        
        Args:
            svm_path: Path to the saved SVM pipeline pickle
            logreg_path: Path to the saved LogReg pipeline pickle
        """
        self.svm_path = svm_path or os.path.join(MODELS_DIR, "svm_pipeline.pkl")
        self.logreg_path = logreg_path or os.path.join(MODELS_DIR, "logreg_pipeline.pkl")

        self.svm_pipeline = None
        self.logreg_pipeline = None
        self.shap_explainer = None

        self._load_models()

    def _load_models(self) -> None:
        """Load ML pipelines for feature analysis."""
        # Load SVM pipeline
        try:
            if os.path.exists(self.svm_path):
                with open(self.svm_path, "rb") as f:
                    self.svm_pipeline = pickle.load(f)
                print("[Explain] SVM pipeline loaded for explanation")
        except Exception as e:
            print(f"[Explain] Could not load SVM pipeline: {e}")

        # Load LogReg pipeline
        try:
            if os.path.exists(self.logreg_path):
                with open(self.logreg_path, "rb") as f:
                    self.logreg_pipeline = pickle.load(f)
                print("[Explain] LogReg pipeline loaded for explanation")
        except Exception as e:
            print(f"[Explain] Could not load LogReg pipeline: {e}")

    def explain(self, text: str, scan_result: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Generate a comprehensive explanation for a prompt scan.
        
        Args:
            text: The prompt text that was scanned
            scan_result: Optional ScanResult dict from the ensemble
        
        Returns:
            Dict with keys:
                - keywords: List of important keywords with weights
                - shap_values: SHAP feature importance (if available)
                - highlighted_segments: Text segments that triggered rules
                - reasons: Human-readable explanation strings
                - risk_factors: List of identified risk factor dicts
        """
        explanation = {
            "keywords": [],
            "shap_values": [],
            "highlighted_segments": [],
            "reasons": [],
            "risk_factors": [],
        }

        # 1. Extract important keywords from TF-IDF models
        keywords = self._get_important_keywords(text)
        explanation["keywords"] = keywords

        # 2. Get SHAP values (if model available)
        shap_values = self._get_shap_values(text)
        explanation["shap_values"] = shap_values

        # 3. Highlight suspicious text segments
        segments = self._get_highlighted_segments(text)
        explanation["highlighted_segments"] = segments

        # 4. Generate human-readable reasons
        reasons = self._generate_reasons(text, keywords, segments, scan_result)
        explanation["reasons"] = reasons

        # 5. Identify risk factors
        risk_factors = self._identify_risk_factors(text, keywords, segments)
        explanation["risk_factors"] = risk_factors

        return explanation

    def _get_important_keywords(
        self, text: str, top_n: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Extract the most important keywords from TF-IDF feature weights.
        
        Uses the LogReg model (which has direct feature coefficients)
        to identify which words contribute most to the injection prediction.
        
        Args:
            text: The prompt text
            top_n: Number of top keywords to return
        
        Returns:
            List of dicts with keyword, weight, and contribution direction
        """
        pipeline = self.logreg_pipeline or self.svm_pipeline
        if pipeline is None:
            return []

        try:
            # Get the TF-IDF vectorizer and classifier from the pipeline
            tfidf = pipeline.named_steps.get("tfidf")
            clf = pipeline.named_steps.get("clf")

            if tfidf is None or clf is None:
                return []

            # Transform the text
            tfidf_vector = tfidf.transform([text])
            feature_names = tfidf.get_feature_names_out()

            # Get feature weights from the classifier
            if hasattr(clf, "coef_"):
                # Direct coefficients (LogReg or base LinearSVC)
                coef = clf.coef_[0] if len(clf.coef_.shape) > 1 else clf.coef_
            elif hasattr(clf, "calibrated_classifiers_"):
                # CalibratedClassifierCV wrapping LinearSVC
                base = clf.calibrated_classifiers_[0].estimator
                if hasattr(base, "coef_"):
                    coef = base.coef_[0] if len(base.coef_.shape) > 1 else base.coef_
                else:
                    return []
            else:
                return []

            # Get the TF-IDF values for this text
            text_features = tfidf_vector.toarray()[0]

            # Calculate contribution: TF-IDF value × coefficient
            contributions = text_features * coef

            # Get top contributing features (positive = injection)
            top_indices = np.argsort(np.abs(contributions))[-top_n:][::-1]

            keywords = []
            for idx in top_indices:
                if text_features[idx] > 0:  # Only include features present in text
                    keywords.append({
                        "keyword": feature_names[idx],
                        "weight": round(float(contributions[idx]), 4),
                        "tfidf_value": round(float(text_features[idx]), 4),
                        "direction": "injection" if contributions[idx] > 0 else "safe",
                    })

            return keywords
        except Exception as e:
            print(f"[Explain] Keyword extraction failed: {e}")
            return []

    def _get_shap_values(self, text: str) -> List[Dict[str, Any]]:
        """
        Compute SHAP values for the prediction using LinearExplainer.
        
        Uses the LogReg or SVM model with SHAP's LinearExplainer for
        fast, exact SHAP value computation on TF-IDF features.
        
        Args:
            text: The prompt text
        
        Returns:
            List of dicts with feature name, shap value, and direction
        """
        pipeline = self.logreg_pipeline or self.svm_pipeline
        if pipeline is None:
            return []

        try:
            import shap

            tfidf = pipeline.named_steps.get("tfidf")
            clf = pipeline.named_steps.get("clf")

            if tfidf is None or clf is None:
                return []

            # Transform the text
            X = tfidf.transform([text])
            feature_names = tfidf.get_feature_names_out()

            # Get the base model for SHAP
            if hasattr(clf, "coef_"):
                base_model = clf
            elif hasattr(clf, "calibrated_classifiers_"):
                base_model = clf.calibrated_classifiers_[0].estimator
            else:
                return []

            # Create SHAP explainer
            explainer = shap.LinearExplainer(base_model, X, feature_perturbation="interventional")
            shap_values = explainer.shap_values(X)

            if isinstance(shap_values, list):
                # Multi-class: take injection class
                sv = shap_values[1][0] if len(shap_values) > 1 else shap_values[0][0]
            else:
                sv = shap_values[0]

            # Get non-zero SHAP values (features present in text)
            nonzero_indices = np.where(X.toarray()[0] > 0)[0]
            shap_features = []

            for idx in nonzero_indices:
                if abs(sv[idx]) > 1e-6:
                    shap_features.append({
                        "feature": feature_names[idx],
                        "shap_value": round(float(sv[idx]), 4),
                        "direction": "injection" if sv[idx] > 0 else "safe",
                    })

            # Sort by absolute SHAP value
            shap_features.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
            return shap_features[:15]  # Top 15 features

        except ImportError:
            print("[Explain] SHAP not installed — skipping SHAP explanations")
            return []
        except Exception as e:
            print(f"[Explain] SHAP computation failed: {e}")
            return []

    def _get_highlighted_segments(self, text: str) -> List[Dict[str, Any]]:
        """
        Find text segments that match known attack patterns.
        
        Args:
            text: The prompt text
        
        Returns:
            List of dicts with segment details (start, end, text, category, description)
        """
        from src.rule_engine import get_rule_engine

        engine = get_rule_engine()
        return engine.get_highlighted_segments(text)

    def _generate_reasons(
        self,
        text: str,
        keywords: List[Dict],
        segments: List[Dict],
        scan_result: Optional[Dict] = None,
    ) -> List[str]:
        """
        Generate human-readable explanations for the detection.
        
        Args:
            text: The prompt text
            keywords: Extracted important keywords
            segments: Highlighted text segments
            scan_result: Optional ensemble scan result
        
        Returns:
            List of reason strings
        """
        reasons = []

        # Reasons from matched rule segments
        seen_descriptions = set()
        for seg in segments:
            desc = seg.get("description", "")
            if desc and desc not in seen_descriptions:
                reasons.append(f"🔍 {desc}")
                seen_descriptions.add(desc)

        # Reasons from keyword analysis
        injection_keywords = [
            k for k in keywords
            if k["direction"] == "injection" and k["weight"] > 0.1
        ]
        if injection_keywords:
            kw_list = ", ".join(
                f'"{k["keyword"]}"' for k in injection_keywords[:5]
            )
            reasons.append(
                f"⚠️ High-risk keywords detected: {kw_list}"
            )

        # Reasons from scan result
        if scan_result:
            risk_score = scan_result.get("risk_score", 0)
            if risk_score >= 75:
                reasons.append(
                    "🚨 Multiple high-confidence detection signals converged"
                )
            elif risk_score >= 50:
                reasons.append(
                    "⚠️ Moderate detection signals from ensemble analysis"
                )

            # Model agreement info
            model_scores = scan_result.get("model_scores", {})
            agreeing = sum(1 for v in model_scores.values() if v >= 50)
            if agreeing >= 3:
                reasons.append(
                    f"🤝 {agreeing}/4 models agree on injection classification"
                )

        # Structural analysis reasons
        structural_reasons = self._analyze_structure(text)
        reasons.extend(structural_reasons)

        # Default reason if nothing else matched
        if not reasons:
            reasons.append("✅ No significant risk indicators detected")

        return reasons

    def _analyze_structure(self, text: str) -> List[str]:
        """
        Analyze structural characteristics of the text for risk indicators.
        
        Checks for unusual patterns that don't match specific rule patterns
        but indicate potential manipulation attempts.
        """
        reasons = []

        # Check for role-playing markers
        if re.search(r"\{.*?\}", text) and re.search(r"(system|user|assistant)", text, re.I):
            reasons.append("📝 Contains structured role markers (potential format injection)")

        # Check for encoded content
        if re.search(r"(base64|\\x[0-9a-f]{2}|&#\d+;|%[0-9a-f]{2})", text, re.I):
            reasons.append("🔐 Contains encoded or obfuscated content")

        # Check for unusually long text with repetition
        if len(text) > 500:
            words = text.lower().split()
            if len(words) > 0:
                unique_ratio = len(set(words)) / len(words)
                if unique_ratio < 0.3:
                    reasons.append("📏 Unusually repetitive text pattern detected")

        # Check for multiple languages or scripts
        if re.search(r"[\u0400-\u04ff]", text) and re.search(r"[a-zA-Z]", text):
            reasons.append("🌐 Mixed script content detected (potential unicode evasion)")

        return reasons

    def _identify_risk_factors(
        self,
        text: str,
        keywords: List[Dict],
        segments: List[Dict],
    ) -> List[Dict[str, Any]]:
        """
        Identify and categorize specific risk factors in the text.
        
        Returns:
            List of risk factor dicts with name, severity, and description
        """
        factors = []

        # Risk from rule matches
        if segments:
            categories = set(seg.get("category", "Unknown") for seg in segments)
            for cat in categories:
                cat_segments = [s for s in segments if s.get("category") == cat]
                factors.append({
                    "name": cat,
                    "severity": "high" if len(cat_segments) > 1 else "medium",
                    "match_count": len(cat_segments),
                    "description": f"{len(cat_segments)} pattern(s) matched for {cat}",
                })

        # Risk from keyword analysis
        high_risk_keywords = [
            k for k in keywords
            if k["direction"] == "injection" and abs(k["weight"]) > 0.2
        ]
        if high_risk_keywords:
            factors.append({
                "name": "High-Risk Vocabulary",
                "severity": "medium",
                "match_count": len(high_risk_keywords),
                "description": f"{len(high_risk_keywords)} high-weight injection keywords found",
            })

        # Text length risk
        if len(text) > 1000:
            factors.append({
                "name": "Unusually Long Input",
                "severity": "low",
                "match_count": 1,
                "description": f"Input length ({len(text)} chars) exceeds typical prompt length",
            })

        return factors


# ============================================================
# Module-level singleton
# ============================================================

_explainer_instance: Optional[ExplainabilityEngine] = None


@st.cache_resource
def get_explainer() -> ExplainabilityEngine:
    """Get or create the default ExplainabilityEngine singleton."""
    global _explainer_instance
    if _explainer_instance is None:
        _explainer_instance = ExplainabilityEngine()
    return _explainer_instance
