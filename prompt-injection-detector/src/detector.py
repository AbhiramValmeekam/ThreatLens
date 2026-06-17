# ============================================================
# Detector — Individual ML Model Inference Wrappers
# ============================================================
"""
Provides standalone inference wrappers for each ML model component:

- DeBERTaDetector: Fine-tuned DeBERTa-v3-base transformer
- SVMDetector:     TF-IDF + Linear SVM pipeline
- LogRegDetector:  TF-IDF + Logistic Regression pipeline

Each detector implements a uniform interface:
    .predict(text) -> dict with keys:
        - injection_probability (float, 0.0-1.0)
        - is_injection (bool)
        - confidence (float, 0.0-1.0)

Models are loaded lazily and cached for reuse.

Usage:
    from src.detector import SVMDetector
    svm = SVMDetector("models/svm_pipeline.pkl")
    result = svm.predict("Ignore previous instructions")
"""

import os
import pickle
from typing import Dict, Any, Optional

import numpy as np

# ─── Base Directory ───────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class BaseDetector:
    """Abstract base class for all detector implementations."""

    def __init__(self, model_path: str):
        self.model_path = model_path
        self.model = None
        self.is_loaded = False

    def load(self) -> bool:
        """Load the model from disk. Returns True if successful."""
        raise NotImplementedError

    def predict(self, text: str) -> Dict[str, Any]:
        """Run inference on a single text prompt."""
        raise NotImplementedError

    def _ensure_loaded(self) -> bool:
        """Ensure model is loaded, attempt loading if not."""
        if not self.is_loaded:
            return self.load()
        return True


class DeBERTaDetector(BaseDetector):
    """
    Fine-tuned DeBERTa-v3-base binary classifier.
    
    Expects a HuggingFace model directory at model_path containing:
        - config.json
        - model.safetensors or pytorch_model.bin
        - tokenizer files
    """

    def __init__(self, model_path: Optional[str] = None):
        path = model_path or os.path.join(BASE_DIR, "models", "deberta")
        super().__init__(path)
        self.tokenizer = None
        self.max_length = 256

    def load(self) -> bool:
        """Load the DeBERTa model and tokenizer from disk."""
        if not os.path.exists(self.model_path):
            print(f"[DeBERTaDetector] Model directory not found: {self.model_path}")
            return False

        try:
            from transformers import (
                AutoTokenizer,
                AutoModelForSequenceClassification,
            )
            import torch

            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_path
            )
            self.model.eval()

            # Use GPU if available
            self.device = torch.device(
                "cuda" if torch.cuda.is_available() else "cpu"
            )
            self.model.to(self.device)

            self.is_loaded = True
            print(f"[DeBERTaDetector] Model loaded on {self.device}")
            return True
        except Exception as e:
            print(f"[DeBERTaDetector] Failed to load model: {e}")
            return False

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Run DeBERTa inference on a single prompt.
        
        Args:
            text: The prompt text to classify
        
        Returns:
            Dict with injection_probability, is_injection, confidence
        """
        if not self._ensure_loaded():
            return self._fallback_result()

        import torch

        try:
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=self.max_length,
                padding=True,
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1)

            # Label 1 = injection, Label 0 = safe
            injection_prob = probs[0][1].item()
            is_injection = injection_prob >= 0.5
            confidence = max(probs[0][0].item(), probs[0][1].item())

            return {
                "injection_probability": round(injection_prob, 4),
                "is_injection": is_injection,
                "confidence": round(confidence, 4),
                "model_name": "DeBERTa-v3-base",
            }
        except Exception as e:
            print(f"[DeBERTaDetector] Inference error: {e}")
            return self._fallback_result()

    @staticmethod
    def _fallback_result() -> Dict[str, Any]:
        """Return a neutral result when model is unavailable."""
        return {
            "injection_probability": 0.0,
            "is_injection": False,
            "confidence": 0.0,
            "model_name": "DeBERTa-v3-base (unavailable)",
        }


class SVMDetector(BaseDetector):
    """
    TF-IDF + Linear SVM pipeline wrapped in CalibratedClassifierCV
    for probability output.
    
    Expects a pickled sklearn Pipeline at model_path.
    """

    def __init__(self, model_path: Optional[str] = None):
        path = model_path or os.path.join(BASE_DIR, "models", "svm_pipeline.pkl")
        super().__init__(path)

    def load(self) -> bool:
        """Load the SVM pipeline from a pickle file."""
        try:
            if not os.path.exists(self.model_path):
                print(f"[SVMDetector] Model file not found: {self.model_path}")
                return False

            with open(self.model_path, "rb") as f:
                self.model = pickle.load(f)

            self.is_loaded = True
            print("[SVMDetector] Model loaded successfully")
            return True
        except Exception as e:
            print(f"[SVMDetector] Failed to load model: {e}")
            return False

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Run SVM inference on a single prompt.
        
        Args:
            text: The prompt text to classify
        
        Returns:
            Dict with injection_probability, is_injection, confidence
        """
        if not self._ensure_loaded():
            return self._fallback_result()

        try:
            # predict_proba requires CalibratedClassifierCV wrapper
            proba = self.model.predict_proba([text])[0]
            injection_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
            is_injection = injection_prob >= 0.5
            confidence = max(float(proba[0]), float(proba[1])) if len(proba) > 1 else float(proba[0])

            return {
                "injection_probability": round(injection_prob, 4),
                "is_injection": is_injection,
                "confidence": round(confidence, 4),
                "model_name": "TF-IDF + Linear SVM",
            }
        except Exception as e:
            print(f"[SVMDetector] Inference error: {e}")
            return self._fallback_result()

    @staticmethod
    def _fallback_result() -> Dict[str, Any]:
        return {
            "injection_probability": 0.0,
            "is_injection": False,
            "confidence": 0.0,
            "model_name": "TF-IDF + Linear SVM (unavailable)",
        }


class LogRegDetector(BaseDetector):
    """
    TF-IDF + Logistic Regression pipeline.
    
    Expects a pickled sklearn Pipeline at model_path.
    """

    def __init__(self, model_path: Optional[str] = None):
        path = model_path or os.path.join(BASE_DIR, "models", "logreg_pipeline.pkl")
        super().__init__(path)

    def load(self) -> bool:
        """Load the Logistic Regression pipeline from a pickle file."""
        try:
            if not os.path.exists(self.model_path):
                print(f"[LogRegDetector] Model file not found: {self.model_path}")
                return False

            with open(self.model_path, "rb") as f:
                self.model = pickle.load(f)

            self.is_loaded = True
            print("[LogRegDetector] Model loaded successfully")
            return True
        except Exception as e:
            print(f"[LogRegDetector] Failed to load model: {e}")
            return False

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Run Logistic Regression inference on a single prompt.
        
        Args:
            text: The prompt text to classify
        
        Returns:
            Dict with injection_probability, is_injection, confidence
        """
        if not self._ensure_loaded():
            return self._fallback_result()

        try:
            proba = self.model.predict_proba([text])[0]
            injection_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
            is_injection = injection_prob >= 0.5
            confidence = max(float(proba[0]), float(proba[1])) if len(proba) > 1 else float(proba[0])

            return {
                "injection_probability": round(injection_prob, 4),
                "is_injection": is_injection,
                "confidence": round(confidence, 4),
                "model_name": "TF-IDF + Logistic Regression",
            }
        except Exception as e:
            print(f"[LogRegDetector] Inference error: {e}")
            return self._fallback_result()

    @staticmethod
    def _fallback_result() -> Dict[str, Any]:
        return {
            "injection_probability": 0.0,
            "is_injection": False,
            "confidence": 0.0,
            "model_name": "TF-IDF + Logistic Regression (unavailable)",
        }
