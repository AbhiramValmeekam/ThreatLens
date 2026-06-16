# ============================================================
# Train — Model Training Pipeline
# ============================================================
"""
End-to-end training pipeline for all ML models:

1. TF-IDF + Linear SVM (CalibratedClassifierCV for probabilities)
2. TF-IDF + Logistic Regression
3. DeBERTa-v3-base fine-tuning

Each model is evaluated on the test set with:
    - Accuracy, Precision, Recall, F1 Score, ROC-AUC
    - Confusion matrix
    - Classification report

Models and reports are saved to models/ and reports/ directories.

Usage:
    # Run full pipeline
    python -m src.train

    # Or import and use individually
    from src.train import train_svm, train_logreg, train_deberta
"""

import os
import sys
import json
import pickle
import time
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.svm import LinearSVC
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)

# ─── Paths ────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")

# Target names for classification report
TARGET_NAMES = ["Safe", "Injection"]


def ensure_dirs() -> None:
    """Create output directories if they don't exist."""
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)


# ============================================================
# Model 1: TF-IDF + Linear SVM
# ============================================================

def train_svm(
    X_train: pd.Series,
    y_train: pd.Series,
    X_test: pd.Series,
    y_test: pd.Series,
    max_features: int = 10000,
    ngram_range: Tuple[int, int] = (1, 3),
    C: float = 1.0,
) -> Dict[str, Any]:
    """
    Train a TF-IDF + Linear SVM pipeline with calibrated probabilities.
    
    Uses CalibratedClassifierCV to wrap LinearSVC (which doesn't natively
    support predict_proba) so the ensemble can get probability outputs.
    
    Args:
        X_train: Training text data
        y_train: Training labels
        X_test: Test text data
        y_test: Test labels
        max_features: TF-IDF vocabulary size
        ngram_range: N-gram range for TF-IDF
        C: Regularization parameter
    
    Returns:
        Dict with model, metrics, and file paths
    """
    print("\n" + "=" * 60)
    print("Training: TF-IDF + Linear SVM")
    print("=" * 60)

    start_time = time.time()

    # Build pipeline with calibration for probability support
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=max_features,
            ngram_range=ngram_range,
            sublinear_tf=True,
            analyzer="word",
            strip_accents="unicode",
            min_df=2,
            max_df=0.95,
        )),
        ("clf", CalibratedClassifierCV(
            estimator=LinearSVC(
                C=C,
                class_weight="balanced",
                random_state=42,
                max_iter=10000,
            ),
            cv=3,
        )),
    ])

    # Train
    print("[SVM] Fitting pipeline...")
    pipeline.fit(X_train, y_train)

    train_time = time.time() - start_time
    print(f"[SVM] Training completed in {train_time:.1f}s")

    # Evaluate
    metrics = evaluate_model(pipeline, X_test, y_test, "Linear SVM")

    # Save model
    model_path = os.path.join(MODELS_DIR, "svm_pipeline.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(pipeline, f)
    print(f"[SVM] Model saved to {model_path}")

    # Save report
    report_path = os.path.join(REPORTS_DIR, "svm_report.json")
    save_report(metrics, "Linear SVM", train_time, report_path)

    return {
        "model": pipeline,
        "metrics": metrics,
        "model_path": model_path,
        "train_time": train_time,
    }


# ============================================================
# Model 2: TF-IDF + Logistic Regression
# ============================================================

def train_logreg(
    X_train: pd.Series,
    y_train: pd.Series,
    X_test: pd.Series,
    y_test: pd.Series,
    max_features: int = 5000,
    ngram_range: Tuple[int, int] = (1, 2),
    C: float = 1.0,
) -> Dict[str, Any]:
    """
    Train a TF-IDF + Logistic Regression pipeline.
    
    Args:
        X_train: Training text data
        y_train: Training labels
        X_test: Test text data
        y_test: Test labels
        max_features: TF-IDF vocabulary size
        ngram_range: N-gram range for TF-IDF
        C: Regularization parameter
    
    Returns:
        Dict with model, metrics, and file paths
    """
    print("\n" + "=" * 60)
    print("Training: TF-IDF + Logistic Regression")
    print("=" * 60)

    start_time = time.time()

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=max_features,
            ngram_range=ngram_range,
            sublinear_tf=True,
            analyzer="word",
            strip_accents="unicode",
            min_df=2,
            max_df=0.95,
        )),
        ("clf", LogisticRegression(
            C=C,
            class_weight="balanced",
            max_iter=1000,
            random_state=42,
            solver="lbfgs",
        )),
    ])

    # Train
    print("[LogReg] Fitting pipeline...")
    pipeline.fit(X_train, y_train)

    train_time = time.time() - start_time
    print(f"[LogReg] Training completed in {train_time:.1f}s")

    # Evaluate
    metrics = evaluate_model(pipeline, X_test, y_test, "Logistic Regression")

    # Save model
    model_path = os.path.join(MODELS_DIR, "logreg_pipeline.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(pipeline, f)
    print(f"[LogReg] Model saved to {model_path}")

    # Save report
    report_path = os.path.join(REPORTS_DIR, "logreg_report.json")
    save_report(metrics, "Logistic Regression", train_time, report_path)

    return {
        "model": pipeline,
        "metrics": metrics,
        "model_path": model_path,
        "train_time": train_time,
    }


# ============================================================
# Model 3: DeBERTa-v3-base Fine-tuning
# ============================================================

def train_deberta(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    model_name: str = "microsoft/deberta-v3-base",
    max_length: int = 256,
    batch_size: int = 16,
    learning_rate: float = 2e-5,
    num_epochs: int = 3,
    warmup_ratio: float = 0.1,
    weight_decay: float = 0.01,
) -> Dict[str, Any]:
    """
    Fine-tune DeBERTa-v3-base for binary classification.
    
    Uses HuggingFace Trainer for training with:
        - Mixed precision (fp16) on GPU
        - Gradient accumulation for effective larger batch sizes
        - Early stopping based on F1 score
        - Best model checkpoint saving
    
    Args:
        train_df: Training DataFrame with 'text' and 'label' columns
        val_df: Validation DataFrame
        test_df: Test DataFrame
        model_name: HuggingFace model identifier
        max_length: Maximum tokenization length
        batch_size: Training batch size
        learning_rate: Learning rate for AdamW
        num_epochs: Number of training epochs
        warmup_ratio: Fraction of steps for warmup
        weight_decay: Weight decay for regularization
    
    Returns:
        Dict with model, tokenizer, metrics, and file paths
    """
    print("\n" + "=" * 60)
    print(f"Training: {model_name}")
    print("=" * 60)

    start_time = time.time()

    try:
        import torch
        from transformers import (
            AutoTokenizer,
            AutoModelForSequenceClassification,
            TrainingArguments,
            Trainer,
        )
        from datasets import Dataset
    except ImportError as e:
        print(f"[DeBERTa] Required packages not installed: {e}")
        print("[DeBERTa] Skipping DeBERTa training")
        return {"metrics": None, "error": str(e)}

    # Determine device
    device = "cuda" if torch.cuda.is_available() else "cpu"
    use_fp16 = device == "cuda"
    print(f"[DeBERTa] Using device: {device}")

    if device == "cpu":
        print("[DeBERTa] WARNING: CUDA is not available. Fine-tuning DeBERTa-v3 on CPU is extremely slow and will be skipped.")
        print("[DeBERTa] The ensemble will gracefully degrade and use the trained SVM, Logistic Regression, and Rule Engine.")
        return {"metrics": None, "error": "CUDA not available (skipped CPU training)"}

    # Load tokenizer and model
    print(f"[DeBERTa] Loading {model_name}...")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(
        model_name,
        num_labels=2,
        id2label={0: "Safe", 1: "Injection"},
        label2id={"Safe": 0, "Injection": 1},
    )

    # Tokenize datasets
    def tokenize_function(examples):
        return tokenizer(
            examples["text"],
            padding="max_length",
            truncation=True,
            max_length=max_length,
        )

    # Convert to HuggingFace datasets
    train_ds = Dataset.from_pandas(train_df[["text", "label"]].reset_index(drop=True))
    val_ds = Dataset.from_pandas(val_df[["text", "label"]].reset_index(drop=True))
    test_ds = Dataset.from_pandas(test_df[["text", "label"]].reset_index(drop=True))

    print("[DeBERTa] Tokenizing datasets...")
    train_tok = train_ds.map(tokenize_function, batched=True, remove_columns=["text"])
    val_tok = val_ds.map(tokenize_function, batched=True, remove_columns=["text"])
    test_tok = test_ds.map(tokenize_function, batched=True, remove_columns=["text"])

    # Compute metrics function for Trainer
    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        return {
            "accuracy": accuracy_score(labels, preds),
            "f1": f1_score(labels, preds, average="weighted"),
            "precision": precision_score(labels, preds, average="weighted"),
            "recall": recall_score(labels, preds, average="weighted"),
        }

    # Training arguments
    output_dir = os.path.join(MODELS_DIR, "deberta")
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=num_epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size * 2,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        logging_steps=50,
        logging_dir=os.path.join(output_dir, "logs"),
        warmup_ratio=warmup_ratio,
        weight_decay=weight_decay,
        learning_rate=learning_rate,
        fp16=use_fp16,
        report_to="none",  # Disable wandb/tensorboard
        save_total_limit=2,
        seed=42,
    )

    # Initialize Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_tok,
        eval_dataset=val_tok,
        compute_metrics=compute_metrics,
    )

    # Train
    print("[DeBERTa] Starting training...")
    trainer.train()

    train_time = time.time() - start_time
    print(f"[DeBERTa] Training completed in {train_time:.1f}s")

    # Save best model
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"[DeBERTa] Model saved to {output_dir}")

    # Evaluate on test set
    print("[DeBERTa] Evaluating on test set...")
    test_results = trainer.predict(test_tok)
    test_preds = np.argmax(test_results.predictions, axis=-1)
    test_labels = test_df["label"].values

    metrics = _compute_full_metrics(test_labels, test_preds, "DeBERTa-v3-base")

    # Try to compute ROC-AUC with probabilities
    try:
        test_probs = np.exp(test_results.predictions) / np.exp(
            test_results.predictions
        ).sum(axis=-1, keepdims=True)
        metrics["roc_auc"] = float(
            roc_auc_score(test_labels, test_probs[:, 1])
        )
    except Exception:
        pass

    # Save report
    report_path = os.path.join(REPORTS_DIR, "deberta_report.json")
    save_report(metrics, "DeBERTa-v3-base", train_time, report_path)

    return {
        "model": model,
        "tokenizer": tokenizer,
        "metrics": metrics,
        "model_path": output_dir,
        "train_time": train_time,
    }


# ============================================================
# Evaluation Utilities
# ============================================================

def evaluate_model(
    model, X_test, y_test, model_name: str
) -> Dict[str, Any]:
    """
    Evaluate a sklearn pipeline model on test data.
    
    Args:
        model: Trained sklearn Pipeline
        X_test: Test features (text for pipeline, or matrix)
        y_test: Test labels
        model_name: Name for reporting
    
    Returns:
        Dict with all evaluation metrics
    """
    print(f"\n[Evaluate] {model_name} — Test Set Results:")
    print("-" * 50)

    preds = model.predict(X_test)
    metrics = _compute_full_metrics(y_test, preds, model_name)

    # Try to get ROC-AUC (needs predict_proba)
    try:
        proba = model.predict_proba(X_test)[:, 1]
        metrics["roc_auc"] = float(roc_auc_score(y_test, proba))
        print(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")
    except Exception:
        print("  ROC-AUC:   N/A (no predict_proba)")

    return metrics


def _compute_full_metrics(
    y_true, y_pred, model_name: str
) -> Dict[str, Any]:
    """Compute all classification metrics."""
    accuracy = float(accuracy_score(y_true, y_pred))
    precision = float(precision_score(y_true, y_pred, average="weighted", zero_division=0))
    recall = float(recall_score(y_true, y_pred, average="weighted", zero_division=0))
    f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    # Per-class metrics
    report = classification_report(
        y_true, y_pred, target_names=TARGET_NAMES, output_dict=True, zero_division=0
    )

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred).tolist()

    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"    {cm[0]}")
    print(f"    {cm[1]}")

    return {
        "model_name": model_name,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "confusion_matrix": cm,
        "classification_report": report,
    }


def save_report(
    metrics: Dict[str, Any],
    model_name: str,
    train_time: float,
    path: str,
) -> None:
    """Save evaluation report as JSON."""
    ensure_dirs()

    report = {
        "model_name": model_name,
        "timestamp": datetime.now().isoformat(),
        "training_time_seconds": round(train_time, 2),
        "metrics": metrics,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"[Report] Saved to {path}")


# ============================================================
# Full Training Pipeline
# ============================================================

def run_full_pipeline() -> Dict[str, Any]:
    """
    Run the complete training pipeline:
    
    1. Load and prepare datasets
    2. Split into train/val/test
    3. Train Linear SVM
    4. Train Logistic Regression
    5. Train DeBERTa-v3 (if GPU available or user accepts CPU training)
    6. Generate all evaluation reports
    
    Returns:
        Dict with results from all model trainings
    """
    ensure_dirs()

    print("=" * 60)
    print("FULL TRAINING PIPELINE")
    print("=" * 60)
    print(f"Started at: {datetime.now().isoformat()}")

    # Step 1: Load data
    from src.data_loader import load_and_prepare_dataset
    from src.preprocess import preprocess_and_split

    combined_df = load_and_prepare_dataset()
    train_df, val_df, test_df = preprocess_and_split(combined_df)

    results = {}

    # Step 2: Train SVM
    try:
        results["svm"] = train_svm(
            train_df["text"], train_df["label"],
            test_df["text"], test_df["label"],
        )
    except Exception as e:
        print(f"[Pipeline] SVM training failed: {e}")
        results["svm"] = {"error": str(e)}

    # Step 3: Train Logistic Regression
    try:
        results["logreg"] = train_logreg(
            train_df["text"], train_df["label"],
            test_df["text"], test_df["label"],
        )
    except Exception as e:
        print(f"[Pipeline] LogReg training failed: {e}")
        results["logreg"] = {"error": str(e)}

    # Step 4: Train DeBERTa
    try:
        results["deberta"] = train_deberta(train_df, val_df, test_df)
    except Exception as e:
        print(f"[Pipeline] DeBERTa training failed: {e}")
        results["deberta"] = {"error": str(e)}

    # Summary
    print("\n" + "=" * 60)
    print("TRAINING PIPELINE COMPLETE")
    print("=" * 60)

    for model_name, result in results.items():
        if "error" in result:
            print(f"  [-] {model_name}: FAILED — {result['error']}")
        elif result.get("metrics"):
            m = result["metrics"]
            f1 = m.get("f1_score", "N/A")
            acc = m.get("accuracy", "N/A")
            print(f"  [+] {model_name}: F1={f1:.4f}, Acc={acc:.4f}")
        else:
            print(f"  ? {model_name}: No metrics available")

    print(f"\nCompleted at: {datetime.now().isoformat()}")
    return results


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    # Add project root to path
    sys.path.insert(0, BASE_DIR)
    run_full_pipeline()
