# ============================================================
# Preprocess — Text Cleaning, Feature Extraction, Data Splitting
# ============================================================
"""
Handles the data preprocessing pipeline:

1. Text cleaning and normalization
2. Train / Validation / Test split (70/15/15)
3. TF-IDF feature extraction and vectorizer persistence
4. Tokenization preparation for DeBERTa

Usage:
    from src.preprocess import preprocess_and_split
    train_df, val_df, test_df = preprocess_and_split(combined_df)
"""

import os
import pickle
from typing import Tuple, Optional

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer

# ─── Paths ────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")
MODELS_DIR = os.path.join(BASE_DIR, "models")


def preprocess_and_split(
    df: pd.DataFrame,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_seed: int = 42,
    save: bool = True,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Split the dataset into train/validation/test sets and save to disk.
    
    Args:
        df: Combined DataFrame with 'text' and 'label' columns
        train_ratio: Fraction for training (default 0.70)
        val_ratio: Fraction for validation (default 0.15)
        test_ratio: Fraction for testing (default 0.15)
        random_seed: Random seed for reproducibility
        save: Whether to save splits to CSV files
    
    Returns:
        Tuple of (train_df, val_df, test_df)
    """
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6, \
        "Ratios must sum to 1.0"

    print("[Preprocess] Splitting dataset...")

    # First split: train vs (val + test)
    val_test_ratio = val_ratio + test_ratio
    train_df, val_test_df = train_test_split(
        df,
        test_size=val_test_ratio,
        random_state=random_seed,
        stratify=df["label"],
    )

    # Second split: val vs test
    relative_test_ratio = test_ratio / val_test_ratio
    val_df, test_df = train_test_split(
        val_test_df,
        test_size=relative_test_ratio,
        random_state=random_seed,
        stratify=val_test_df["label"],
    )

    # Reset indices
    train_df = train_df.reset_index(drop=True)
    val_df = val_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)

    print(f"  Train:      {len(train_df)} samples")
    print(f"  Validation: {len(val_df)} samples")
    print(f"  Test:       {len(test_df)} samples")

    # Save splits
    if save:
        os.makedirs(PROCESSED_DIR, exist_ok=True)
        train_df.to_csv(os.path.join(PROCESSED_DIR, "train.csv"), index=False)
        val_df.to_csv(os.path.join(PROCESSED_DIR, "val.csv"), index=False)
        test_df.to_csv(os.path.join(PROCESSED_DIR, "test.csv"), index=False)
        print(f"[Preprocess] Saved splits to {PROCESSED_DIR}")

    return train_df, val_df, test_df


def build_tfidf_features(
    train_texts: pd.Series,
    val_texts: Optional[pd.Series] = None,
    test_texts: Optional[pd.Series] = None,
    max_features: int = 10000,
    ngram_range: Tuple[int, int] = (1, 3),
    sublinear_tf: bool = True,
    save_vectorizer: bool = True,
    vectorizer_name: str = "tfidf_vectorizer.pkl",
) -> dict:
    """
    Build TF-IDF features from text data.
    
    Fits the vectorizer on training data only, then transforms all splits.
    Saves the fitted vectorizer for inference-time use.
    
    Args:
        train_texts: Training set text Series
        val_texts: Validation set text Series (optional)
        test_texts: Test set text Series (optional)
        max_features: Maximum number of TF-IDF features
        ngram_range: N-gram range for feature extraction
        sublinear_tf: Whether to apply sublinear TF scaling
        save_vectorizer: Whether to save the vectorizer to disk
        vectorizer_name: Filename for the saved vectorizer
    
    Returns:
        Dict with keys: 'X_train', 'X_val', 'X_test', 'vectorizer'
    """
    print(f"[Preprocess] Building TF-IDF features (max={max_features}, ngrams={ngram_range})...")

    vectorizer = TfidfVectorizer(
        max_features=max_features,
        ngram_range=ngram_range,
        sublinear_tf=sublinear_tf,
        analyzer="word",
        strip_accents="unicode",
        token_pattern=r"(?u)\b\w+\b",
        min_df=2,
        max_df=0.95,
    )

    # Fit on training data only
    X_train = vectorizer.fit_transform(train_texts)
    print(f"  → Training features shape: {X_train.shape}")

    result = {
        "X_train": X_train,
        "vectorizer": vectorizer,
    }

    if val_texts is not None:
        X_val = vectorizer.transform(val_texts)
        result["X_val"] = X_val
        print(f"  → Validation features shape: {X_val.shape}")

    if test_texts is not None:
        X_test = vectorizer.transform(test_texts)
        result["X_test"] = X_test
        print(f"  → Test features shape: {X_test.shape}")

    # Save vectorizer for inference
    if save_vectorizer:
        os.makedirs(MODELS_DIR, exist_ok=True)
        vec_path = os.path.join(MODELS_DIR, vectorizer_name)
        with open(vec_path, "wb") as f:
            pickle.dump(vectorizer, f)
        print(f"[Preprocess] Saved vectorizer to {vec_path}")

    return result


def load_processed_splits() -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Load pre-processed train/val/test splits from disk.
    
    Returns:
        Tuple of (train_df, val_df, test_df)
    
    Raises:
        FileNotFoundError if processed files don't exist
    """
    train_path = os.path.join(PROCESSED_DIR, "train.csv")
    val_path = os.path.join(PROCESSED_DIR, "val.csv")
    test_path = os.path.join(PROCESSED_DIR, "test.csv")

    for path in [train_path, val_path, test_path]:
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"Processed data not found at {path}. "
                f"Run the data pipeline first."
            )

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)

    print(f"[Preprocess] Loaded splits: train={len(train_df)}, "
          f"val={len(val_df)}, test={len(test_df)}")

    return train_df, val_df, test_df
