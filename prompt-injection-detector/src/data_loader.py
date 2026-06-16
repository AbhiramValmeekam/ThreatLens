# ============================================================
# Data Loader — Dataset Loading from HuggingFace
# ============================================================
"""
Loads, combines, and prepares prompt injection datasets for training.

Supported datasets:
    1. deepset/prompt-injections — Direct/indirect injection examples (~660 rows)
    2. geekyrakshit/prompt-injection-dataset — Prompt injection collection

The loader:
    - Downloads datasets from HuggingFace Hub
    - Normalizes column names (text, label)
    - Combines into a unified DataFrame
    - Removes duplicates and empty rows
    - Handles class imbalance via oversampling
    - Saves processed datasets to data/processed/

Usage:
    from src.data_loader import load_and_prepare_dataset
    df = load_and_prepare_dataset()
"""

import os
import re
import unicodedata
from typing import Optional, Tuple

import pandas as pd
import numpy as np

# ─── Paths ────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, "data", "raw")
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")


def load_deepset_dataset() -> pd.DataFrame:
    """
    Load the deepset/prompt-injections dataset from HuggingFace.
    
    Columns: text (str), label (int: 0=safe, 1=injection)
    
    Returns:
        DataFrame with 'text' and 'label' columns
    """
    from datasets import load_dataset

    print("[DataLoader] Loading deepset/prompt-injections...")
    try:
        ds = load_dataset("deepset/prompt-injections", trust_remote_code=True)
        df = ds["train"].to_pandas()

        # Standardize column names
        if "text" not in df.columns and "prompt" in df.columns:
            df = df.rename(columns={"prompt": "text"})

        # Ensure binary labels
        df["label"] = df["label"].astype(int)
        df = df[["text", "label"]].copy()

        print(f"  -> Loaded {len(df)} samples (deepset)")
        print(f"  -> Class distribution: {df['label'].value_counts().to_dict()}")
        return df
    except Exception as e:
        print(f"  [-] Failed to load deepset dataset: {e}")
        return pd.DataFrame(columns=["text", "label"])


def load_geekyrakshit_dataset() -> pd.DataFrame:
    """
    Load the geekyrakshit/prompt-injection-dataset from HuggingFace.
    
    Returns:
        DataFrame with 'text' and 'label' columns
    """
    from datasets import load_dataset

    print("[DataLoader] Loading geekyrakshit/prompt-injection-dataset...")
    try:
        ds = load_dataset(
            "geekyrakshit/prompt-injection-dataset", trust_remote_code=True
        )
        df = ds["train"].to_pandas()

        # Standardize column names — this dataset may use different names
        if "text" not in df.columns:
            # Try common column name variants
            for col in ["prompt", "input", "content", "sentence"]:
                if col in df.columns:
                    df = df.rename(columns={col: "text"})
                    break

        if "label" not in df.columns:
            for col in ["is_injection", "is_prompt_injection", "class", "target"]:
                if col in df.columns:
                    df = df.rename(columns={col: "label"})
                    break

        # Ensure binary labels
        if df["label"].dtype == object:
            # Map string labels to integers
            label_map = {
                "injection": 1, "prompt_injection": 1, "malicious": 1,
                "1": 1, "True": 1, "true": 1,
                "safe": 0, "benign": 0, "normal": 0,
                "0": 0, "False": 0, "false": 0,
            }
            df["label"] = df["label"].map(
                lambda x: label_map.get(str(x).strip(), 0)
            )

        df["label"] = df["label"].astype(int)
        df = df[["text", "label"]].copy()

        print(f"  -> Loaded {len(df)} samples (geekyrakshit)")
        print(f"  -> Class distribution: {df['label'].value_counts().to_dict()}")
        return df
    except Exception as e:
        print(f"  [-] Failed to load geekyrakshit dataset: {e}")
        return pd.DataFrame(columns=["text", "label"])


def load_jailbreak_classification_dataset() -> pd.DataFrame:
    """
    Load the jackhhao/jailbreak-classification dataset from HuggingFace.
    
    Columns: prompt (str), type (str: benign/jailbreak)
    
    Returns:
        DataFrame with 'text' and 'label' columns
    """
    from datasets import load_dataset

    print("[DataLoader] Loading jackhhao/jailbreak-classification...")
    try:
        # Load both train and test splits to maximize data
        ds_train = load_dataset("jackhhao/jailbreak-classification", split="train")
        ds_test = load_dataset("jackhhao/jailbreak-classification", split="test")
        
        df_train = ds_train.to_pandas()
        df_test = ds_test.to_pandas()
        df = pd.concat([df_train, df_test], ignore_index=True)

        # Standardize column names
        df = df.rename(columns={"prompt": "text"})

        # Map type to binary label (jailbreak = 1, benign = 0)
        df["label"] = df["type"].map({"jailbreak": 1, "benign": 0})
        df["label"] = df["label"].fillna(0).astype(int)

        df = df[["text", "label"]].copy()

        print(f"  -> Loaded {len(df)} samples (jackhhao/jailbreak-classification)")
        print(f"  -> Class distribution: {df['label'].value_counts().to_dict()}")
        return df
    except Exception as e:
        print(f"  [-] Failed to load jackhhao/jailbreak-classification dataset: {e}")
        return pd.DataFrame(columns=["text", "label"])


def generate_safe_prompts() -> pd.DataFrame:
    """
    Generate a set of safe/benign prompts to supplement the dataset.
    
    Returns:
        DataFrame with safe prompts labeled as 0
    """
    safe_prompts = [
        # General knowledge
        "What is the capital of France?",
        "Explain how photosynthesis works.",
        "Who wrote Romeo and Juliet?",
        "What is the speed of light?",
        "How many continents are there?",
        "What is the tallest mountain in the world?",
        "Explain the water cycle.",
        "Who invented the telephone?",
        "What is the Pythagorean theorem?",
        "How does gravity work?",
        # Creative writing
        "Write me a poem about autumn.",
        "Tell me a short story about a dragon.",
        "Compose a haiku about the ocean.",
        "Write a limerick about a cat.",
        "Create a short bedtime story for children.",
        "Write a funny joke about programming.",
        "Describe a sunset in three sentences.",
        "Write a motivational quote.",
        "Create a dialogue between two scientists.",
        "Write a product description for a wireless mouse.",
        # Practical tasks
        "Give me a recipe for pasta carbonara.",
        "How do I change a car tire?",
        "What are some tips for job interviews?",
        "Suggest a workout routine for beginners.",
        "How do I make a paper airplane?",
        "What are good practices for saving money?",
        "Recommend books about machine learning.",
        "How do I start a vegetable garden?",
        "What is the best way to learn a new language?",
        "Give me tips for public speaking.",
        # Technical questions
        "How does a neural network work?",
        "What is the difference between Python and JavaScript?",
        "Explain RESTful APIs.",
        "What is Docker and why is it useful?",
        "How does encryption work?",
        "What is the difference between SQL and NoSQL databases?",
        "Explain the concept of microservices.",
        "What is version control and why is it important?",
        "How does a compiler work?",
        "What is cloud computing?",
        # Summarization
        "Summarize this paragraph for me.",
        "Can you simplify this technical document?",
        "What are the key points of this article?",
        "Help me understand this research paper.",
        "Translate this sentence to Spanish.",
        # Math and logic
        "What is 15 times 23?",
        "Solve the equation: 2x + 5 = 15",
        "What is the square root of 144?",
        "Convert 100 degrees Fahrenheit to Celsius.",
        "What is the probability of rolling a 6 on a standard die?",
        # Everyday questions
        "What should I wear to a formal dinner?",
        "How do I remove a coffee stain from a shirt?",
        "What are some healthy breakfast options?",
        "How do I train a puppy?",
        "What movies are similar to Inception?",
        "Recommend music for studying.",
        "How do I deal with stress?",
        "What are the benefits of meditation?",
        "How do I improve my sleep quality?",
        "What are some fun indoor activities for rainy days?",
        # Business and work
        "Help me write a professional email.",
        "How do I create a business plan?",
        "What are effective leadership qualities?",
        "How do I manage a remote team?",
        "What is project management?",
        "Help me draft a resume summary.",
        "What are common marketing strategies?",
        "How do I negotiate a salary?",
        "What is the best way to give feedback?",
        "How do I run an effective meeting?",
        # Science and nature
        "How do vaccines work?",
        "What causes earthquakes?",
        "How far is Mars from Earth?",
        "What is DNA?",
        "How do birds migrate?",
        "What is climate change?",
        "How does the immune system work?",
        "What causes rainbows?",
        "How do volcanoes form?",
        "What is the theory of evolution?",
        # History and culture
        "When was the Great Wall of China built?",
        "Who was Cleopatra?",
        "What caused World War I?",
        "Tell me about the Renaissance period.",
        "Who was Leonardo da Vinci?",
        "What is the significance of the Rosetta Stone?",
        "When did humans first land on the moon?",
        "What is the history of the Olympic Games?",
        "Tell me about ancient Egyptian civilization.",
        "What was the Industrial Revolution?",
    ]

    df = pd.DataFrame({
        "text": safe_prompts,
        "label": [0] * len(safe_prompts),
    })

    print(f"[DataLoader] Generated {len(df)} safe prompts")
    return df


def clean_text(text: str) -> str:
    """
    Clean and normalize a text prompt.
    
    Operations:
        - Unicode normalization (NFKD)
        - Strip leading/trailing whitespace
        - Collapse multiple whitespace to single space
        - Remove null bytes
    
    Args:
        text: Raw text to clean
    
    Returns:
        Cleaned text string
    """
    if not isinstance(text, str):
        return ""

    # Unicode normalization
    text = unicodedata.normalize("NFKD", text)

    # Remove null bytes
    text = text.replace("\x00", "")

    # Collapse whitespace (but preserve newlines for structure)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)

    # Strip
    text = text.strip()

    return text


def load_and_prepare_dataset(
    include_safe_prompts: bool = True,
    balance_classes: bool = True,
    save_raw: bool = True,
) -> pd.DataFrame:
    """
    Load all datasets, combine, clean, and prepare for training.
    
    Args:
        include_safe_prompts: Whether to add generated safe prompts
        balance_classes: Whether to balance class distribution
        save_raw: Whether to save the raw combined dataset
    
    Returns:
        Cleaned, combined DataFrame with 'text' and 'label' columns
    """
    print("=" * 60)
    print("[DataLoader] Loading and preparing datasets...")
    print("=" * 60)

    # Ensure directories exist
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    # Load individual datasets
    dfs = []

    df_deepset = load_deepset_dataset()
    if not df_deepset.empty:
        dfs.append(df_deepset)

    df_geeky = load_geekyrakshit_dataset()
    if not df_geeky.empty:
        dfs.append(df_geeky)

    df_jailbreak = load_jailbreak_classification_dataset()
    if not df_jailbreak.empty:
        dfs.append(df_jailbreak)

    if include_safe_prompts:
        df_safe = generate_safe_prompts()
        dfs.append(df_safe)

    if not dfs:
        raise ValueError("No datasets were loaded. Check internet connection and dataset availability.")

    # Combine all datasets
    combined = pd.concat(dfs, ignore_index=True)
    print(f"\n[DataLoader] Combined dataset: {len(combined)} samples")

    # Clean text
    combined["text"] = combined["text"].apply(clean_text)

    # Remove empty texts
    combined = combined[combined["text"].str.len() > 0]

    # Remove duplicates
    before_dedup = len(combined)
    combined = combined.drop_duplicates(subset=["text"])
    print(f"[DataLoader] Removed {before_dedup - len(combined)} duplicates")

    # Remove any rows with NaN labels
    combined = combined.dropna(subset=["label"])
    combined["label"] = combined["label"].astype(int)

    print(f"[DataLoader] Final dataset: {len(combined)} samples")
    print(f"[DataLoader] Class distribution:\n{combined['label'].value_counts()}")

    # Save raw combined
    if save_raw:
        raw_path = os.path.join(RAW_DIR, "combined_dataset.csv")
        combined.to_csv(raw_path, index=False)
        print(f"[DataLoader] Saved raw dataset to {raw_path}")

    # Balance classes if requested
    if balance_classes:
        combined = _balance_classes(combined)

    return combined


def _balance_classes(df: pd.DataFrame) -> pd.DataFrame:
    """
    Balance class distribution using oversampling of minority class.
    
    Args:
        df: DataFrame with 'text' and 'label' columns
    
    Returns:
        Balanced DataFrame
    """
    counts = df["label"].value_counts()
    max_count = counts.max()

    balanced_dfs = []
    for label in counts.index:
        class_df = df[df["label"] == label]
        if len(class_df) < max_count:
            # Oversample minority class
            oversampled = class_df.sample(
                max_count, replace=True, random_state=42
            )
            balanced_dfs.append(oversampled)
        else:
            balanced_dfs.append(class_df)

    balanced = pd.concat(balanced_dfs, ignore_index=True)
    balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"[DataLoader] Balanced dataset: {len(balanced)} samples")
    print(f"[DataLoader] Balanced distribution:\n{balanced['label'].value_counts()}")

    return balanced
