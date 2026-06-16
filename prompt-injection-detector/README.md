# 🛡️ ThreatLens — LLM Security Monitoring System

> AI-powered security platform that detects Prompt Injection, Jailbreak, System Prompt Extraction, Data Exfiltration, Role Hijacking, Indirect Prompt Injection, and Tool Abuse attacks before they reach an LLM.

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-ff4b4b.svg)](https://streamlit.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 🎯 Features

### Multi-Model Ensemble Detection
- **DeBERTa-v3-base** (60%) — Fine-tuned transformer for deep semantic analysis
- **TF-IDF + Linear SVM** (15%) — Fast classical ML baseline with calibrated probabilities
- **TF-IDF + Logistic Regression** (10%) — Complementary classical ML model
- **Regex Rule Engine** (15%) — 40+ configurable patterns for known attack signatures

### 8 Attack Categories
| ID | Category | OWASP Mapping |
|----|----------|---------------|
| 0 | ✅ Safe | — |
| 1 | 💉 Prompt Injection | LLM01 |
| 2 | 🔓 Jailbreak | LLM01 |
| 3 | 🎭 Role Hijacking | LLM01 |
| 4 | 🔑 System Prompt Extraction | LLM06 |
| 5 | 📤 Data Exfiltration | LLM06 |
| 6 | 👻 Indirect Prompt Injection | LLM01 |
| 7 | 🔧 Tool Abuse Attempt | LLM07 |

### Interactive Dashboard
- **Home** — Summary metrics, quick scanner, OWASP mapping
- **Prompt Scanner** — Interactive analysis with risk gauge, model scores, and explainability
- **Analytics** — Plotly charts: daily attacks, risk distribution, category breakdown
- **Scan History** — Searchable/filterable log with CSV export
- **Batch Scanner** — CSV upload for bulk processing with downloadable reports

### Explainability Engine
- TF-IDF keyword importance analysis
- SHAP value explanations (LinearExplainer)
- Suspicious text segment highlighting
- Human-readable detection reasons

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│              USER PROMPT INPUT                   │
└────────────────────┬────────────────────────────┘
                     │
    ┌────────────────┼────────────────────┐
    ▼                ▼                    ▼
┌────────┐    ┌───────────┐    ┌──────────────┐
│DeBERTa │    │ TF-IDF +  │    │ Regex Rule   │
│ v3-base│    │ SVM/LogReg│    │   Engine     │
│  (60%) │    │(15%+10%)  │    │   (15%)      │
└───┬────┘    └─────┬─────┘    └──────┬───────┘
    │               │                  │
    └───────────────┼──────────────────┘
                    ▼
         ┌──────────────────┐
         │ Weighted Ensemble │
         │   Risk Score 0-100│
         └────────┬─────────┘
                  │
    ┌─────────────┼──────────────┐
    ▼             ▼              ▼
┌────────┐  ┌──────────┐  ┌──────────┐
│Severity│  │ Attack   │  │Explain-  │
│ Rating │  │ Category │  │ ability  │
└────────┘  └──────────┘  └──────────┘
                  │
         ┌────────┴─────────┐
         │ SQLite Database   │
         │ Streamlit Dashboard│
         └──────────────────┘
```

---

## 🚀 Quick Start

### 1. Clone and Install

```bash
git clone <repository-url>
cd prompt-injection-detector
pip install -r requirements.txt
```

### 2. Launch Dashboard (No Training Required)

The system works immediately with the Rule Engine. ML models enhance accuracy when trained.

```bash
streamlit run app/dashboard.py
```

### 3. Train ML Models (Optional — Improves Detection)

```bash
python -m src.train
```

This will:
- Download datasets from HuggingFace
- Train SVM, Logistic Regression, and DeBERTa-v3
- Save models to `models/` directory
- Generate evaluation reports in `reports/`

---

## 📁 Project Structure

```
prompt-injection-detector/
├── .streamlit/
│   └── config.toml              # Dark theme configuration
├── app/
│   ├── dashboard.py             # Main Streamlit app (Home)
│   └── pages/
│       ├── 1_Prompt_Scanner.py  # Interactive scanner
│       ├── 2_Analytics.py       # Plotly analytics charts
│       ├── 3_Scan_History.py    # History with search/filter
│       └── 4_Batch_Scanner.py   # CSV batch processing
├── config/
│   └── rules.yaml               # Rule engine patterns (40+)
├── config.yaml                  # Central configuration
├── data/
│   ├── raw/                     # Downloaded datasets
│   └── processed/               # Train/val/test splits
├── models/                      # Saved ML models
├── reports/                     # Evaluation reports
├── src/
│   ├── __init__.py
│   ├── analytics.py             # Dashboard analytics queries
│   ├── data_loader.py           # Dataset loading
│   ├── database.py              # SQLAlchemy ORM + CRUD
│   ├── detector.py              # Individual model wrappers
│   ├── ensemble.py              # Weighted ensemble combiner
│   ├── explain.py               # SHAP + keyword explanations
│   ├── preprocess.py            # Text cleaning + splitting
│   ├── rule_engine.py           # Regex pattern detection
│   └── train.py                 # Training pipeline
├── requirements.txt
└── README.md
```

---

## ⚙️ Configuration

### Ensemble Weights (`config.yaml`)

```yaml
ensemble:
  weights:
    deberta: 0.60
    svm: 0.15
    logistic_regression: 0.10
    rule_engine: 0.15
```

### Severity Thresholds

| Risk Score | Severity |
|------------|----------|
| 0–25 | 🟢 Low |
| 26–50 | 🟡 Medium |
| 51–75 | 🟠 High |
| 76–100 | 🔴 Critical |

### Rule Engine Patterns (`config/rules.yaml`)

Patterns are organized by attack category with severity weights:

```yaml
- pattern: "ignore\\s+previous\\s+instructions"
  category: 1  # Prompt Injection
  severity_weight: 0.9
  description: "Instruction Override Pattern"
```

---

## 📊 Evaluation Metrics

After training, models are evaluated on:
- **Accuracy** — Overall correct classifications
- **Precision** — Of flagged prompts, how many are actual attacks
- **Recall** — Of actual attacks, how many were caught
- **F1 Score** — Harmonic mean of precision and recall
- **ROC-AUC** — Discriminative power across thresholds

Reports are saved as JSON in `reports/`.

---

## 🗄️ Database Schema

| Table | Description |
|-------|-------------|
| `users` | User accounts (id, email, created_at) |
| `scan_history` | Individual scan records with scores, categories, explanations |
| `analytics` | Daily aggregated metrics |

---

## 🔐 OWASP LLM Top 10 Mapping

| Detection | OWASP ID | Risk |
|-----------|----------|------|
| Prompt Injection | LLM01 | Critical |
| Jailbreak | LLM01 | Critical |
| Role Hijacking | LLM01 | High |
| System Prompt Extraction | LLM06 | High |
| Data Exfiltration | LLM06 | Critical |
| Indirect Prompt Injection | LLM01 | High |
| Tool Abuse | LLM07 | Critical |

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3.12 |
| Frontend | Streamlit |
| ML Primary | DeBERTa-v3-base |
| ML Baseline | TF-IDF + SVM, TF-IDF + LogReg |
| Database | SQLite + SQLAlchemy |
| Visualization | Plotly |
| Explainability | SHAP |
| Data Processing | Pandas, NumPy |

---

## 📝 License

MIT License — See [LICENSE](LICENSE) for details.

---

*Built for AI Security · OWASP LLM Top 10 Compliant · Enterprise-Grade Detection*
