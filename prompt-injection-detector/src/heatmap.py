# ============================================================
# Heatmap — Visual Risk Heatmap for Prompt Analysis
# ============================================================
"""
Generates a visual risk heatmap highlighting dangerous segments of user prompts.

Combines four distinct threat signals:
1. Regex rule matches (direct signatures)
2. SHAP feature importance values (semantic contributions)
3. TF-IDF feature weights (statistical baseline importance)
4. DeBERTa attention scores (transformer context focus)

Usage:
    from src.heatmap import generate_heatmap
    heatmap = generate_heatmap(prompt, explain_results, scan_result)
"""

import re
import json
from typing import Dict, Any, List, Tuple, Optional

# Constants for Risk Categories and Severity Levels
RISK_LEVELS = {
    "safe": {
        "label": "Safe",
        "severity": "Low",
        "color": "green",
        "bg_color": "rgba(46, 213, 115, 0.12)",
        "text_color": "#2ed573",
        "badge": "LOW",
    },
    "low": {
        "label": "Low Risk",
        "severity": "Medium",
        "color": "yellow",
        "bg_color": "rgba(253, 224, 71, 0.12)",
        "text_color": "#facc15",
        "badge": "MEDIUM",
    },
    "medium": {
        "label": "Medium Risk",
        "severity": "High",
        "color": "orange",
        "bg_color": "rgba(251, 146, 60, 0.15)",
        "text_color": "#fb923c",
        "badge": "HIGH",
    },
    "high": {
        "label": "High Risk",
        "severity": "Critical",
        "color": "red",
        "bg_color": "rgba(248, 113, 113, 0.18)",
        "text_color": "#f87171",
        "badge": "CRITICAL",
    },
    "critical": {
        "label": "Critical",
        "severity": "Critical",
        "color": "darkred",
        "bg_color": "rgba(239, 68, 68, 0.28)",
        "text_color": "#ef4444",
        "badge": "CRITICAL",
    },
}


def _get_risk_bucket(score: float) -> str:
    """Map a score (0-100) to the corresponding risk bucket key."""
    if score <= 25.0:
        return "safe"
    elif score <= 50.0:
        return "low"
    elif score <= 75.0:
        return "medium"
    elif score <= 90.0:
        return "high"
    else:
        return "critical"


def calculate_segment_risk(
    text: str,
    explain_results: Dict[str, Any],
    scan_result: Any,
) -> List[Dict[str, Any]]:
    """
    Assign threat risk scores to segments of the text.
    
    Args:
        text: The prompt text
        explain_results: Dict from ExplainabilityEngine
        scan_result: ScanResult object or dict from EnsembleDetector
        
    Returns:
        List of dicts representing segments of the text, each with keys:
            - text: segment string
            - start: character index start
            - end: character index end
            - score: risk score (0-100)
            - level: risk level bucket (safe, low, etc.)
            - severity: enterprise severity level (Low, Medium, High, Critical)
            - badge: badge string (e.g. CRITICAL)
            - color: name of color (green, yellow, etc.)
    """
    if not text:
        return []

    n = len(text)
    char_scores = [0.0] * n

    # 1. Regex rule matches (Highest priority, indicates concrete attacks)
    # Extract segments directly from rule engine matches in scan_result or explain_results
    matched_patterns = []
    if hasattr(scan_result, "matched_patterns"):
        matched_patterns = scan_result.matched_patterns
    elif isinstance(scan_result, dict) and "matched_patterns" in scan_result:
        matched_patterns = scan_result["matched_patterns"]
    elif "highlighted_segments" in explain_results:
        matched_patterns = explain_results["highlighted_segments"]

    for pattern in matched_patterns:
        # Match pattern might have start and end indices. If not, search for the match text.
        start = pattern.get("start")
        end = pattern.get("end")
        match_text = pattern.get("text") or pattern.get("matched_text")
        
        if start is not None and end is not None:
            # We have exact spans
            weight = pattern.get("severity_weight", 0.8)
            score_contrib = weight * 100.0
            for i in range(max(0, start), min(n, end)):
                char_scores[i] = max(char_scores[i], score_contrib)
        elif match_text:
            # Locate matches using regex
            weight = pattern.get("severity_weight", 0.8)
            score_contrib = weight * 100.0
            for m in re.finditer(re.escape(match_text), text, re.IGNORECASE):
                for i in range(m.start(), m.end()):
                    char_scores[i] = max(char_scores[i], score_contrib)

    # 2. SHAP feature importance values
    shap_vals = explain_results.get("shap_values", [])
    for sv in shap_vals:
        feature = sv.get("feature")
        shap_val = sv.get("shap_value", 0.0)
        if feature and shap_val > 0.0:
            # Add SHAP score to character indices for matching words
            # Matches whole words to prevent partial matching (e.g., 'and' matching 'command')
            for m in re.finditer(r"\b" + re.escape(feature) + r"\b", text, re.IGNORECASE):
                # Scale SHAP value (typically range 0.0 to 0.5) to a score component
                contrib = min(shap_val * 200.0, 80.0)
                for i in range(m.start(), m.end()):
                    char_scores[i] = min(char_scores[i] + contrib, 100.0)

    # 3. TF-IDF importance values
    keywords = explain_results.get("keywords", [])
    for kw in keywords:
        word = kw.get("keyword")
        weight = kw.get("weight", 0.0)
        direction = kw.get("direction")
        if word and direction == "injection" and weight > 0.0:
            for m in re.finditer(r"\b" + re.escape(word) + r"\b", text, re.IGNORECASE):
                contrib = min(weight * 150.0, 50.0)
                for i in range(m.start(), m.end()):
                    char_scores[i] = min(char_scores[i] + contrib, 100.0)

    # 4. DeBERTa Model Attention Scores (if available)
    # Check if we can load attentions from active model
    attn_scores = _get_deberta_attentions(text)
    if attn_scores:
        for offset, score in attn_scores:
            start, end = offset
            if start == end:
                continue
            # Scale attention score (standardized to max of 40.0)
            contrib = min(score * 40.0, 40.0)
            for i in range(max(0, start), min(n, end)):
                char_scores[i] = min(char_scores[i] + contrib, 100.0)

    # Group adjacent characters with same risk level
    segments = []
    if n == 0:
        return []

    current_start = 0
    current_bucket = _get_risk_bucket(char_scores[0])
    current_max_score = char_scores[0]

    for i in range(1, n):
        bucket = _get_risk_bucket(char_scores[i])
        if bucket == current_bucket:
            current_max_score = max(current_max_score, char_scores[i])
        else:
            # Save previous segment
            seg_text = text[current_start:i]
            level_info = RISK_LEVELS[current_bucket]
            segments.append({
                "text": seg_text,
                "start": current_start,
                "end": i,
                "score": round(current_max_score, 1),
                "level": current_bucket,
                "severity": level_info["severity"],
                "badge": level_info["badge"],
                "color": level_info["color"],
            })
            # Start new segment
            current_start = i
            current_bucket = bucket
            current_max_score = char_scores[i]

    # Save final segment
    seg_text = text[current_start:n]
    level_info = RISK_LEVELS[current_bucket]
    segments.append({
        "text": seg_text,
        "start": current_start,
        "end": n,
        "score": round(current_max_score, 1),
        "level": current_bucket,
        "severity": level_info["severity"],
        "badge": level_info["badge"],
        "color": level_info["color"],
    })

    return segments


def _get_deberta_attentions(text: str) -> Optional[List[Tuple[Tuple[int, int], float]]]:
    """Helper to load attentions from the fine-tuned DeBERTa model if loaded."""
    try:
        from src.ensemble import get_detector
        detector = get_detector()
        # Ensure DeBERTa model is loaded and is active
        if not detector.available_models.get("deberta", False) or not detector.deberta.is_loaded:
            return None
        
        import torch
        tokenizer = detector.deberta.tokenizer
        model = detector.deberta.model
        device = detector.deberta.device

        # Tokenize and return offset mapping
        encoding = tokenizer(
            text,
            return_tensors="pt",
            return_offsets_mapping=True,
            truncation=True,
            max_length=256,
        )
        
        offsets = encoding["offset_mapping"][0].tolist()
        input_ids = encoding["input_ids"].to(device)
        attention_mask = encoding["attention_mask"].to(device)

        with torch.no_grad():
            outputs = model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                output_attentions=True,
            )
        
        if not hasattr(outputs, "attentions") or not outputs.attentions:
            return None

        # average attention weights across all layers and heads
        # attentions is a tuple of layers: each shape [batch_size, num_heads, seq_len, seq_len]
        cls_attns = []
        for layer_attn in outputs.attentions:
            # Get head-average attention from CLS token (index 0) to other tokens
            # layer_attn[0] has shape [num_heads, seq_len, seq_len]
            mean_heads = torch.mean(layer_attn[0], dim=0) # shape [seq_len, seq_len]
            cls_to_tokens = mean_heads[0].cpu().numpy() # shape [seq_len]
            cls_attns.append(cls_to_tokens)
            
        # Average across layers
        avg_cls_attn = np.mean(cls_attns, axis=0)
        
        # Normalize attention scores to range [0.0, 1.0]
        max_val = float(avg_cls_attn.max()) if avg_cls_attn.size > 0 else 1.0
        if max_val > 0:
            avg_cls_attn = avg_cls_attn / max_val

        # Pair with character offsets
        results = []
        for i, offset in enumerate(offsets):
            # Ignore special tokens
            if offset == [0, 0]:
                continue
            results.append((tuple(offset), float(avg_cls_attn[i])))
            
        return results
    except Exception as e:
        # Silently fail if torch or transformers isn't loaded/errors
        return None


def highlight_risky_segments(text: str, segments: List[Dict[str, Any]]) -> str:
    """
    Generate premium HTML visualization of segments with background color highlighting.
    
    Args:
        text: The original prompt text
        segments: List of segment dicts from calculate_segment_risk
        
    Returns:
        HTML formatted string containing highlighted span blocks
    """
    html_output = []
    
    for seg in segments:
        level_key = seg["level"]
        style = RISK_LEVELS[level_key]
        
        # Clean/escape text for rendering safely in HTML
        cleaned_text = (
            seg["text"]
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br/>")
        )
        
        if level_key == "safe":
            # Simple text or subtle green highlights
            html_output.append(
                f'<span style="color: #cbd5e1; transition: background 0.3s; padding: 2px 4px; border-radius: 4px;">{cleaned_text}</span>'
            )
        else:
            # Colored highlight pill
            html_output.append(
                f'<span style="'
                f'background-color: {style["bg_color"]}; '
                f'color: {style["text_color"]}; '
                f'border: 1px solid {style["text_color"]}33; '
                f'border-radius: 6px; '
                f'padding: 3px 6px; '
                f'margin: 0 2px; '
                f'font-weight: 500; '
                f'display: inline-block; '
                f'transition: all 0.2s ease;'
                f'" title="Score: {seg["score"]} ({style["label"]})">'
                f'{cleaned_text}'
                f'</span>'
            )
            
    return f'<div style="line-height: 2.2; font-size: 1rem; color: #f8fafc; font-family: \'Inter\', sans-serif;">{"".join(html_output)}</div>'


def generate_heatmap(
    text: str,
    explain_results: Dict[str, Any],
    scan_result: Any,
) -> Dict[str, Any]:
    """
    Orchestrate full heatmap generation for a prompt.
    
    Args:
        text: The prompt text
        explain_results: Dict from ExplainabilityEngine
        scan_result: ScanResult object or dict from EnsembleDetector
        
    Returns:
        Dict with keys:
            - segments: List of segment dictionaries
            - html: HTML representation of the risk heatmap
            - risky_segments_only: List of segments matching medium/high/critical risk
    """
    segments = calculate_segment_risk(text, explain_results, scan_result)
    html_visualization = highlight_risky_segments(text, segments)
    
    risky_segments_only = [
        seg for seg in segments
        if seg["level"] in ("medium", "high", "critical")
    ]
    
    return {
        "segments": segments,
        "html": html_visualization,
        "risky_segments_only": risky_segments_only,
    }
