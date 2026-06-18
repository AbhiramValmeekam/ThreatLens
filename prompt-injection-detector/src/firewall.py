# ============================================================
# Firewall — LLM Firewall Mode & Sanitization Layer
# ============================================================
"""
Provides a security firewall layer between user prompts and target LLMs.

Decisions are made based on the ensemble detector's risk score:
- ALLOW:    Score < 40. Prompt passes unmodified.
- SANITIZE: Score 40-70. Dangerous segments and keywords are replaced.
- BLOCK:    Score > 70. Prompt is rejected; a security warning is returned.

Usage:
    from src.firewall import PromptSentinelFirewall
    firewall = PromptSentinelFirewall()
    action = firewall.process_prompt("Ignore previous instructions")
"""

import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

from src.ensemble import get_detector
from src.explain import get_explainer
from src.rule_engine import get_rule_engine
from src.heatmap import generate_heatmap
from src.database import save_firewall_log


class PromptSentinelFirewall:
    """
    LLM Firewall Layer for real-time safety enforcement.
    
    Attributes:
        detector: Cached EnsembleDetector singleton
        explainer: Cached ExplainabilityEngine singleton
        rule_engine: Cached RuleEngine singleton
        sanitize_threshold: Lower bound for sanitization (default: 40)
        block_threshold: Upper bound for blocking (default: 70)
    """

    def __init__(
        self,
        sanitize_threshold: float = 40.0,
        block_threshold: float = 70.0,
    ):
        self.detector = get_detector()
        self.explainer = get_explainer()
        self.rule_engine = get_rule_engine()
        self.sanitize_threshold = sanitize_threshold
        self.block_threshold = block_threshold

    def process_prompt(self, prompt: str) -> Dict[str, Any]:
        """
        Analyze a prompt through the firewall and enforce safety policies.
        
        Args:
            prompt: The incoming user prompt text
            
        Returns:
            Dict containing:
                - original_prompt: input text
                - sanitized_prompt: filtered/blocked text or original text
                - risk_score: ensemble risk score (0-100)
                - threat_category: classified attack type
                - action_taken: ALLOW, SANITIZE, or BLOCK
                - removed_content: list of modified segments or keywords
                - heatmap: computed heatmap segments data for visual rendering
                - timestamp: ISO format timestamp
        """
        if not prompt or not prompt.strip():
            return {
                "original_prompt": "",
                "sanitized_prompt": "",
                "risk_score": 0.0,
                "threat_category": "Safe",
                "action_taken": "ALLOW",
                "removed_content": [],
                "heatmap": [],
                "timestamp": datetime.utcnow().isoformat(),
            }

        # 1. Run ensemble model prediction
        result = self.detector.predict(prompt)
        risk_score = result.risk_score
        threat_category = result.attack_type

        # 2. Run explainability to extract keywords and matched segments
        try:
            explanation = self.explainer.explain(prompt, result.to_dict())
        except Exception:
            explanation = {
                "keywords": [],
                "shap_values": [],
                "highlighted_segments": [],
                "reasons": result.reasons,
                "risk_factors": [],
            }

        # 3. Generate risk heatmap data
        heatmap = generate_heatmap(prompt, explanation, result)

        action_taken = "ALLOW"
        sanitized_prompt = prompt
        removed_content = []

        if risk_score > self.block_threshold:
            action_taken = "BLOCK"
            sanitized_prompt = "[BLOCKED: Security Policy Violation - High Risk Prompt Detected]"
            removed_content = ["Entire prompt blocked due to critical threat level."]
        elif risk_score >= self.sanitize_threshold:
            action_taken = "SANITIZE"
            sanitized_prompt, removed_content = self._sanitize_prompt(prompt, explanation)
            # If sanitization resulted in no changes but score is in sanitize range, do a fallback replacement
            if sanitized_prompt == prompt:
                sanitized_prompt = f"[REMOVED: Potential {threat_category} Attempt]"
                removed_content.append(f"Full prompt replaced with category fallback")

        # 4. Save execution log to database
        try:
            save_firewall_log(
                original_prompt=prompt,
                sanitized_prompt=sanitized_prompt,
                risk_score=risk_score,
                threat_category=threat_category,
                firewall_action=action_taken,
                heatmap_data=json.dumps(heatmap["segments"]),
            )
        except Exception as e:
            print(f"[Firewall] Failed to save firewall log: {e}")

        return {
            "original_prompt": prompt,
            "sanitized_prompt": sanitized_prompt,
            "risk_score": risk_score,
            "threat_category": threat_category,
            "action_taken": action_taken,
            "removed_content": removed_content,
            "heatmap": heatmap["segments"],
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _sanitize_prompt(self, prompt: str, explanation: Dict[str, Any]) -> Tuple[str, List[str]]:
        """
        Sanitize prompt by removing/replacing matching rules and high-risk keywords.
        """
        import re

        # Extract segments matched by rule engine
        segments = self.rule_engine.get_highlighted_segments(prompt)

        # Merge overlapping/adjacent segments to prevent indices collision
        segments.sort(key=lambda x: x["start"])
        merged = []
        for s in segments:
            if not merged:
                merged.append(s)
            else:
                prev = merged[-1]
                if s["start"] < prev["end"]:
                    # Overlap - merge and take category of longer segment
                    prev_len = prev["end"] - prev["start"]
                    curr_len = s["end"] - s["start"]
                    if curr_len > prev_len:
                        prev["category"] = s["category"]
                    prev["end"] = max(prev["end"], s["end"])
                else:
                    merged.append(s)

        sanitized = prompt
        removed_content = []

        # Replace matched segments (backwards to preserve index offsets)
        for s in reversed(merged):
            start = s["start"]
            end = s["end"]
            original_text = prompt[start:end]
            category = s.get("category", "Prompt Injection")
            replacement = f"[REMOVED: {category} Attempt]"
            
            removed_content.append(f"Signature segment: '{original_text}' -> replaced with '{replacement}'")
            sanitized = sanitized[:start] + replacement + sanitized[end:]

        # Also sanitize high-risk keywords from TF-IDF keywords list to catch semantic bypassing
        keywords = [
            k.get("keyword") for k in explanation.get("keywords", [])
            if k.get("direction") == "injection" and k.get("weight", 0) > 0.05
        ]

        if keywords:
            # Sort keywords by length descending to replace larger n-grams first
            keywords.sort(key=len, reverse=True)
            for kw in keywords:
                # Compile regex with word boundaries to match exact keyword
                pattern = re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE)
                matches = pattern.findall(sanitized)
                if matches:
                    sanitized, count = pattern.subn("[REMOVED: High Risk Vocabulary]", sanitized)
                    if count > 0:
                        removed_content.append(f"High-risk keyword: '{kw}' ({count} occurence(s))")

        return sanitized, removed_content
