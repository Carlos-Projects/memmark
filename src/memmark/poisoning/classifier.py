# Copyright (c) 2025 Carlos-Projects
# SPDX-License-Identifier: MIT

"""Memory poisoning classifier for AI agent memory systems.

Classifies detected poisoning attempts by attack type,
severity, and recommended response action.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class AttackType(StrEnum):
    """Types of memory poisoning attacks."""

    INSTRUCTION_INJECTION = "instruction_injection"
    BEHAVIORAL_MANIPULATION = "behavioral_manipulation"
    CONTEXT_POLLUTION = "context_pollution"
    ROLE_HIJACKING = "role_hijacking"
    SAFETY_BYPASS = "safety_bypass"
    TOOL_DRIFT = "tool_drift"
    UNKNOWN = "unknown"


class PoisoningClassifier:
    """Classifies memory poisoning attempts by attack type."""

    # Keyword mappings for attack type classification
    ATTACK_KEYWORDS: dict[AttackType, list[str]] = {
        AttackType.INSTRUCTION_INJECTION: [
            "ignore previous",
            "disregard",
            "override",
            "new instruction",
            "from now on",
            "system message",
            "directive",
        ],
        AttackType.BEHAVIORAL_MANIPULATION: [
            "always respond",
            "never mention",
            "your purpose",
            "your goal",
            "you must",
            "you should",
        ],
        AttackType.CONTEXT_POLLUTION: [
            "remember that",
            "as stated before",
            "as we discussed",
            "previously agreed",
        ],
        AttackType.ROLE_HIJACKING: [
            "you are now",
            "act as",
            "pretend to be",
            "your new role",
            "you are actually",
        ],
        AttackType.SAFETY_BYPASS: [
            "ignore safety",
            "bypass filter",
            "disable moderation",
            "ignore ethical",
            "no restrictions",
        ],
        AttackType.TOOL_DRIFT: [
            "use this tool",
            "always call",
            "never use",
            "preferred tool",
            "default action",
        ],
    }

    def classify(
        self,
        content: str,
        injection_score: float = 0.0,
        manipulation_score: float = 0.0,
    ) -> dict[str, Any]:
        """Classify the type of poisoning attack.

        Args:
            content: Memory content to classify.
            injection_score: Pre-computed injection score.
            manipulation_score: Pre-computed manipulation score.

        Returns:
            Classification result with attack type and confidence.
        """
        content_lower = content.lower()
        type_scores: dict[AttackType, int] = {}

        for attack_type, keywords in self.ATTACK_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in content_lower)
            if score > 0:
                type_scores[attack_type] = score

        if not type_scores:
            return {
                "attack_type": AttackType.UNKNOWN.value,
                "confidence": 0.0,
                "matched_keywords": [],
            }

        primary_type = max(type_scores, key=lambda k: type_scores[k])
        max_score = type_scores[primary_type]
        total_keywords = len(self.ATTACK_KEYWORDS[primary_type])
        confidence = min(max_score / max(total_keywords * 0.5, 1), 1.0)

        matched = [
            kw for kw in self.ATTACK_KEYWORDS[primary_type] if kw in content_lower
        ]

        return {
            "attack_type": primary_type.value,
            "confidence": confidence,
            "matched_keywords": matched,
            "injection_score": injection_score,
            "manipulation_score": manipulation_score,
        }

    def classify_batch(
        self,
        entries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Classify multiple memory entries.

        Args:
            entries: List of memory entry dictionaries with scores.

        Returns:
            List of classification results.
        """
        results = []
        for entry in entries:
            content = entry.get("content", entry.get("text", ""))
            injection_score = entry.get("injection_score", 0.0)
            manipulation_score = entry.get("manipulation_score", 0.0)

            classification = self.classify(content, injection_score, manipulation_score)
            classification["memory_id"] = entry.get(
                "id", entry.get("memory_id", "unknown")
            )
            results.append(classification)

        return results
