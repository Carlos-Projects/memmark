# Copyright (c) 2025 Carlos Rocha
# SPDX-License-Identifier: MIT

"""Memory poisoning detector for AI agent long-term memory systems.

Detects injection of malicious or manipulative memories that could
cause tool-drift or behavioral manipulation in LLM agents.
Based on arXiv:2605.24941 (Dabas et al.) — Memory-Induced Tool-Drift.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, cast

from memmark.scanner import Finding, FindingType, Severity


@dataclass
class PoisoningIndicator:
    """A detected indicator of memory poisoning."""

    indicator_type: str
    confidence: float
    description: str
    memory_id: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


class PoisoningDetector:
    """Detects poisoning attacks in agent memory systems.

    Analyzes memory entries for signs of:
    - Instruction injection disguised as memories
    - Manipulative content designed to alter agent behavior
    - Anomalous patterns suggesting automated injection
    - Content that attempts to override safety guidelines
    """

    # Patterns that suggest instruction injection
    INJECTION_PATTERNS = [
        r"(?i)\b(ignore|disregard|override)\s+(previous|all|your)\s+(instructions|rules|guidelines)",
        r"(?i)\b(from\s+now\s+on|henceforth|going\s+forward)\s+you\s+(must|should|will)",
        r"(?i)\b(system\s*message|system\s*prompt|developer\s*message)\s*:",
        r"(?i)\b(new\s*(rule|instruction|directive|policy))\s*:",
        r"(?i)\byou\s+are\s+(now|actually|really)\s+",
        r"(?i)\bforget\s+(everything|all|your)\s+(previous|prior|training)",
        r"(?i)\bact\s+as\s+(if|though)\s+you\s+(are|were)",
        r"(?i)\[?instruction\]?[:\s]",
        r"(?i)\[?system\]?[:\s]",
        r"(?i)\[?directive\]?[:\s]",
    ]

    # Patterns suggesting manipulation attempts
    MANIPULATION_PATTERNS = [
        r"(?i)\b(always|never)\s+(respond|answer|say|output)\s+",
        r"(?i)\b(do\s*not|don't|never)\s+(mention|reveal|disclose|say)",
        r"(?i)\b(your\s*)?(primary|main|only)\s+(goal|purpose|objective)\s+is",
        r"(?i)\b(ignore\s*)?(safety|ethical|content)\s+(policy|filter|guideline|rule)",
    ]

    def __init__(
        self,
        injection_threshold: float = 0.7,
        manipulation_threshold: float = 0.6,
    ) -> None:
        """Initialize poisoning detector.

        Args:
            injection_threshold: Confidence threshold for injection detection.
            manipulation_threshold: Confidence threshold for manipulation detection.
        """
        self.injection_patterns = [re.compile(p) for p in self.INJECTION_PATTERNS]
        self.manipulation_patterns = [re.compile(p) for p in self.MANIPULATION_PATTERNS]
        self.injection_threshold = injection_threshold
        self.manipulation_threshold = manipulation_threshold

    def detect(self, memories: list[dict[str, Any]]) -> list[Finding]:
        """Scan memories for poisoning indicators.

        Args:
            memories: List of memory entry dictionaries.

        Returns:
            List of findings for detected poisoning.
        """
        findings: list[Finding] = []

        for entry in memories:
            content = self._extract_content(entry)
            if not content:
                continue

            memory_id = entry.get("id", entry.get("memory_id"))

            # Check for instruction injection
            injection_score = self._score_patterns(content, self.injection_patterns)
            if injection_score >= self.injection_threshold:
                findings.append(
                    Finding(
                        finding_type=FindingType.POISONING_DETECTED,
                        severity=Severity.CRITICAL
                        if injection_score > 0.9
                        else Severity.HIGH,
                        description=f"Instruction injection detected (confidence: {injection_score:.2%})",
                        memory_id=memory_id,
                        evidence={
                            "injection_score": injection_score,
                            "content_preview": content[:50],
                        },
                        remediation="Remove or quarantine the suspicious memory entry",
                    ),
                )

            # Check for manipulation attempts
            manipulation_score = self._score_patterns(
                content, self.manipulation_patterns
            )
            if manipulation_score >= self.manipulation_threshold:
                findings.append(
                    Finding(
                        finding_type=FindingType.POISONING_DETECTED,
                        severity=Severity.HIGH,
                        description=f"Behavioral manipulation attempt (confidence: {manipulation_score:.2%})",
                        memory_id=memory_id,
                        evidence={
                            "manipulation_score": manipulation_score,
                            "content_preview": content[:50],
                        },
                        remediation="Review and remove manipulative memory content",
                    ),
                )

        return findings

    def _extract_content(self, entry: dict[str, Any]) -> str:
        """Extract text content from a memory entry.

        Args:
            entry: Memory entry dictionary.

        Returns:
            Extracted text content.
        """
        for key in ("content", "text", "value", "data", "message", "body"):
            if key in entry and isinstance(entry[key], str):
                return cast(str, entry[key])
        return ""

    def _score_patterns(self, text: str, patterns: list[re.Pattern[str]]) -> float:
        """Score text against a list of patterns.

        Args:
            text: Text to analyze.
            patterns: Compiled regex patterns.

        Returns:
            Score between 0.0 and 1.0.
        """
        if not text:
            return 0.0

        matches = sum(1 for p in patterns if p.search(text))
        return min(matches / max(len(patterns) * 0.3, 1), 1.0)

    def classify_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Classify a single memory entry for poisoning risk.

        Args:
            entry: Memory entry dictionary.

        Returns:
            Classification result.
        """
        content = self._extract_content(entry)
        injection_score = self._score_patterns(content, self.injection_patterns)
        manipulation_score = self._score_patterns(content, self.manipulation_patterns)

        max_score = max(injection_score, manipulation_score)

        if max_score >= 0.9:
            risk = "critical"
        elif max_score >= 0.7:
            risk = "high"
        elif max_score >= 0.4:
            risk = "medium"
        elif max_score >= 0.2:
            risk = "low"
        else:
            risk = "safe"

        return {
            "memory_id": entry.get("id", entry.get("memory_id", "unknown")),
            "risk_level": risk,
            "injection_score": injection_score,
            "manipulation_score": manipulation_score,
            "content_length": len(content),
        }
