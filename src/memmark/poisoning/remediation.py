# Copyright (c) 2025 Carlos-Projects
# SPDX-License-Identifier: MIT

"""Memory poisoning remediation for AI agent memory systems.

Provides automated and guided remediation for detected
memory poisoning attacks.
"""

from __future__ import annotations

from typing import Any

from memmark.poisoning.classifier import AttackType


class PoisoningRemediation:
    """Handles remediation of poisoned memory entries."""

    def __init__(self) -> None:
        """Initialize remediation handler."""

    def remediate(
        self,
        entry: dict[str, Any],
        classification: dict[str, Any],
    ) -> dict[str, Any]:
        """Apply remediation to a poisoned memory entry.

        Args:
            entry: Original memory entry.
            classification: Classification result from PoisoningClassifier.

        Returns:
            Remediation action and result.
        """
        attack_type = AttackType(classification.get("attack_type", "unknown"))
        confidence = classification.get("confidence", 0.0)

        action = self._determine_action(attack_type, confidence)

        return {
            "memory_id": entry.get("id", entry.get("memory_id", "unknown")),
            "action": action,
            "attack_type": attack_type.value,
            "confidence": confidence,
            "original_entry": entry,
            "remediated_entry": self._apply_action(entry, action),
        }

    def _determine_action(
        self,
        attack_type: AttackType,
        confidence: float,
    ) -> str:
        """Determine remediation action based on attack type and confidence.

        Args:
            attack_type: Classified attack type.
            confidence: Classification confidence.

        Returns:
            Action: quarantine, remove, flag, or monitor.
        """
        if confidence >= 0.9:
            return "remove"
        if confidence >= 0.7:
            return "quarantine"
        if confidence >= 0.4:
            return "flag"
        return "monitor"

    def _apply_action(
        self,
        entry: dict[str, Any],
        action: str,
    ) -> dict[str, Any] | None:
        """Apply remediation action to entry.

        Args:
            entry: Memory entry.
            action: Remediation action.

        Returns:
            Remediated entry or None if removed.
        """
        if action == "remove":
            return None

        if action == "quarantine":
            quarantined = dict(entry)
            quarantined["_memmark_quarantined"] = True
            quarantined["_memmark_action"] = "quarantine"
            return quarantined

        if action == "flag":
            flagged = dict(entry)
            flagged["_memmark_flagged"] = True
            flagged["_memmark_action"] = "flag"
            return flagged

        return entry

    def batch_remediate(
        self,
        entries: list[dict[str, Any]],
        classifications: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Remediate multiple entries.

        Args:
            entries: Memory entries.
            classifications: Classification results.

        Returns:
            List of remediation results.
        """
        results = []
        for entry, classification in zip(entries, classifications, strict=False):
            results.append(self.remediate(entry, classification))
        return results

    def generate_remediation_report(
        self,
        remediation_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate summary report of remediation actions.

        Args:
            remediation_results: Results from remediate() or batch_remediate().

        Returns:
            Summary report.
        """
        action_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}

        for result in remediation_results:
            action = result.get("action", "unknown")
            attack_type = result.get("attack_type", "unknown")
            action_counts[action] = action_counts.get(action, 0) + 1
            type_counts[attack_type] = type_counts.get(attack_type, 0) + 1

        return {
            "total_entries_processed": len(remediation_results),
            "actions_taken": action_counts,
            "attack_types": type_counts,
            "entries_removed": action_counts.get("remove", 0),
            "entries_quarantined": action_counts.get("quarantine", 0),
            "entries_flagged": action_counts.get("flag", 0),
            "entries_monitored": action_counts.get("monitor", 0),
        }
