"""Watermark robustness testing for AI agent memory systems.

Tests watermark resilience against common transformations:
paraphrasing, truncation, reordering, and partial deletion.
Based on arXiv:2605.25717 (SAMark) — paragraph-level paraphrase robustness.
"""

from __future__ import annotations

import random
from typing import Any

from memmark.watermark.detector import WatermarkDetector
from memmark.watermark.injector import WatermarkInjector


class WatermarkRobustnessTester:
    """Tests watermark robustness against memory transformations."""

    def __init__(self, secret_key: str = "default-memmark-key") -> None:
        """Initialize robustness tester.

        Args:
            secret_key: Secret key for watermark operations.
        """
        self.injector = WatermarkInjector(secret_key)
        self.detector = WatermarkDetector(secret_key)

    def test_robustness(
        self,
        memories: list[dict[str, Any]],
        transformations: list[str] | None = None,
    ) -> dict[str, Any]:
        """Test watermark robustness against transformations.

        Args:
            memories: Original memory entries.
            transformations: List of transformation names to test.

        Returns:
            Robustness test results.
        """
        if transformations is None:
            transformations = ["reorder", "truncate", "paraphrase_simulated"]

        watermarked = self.injector.inject(memories)
        baseline = self.detector.detect(watermarked)
        baseline_valid = sum(1 for r in baseline if r["valid"])

        results: dict[str, Any] = {
            "baseline_valid": baseline_valid,
            "baseline_total": len(baseline),
            "transformations": {},
        }

        for transform in transformations:
            transformed = self._apply_transform(watermarked, transform)
            detection = self.detector.detect(transformed)
            valid_after = sum(1 for r in detection if r["valid"])

            results["transformations"][transform] = {
                "valid_before": baseline_valid,
                "valid_after": valid_after,
                "retention_rate": valid_after / baseline_valid if baseline_valid > 0 else 0.0,
            }

        return results

    def _apply_transform(
        self,
        memories: list[dict[str, Any]],
        transform: str,
    ) -> list[dict[str, Any]]:
        """Apply a transformation to watermarked memories.

        Args:
            memories: Watermarked memory entries.
            transform: Transformation name.

        Returns:
            Transformed memory entries.
        """
        if transform == "reorder":
            shuffled = list(memories)
            random.shuffle(shuffled)
            return shuffled

        if transform == "truncate":
            # Remove watermark from last entry
            if memories:
                truncated = [dict(m) for m in memories]
                last = truncated[-1]
                last.pop(WatermarkInjector.SIGNATURE_KEY, None)
                last.pop(WatermarkInjector.WATERMARK_KEY, None)
                return truncated
            return memories

        if transform == "paraphrase_simulated":
            # Simulate paraphrasing by modifying content field text
            transformed = []
            for entry in memories:
                new_entry = dict(entry)
                if "content" in new_entry and isinstance(new_entry["content"], str):
                    words = new_entry["content"].split()
                    if len(words) > 4:
                        # Swap two adjacent words to simulate paraphrase
                        idx = random.randint(0, len(words) - 2)
                        words[idx], words[idx + 1] = words[idx + 1], words[idx]
                        new_entry["content"] = " ".join(words)
                transformed.append(new_entry)
            return transformed

        return memories

    def compute_robustness_score(
        self,
        robustness_results: dict[str, Any],
    ) -> float:
        """Compute overall robustness score from test results.

        Args:
            robustness_results: Results from test_robustness().

        Returns:
            Score between 0.0 (no robustness) and 1.0 (fully robust).
        """
        transforms = robustness_results.get("transformations", {})
        if not transforms:
            return 0.0

        rates = [t["retention_rate"] for t in transforms.values()]
        return sum(rates) / len(rates)
