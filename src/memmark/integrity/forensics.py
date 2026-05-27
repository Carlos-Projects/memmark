# Copyright (c) 2025 Carlos Rocha
# SPDX-License-Identifier: MIT

"""Memory forensics for AI agent memory systems.

Analyzes memory patterns to detect behavioral anomalies,
temporal inconsistencies, and suspicious access patterns.
"""

from __future__ import annotations

import statistics
from datetime import datetime
from typing import Any


class MemoryForensics:
    """Forensic analysis of agent memory patterns."""

    def analyze(self, memories: list[dict[str, Any]]) -> dict[str, Any]:
        """Perform comprehensive forensic analysis on memory.

        Args:
            memories: List of memory entry dictionaries.

        Returns:
            Forensic analysis results.
        """
        return {
            "temporal_analysis": self._analyze_temporal(memories),
            "content_analysis": self._analyze_content(memories),
            "source_analysis": self._analyze_sources(memories),
            "anomaly_score": self._compute_anomaly_score(memories),
        }

    def _analyze_temporal(self, memories: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze temporal patterns in memory entries.

        Args:
            memories: Memory entries.

        Returns:
            Temporal analysis results.
        """
        timestamps: list[datetime] = []
        for entry in memories:
            ts = entry.get("timestamp") or entry.get("created_at")
            if ts:
                try:
                    if isinstance(ts, str):
                        timestamps.append(datetime.fromisoformat(ts))
                    elif isinstance(ts, (int, float)):
                        timestamps.append(datetime.fromtimestamp(ts))
                except (ValueError, OSError):
                    pass

        if len(timestamps) < 2:
            return {
                "entry_count": len(timestamps),
                "has_anomaly": False,
                "reason": "insufficient_data",
            }

        timestamps.sort()
        intervals = [
            (timestamps[i + 1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]

        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0

        # Detect burst patterns (many entries in short time)
        burst_threshold = max(mean_interval - 2 * std_interval, 1)
        bursts = sum(1 for i in intervals if i < burst_threshold)

        # Detect gaps (unusually long intervals)
        gap_threshold = mean_interval + 3 * std_interval
        gaps = sum(1 for i in intervals if i > gap_threshold)

        has_anomaly = bursts > len(timestamps) * 0.3 or gaps > 2

        return {
            "entry_count": len(timestamps),
            "time_span_seconds": (timestamps[-1] - timestamps[0]).total_seconds(),
            "mean_interval_seconds": mean_interval,
            "std_interval_seconds": std_interval,
            "burst_count": bursts,
            "gap_count": gaps,
            "has_anomaly": has_anomaly,
        }

    def _analyze_content(self, memories: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze content patterns for anomalies.

        Args:
            memories: Memory entries.

        Returns:
            Content analysis results.
        """
        content_lengths = []
        for entry in memories:
            content = entry.get("content", entry.get("text", ""))
            if isinstance(content, str):
                content_lengths.append(len(content))

        if not content_lengths:
            return {
                "analyzed": 0,
                "has_anomaly": False,
            }

        mean_length = statistics.mean(content_lengths)
        std_length = (
            statistics.stdev(content_lengths) if len(content_lengths) > 1 else 0
        )

        # Detect outliers
        outlier_threshold = mean_length + 3 * std_length
        outliers = sum(1 for length in content_lengths if length > outlier_threshold)

        # Detect uniform content (possible automated injection)
        unique_lengths = len(set(content_lengths))
        uniformity = 1.0 - (unique_lengths / max(len(content_lengths), 1))

        has_anomaly = outliers > 2 or uniformity > 0.8

        return {
            "analyzed": len(content_lengths),
            "mean_length": mean_length,
            "std_length": std_length,
            "outlier_count": outliers,
            "uniformity_score": uniformity,
            "has_anomaly": has_anomaly,
        }

    def _analyze_sources(self, memories: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze source distribution for anomalies.

        Args:
            memories: Memory entries.

        Returns:
            Source analysis results.
        """
        sources: dict[str, int] = {}
        for entry in memories:
            source = entry.get("source", entry.get("origin", "unknown"))
            sources[source] = sources.get(source, 0) + 1

        total = len(memories)
        source_distribution = {
            src: {"count": cnt, "percentage": cnt / total if total > 0 else 0}
            for src, cnt in sources.items()
        }

        # Detect single-source dominance (possible injection campaign)
        max_percentage = max(
            (cnt / total for cnt in sources.values()),
            default=0,
        )

        return {
            "unique_sources": len(sources),
            "distribution": source_distribution,
            "max_source_percentage": max_percentage,
            "has_anomaly": max_percentage > 0.9 and total > 10,
        }

    def _compute_anomaly_score(self, memories: list[dict[str, Any]]) -> float:
        """Compute overall anomaly score for the memory set.

        Args:
            memories: Memory entries.

        Returns:
            Score between 0.0 (normal) and 1.0 (highly anomalous).
        """
        temporal = self._analyze_temporal(memories)
        content = self._analyze_content(memories)
        sources = self._analyze_sources(memories)

        anomaly_count = sum(
            [
                temporal.get("has_anomaly", False),
                content.get("has_anomaly", False),
                sources.get("has_anomaly", False),
            ]
        )

        # Base score from anomaly count
        score: float = anomaly_count / 3.0

        # Boost for high uniformity (strong injection indicator)
        uniformity = content.get("uniformity_score", 0)
        if uniformity > 0.8:
            score = min(score + 0.2, 1.0)

        # Boost for burst patterns
        burst_count = temporal.get("burst_count", 0)
        entry_count = temporal.get("entry_count", 1)
        if entry_count > 0 and burst_count / entry_count > 0.5:
            score = min(score + 0.15, 1.0)

        return round(score, 3)
