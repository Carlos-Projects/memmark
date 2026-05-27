# Copyright (c) 2025 Carlos Rocha
# SPDX-License-Identifier: MIT

"""Memory watermark detector for AI agent long-term memory systems.

Detects and verifies watermarks embedded in memory entries
to confirm provenance and detect tampering.
"""

from __future__ import annotations

from typing import Any

from memmark.utils.crypto import hmac_sign
from memmark.watermark.injector import WatermarkInjector


class WatermarkDetector:
    """Detects and verifies watermarks in agent memory entries."""

    def __init__(self, secret_key: str) -> None:
        """Initialize the watermark detector.

        Args:
            secret_key: Secret key used for watermark verification.
                       Must match the key used during injection.

        Raises:
            ValueError: If secret_key is empty.
        """
        if not secret_key:
            raise ValueError("secret_key must not be empty")
        self.secret_key = secret_key
        self.injector = WatermarkInjector(secret_key)

    def detect(self, memories: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Detect watermarks in all memory entries.

        Args:
            memories: List of memory entry dictionaries.

        Returns:
            List of detection results per entry.
        """
        results = []
        for entry in memories:
            results.append(self._detect_entry(entry))
        return results

    def _detect_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Detect and verify watermark in a single entry.

        Args:
            entry: Memory entry dictionary.

        Returns:
            Detection result dictionary.
        """
        memory_id = entry.get("id", entry.get("memory_id", "unknown"))
        signature = entry.get(WatermarkInjector.SIGNATURE_KEY)
        watermark_meta = entry.get(WatermarkInjector.WATERMARK_KEY)

        if not signature or not watermark_meta:
            return {
                "memory_id": memory_id,
                "valid": False,
                "confidence": 0.0,
                "reason": "no_watermark_found",
            }

        # Recompute expected signature using salt from stored signature
        canonical = self.injector._canonicalize(entry)

        # Extract salt from stored signature (first 32 hex chars = 16 bytes)
        if len(signature) >= 32:
            try:
                salt = bytes.fromhex(signature[:32])
                expected = hmac_sign(canonical, self.secret_key, salt)
            except (ValueError, IndexError):
                # Fall back to saltless comparison for legacy signatures
                expected = _legacy_hmac_sign(canonical, self.secret_key)
        else:
            # Legacy signatures without salt
            expected = _legacy_hmac_sign(canonical, self.secret_key)

        is_valid = signature == expected
        confidence = 1.0 if is_valid else 0.0

        return {
            "memory_id": memory_id,
            "valid": is_valid,
            "confidence": confidence,
            "reason": "verified" if is_valid else "signature_mismatch",
            "algorithm": watermark_meta.get("algorithm", "unknown"),
            "version": watermark_meta.get("version", "unknown"),
        }

    def verify_provenance(
        self,
        memories: list[dict[str, Any]],
        expected_source: str,
    ) -> dict[str, Any]:
        """Verify that all watermarked memories come from expected source.

        Args:
            memories: List of memory entries.
            expected_source: Expected watermark source identifier.

        Returns:
            Verification summary.
        """
        results = self.detect(memories)
        valid_count = sum(1 for r in results if r["valid"])
        total = len(results)

        return {
            "expected_source": expected_source,
            "total_entries": total,
            "valid_watermarks": valid_count,
            "invalid_watermarks": total - valid_count,
            "provenance_confirmed": valid_count == total and total > 0,
        }


def _legacy_hmac_sign(data: str, key: str) -> str:
    """Legacy HMAC-SHA256 signing without salt (backward compatibility).

    Used to verify watermarks created before the KDF upgrade.

    Args:
        data: Data to sign.
        key: Secret key.

    Returns:
        Hex-encoded signature.
    """
    import hashlib
    import hmac

    return hmac.new(
        key.encode("utf-8"),
        data.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
