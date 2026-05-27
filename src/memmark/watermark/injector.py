# Copyright (c) 2025 Carlos-Projects
# SPDX-License-Identifier: MIT

"""Memory watermark injector for AI agent long-term memory systems.

Implements state-evolution attribution watermarking based on
arXiv:2605.25073 (Zhang et al.) — MemMark.

SECURITY NOTE: A secret_key MUST be provided. There is no default
for security reasons — using a default key would make watermarks
trivially forgeable.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from memmark.utils.crypto import hmac_sign


class WatermarkInjector:
    """Injects imperceptible watermarks into agent memory entries.

    Watermarks are embedded as cryptographic signatures attached to
    each memory entry, enabling provenance tracking and tamper detection.
    """

    WATERMARK_KEY = "_memmark_wm"
    SIGNATURE_KEY = "_memmark_sig"

    def __init__(self, secret_key: str) -> None:
        """Initialize the watermark injector.

        Args:
            secret_key: Secret key for HMAC watermark generation.
                       Must be a non-empty string unique to your deployment.

        Raises:
            ValueError: If secret_key is empty.
        """
        if not secret_key:
            raise ValueError("secret_key must not be empty")
        self.secret_key = secret_key

    def inject(self, memories: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Inject watermarks into all memory entries.

        Args:
            memories: List of memory entry dictionaries.

        Returns:
            New list with watermarked entries.
        """
        watermarked = []
        for entry in memories:
            if not isinstance(entry, dict):
                watermarked.append(entry)
                continue
            watermarked.append(self._inject_entry(entry))
        return watermarked

    def _inject_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Inject watermark into a single memory entry.

        Args:
            entry: Memory entry dictionary.

        Returns:
            Copy of entry with watermark metadata.
        """
        watermarked = dict(entry)

        # Create canonical representation excluding watermark fields
        canonical = self._canonicalize(entry)

        # Generate watermark signature
        signature = hmac_sign(canonical, self.secret_key)

        # Embed watermark metadata
        watermarked[self.WATERMARK_KEY] = {
            "version": "1.0",
            "algorithm": "hmac-sha256",
        }
        watermarked[self.SIGNATURE_KEY] = signature

        return watermarked

    def _canonicalize(self, entry: dict[str, Any]) -> str:
        """Create canonical string representation of entry.

        Args:
            entry: Memory entry dictionary.

        Returns:
            Canonical JSON string.
        """
        filtered = {
            k: v
            for k, v in entry.items()
            if k not in (self.WATERMARK_KEY, self.SIGNATURE_KEY)
        }
        return json.dumps(filtered, sort_keys=True, separators=(",", ":"))

    def generate_watermark_token(self, content: str) -> str:
        """Generate a standalone watermark token for content.

        Args:
            content: Text content to watermark.

        Returns:
        Hex watermark token.
        """
        return hashlib.sha256(
            f"{self.secret_key}:{content}".encode(),
        ).hexdigest()[:16]
