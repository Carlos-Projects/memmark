"""Cryptographic utility functions for memory integrity verification."""

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any


def sha256_hash(data: str | bytes) -> str:
    """Compute SHA-256 hash of the given data.

    Args:
        data: String or bytes to hash.

    Returns:
        Hexadecimal digest string.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_file(file_path: str | Path) -> str:
    """Compute SHA-256 hash of a file.

    Args:
        file_path: Path to the file.

    Returns:
        Hexadecimal digest string.
    """
    h = hashlib.sha256()
    path = Path(file_path)
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def hmac_sign(data: str, key: str) -> str:
    """Create HMAC-SHA256 signature.

    Args:
        data: Data to sign.
        key: Secret key.

    Returns:
        Hexadecimal signature string.
    """
    return hmac.new(
        key.encode("utf-8"),
        data.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def hmac_verify(data: str, key: str, signature: str) -> bool:
    """Verify HMAC-SHA256 signature.

    Args:
        data: Original data.
        key: Secret key.
        signature: Signature to verify.

    Returns:
        True if signature is valid.
    """
    expected = hmac_sign(data, key)
    return hmac.compare_digest(expected, signature)


def hash_memory_entry(entry: dict[str, Any]) -> str:
    """Compute deterministic hash of a memory entry.

    Args:
        entry: Memory entry dictionary.

    Returns:
        SHA-256 hex digest.
    """
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return sha256_hash(canonical)


def hash_memory_state(memories: list[dict[str, Any]]) -> str:
    """Compute deterministic hash of an entire memory state.

    Args:
        memories: List of memory entry dictionaries.

    Returns:
        SHA-256 hex digest.
    """
    canonical = json.dumps(memories, sort_keys=True, separators=(",", ":"))
    return sha256_hash(canonical)
