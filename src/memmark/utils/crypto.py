# Copyright (c) 2025 Carlos-Projects
# SPDX-License-Identifier: MIT

"""Cryptographic utility functions for memory integrity verification."""

import hashlib
import hmac
import json
import os
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


def derive_key(secret_key: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive a strong HMAC key using PBKDF2-SHA256.

    Args:
        secret_key: User-provided secret key.
        salt: Optional salt (auto-generated if None).

    Returns:
        Tuple of (derived_key, salt).
    """
    if salt is None:
        salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        secret_key.encode("utf-8"),
        salt,
        iterations=100000,
        dklen=32,
    )
    return derived, salt


def hmac_sign(data: str, key: str, salt: bytes | None = None) -> str:
    """Create HMAC-SHA256 signature with key derivation.

    Uses PBKDF2 key derivation to strengthen the secret key
    before HMAC computation. The salt is embedded in the output
    for verification.

    Args:
        data: Data to sign.
        key: Secret key (will be derived via PBKDF2).
        salt: Optional salt (auto-generated if None).

    Returns:
        Hex-encoded signature string with embedded salt.
    """
    derived_key, used_salt = derive_key(key, salt)
    signature = hmac.new(
        derived_key,
        data.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    # Embed salt in output: first 32 hex chars = salt, rest = sig
    return used_salt.hex() + signature


def hmac_verify(data: str, key: str, signature: str) -> bool:
    """Verify HMAC-SHA256 signature.

    Extracts the salt from the signature, re-derives the key,
    and compares using constant-time comparison.

    Args:
        data: Original data.
        key: Secret key.
        signature: Signature to verify (includes embedded salt).

    Returns:
        True if signature is valid.
    """
    if len(signature) < 32:
        return False
    salt_hex = signature[:32]
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    expected = hmac_sign(data, key, salt)
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
