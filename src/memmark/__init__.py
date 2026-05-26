"""MemMark — Memory integrity toolkit for AI agent long-term memory."""

from memmark.scanner import (
    Finding,
    FindingType,
    MemoryScanner,
    ScanResult,
    Severity,
    run_full_scan,
)
from memmark.utils.crypto import (
    hash_memory_entry,
    hash_memory_state,
    hmac_sign,
    hmac_verify,
    sha256_hash,
)

__all__ = [
    "Finding",
    "FindingType",
    "MemoryScanner",
    "ScanResult",
    "Severity",
    "hash_memory_entry",
    "hash_memory_state",
    "hmac_sign",
    "hmac_verify",
    "run_full_scan",
    "sha256_hash",
]

__version__ = "0.1.0"
__author__ = "Carlos Rocha"
__email__ = "carlos@syntho.dev"
