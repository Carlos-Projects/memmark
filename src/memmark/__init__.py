# Copyright (c) 2025 Carlos Rocha
# SPDX-License-Identifier: MIT

"""MemMark — Memory integrity toolkit for AI agent long-term memory."""

from memmark.integrity.diff import MemoryDiff
from memmark.integrity.forensics import MemoryForensics
from memmark.integrity.manifest import IntegrityManifest
from memmark.poisoning.classifier import AttackType, PoisoningClassifier
from memmark.poisoning.detector import PoisoningDetector
from memmark.policy.generator import MCPGuardPolicy
from memmark.provenance.graph import ProvenanceGraph
from memmark.provenance.tracker import ProvenanceRecord, ProvenanceTracker
from memmark.provenance.verifier import ProvenanceVerifier
from memmark.reporters.console import ConsoleReporter
from memmark.reporters.html import HtmlReporter
from memmark.reporters.json import JsonReporter
from memmark.scanner import (
    Finding,
    FindingType,
    MemoryEntry,
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
    sha256_file,
    sha256_hash,
)
from memmark.utils.logging import configure_logging, correlation_id, get_logger
from memmark.watermark.detector import WatermarkDetector
from memmark.watermark.injector import WatermarkInjector
from memmark.watermark.robustness import WatermarkRobustnessTester

__all__ = [
    "AttackType",
    "configure_logging",
    "ConsoleReporter",
    "correlation_id",
    "Finding",
    "FindingType",
    "get_logger",
    "HtmlReporter",
    "IntegrityManifest",
    "JsonReporter",
    "MCPGuardPolicy",
    "MemoryDiff",
    "MemoryEntry",
    "MemoryForensics",
    "MemoryScanner",
    "PoisoningClassifier",
    "PoisoningDetector",
    "ProvenanceGraph",
    "ProvenanceRecord",
    "ProvenanceTracker",
    "ProvenanceVerifier",
    "ScanResult",
    "Severity",
    "WatermarkDetector",
    "WatermarkInjector",
    "WatermarkRobustnessTester",
    "hash_memory_entry",
    "hash_memory_state",
    "hmac_sign",
    "hmac_verify",
    "run_full_scan",
    "sha256_file",
    "sha256_hash",
]

__version__ = "0.1.0"
__author__ = "Carlos Rocha"
__email__ = "carlos@syntho.dev"
