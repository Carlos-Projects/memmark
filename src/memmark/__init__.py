# Copyright (c) 2025 Carlos-Projects
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
    PipelineContext,
    ScanPipeline,
    ScanResult,
    ScanStage,
    Severity,
    run_full_scan,
)
from memmark.store import FileMemoryStore, InMemoryMemoryStore, MemoryStore
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
    "FileMemoryStore",
    "Finding",
    "FindingType",
    "get_logger",
    "HtmlReporter",
    "InMemoryMemoryStore",
    "IntegrityManifest",
    "JsonReporter",
    "MCPGuardPolicy",
    "MemoryDiff",
    "MemoryEntry",
    "MemoryForensics",
    "MemoryScanner",
    "MemoryStore",
    "PipelineContext",
    "PoisoningClassifier",
    "PoisoningDetector",
    "ProvenanceGraph",
    "ProvenanceRecord",
    "ProvenanceTracker",
    "ProvenanceVerifier",
    "ScanPipeline",
    "ScanResult",
    "ScanStage",
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
__author__ = "Carlos-Projects"
__email__ = "Carlos@AIAgentObservatory.org"
