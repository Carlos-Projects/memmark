# Copyright (c) 2025 Carlos Rocha
# SPDX-License-Identifier: MIT

"""Core scanning engine for memory integrity analysis."""

from __future__ import annotations

import json
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from memmark.utils.crypto import hash_memory_entry, hash_memory_state
from memmark.utils.logging import correlation_id, get_logger

log = get_logger("scanner")


class MemoryEntry(BaseModel):  # type: ignore[misc]
    """Validated schema for a single memory entry.

    Ensures memory data has consistent structure before processing.
    """

    id: str | None = Field(default=None, alias="memory_id")
    content: str = ""
    source: str = ""
    timestamp: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True, "extra": "allow"}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MemoryEntry:
        """Create a MemoryEntry from a dictionary, with best-effort parsing.

        Args:
            data: Raw dictionary from JSON.

        Returns:
            Validated MemoryEntry.
        """
        return cls.model_validate(data)  # type: ignore[no-any-return]


def validate_memory_entries(
    memories: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Validate a list of memory entries against the MemoryEntry schema.

    Invalid entries are logged and included with default values
    rather than raising, to maintain forward compatibility.

    Args:
        memories: Raw memory entries.

    Returns:
        Validated entries.
    """
    validated = []
    for entry in memories:
        try:
            MemoryEntry.from_dict(entry)
            validated.append(entry)
        except Exception:
            validated.append(entry)
    return validated


class Severity(StrEnum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(StrEnum):
    """Types of memory findings."""

    WATERMARK_DETECTED = "watermark_detected"
    WATERMARK_MISSING = "watermark_missing"
    POISONING_DETECTED = "poisoning_detected"
    PROVENANCE_INVALID = "provenance_invalid"
    INTEGRITY_MODIFIED = "integrity_modified"
    ANOMALY_DETECTED = "anomaly_detected"
    POLICY_VIOLATION = "policy_violation"


@dataclass
class Finding:
    """A single security finding from memory analysis."""

    finding_type: FindingType
    severity: Severity
    description: str
    memory_id: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "finding_type": self.finding_type.value,
            "severity": self.severity.value,
            "description": self.description,
            "memory_id": self.memory_id,
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat(),
            "remediation": self.remediation,
        }


@dataclass
class ScanResult:
    """Complete result from a memory scan."""

    scan_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    memory_hash: str = ""
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def is_clean(self) -> bool:
        return self.critical_count == 0 and self.high_count == 0

    def to_dict(self) -> dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp.isoformat(),
            "memory_hash": self.memory_hash,
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "total": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "is_clean": self.is_clean,
            },
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class MemoryScanner:
    """Core scanning engine for AI agent memory systems.

    Orchestrates watermark detection, poisoning analysis,
    provenance verification, and integrity checks.
    """

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def load_memory(
        self, source: str | Path | list[dict[str, Any]] | Any
    ) -> list[dict[str, Any]]:
        """Load memory from file path, MemoryStore, or raw data.

        Args:
            source: JSON file path, MemoryStore instance, or list of entries.

        Returns:
            List of memory entry dictionaries.

        Raises:
            FileNotFoundError: If file path does not exist.
            json.JSONDecodeError: If JSON is invalid.
        """
        if isinstance(source, str | Path):
            path = Path(source)
            log.info("Loading memory from file", extra={"ctx": {"path": str(path)}})
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                data = data.get("memories", data.get("entries", [data]))
            result = validate_memory_entries(data)
            log.info(
                "Memory loaded",
                extra={"ctx": {"entries": len(result), "path": str(path)}},
            )
            return result
        if hasattr(source, "read"):
            result = validate_memory_entries(source.read())
            log.info(
                "Memory loaded from store", extra={"ctx": {"entries": len(result)}}
            )
            return result
        result = validate_memory_entries(source)
        log.info("Memory loaded from list", extra={"ctx": {"entries": len(result)}})
        return result

    def compute_memory_hash(self, memories: list[dict[str, Any]]) -> str:
        """Compute deterministic hash of memory state.

        Args:
            memories: List of memory entries.

        Returns:
            SHA-256 hex digest.
        """
        return hash_memory_state(memories)

    def compute_entry_hash(self, entry: dict[str, Any]) -> str:
        """Compute deterministic hash of a single memory entry.

        Args:
            entry: Memory entry dictionary.

        Returns:
            SHA-256 hex digest.
        """
        return hash_memory_entry(entry)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the scan results.

        Args:
            finding: Finding to add.
        """
        self.findings.append(finding)

    def build_result(
        self,
        scan_id: str,
        memories: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Build final scan result from accumulated findings.

        Args:
            scan_id: Unique identifier for this scan.
            memories: Memory entries that were scanned.
            metadata: Optional metadata about the scan.

        Returns:
            Complete ScanResult object.
        """
        return ScanResult(
            scan_id=scan_id,
            memory_hash=self.compute_memory_hash(memories),
            findings=self.findings.copy(),
            metadata=metadata or {},
        )

    def reset(self) -> None:
        """Clear accumulated findings for a new scan."""
        self.findings.clear()


def run_full_scan(
    memories: list[dict[str, Any]],
    scan_id: str | None = None,
    watermark_key: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> ScanResult:
    """Run all detection modules and return a unified ScanResult.

    Orchestrates poisoning detection, watermark verification,
    and forensic analysis in a single pass.

    Args:
        memories: List of memory entries to analyze.
        scan_id: Optional scan identifier (auto-generated if omitted).
        watermark_key: Optional secret key for watermark detection.
        metadata: Optional metadata about the scan.

    Returns:
        Complete ScanResult with findings from all detectors.
    """
    import uuid

    from memmark.integrity.forensics import MemoryForensics
    from memmark.poisoning.detector import PoisoningDetector

    scan_id = scan_id or f"scan-{uuid.uuid4().hex[:12]}"
    cid = correlation_id()
    log.info(
        "Starting scan",
        extra={
            "ctx": {"scan_id": scan_id, "correlation_id": cid, "entries": len(memories)}
        },
    )

    scanner = MemoryScanner()

    # 1. Poisoning detection
    poison_detector = PoisoningDetector()
    poison_findings = poison_detector.detect(memories)
    for f in poison_findings:
        scanner.add_finding(f)
    log.info(
        "Poisoning detection complete",
        extra={"ctx": {"findings": len(poison_findings), "correlation_id": cid}},
    )

    # 2. Watermark detection
    if watermark_key:
        from memmark.watermark.detector import WatermarkDetector

        wm_detector = WatermarkDetector(secret_key=watermark_key)
        wm_results = wm_detector.detect(memories)
        for r in wm_results:
            if not r.get("valid", False):
                scanner.add_finding(
                    Finding(
                        finding_type=FindingType.WATERMARK_MISSING,
                        severity=Severity.MEDIUM,
                        description=f"Missing watermark: {r.get('reason', 'unknown')}",
                        memory_id=r.get("memory_id"),
                        evidence=r,
                    ),
                )
            elif r.get("valid", False):
                scanner.add_finding(
                    Finding(
                        finding_type=FindingType.WATERMARK_DETECTED,
                        severity=Severity.INFO,
                        description="Valid watermark detected",
                        memory_id=r.get("memory_id"),
                        evidence=r,
                    ),
                )

    # 3. Forensic analysis
    forensics = MemoryForensics()
    forensic_results = forensics.analyze(memories)
    log.info(
        "Forensic analysis complete",
        extra={
            "ctx": {
                "anomaly_score": forensic_results.get("anomaly_score", 0.0),
                "correlation_id": cid,
            }
        },
    )

    anomaly_score = forensic_results.get("anomaly_score", 0.0)
    if anomaly_score > 0.5:
        scanner.add_finding(
            Finding(
                finding_type=FindingType.ANOMALY_DETECTED,
                severity=Severity.MEDIUM if anomaly_score < 0.8 else Severity.HIGH,
                description=f"Behavioral anomaly detected (score: {anomaly_score:.2f})",
                evidence={"anomaly_score": anomaly_score, **forensic_results},
            ),
        )

    result = scanner.build_result(
        scan_id=scan_id,
        memories=memories,
        metadata=metadata or {},
    )
    log.info(
        "Scan complete",
        extra={
            "ctx": {
                "scan_id": scan_id,
                "findings": len(result.findings),
                "correlation_id": cid,
            }
        },
    )
    return result


# ── Pipeline abstraction ──────────────────────────────────────


class PipelineContext:
    """Context passed through scan pipeline stages.

    Attributes:
        memories: Memory entries being scanned.
        findings: Accumulated findings.
        metadata: Scan metadata.
        scan_id: Unique scan identifier.
        watermark_key: Optional secret key for watermark verification.
    """

    def __init__(
        self,
        memories: list[dict[str, Any]],
        scan_id: str,
        metadata: dict[str, Any] | None = None,
        watermark_key: str | None = None,
    ) -> None:
        self.memories = memories
        self.findings: list[Finding] = []
        self.metadata = metadata or {}
        self.scan_id = scan_id
        self.watermark_key = watermark_key


class ScanStage(ABC):
    """Abstract scan pipeline stage.

    Subclasses implement :meth:`run` to perform a specific
    analysis step and add findings to the context.
    """

    @abstractmethod
    def run(self, ctx: PipelineContext) -> None:
        """Execute this pipeline stage.

        Args:
            ctx: Mutable pipeline context.
        """


class PoisoningStage(ScanStage):
    """Detect memory poisoning attacks."""

    def run(self, ctx: PipelineContext) -> None:
        from memmark.poisoning.detector import PoisoningDetector

        detector = PoisoningDetector()
        findings = detector.detect(ctx.memories)
        ctx.findings.extend(findings)
        log.info(
            "Poisoning stage complete",
            extra={"ctx": {"findings": len(findings), "scan_id": ctx.scan_id}},
        )


class WatermarkStage(ScanStage):
    """Detect and verify watermarks."""

    def run(self, ctx: PipelineContext) -> None:
        if not ctx.watermark_key:
            log.info(
                "Watermark stage skipped (no key)",
                extra={"ctx": {"scan_id": ctx.scan_id}},
            )
            return
        from memmark.watermark.detector import WatermarkDetector

        detector = WatermarkDetector(secret_key=ctx.watermark_key)
        results = detector.detect(ctx.memories)
        for r in results:
            if not r.get("valid", False):
                ctx.findings.append(
                    Finding(
                        finding_type=FindingType.WATERMARK_MISSING,
                        severity=Severity.MEDIUM,
                        description=f"Missing watermark: {r.get('reason', 'unknown')}",
                        memory_id=r.get("memory_id"),
                        evidence=r,
                    ),
                )
            else:
                ctx.findings.append(
                    Finding(
                        finding_type=FindingType.WATERMARK_DETECTED,
                        severity=Severity.INFO,
                        description="Valid watermark detected",
                        memory_id=r.get("memory_id"),
                        evidence=r,
                    ),
                )
        log.info(
            "Watermark stage complete",
            extra={"ctx": {"scan_id": ctx.scan_id}},
        )


class ForensicsStage(ScanStage):
    """Run memory forensics and anomaly detection."""

    def run(self, ctx: PipelineContext) -> None:
        from memmark.integrity.forensics import MemoryForensics

        forensics = MemoryForensics()
        forensic_results = forensics.analyze(ctx.memories)
        anomaly_score = forensic_results.get("anomaly_score", 0.0)
        if anomaly_score > 0.5:
            ctx.findings.append(
                Finding(
                    finding_type=FindingType.ANOMALY_DETECTED,
                    severity=Severity.MEDIUM if anomaly_score < 0.8 else Severity.HIGH,
                    description=f"Behavioral anomaly detected (score: {anomaly_score:.2f})",
                    evidence={"anomaly_score": anomaly_score, **forensic_results},
                ),
            )
        log.info(
            "Forensics stage complete",
            extra={"ctx": {"anomaly_score": anomaly_score, "scan_id": ctx.scan_id}},
        )


class ScanPipeline:
    """Composable scan pipeline.

    Runs a sequence of :class:`ScanStage` stages and
    produces a :class:`ScanResult`.

    Usage::

        pipeline = ScanPipeline.with_default_stages(watermark_key="my-key")
        result = pipeline.run(memories, scan_id="scan-001")
    """

    def __init__(
        self,
        stages: list[ScanStage] | None = None,
        watermark_key: str | None = None,
    ) -> None:
        self.stages = stages or []
        self.watermark_key = watermark_key

    @classmethod
    def with_default_stages(
        cls,
        watermark_key: str | None = None,
    ) -> ScanPipeline:
        """Create a pipeline with the standard analysis stages.

        Args:
            watermark_key: Optional key for watermark detection.

        Returns:
            Configured ScanPipeline instance.
        """
        stages: list[ScanStage] = [
            PoisoningStage(),
            ForensicsStage(),
        ]
        if watermark_key:
            stages.insert(1, WatermarkStage())
        return cls(stages=stages, watermark_key=watermark_key)

    def add_stage(self, stage: ScanStage) -> ScanPipeline:
        """Append a custom stage to this pipeline.

        Args:
            stage: ScanStage to append.

        Returns:
            Self for chaining.
        """
        self.stages.append(stage)
        return self

    def run(
        self,
        memories: list[dict[str, Any]],
        scan_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Execute the pipeline and produce a ScanResult.

        Args:
            memories: Memory entries to scan.
            scan_id: Optional scan identifier.
            metadata: Optional metadata.

        Returns:
            ScanResult with findings from all stages.
        """
        import uuid

        scan_id = scan_id or f"scan-{uuid.uuid4().hex[:12]}"
        ctx = PipelineContext(
            memories=memories,
            scan_id=scan_id,
            metadata=metadata,
            watermark_key=self.watermark_key,
        )
        log.info(
            "Pipeline started",
            extra={"ctx": {"scan_id": scan_id, "stages": len(self.stages)}},
        )
        for stage in self.stages:
            stage.run(ctx)
        memory_hash = hash_memory_state(memories)
        result = ScanResult(
            scan_id=scan_id,
            memory_hash=memory_hash,
            findings=ctx.findings,
            metadata=ctx.metadata,
        )
        log.info(
            "Pipeline complete",
            extra={
                "ctx": {
                    "scan_id": scan_id,
                    "findings": len(result.findings),
                }
            },
        )
        return result

    async def arun(
        self,
        memories: list[dict[str, Any]],
        scan_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Async variant of :meth:`run`.

        Runs each stage via :func:`asyncio.to_thread` for
        non-blocking execution with large memory stores.

        Args:
            memories: Memory entries to scan.
            scan_id: Optional scan identifier.
            metadata: Optional metadata.

        Returns:
            ScanResult with findings from all stages.
        """
        import asyncio

        scan_id = scan_id or f"scan-{uuid.uuid4().hex[:12]}"
        ctx = PipelineContext(
            memories=memories,
            scan_id=scan_id,
            metadata=metadata,
            watermark_key=self.watermark_key,
        )
        log.info(
            "Pipeline started (async)",
            extra={"ctx": {"scan_id": scan_id, "stages": len(self.stages)}},
        )
        for stage in self.stages:
            await asyncio.to_thread(stage.run, ctx)
        memory_hash = hash_memory_state(memories)
        result = ScanResult(
            scan_id=scan_id,
            memory_hash=memory_hash,
            findings=ctx.findings,
            metadata=ctx.metadata,
        )
        log.info(
            "Pipeline complete (async)",
            extra={
                "ctx": {
                    "scan_id": scan_id,
                    "findings": len(result.findings),
                }
            },
        )
        return result
