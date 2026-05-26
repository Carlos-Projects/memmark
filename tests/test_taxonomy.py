"""Tests for the mcp-taxonomy adapter."""

from mcp_taxonomy import AttackCategory, DetectionMethod, TaxonomyEvent

from memmark.scanner import Finding, FindingType, Severity
from memmark.taxonomy.adapter import (
    memmark_finding_to_taxonomy,
    memmark_scan_to_taxonomy_events,
)


class TestMemmarkFindingToTaxonomy:
    def test_poisoning_finding(self) -> None:
        finding = Finding(
            FindingType.POISONING_DETECTED,
            Severity.HIGH,
            "Instruction injection detected",
            memory_id="mem-001",
        )
        event = memmark_finding_to_taxonomy(finding)
        assert isinstance(event, TaxonomyEvent)
        assert event.source == "memmark"
        assert event.attack_category == AttackCategory.TOOL_POISONING
        assert event.severity.value == "high"

    def test_watermark_missing(self) -> None:
        finding = Finding(
            FindingType.WATERMARK_MISSING,
            Severity.LOW,
            "Missing watermark",
        )
        event = memmark_finding_to_taxonomy(finding)
        assert event.attack_category == AttackCategory.ANOMALY

    def test_integrity_modified(self) -> None:
        finding = Finding(
            FindingType.INTEGRITY_MODIFIED,
            Severity.CRITICAL,
            "Memory modified",
        )
        event = memmark_finding_to_taxonomy(finding)
        assert event.attack_category == AttackCategory.POLICY_VIOLATION
        assert event.severity.value == "critical"

    def test_provenance_invalid(self) -> None:
        finding = Finding(
            FindingType.PROVENANCE_INVALID,
            Severity.MEDIUM,
            "Provenance chain broken",
        )
        event = memmark_finding_to_taxonomy(finding)
        assert event.attack_category == AttackCategory.POLICY_VIOLATION

    def test_detection_method(self) -> None:
        finding = Finding(
            FindingType.POISONING_DETECTED,
            Severity.HIGH,
            "test",
        )
        event = memmark_finding_to_taxonomy(finding)
        assert event.detection_method == DetectionMethod.TOOL_POISONING

    def test_title_format(self) -> None:
        finding = Finding(
            FindingType.WATERMARK_DETECTED,
            Severity.INFO,
            "test",
        )
        event = memmark_finding_to_taxonomy(finding)
        assert (
            "Watermark Detected" in event.title or "watermark_detected" in event.title
        )

    def test_target_from_memory_id(self) -> None:
        finding = Finding(
            FindingType.POISONING_DETECTED,
            Severity.HIGH,
            "test",
            memory_id="mem-001",
        )
        event = memmark_finding_to_taxonomy(finding)
        assert event.target == "mem-001"

    def test_risk_score(self) -> None:
        finding = Finding(
            FindingType.POISONING_DETECTED,
            Severity.CRITICAL,
            "test",
        )
        event = memmark_finding_to_taxonomy(finding)
        assert event.risk_score > 0

    def test_from_dict(self) -> None:
        finding_dict = {
            "finding_type": "poisoning_detected",
            "severity": "high",
            "description": "Found injection",
            "memory_id": "mem-001",
            "evidence": {"score": 0.9},
        }
        event = memmark_finding_to_taxonomy(finding_dict)
        assert event.source == "memmark"
        assert event.attack_category == AttackCategory.TOOL_POISONING


class TestMemmarkScanToTaxonomyEvents:
    def test_empty(self) -> None:
        events = memmark_scan_to_taxonomy_events([])
        assert events == []

    def test_multiple_findings(self) -> None:
        findings = [
            Finding(FindingType.POISONING_DETECTED, Severity.HIGH, "poison"),
            Finding(FindingType.WATERMARK_MISSING, Severity.LOW, "missing"),
        ]
        events = memmark_scan_to_taxonomy_events(findings)
        assert len(events) == 2
        assert all(isinstance(e, TaxonomyEvent) for e in events)
