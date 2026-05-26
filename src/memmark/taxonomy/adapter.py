"""mcp-taxonomy adapter for MemMark findings.

Translates MemMark Finding objects into canonical TaxonomyEvent
objects for interoperability with MCPscop and the ecosystem.
"""

from __future__ import annotations

from typing import Any

from mcp_taxonomy import (
    AttackCategory,
    Confidence,
    DetectionMethod,
    TaxonomyEvent,
    severity_weight,
)
from mcp_taxonomy import (
    Severity as TaxonomySeverity,
)

from memmark.scanner import Finding, FindingType
from memmark.scanner import Severity as MemMarkSeverity

_MEMMARK_FINDING_TYPE_MAP: dict[FindingType, AttackCategory] = {
    FindingType.WATERMARK_DETECTED: AttackCategory.ANOMALY,
    FindingType.WATERMARK_MISSING: AttackCategory.ANOMALY,
    FindingType.POISONING_DETECTED: AttackCategory.TOOL_POISONING,
    FindingType.PROVENANCE_INVALID: AttackCategory.POLICY_VIOLATION,
    FindingType.INTEGRITY_MODIFIED: AttackCategory.POLICY_VIOLATION,
    FindingType.ANOMALY_DETECTED: AttackCategory.ANOMALY,
    FindingType.POLICY_VIOLATION: AttackCategory.POLICY_VIOLATION,
}

_MEMMARK_DETECTION_METHOD_MAP: dict[FindingType, DetectionMethod] = {
    FindingType.WATERMARK_DETECTED: DetectionMethod.ANOMALY_DETECTOR,
    FindingType.WATERMARK_MISSING: DetectionMethod.ANOMALY_DETECTOR,
    FindingType.POISONING_DETECTED: DetectionMethod.TOOL_POISONING,
    FindingType.PROVENANCE_INVALID: DetectionMethod.ANOMALY_DETECTOR,
    FindingType.INTEGRITY_MODIFIED: DetectionMethod.ANOMALY_DETECTOR,
    FindingType.ANOMALY_DETECTED: DetectionMethod.ANOMALY_DETECTOR,
    FindingType.POLICY_VIOLATION: DetectionMethod.POLICY_MISMATCH,
}

_SEVERITY_MAP: dict[MemMarkSeverity, TaxonomySeverity] = {
    MemMarkSeverity.CRITICAL: TaxonomySeverity.CRITICAL,
    MemMarkSeverity.HIGH: TaxonomySeverity.HIGH,
    MemMarkSeverity.MEDIUM: TaxonomySeverity.MEDIUM,
    MemMarkSeverity.LOW: TaxonomySeverity.LOW,
    MemMarkSeverity.INFO: TaxonomySeverity.INFO,
}

_CONFIDENCE_MAP: dict[MemMarkSeverity, Confidence] = {
    MemMarkSeverity.CRITICAL: Confidence.CERTAIN,
    MemMarkSeverity.HIGH: Confidence.HIGH,
    MemMarkSeverity.MEDIUM: Confidence.MEDIUM,
    MemMarkSeverity.LOW: Confidence.LOW,
    MemMarkSeverity.INFO: Confidence.NONE,
}


def memmark_finding_to_taxonomy(finding: Finding | dict[str, Any]) -> TaxonomyEvent:
    """Convert a MemMark Finding to a canonical TaxonomyEvent.

    Args:
        finding: MemMark Finding object or dictionary.

    Returns:
        TaxonomyEvent compatible with MCPscop and the ecosystem.
    """
    if isinstance(finding, dict):
        finding_type_str = finding.get("finding_type", "")
        finding_type = (
            FindingType(finding_type_str)
            if finding_type_str in FindingType._value2member_map_
            else FindingType.ANOMALY_DETECTED
        )
        severity_str = finding.get("severity", "medium")
        severities = {s.value: s for s in MemMarkSeverity}
        severity = severities.get(severity_str, MemMarkSeverity.MEDIUM)
        memory_id = finding.get("memory_id")
        description = finding.get("description", "")
        raw = finding
    else:
        finding_type = finding.finding_type
        severity = finding.severity
        memory_id = finding.memory_id
        description = finding.description
        raw = finding.to_dict() if hasattr(finding, "to_dict") else None

    attack_category = _MEMMARK_FINDING_TYPE_MAP.get(
        finding_type,
        AttackCategory.ANOMALY,
    )
    detection_method = _MEMMARK_DETECTION_METHOD_MAP.get(
        finding_type,
        DetectionMethod.ANOMALY_DETECTOR,
    )
    taxonomy_severity = _SEVERITY_MAP.get(severity, TaxonomySeverity.MEDIUM)
    confidence = _CONFIDENCE_MAP.get(severity, Confidence.MEDIUM)

    conf_val = {
        Confidence.CERTAIN: 1.0,
        Confidence.HIGH: 0.8,
        Confidence.MEDIUM: 0.5,
        Confidence.LOW: 0.2,
        Confidence.NONE: 0.0,
    }.get(confidence, 0.5)

    return TaxonomyEvent(
        source="memmark",
        attack_category=attack_category,
        severity=taxonomy_severity,
        confidence=confidence,
        detection_method=detection_method,
        title=finding_type.value.replace("_", " ").title(),
        description=description,
        recommendation="Review and remediate affected memory entries",
        target=memory_id or "",
        snippet=description[:200] if description else "",
        raw=raw,
        risk_score=severity_weight(taxonomy_severity) * int(conf_val * 100) // 25,
    )


def memmark_scan_to_taxonomy_events(
    findings: list[Finding],
) -> list[TaxonomyEvent]:
    """Convert a list of MemMark findings to taxonomy events.

    Args:
        findings: List of MemMark Finding objects.

    Returns:
        List of TaxonomyEvent objects.
    """
    return [memmark_finding_to_taxonomy(f) for f in findings]
