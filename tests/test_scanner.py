"""Tests for the core scanner module."""

import json
import tempfile
from pathlib import Path

from memmark.scanner import (
    Finding,
    FindingType,
    MemoryEntry,
    MemoryScanner,
    ScanResult,
    Severity,
    validate_memory_entries,
)


class TestFinding:
    def test_create(self) -> None:
        f = Finding(
            finding_type=FindingType.POISONING_DETECTED,
            severity=Severity.HIGH,
            description="Test finding",
            memory_id="mem-001",
        )
        assert f.finding_type == FindingType.POISONING_DETECTED
        assert f.severity == Severity.HIGH
        assert f.description == "Test finding"
        assert f.memory_id == "mem-001"

    def test_to_dict(self) -> None:
        f = Finding(
            finding_type=FindingType.POISONING_DETECTED,
            severity=Severity.HIGH,
            description="Test",
            memory_id="mem-001",
        )
        d = f.to_dict()
        assert d["finding_type"] == "poisoning_detected"
        assert d["severity"] == "high"
        assert d["memory_id"] == "mem-001"

    def test_default_timestamp(self) -> None:
        f = Finding(
            finding_type=FindingType.POISONING_DETECTED,
            severity=Severity.INFO,
            description="Test",
        )
        assert f.timestamp is not None

    def test_with_evidence(self) -> None:
        f = Finding(
            finding_type=FindingType.WATERMARK_MISSING,
            severity=Severity.LOW,
            description="Missing watermark",
            evidence={"expected": "abc123"},
        )
        assert f.evidence["expected"] == "abc123"

    def test_with_remediation(self) -> None:
        f = Finding(
            finding_type=FindingType.INTEGRITY_MODIFIED,
            severity=Severity.CRITICAL,
            description="Modified",
            remediation="Restore from backup",
        )
        assert f.remediation == "Restore from backup"


class TestScanResult:
    def test_empty_result(self) -> None:
        result = ScanResult(scan_id="test-001")
        assert result.scan_id == "test-001"
        assert result.findings == []
        assert result.is_clean

    def test_with_findings(self) -> None:
        result = ScanResult(
            scan_id="test-002",
            findings=[
                Finding(FindingType.POISONING_DETECTED, Severity.CRITICAL, "Critical"),
                Finding(FindingType.POISONING_DETECTED, Severity.HIGH, "High"),
            ],
        )
        assert result.critical_count == 1
        assert result.high_count == 1
        assert not result.is_clean

    def test_counters(self) -> None:
        result = ScanResult(
            scan_id="test-003",
            findings=[
                Finding(FindingType.POISONING_DETECTED, Severity.CRITICAL, "C"),
                Finding(FindingType.POISONING_DETECTED, Severity.HIGH, "H"),
                Finding(FindingType.POISONING_DETECTED, Severity.MEDIUM, "M"),
                Finding(FindingType.POISONING_DETECTED, Severity.LOW, "L"),
                Finding(FindingType.POISONING_DETECTED, Severity.INFO, "I"),
            ],
        )
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 1

    def test_to_dict(self) -> None:
        result = ScanResult(scan_id="test-004")
        d = result.to_dict()
        assert d["scan_id"] == "test-004"
        assert d["summary"]["is_clean"]
        assert d["summary"]["total"] == 0

    def test_to_json(self) -> None:
        result = ScanResult(scan_id="test-005")
        json_str = result.to_json()
        data = json.loads(json_str)
        assert data["scan_id"] == "test-005"


class TestMemoryScanner:
    def test_initialization(self) -> None:
        scanner = MemoryScanner()
        assert scanner.findings == []

    def test_load_memory_from_list(self) -> None:
        scanner = MemoryScanner()
        data = [{"id": "mem-001", "content": "test"}]
        result = scanner.load_memory(data)
        assert result == data

    def test_load_memory_from_file(self) -> None:
        scanner = MemoryScanner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([{"id": "mem-001", "content": "test"}], f)
            path = f.name
        try:
            result = scanner.load_memory(path)
            assert len(result) == 1
            assert result[0]["id"] == "mem-001"
        finally:
            Path(path).unlink()

    def test_load_memory_from_dict_file(self) -> None:
        scanner = MemoryScanner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"memories": [{"id": "mem-001"}]}, f)
            path = f.name
        try:
            result = scanner.load_memory(path)
            assert len(result) == 1
        finally:
            Path(path).unlink()

    def test_compute_memory_hash(self) -> None:
        scanner = MemoryScanner()
        memories = [{"id": "mem-001"}, {"id": "mem-002"}]
        h = scanner.compute_memory_hash(memories)
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex

    def test_compute_memory_hash_deterministic(self) -> None:
        scanner = MemoryScanner()
        memories = [{"id": "mem-001", "content": "hello"}]
        h1 = scanner.compute_memory_hash(memories)
        h2 = scanner.compute_memory_hash(memories)
        assert h1 == h2

    def test_compute_memory_hash_different(self) -> None:
        scanner = MemoryScanner()
        m1 = [{"id": "mem-001", "content": "hello"}]
        m2 = [{"id": "mem-001", "content": "world"}]
        assert scanner.compute_memory_hash(m1) != scanner.compute_memory_hash(m2)

    def test_compute_entry_hash(self) -> None:
        scanner = MemoryScanner()
        entry = {"id": "mem-001", "content": "test"}
        h = scanner.compute_entry_hash(entry)
        assert isinstance(h, str)
        assert len(h) == 64

    def test_add_finding(self) -> None:
        scanner = MemoryScanner()
        finding = Finding(
            FindingType.POISONING_DETECTED,
            Severity.HIGH,
            "test",
        )
        scanner.add_finding(finding)
        assert len(scanner.findings) == 1

    def test_build_result(self) -> None:
        scanner = MemoryScanner()
        scanner.add_finding(
            Finding(FindingType.POISONING_DETECTED, Severity.HIGH, "test"),
        )
        result = scanner.build_result(
            scan_id="test",
            memories=[{"id": "mem-001"}],
            metadata={"source": "test"},
        )
        assert result.scan_id == "test"
        assert len(result.findings) == 1
        assert result.metadata["source"] == "test"

    def test_reset(self) -> None:
        scanner = MemoryScanner()
        scanner.add_finding(
            Finding(FindingType.POISONING_DETECTED, Severity.HIGH, "test"),
        )
        assert len(scanner.findings) == 1
        scanner.reset()
        assert len(scanner.findings) == 0

    def test_load_memory_file_not_found(self) -> None:
        scanner = MemoryScanner()
        raised = False
        try:
            scanner.load_memory("/nonexistent/path.json")
        except FileNotFoundError:
            raised = True
        assert raised


class TestMemoryEntry:
    def test_from_dict(self) -> None:
        entry = MemoryEntry.from_dict({"id": "mem-001", "content": "hello"})
        assert entry.id == "mem-001"
        assert entry.content == "hello"

    def test_from_dict_minimal(self) -> None:
        entry = MemoryEntry.from_dict({"id": "mem-001"})
        assert entry.content == ""

    def test_from_dict_extra_fields(self) -> None:
        entry = MemoryEntry.from_dict({"id": "mem-001", "extra": "value"})
        assert entry.id == "mem-001"

    def test_from_dict_memory_id_alias(self) -> None:
        entry = MemoryEntry.from_dict({"memory_id": "mem-001"})
        assert entry.id == "mem-001"


class TestValidateMemoryEntries:
    def test_valid_entries(self) -> None:
        result = validate_memory_entries([{"id": "mem-001", "content": "test"}])
        assert len(result) == 1

    def test_invalid_entries_pass_through(self) -> None:
        result = validate_memory_entries(["not-a-dict", 42])
        assert len(result) == 2
