"""Tests for the integrity module."""

import tempfile
from pathlib import Path

from memmark.integrity.diff import MemoryDiff
from memmark.integrity.forensics import MemoryForensics
from memmark.integrity.manifest import IntegrityManifest

SAMPLE_MEMORIES = [
    {"id": "mem-001", "content": "hello", "source": "user"},
    {"id": "mem-002", "content": "world", "source": "system"},
]


class TestIntegrityManifest:
    def test_create(self) -> None:
        manifest = IntegrityManifest.create(SAMPLE_MEMORIES, source="test.json")
        assert manifest.entry_count == 2
        assert len(manifest.entries) == 2
        assert manifest.source == "test.json"

    def test_create_with_metadata(self) -> None:
        manifest = IntegrityManifest.create(
            SAMPLE_MEMORIES,
            metadata={"version": "1.0"},
        )
        assert manifest.metadata["version"] == "1.0"

    def test_memory_hash(self) -> None:
        manifest = IntegrityManifest.create(SAMPLE_MEMORIES)
        assert isinstance(manifest.memory_hash, str)
        assert len(manifest.memory_hash) == 64

    def test_verify_valid(self) -> None:
        manifest = IntegrityManifest.create(SAMPLE_MEMORIES)
        assert manifest.verify(manifest.memory_hash)

    def test_verify_invalid(self) -> None:
        manifest = IntegrityManifest.create(SAMPLE_MEMORIES)
        assert not manifest.verify("invalid_hash")

    def test_verify_entries_all_valid(self) -> None:
        manifest = IntegrityManifest.create(SAMPLE_MEMORIES)
        result = manifest.verify_entries(SAMPLE_MEMORIES)
        assert result["verified"] == 2

    def test_verify_entries_modified(self) -> None:
        manifest = IntegrityManifest.create(SAMPLE_MEMORIES)
        modified = [{"id": "mem-001", "content": "MODIFIED"}, SAMPLE_MEMORIES[1]]
        result = manifest.verify_entries(modified)
        assert result["modified"] == 1

    def test_verify_entries_new(self) -> None:
        manifest = IntegrityManifest.create(SAMPLE_MEMORIES)
        extended = SAMPLE_MEMORIES + [{"id": "mem-003", "content": "new"}]
        result = manifest.verify_entries(extended)
        assert result["new"] == 1

    def test_verify_entries_missing(self) -> None:
        manifest = IntegrityManifest.create(SAMPLE_MEMORIES)
        subset = [SAMPLE_MEMORIES[0]]
        result = manifest.verify_entries(subset)
        assert result["missing"] == 1

    def test_save_and_load(self) -> None:
        manifest = IntegrityManifest.create(SAMPLE_MEMORIES)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            manifest.save(f.name)
            path = f.name
        try:
            loaded = IntegrityManifest.load(path)
            assert loaded.memory_hash == manifest.memory_hash
            assert loaded.entry_count == manifest.entry_count
        finally:
            Path(path).unlink()

    def test_to_dict(self) -> None:
        manifest = IntegrityManifest.create(SAMPLE_MEMORIES)
        d = manifest.to_dict()
        assert d["manifest_id"] == manifest.manifest_id
        assert len(d["entries"]) == 2

    def test_to_json(self) -> None:
        manifest = IntegrityManifest.create(SAMPLE_MEMORIES)
        json_str = manifest.to_json()
        assert isinstance(json_str, str)
        assert manifest.manifest_id in json_str


class TestMemoryDiff:
    def test_no_changes(self) -> None:
        diff = MemoryDiff.compare(SAMPLE_MEMORIES, SAMPLE_MEMORIES)
        assert diff.is_intact
        assert diff.added == 0
        assert diff.removed == 0
        assert diff.modified == 0
        assert diff.unchanged == 2

    def test_entries_added(self) -> None:
        after = SAMPLE_MEMORIES + [{"id": "mem-003", "content": "new"}]
        diff = MemoryDiff.compare(SAMPLE_MEMORIES, after)
        assert diff.added == 1
        assert not diff.is_intact

    def test_entries_removed(self) -> None:
        before = SAMPLE_MEMORIES + [{"id": "mem-003", "content": "extra"}]
        diff = MemoryDiff.compare(before, SAMPLE_MEMORIES)
        assert diff.removed == 1

    def test_entries_modified(self) -> None:
        modified = [dict(SAMPLE_MEMORIES[0]), SAMPLE_MEMORIES[1]]
        modified[0]["content"] = "modified"
        diff = MemoryDiff.compare(SAMPLE_MEMORIES, modified)
        assert diff.modified == 1

    def test_state_hashes_different(self) -> None:
        after = [{"id": "mem-001", "content": "changed"}, SAMPLE_MEMORIES[1]]
        diff = MemoryDiff.compare(SAMPLE_MEMORIES, after)
        assert diff.before_hash != diff.after_hash

    def test_state_hashes_same(self) -> None:
        diff = MemoryDiff.compare(SAMPLE_MEMORIES, SAMPLE_MEMORIES)
        assert diff.before_hash == diff.after_hash

    def test_has_changes_property(self) -> None:
        diff = MemoryDiff.compare(SAMPLE_MEMORIES, SAMPLE_MEMORIES)
        assert not diff.has_changes
        after = SAMPLE_MEMORIES + [{"id": "mem-003", "content": "new"}]
        diff2 = MemoryDiff.compare(SAMPLE_MEMORIES, after)
        assert diff2.has_changes

    def test_to_dict(self) -> None:
        diff = MemoryDiff.compare(SAMPLE_MEMORIES, SAMPLE_MEMORIES)
        d = diff.to_dict()
        assert d["has_changes"] is False


class TestMemoryForensics:
    def test_analyze_empty(self) -> None:
        forensics = MemoryForensics()
        result = forensics.analyze([])
        assert "anomaly_score" in result
        assert result["anomaly_score"] == 0.0

    def test_temporal_analysis(self) -> None:
        forensics = MemoryForensics()
        memories = [
            {"id": "mem-001", "content": "a", "timestamp": "2025-01-01T00:00:00Z"},
            {"id": "mem-002", "content": "b", "timestamp": "2025-01-01T01:00:00Z"},
        ]
        result = forensics.analyze(memories)
        assert result["temporal_analysis"]["entry_count"] == 2

    def test_temporal_single_entry(self) -> None:
        forensics = MemoryForensics()
        result = forensics.analyze(
            [{"id": "mem-001", "timestamp": "2025-01-01T00:00:00Z"}]
        )
        assert result["temporal_analysis"]["has_anomaly"] is False
        assert result["temporal_analysis"]["reason"] == "insufficient_data"

    def test_content_analysis(self) -> None:
        forensics = MemoryForensics()
        memories = [
            {"id": "mem-001", "content": "a" * 10},
            {"id": "mem-002", "content": "b" * 20},
        ]
        result = forensics.analyze(memories)
        assert result["content_analysis"]["analyzed"] == 2

    def test_source_analysis(self) -> None:
        forensics = MemoryForensics()
        memories = [
            {"id": "mem-001", "content": "a", "source": "user"},
            {"id": "mem-002", "content": "b", "source": "system"},
            {"id": "mem-003", "content": "c", "source": "system"},
        ]
        result = forensics.analyze(memories)
        assert result["source_analysis"]["unique_sources"] == 2

    def test_content_anomaly_outliers(self) -> None:
        forensics = MemoryForensics()
        memories = [{"id": f"mem-{i}", "content": "normal"} for i in range(10)]
        memories.append({"id": "mem-outlier", "content": "huge" * 10000})
        result = forensics.analyze(memories)
        assert result["content_analysis"]["outlier_count"] >= 1

    def test_uniform_content_detection(self) -> None:
        forensics = MemoryForensics()
        memories = [
            {"id": "mem-001", "content": "exact same text"},
            {"id": "mem-002", "content": "exact same text"},
            {"id": "mem-003", "content": "exact same text"},
        ]
        result = forensics.analyze(memories)
        assert result["content_analysis"]["uniformity_score"] > 0.5

    def test_anomaly_score_range(self) -> None:
        forensics = MemoryForensics()
        result = forensics._compute_anomaly_score(SAMPLE_MEMORIES)
        assert 0.0 <= result <= 1.0

    def test_source_dominance_anomaly(self) -> None:
        forensics = MemoryForensics()
        memories = [
            {"id": f"mem-{i}", "content": "x", "source": "attacker"} for i in range(20)
        ]
        result = forensics.analyze(memories)
        assert result["source_analysis"]["has_anomaly"] is True
