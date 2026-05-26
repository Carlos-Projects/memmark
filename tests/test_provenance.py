"""Tests for the provenance module."""

from memmark.provenance.graph import ProvenanceGraph, ProvenanceNode
from memmark.provenance.tracker import ProvenanceRecord, ProvenanceTracker
from memmark.provenance.verifier import ProvenanceVerifier


class TestProvenanceTracker:
    def test_init(self) -> None:
        tracker = ProvenanceTracker()
        assert tracker.records == {}
        assert tracker.chain_head == ""

    def test_register(self) -> None:
        tracker = ProvenanceTracker()
        record = tracker.register("mem-001", "user")
        assert record.memory_id == "mem-001"
        assert record.source == "user"
        assert record.version == 1
        assert len(record.chain_hash) == 64

    def test_register_with_metadata(self) -> None:
        tracker = ProvenanceTracker()
        record = tracker.register(
            "mem-001", "user", metadata={"category": "preference"}
        )
        assert record.metadata["category"] == "preference"

    def test_register_with_parent(self) -> None:
        tracker = ProvenanceTracker()
        tracker.register("mem-001", "user")
        child = tracker.register("mem-002", "system", parent_id="mem-001")
        assert child.parent_id == "mem-001"

    def test_update(self) -> None:
        tracker = ProvenanceTracker()
        tracker.register("mem-001", "user")
        updated = tracker.update("mem-001", {"new": "data"})
        assert updated is not None
        assert updated.version == 2

    def test_update_nonexistent(self) -> None:
        tracker = ProvenanceTracker()
        result = tracker.update("nonexistent")
        assert result is None

    def test_get_record(self) -> None:
        tracker = ProvenanceTracker()
        tracker.register("mem-001", "user")
        record = tracker.get_record("mem-001")
        assert record is not None
        assert record.memory_id == "mem-001"

    def test_get_record_nonexistent(self) -> None:
        tracker = ProvenanceTracker()
        assert tracker.get_record("nonexistent") is None

    def test_get_chain(self) -> None:
        tracker = ProvenanceTracker()
        parent = tracker.register("mem-001", "user")
        tracker.register("mem-002", "system", parent_id=parent.memory_id)
        chain = tracker.get_chain("mem-002")
        assert len(chain) == 2
        assert chain[0].memory_id == "mem-001"
        assert chain[1].memory_id == "mem-002"

    def test_export(self) -> None:
        tracker = ProvenanceTracker()
        tracker.register("mem-001", "user")
        exported = tracker.export()
        assert "records" in exported
        assert "mem-001" in exported["records"]

    def test_load(self) -> None:
        tracker = ProvenanceTracker()
        tracker.register("mem-001", "user")
        exported = tracker.export()
        new_tracker = ProvenanceTracker()
        new_tracker.load(exported)
        assert new_tracker.get_record("mem-001") is not None

    def test_to_json(self) -> None:
        tracker = ProvenanceTracker()
        tracker.register("mem-001", "user")
        json_str = tracker.to_json()
        assert isinstance(json_str, str)
        assert "mem-001" in json_str


class TestProvenanceRecord:
    def test_compute_chain_hash(self) -> None:
        record = ProvenanceRecord(memory_id="mem-001", source="user")
        h = record.compute_chain_hash()
        assert isinstance(h, str)
        assert len(h) == 64

    def test_compute_chain_hash_with_previous(self) -> None:
        record = ProvenanceRecord(memory_id="mem-001", source="user")
        h1 = record.compute_chain_hash()
        h2 = record.compute_chain_hash(previous_hash="abc")
        assert h1 != h2

    def test_to_dict(self) -> None:
        record = ProvenanceRecord(memory_id="mem-001", source="user")
        d = record.to_dict()
        assert d["memory_id"] == "mem-001"
        assert d["source"] == "user"
        assert d["version"] == 1


class TestProvenanceVerifier:
    def test_verify_empty(self) -> None:
        verifier = ProvenanceVerifier()
        tracker = ProvenanceTracker()
        result = verifier.verify_chain(tracker)
        assert result["valid"]

    def test_verify_single(self) -> None:
        verifier = ProvenanceVerifier()
        tracker = ProvenanceTracker()
        tracker.register("mem-001", "user")
        result = verifier.verify_chain(tracker)
        assert result["valid"]

    def test_verify_chain_linked(self) -> None:
        verifier = ProvenanceVerifier()
        tracker = ProvenanceTracker()
        tracker.register("mem-001", "user")
        tracker.register("mem-002", "system", parent_id="mem-001")
        result = verifier.verify_chain(tracker)
        assert result["valid"]

    def test_verify_entry(self) -> None:
        verifier = ProvenanceVerifier()
        tracker = ProvenanceTracker()
        record = tracker.register("mem-001", "user")
        result = verifier.verify_entry(record)
        assert result["valid"]

    def test_detect_forged_provenance(self) -> None:
        verifier = ProvenanceVerifier()
        tracker = ProvenanceTracker()
        tracker.register("mem-001", "user")
        forged = [
            {"id": "mem-999", "content": "forged"},
            {"id": "mem-001", "content": "original"},
        ]
        suspicious = verifier.detect_forged_provenance(forged, tracker)
        assert len(suspicious) == 1
        assert suspicious[0]["issue"] == "no_provenance_record"


class TestProvenanceGraph:
    def test_from_tracker(self) -> None:
        tracker = ProvenanceTracker()
        tracker.register("mem-001", "user")
        graph = ProvenanceGraph.from_tracker(tracker)
        assert "mem-001" in graph.nodes

    def test_roots(self) -> None:
        tracker = ProvenanceTracker()
        tracker.register("mem-001", "user")
        tracker.register("mem-002", "system", parent_id="mem-001")
        graph = ProvenanceGraph.from_tracker(tracker)
        roots = graph.get_roots()
        assert len(roots) == 1
        assert roots[0].memory_id == "mem-001"

    def test_get_children(self) -> None:
        tracker = ProvenanceTracker()
        parent = tracker.register("mem-001", "user")
        child = tracker.register("mem-002", "system", parent_id=parent.memory_id)
        graph = ProvenanceGraph.from_tracker(tracker)
        children = graph.get_children("mem-001")
        assert child.memory_id in children

    def test_get_depth(self) -> None:
        tracker = ProvenanceTracker()
        tracker.register("mem-001", "user")
        child = tracker.register("mem-002", "system", parent_id="mem-001")
        tracker.register("mem-003", "system", parent_id=child.memory_id)
        graph = ProvenanceGraph.from_tracker(tracker)
        assert graph.get_depth("mem-001") == 0
        assert graph.get_depth("mem-003") == 2

    def test_detect_orphan_anomaly(self) -> None:
        graph = ProvenanceGraph()
        graph.nodes["mem-002"] = ProvenanceNode(
            memory_id="mem-002",
            source="test",
            parent="mem-001",
        )
        anomalies = graph.detect_anomalies()
        orphan_anomalies = [a for a in anomalies if a["type"] == "orphan_node"]
        assert len(orphan_anomalies) > 0

    def test_to_dict(self) -> None:
        tracker = ProvenanceTracker()
        tracker.register("mem-001", "user")
        graph = ProvenanceGraph.from_tracker(tracker)
        d = graph.to_dict()
        assert d["root_count"] > 0
        assert d["total_nodes"] > 0

    def test_get_descendants(self) -> None:
        tracker = ProvenanceTracker()
        tracker.register("mem-001", "user")
        child = tracker.register("mem-002", "system", parent_id="mem-001")
        tracker.register("mem-003", "system", parent_id=child.memory_id)
        graph = ProvenanceGraph.from_tracker(tracker)
        descendants = graph.get_descendants("mem-001")
        assert len(descendants) == 2
