# Provenance

MemMark tracks the **lineage and ancestry** of memory entries through a cryptographic chain.

## Provenance Tracker

Each memory entry is registered with:

- `memory_id`: Unique identifier
- `source`: Origin of the entry
- `parent_id`: ID of the parent entry (for chain linking)
- `version`: Version number (incremented on updates)
- `chain_hash`: SHA-256 hash of the record + previous chain hash

### Chain Hashing

```text
chain_hash(record) = SHA-256(
    memory_id + source + parent_id + version + metadata + previous_hash
)
```

This creates an immutable chain where tampering with any link breaks the chain.

## Provenance Graph

The `ProvenanceGraph` builds a directed graph from tracker records:

```python
from memmark import ProvenanceTracker, ProvenanceGraph

tracker = ProvenanceTracker()
tracker.register("mem-001", "user")
tracker.register("mem-002", "system", parent_id="mem-001")

graph = ProvenanceGraph.from_tracker(tracker)
roots = graph.get_roots()
depth = graph.get_depth("mem-002")
anomalies = graph.detect_anomalies()
```

### Anomaly Detection

| Anomaly | Description | Severity |
|---------|-------------|----------|
| `orphan_node` | Parent referenced but not found | High |
| `provenance_cycle` | Circular dependency detected | Critical |
| `deep_chain` | Chain depth > 10 | Medium |

## Provenance Verifier

The verifier checks chain integrity:

```python
from memmark import ProvenanceVerifier

verifier = ProvenanceVerifier()
result = verifier.verify_chain(tracker)
# result["valid"]: bool
# result["issues"]: list[str]

forged = verifier.detect_forged_provenance(memories, tracker)
# Returns entries with missing or invalid provenance
```

## CLI Usage

Provenance verification is included in `memmark scan`:

```bash
memmark scan memories.json --key my-key
```

Results include provenance chain validity and any orphan/cycle anomalies.
