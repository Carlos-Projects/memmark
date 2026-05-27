# Integrity

## Manifests

Generate SHA-256 manifests to detect memory state tampering:

```bash
memmark manifest generate memories.json --output manifest.json

memmark verify memories.json manifest.json
```

```python
from memmark.integrity.manifest import IntegrityManifest

manifest = IntegrityManifest.create(memories)
manifest.save("manifest.json")

loaded = IntegrityManifest.load("manifest.json")
is_valid = loaded.verify(current_hash)
results = loaded.verify_entries(memories)
# Checks per-entry: verified, modified, missing, new
```

## Memory Diff

Compare two memory states to identify changes:

```bash
memmark diff original.json modified.json
```

```python
from memmark import MemoryDiff

diff = MemoryDiff(memories_a, memories_b)
print(diff.entries_added)    # list of new entry IDs
print(diff.entries_removed)  # list of removed entry IDs
print(diff.entries_modified)  # list of modified entry IDs
print(diff.has_changes)       # bool
```

## Memory Forensics

Analyze memory stores for suspicious patterns:

```python
from memmark import MemoryForensics

forensics = MemoryForensics()
analysis = forensics.analyze(memories)
# {
#   "temporal_analysis": {...},
#   "content_analysis": {...},
#   "source_analysis": {...},
#   "anomaly_score": 0.0-1.0,
# }
```

Detects:
- **Temporal anomalies**: Bursts of entries, gaps, unusual timestamps
- **Content anomalies**: Near-duplicate entries, outlier lengths
- **Source anomalies**: Single-source dominance, unexpected sources
