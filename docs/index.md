# MemMark

Memory integrity and watermarking toolkit for AI agent long-term memory systems.

## Features

- **Watermarking** — Inject and verify cryptographic watermarks bind memory entries to a secret key.
- **Poisoning Detection** — Detect instruction injection and behavioral manipulation attacks.
- **Provenance Tracking** — Track memory lineage with chain hashing and cycle-safe graph analysis.
- **Integrity Manifests** — Generate and verify SHA-256 manifests for memory state integrity.
- **Memory Forensics** — Analyze memory stores for temporal, content, and source anomalies.
- **Policy Generation** — Export scan results as MCPGuard-compatible YAML policies.
- **Ecosystem Interop** — Convert findings to canonical `mcp-taxonomy` events.

## Quick Install

```bash
pip install memmark-agent
```

## Quick Start

```bash
# Scan a memory file
memmark scan examples/sample_memory.json --key my-secret-key

# Inject watermarks
memmark watermark inject examples/sample_memory.json --key my-secret-key --output watermarked.json

# Verify watermarks
memmark watermark verify watermarked.json --key my-secret-key
```

## Architecture

MemMark follows a modular architecture with independent subsystems:

```text
CLI (typer)
  └─ Scanner (orchestrator)
       ├─ WatermarkInjector / WatermarkDetector
       ├─ PoisoningDetector / PoisoningClassifier
       ├─ ProvenanceTracker / ProvenanceVerifier
       ├─ IntegrityManifest / MemoryDiff / MemoryForensics
       └─ MCPGuardPolicy (policy export)
```

Each subsystem can be used independently via the Python API or composed via `run_full_scan()`.

## Academic Foundation

MemMark implements techniques from:

- **Zhang et al. (2025)** — *State-Evolution Attribution Watermarking* (arXiv:2605.25073)
- **Dabas et al. (2025)** — *Memory-Induced Tool-Drift in LLM Agents* (arXiv:2605.24941)

## License

MIT — see [LICENSE](https://github.com/Carlos-Projects/memmark/blob/main/LICENSE).
