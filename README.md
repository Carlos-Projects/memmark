# MemMark

**Memory integrity and watermarking toolkit for AI agent long-term memory systems.**

[![PyPI version](https://img.shields.io/pypi/v/memmark-agent?color=blue)](https://pypi.org/project/memmark-agent/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Carlos-Projects/memmark/actions/workflows/ci.yml/badge.svg)](https://github.com/Carlos-Projects/memmark/actions/workflows/ci.yml)
[![Docs](https://github.com/Carlos-Projects/memmark/actions/workflows/docs.yml/badge.svg)](https://carlos-projects.github.io/memmark)
[![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)](https://github.com/Carlos-Projects/memmark)

MemMark detects memory poisoning, verifies provenance, generates integrity manifests, and embeds cryptographic watermarks in AI agent memory systems — ensuring the memories your agent trusts are actually legitimate.

**Documentation**: [carlos-projects.github.io/memmark](https://carlos-projects.github.io/memmark)

## Features

| Feature | Description |
|---------|-------------|
| 🏷️ **Memory Watermarking** | HMAC-SHA256 + PBKDF2 watermarks with entropy salt |
| 🛡️ **Poisoning Detection** | Configurable pattern-based injection & manipulation detection |
| 🔍 **Provenance Tracking** | SHA-256 chain hashing with cycle-safe graph analysis |
| 📋 **Integrity Manifests** | Generate & verify SHA-256 manifests per entry & state |
| 📊 **Memory Diff** | Compare memory states (added, removed, modified entries) |
| 🔬 **Memory Forensics** | Temporal, content & source anomaly scoring |
| 📝 **Policy Generation** | MCPGuard-compatible YAML policies from scan results |
| 🔄 **Pluggable Store** | `FileMemoryStore`, `InMemoryMemoryStore`, custom backends |
| 🧩 **Composable Pipeline** | `ScanPipeline` + `ScanStage` for custom analysis workflows |
| 📋 **Structured Logging** | JSON logging with correlation IDs for pipeline tracing |

## Installation

```bash
pip install memmark-agent
```

## Quick Start

### Scan memory for integrity issues

```bash
memmark scan memory.json -k my-secret-key
```

### Full example — inject, detect, verify

```bash
# Inject watermarks
memmark watermark memory.json --action inject --key my-key -o watermarked.json

# Detect watermarks
memmark watermark watermarked.json --action detect --key my-key

# Integrity manifest
memmark manifest memory.json -o manifest.json

# Verify against manifest
memmark verify memory.json --manifest manifest.json

# Generate MCPGuard policy
memmark generate-policy memory.json -o policy.yaml
```

## Python API

### Full scan pipeline

```python
from memmark import run_full_scan

memories = [{"id": "mem-001", "content": "User likes dark mode"}]
result = run_full_scan(memories, watermark_key="my-secret")
for f in result.findings:
    print(f"  [{f.severity}] {f.description}")
```

### Composable pipeline

```python
from memmark import ScanPipeline

pipeline = ScanPipeline.with_default_stages(watermark_key="my-secret")
result = pipeline.run(memories, scan_id="custom-scan")

# Async variant
result = await pipeline.arun(memories)
```

### Custom stages

```python
from memmark import ScanStage, PipelineContext

class CustomStage(ScanStage):
    def run(self, ctx: PipelineContext) -> None:
        # Access ctx.memories, ctx.findings, ctx.metadata
        ...

pipeline = ScanPipeline.with_default_stages(watermark_key="k")
pipeline.add_stage(CustomStage())
```

### MemoryStore backends

```python
from memmark import FileMemoryStore, InMemoryMemoryStore, MemoryScanner

store = FileMemoryStore("memories.json")
memories = store.read()

scanner = MemoryScanner()
memories = scanner.load_memory(store)  # auto-detects MemoryStore
```

## Architecture

```
CLI (typer)
  └─ ScanPipeline (composable stages)
       ├─ PoisoningStage     — configurable pattern injection/manipulation detection
       ├─ WatermarkStage     — HMAC-SHA256 + PBKDF2 verification
       └─ ForensicsStage     — temporal/content/source anomaly scoring
  └─ WatermarkInjector / WatermarkDetector
  └─ PoisoningDetector / PoisoningClassifier / PoisoningRemediation
  └─ ProvenanceTracker / ProvenanceVerifier / ProvenanceGraph
  └─ IntegrityManifest / MemoryDiff / MemoryForensics
  └─ MCPGuardPolicy
  └─ MemoryStore (FileMemoryStore / InMemoryMemoryStore)
```

## Development

```bash
# Install dev + docs dependencies
pip install -e ".[dev,docs]

# Run tests with coverage
make test        # or: python -m pytest tests/ -v

# Lint + type check
make lint        # ruff check src/ tests/
make typecheck   # mypy src/

# Build docs
make serve-docs  # mkdocs serve → localhost:8000

# Build package
make build       # python -m build

# Run pre-commit hooks
make precommit   # pre-commit run --all-files

# Full CI pipeline
make all         # install → lint → typecheck → test → coverage
```

## Ecosystem Integration

| Project | Integration |
|---------|-------------|
| [MCPGuard](https://github.com/Carlos-Projects/mcpguard) | MemMark generates memory protection policies |
| [MCPscop](https://github.com/Carlos-Projects/mcpscope) | MemMark reports consumable by MCPscop dashboard |
| [mcp-taxonomy](https://github.com/Carlos-Projects/mcp-taxonomy) | Standardized finding classification |

## Academic Foundation

- **arXiv:2605.25073** — State-Evolution Attribution Watermarking (Zhang et al.)
- **arXiv:2605.24941** — Memory-Induced Tool-Drift in LLM Agents (Dabas et al.)
- **arXiv:2605.25717** — SAMark: Self-Anchored Text Watermarking
- **MITRE ATLAS** — Agent Memory Attack Patterns

## License

MIT — See [LICENSE](LICENSE).

## Author

Carlos Rocha — [GitHub](https://github.com/Carlos-Projects)
