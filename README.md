# MemMark 🔐

**Memory integrity and watermarking toolkit for AI agent long-term memory systems.**

[![PyPI version](https://img.shields.io/badge/pypi-0.1.0-blue.svg)](https://pypi.org/project/memmark-agent/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Carlos-Projects/memmark/actions/workflows/ci.yml/badge.svg)](https://github.com/Carlos-Projects/memmark/actions/workflows/ci.yml)

MemMark detects memory poisoning, verifies provenance of injected memories, generates integrity manifests, and embeds watermarks in AI agent memory systems — ensuring the memories your agent trusts are actually legitimate.

## Features

| Feature | Description |
|---------|-------------|
| 🏷️ **Memory Watermarking** | Embed imperceptible cryptographic watermarks to verify memory provenance |
| 🛡️ **Poisoning Detection** | Detect instruction injection, behavioral manipulation, and tool-drift attacks |
| 🔍 **Provenance Verification** | Track and verify the origin chain of every memory entry |
| 📋 **Integrity Manifests** | Generate SHA-256 manifests for memory state verification |
| 📊 **Memory Diff** | Compare memory states to detect unauthorized changes |
| 🔬 **Memory Forensics** | Analyze temporal, content, and source patterns for anomalies |
| 📝 **Policy Generation** | Generate protection policies compatible with MCPGuard |

## Installation

```bash
pip install memmark-agent
```

## Quick Start

### Scan memory for integrity issues

```bash
memmark scan memory.json
```

### Inject watermarks into memory

```bash
memmark watermark memory.json --action inject --key my-secret-key
```

### Detect watermarks

```bash
memmark watermark memory.json --action detect --key my-secret-key
```

### Generate integrity manifest

```bash
memmark manifest memory.json -o manifest.json
```

### Verify memory against manifest

```bash
memmark verify memory.json --manifest manifest.json
```

### Compare memory states

```bash
memmark diff before.json after.json
```

### Generate MCPGuard protection policy

```bash
memmark generate-policy memory.json -o mcpguard-policy.yaml
```

## Python API

```python
from memmark import Finding, Severity, run_full_scan
from memmark.watermark.injector import WatermarkInjector
from memmark.integrity.manifest import IntegrityManifest

memories = [{"id": "mem-001", "content": "User likes dark mode"}]

# Full scan — runs poisoning, watermark, and forensic detection
result = run_full_scan(memories, watermark_key="my-secret")
if result.is_clean:
    print("Memory is clean")
else:
    for f in result.findings:
        print(f"  [{f.severity.value}] {f.description}")

# Inject watermarks
injector = WatermarkInjector(secret_key="my-secret")
watermarked = injector.inject(memories)

# Generate integrity manifest
manifest = IntegrityManifest.create(memories, source="agent_memory.json")
manifest.save("manifest.json")
```

## Architecture

```
memmark/
├── scanner.py          # Core scanning engine + run_full_scan() orchestrator
├── cli.py              # Typer CLI (scan, watermark, verify, manifest, diff, generate-policy)
├── watermark/
│   ├── injector.py     # HMAC-SHA256 watermark injection
│   ├── detector.py     # Watermark detection & verification
│   └── robustness.py   # Robustness testing against transformations
├── poisoning/
│   ├── detector.py     # Pattern-based poisoning detection
│   ├── classifier.py   # Attack type classification (7 types)
│   └── remediation.py  # Automated remediation actions
├── provenance/
│   ├── tracker.py      # Provenance chain tracking
│   ├── verifier.py     # Chain integrity verification
│   └── graph.py        # Provenance dependency graph with anomaly detection
├── integrity/
│   ├── manifest.py     # SHA-256 integrity manifests
│   ├── diff.py         # Memory state comparison
│   └── forensics.py    # Temporal, content, source anomaly analysis
├── policy/
│   └── generator.py    # MCPGuard-compatible YAML policy generation
├── taxonomy/
│   └── adapter.py      # mcp-taxonomy integration (memmark_finding_to_taxonomy)
├── reporters/
│   ├── console.py      # Rich console output
│   ├── json.py         # JSON export
│   └── html.py         # HTML report generation
└── utils/
    └── crypto.py       # SHA-256, HMAC utilities
```

## Academic Foundation

MemMark is based on cutting-edge research in AI agent memory security:

- **arXiv:2605.25073** — "MemMark: State-Evolution Attribution Watermarking for Agent Long-Term Memory Systems" (Zhang et al.)
- **arXiv:2605.24941** — "Memory-Induced Tool-Drift in LLM Agents" (Dabas et al.)
- **arXiv:2605.25717** — "SAMark: A Self-Anchored Text Watermarking with Paragraph-Level Paraphrase Robustness"
- **MITRE ATLAS** — Agent Memory Attack Patterns

## Ecosystem Integration

| Project | Integration |
|---------|-------------|
| [MCPGuard](https://github.com/Carlos-Projects/mcpguard) | MemMark generates memory protection policies |
| [MCPscop](https://github.com/Carlos-Projects/mcpscope) | MemMark reports are consumable by MCPscop dashboard |
| [reverse-abliterate](https://github.com/Carlos-Projects/reverse-abliterate) | Complementary integrity scanning (models vs memory) |
| [mcp-taxonomy](https://github.com/Carlos-Projects/mcp-taxonomy) | Standardized finding classification |

## CLI Commands

```
memmark scan <file>            Scan memory for integrity issues
memmark watermark <file>       Inject, detect, or verify watermarks
memmark verify <file>          Verify memory against manifest
memmark manifest <file>        Generate integrity manifest
memmark diff <before> <after>  Compare two memory states
memmark generate-policy <file> Generate MCPGuard-compatible protection policy
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
python -m pytest tests/ -v

# Lint
ruff check src/ tests/

# Build
python -m build
```

## License

MIT — See [LICENSE](LICENSE) for details.

## Author

Carlos Rocha — [GitHub](https://github.com/Carlos-Projects)
