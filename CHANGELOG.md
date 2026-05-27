# Changelog

## [0.2.0] — 2026-05-26

### Added
- Composable `ScanPipeline` with `ScanStage` classes (PoisoningStage, WatermarkStage, ForensicsStage)
- Async support via `ScanPipeline.arun()` using `asyncio.to_thread`
- `MemoryStore` ABC with `FileMemoryStore`, `InMemoryMemoryStore` implementations
- `MemoryScanner.load_memory()` now accepts `MemoryStore` instances
- Configurable poisoning patterns via `PoisoningDetector(config_path=...)` YAML loading
- Structured logging module (`memmark.utils.logging`) with JSON formatter and correlation IDs
- 18 E2E integration tests exercising real CLI subprocess + API pipelines
- `Makefile` with standardized commands (test, lint, typecheck, coverage, docs, build)
- `python -m memmark` entry point via `__main__.py`
- GitHub Actions `Docs` workflow for GitHub Pages deployment
- Migration guide for v0.1.0 → v0.2.0
- README updated with full v0.2.0 API and architecture

### Fixed
- Legacy HMAC signature detection: now correctly checks signature length (96 vs 64 chars) instead of using `bytes.fromhex` try/except which silently broke 64-char legacy signatures
- YAML syntax in `default_patterns.yaml` (patterns with colons were unparseable)
- All pre-commit hooks passing (ruff, mypy, check-yaml, trailing-whitespace)
- CLI `scan` option renamed to `--watermark-key` / `-k` for consistency

### Quality
- 275 tests, 96% coverage, 0 ruff errors, 0 mypy errors
- pre-commit: ruff + ruff-format + check-json + check-yaml + end-of-file-fixer + trailing-whitespace + mypy

## [0.1.0] — 2026-05-25

### Added
- Watermark injection and detection with HMAC-SHA256 + PBKDF2
- Poisoning detection (instruction injection and behavioral manipulation)
- Provenance graph tracking with cycle detection
- Integrity manifests for memory state verification
- Memory diffing between states
- Memory forensics and anomaly detection
- MCPGuard-compatible policy generation
- mcp-taxonomy adapter for ecosystem interoperability
- CLI with 6 commands: scan, watermark, verify, manifest, diff, generate-policy
- Python API with full type hints and pydantic validation
- 243 tests with 97% coverage
- GitHub Actions CI (ruff, pytest, coverage, CodeQL, mypy)
- PyPI trusted publishing via OIDC
- Cryptographic hardening: PBKDF2-SHA256 (100k iters), CSPRNG salt, constant-time compare
- Memory schema validation via Pydantic `MemoryEntry` model
- PII-safe content previews (50-char truncation)
