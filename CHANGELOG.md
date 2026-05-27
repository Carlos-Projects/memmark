# Changelog

## [0.1.0] — 2025-05-26

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
