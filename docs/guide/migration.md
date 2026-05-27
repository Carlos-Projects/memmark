# Migration Guide

## v0.1.0 → v0.2.0

### Signature Format (Breaking)

v0.2.0 fixes the legacy HMAC signature detection bug. If you have watermarked memories from v0.1.0, detection now correctly verifies them:

- **64-char signatures** (v0.1.0 legacy format, no salt) — detected as legacy, verified with bare HMAC-SHA256
- **96-char signatures** (v0.2.0 new format, 32 salt + 64 HMAC) — salt-extracted, verified with PBKDF2-derived key

No migration action needed — both formats are auto-detected.

### API Changes

**New public symbols** (add to imports):

```python
# v0.2.0 additions
from memmark import (
    ScanPipeline,        # Composable scan pipeline
    ScanStage,           # Abstract pipeline stage
    PipelineContext,     # Pipeline execution context
    MemoryStore,         # ABC for memory backends
    FileMemoryStore,     # File-backed store
    InMemoryMemoryStore, # In-memory store
    configure_logging,   # Structured logging setup
    get_logger,          # MemMark logger
    correlation_id,      # Pipeline tracing ID
)
```

**Deprecated**: None.

### CLI Changes

The `scan` command now uses `-k` / `--watermark-key` (previously `--key` was ambiguous between commands).

```bash
# v0.1.0
memmark scan memory.json --key my-key     # Error: no such option

# v0.2.0
memmark scan memory.json -k my-key         # OK
memmark scan memory.json --watermark-key my-key  # OK (explicit)
```

The `watermark` command continues to use `--key` / `-k`:

```bash
memmark watermark memory.json --action detect --key my-key  # unchanged
```

### Configuration Files

Poisoning patterns can now be loaded from YAML:

```yaml
# custom_patterns.yaml
injection:
  - pattern: '(?i)\bcustom\s+pattern\s+here'
    description: My custom injection pattern
```

```python
detector = PoisoningDetector(config_path="custom_patterns.yaml")
```
