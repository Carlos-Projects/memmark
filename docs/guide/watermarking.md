# Watermarking

MemMark implements **state-evolution attribution watermarking** based on Zhang et al. (2025).

## How It Works

Each memory entry gets a cryptographic HMAC-SHA256 signature computed from:

1. A canonical JSON representation of the entry (sorted keys, no whitespace)
2. A **secret key** known only to the deployment
3. A **random salt** (16 bytes from `os.urandom`), stored in the first 32 hex chars of the signature

The signature is stored alongside the entry in `_memmark_sig` and `_memmark_wm` fields.

## Signature Format

```
96 hex chars = 32 (salt) + 64 (HMAC-SHA256)
```

The salt is derived through PBKDF2-SHA256 with 100,000 iterations:

```
derived_key = PBKDF2(secret_key, salt, 100000)
signature = HMAC-SHA256(derived_key, canonical_json)
```

## CLI Usage

```bash
# Inject watermarks
memmark watermark inject input.json --key my-key --output watermarked.json

# Detect watermarks
memmark watermark detect input.json --key my-key

# Verify provenance
memmark watermark verify input.json --key my-key --source preference
```

## Python API

```python
from memmark import WatermarkInjector, WatermarkDetector

# Inject
injector = WatermarkInjector(secret_key="my-key")
watermarked = injector.inject(memories)

# Detect
detector = WatermarkDetector(secret_key="my-key")
results = detector.detect(watermarked)
# Each result: {"valid": bool, "confidence": float, "reason": str}

# Verify provenance
provenance = detector.verify_provenance(watermarked, expected_source="preference")
```

## Security

!!! warning "Key Management"
    The `secret_key` is mandatory. There is no default — using a default key would make watermarks trivially forgeable.

    - Keys should be unique per deployment
    - Rotate keys periodically
    - Store keys in a secrets manager (never in code)

## Signature Evolution

Signatures are computed from the **canonical representation** of the entry, excluding the `_memmark_wm` and `_memmark_sig` fields themselves. This means:

- Adding or removing fields → invalidates the signature
- Reordering fields → does NOT invalidate (canonicalization sorts keys)
- Changing content → invalidates the signature

## Robustness Testing

```python
from memmark import WatermarkRobustnessTester

tester = WatermarkRobustnessTester(secret_key="my-key")
results = tester.test_robustness(memories, transformations=["reorder", "truncate"])
score = tester.compute_robustness_score(results)
```
