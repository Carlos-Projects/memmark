# Security Model

## Threat Model

### Attacker Capabilities

- **Read access**: Can read the agent's memory file (JSON)
- **Write access**: Can write/modify the agent's memory file
- **Observation**: Can observe watermarked entries and their signatures
- **No key access**: Does NOT know the secret key

### Protected Assets

1. **Memory integrity** — Entries should not be tampered with undetected
2. **Provenance** — Entry origin should be verifiable
3. **Behavioral safety** — Malicious instructions should not alter agent behavior

## Defenses

### Watermarking (Forgery Prevention)

| Attack | Defense |
|--------|---------|
| Memory forgery | HMAC-SHA256 binds content to secret key |
| Tampering | Signature invalidated on any content change |
| Key brute force | PBKDF2-SHA256 (100k iterations) slows attempts |
| Signature replay | Random salt ensures unique signatures per entry |
| Signature stripping | `verify_provenance` detects missing watermarks |

### Poisoning Detection

| Attack | Defense |
|--------|---------|
| Instruction injection | Regex pattern matching (10 patterns) |
| Behavioral manipulation | Behavioral pattern detection (4 patterns) |
| Context pollution | Keyword-based classifier (6 attack types) |
| Coordinated injection | Temporal/content anomaly detection via forensics |

### Provenance & Integrity

| Attack | Defense |
|--------|---------|
| Chain tampering | SHA-256 chain hashing breaks on modification |
| Orphan entries | Graph anomaly detection flags missing parents |
| Cycle injection | Cycle-safe graph traversal prevents infinite loops |
| State rollback | Integrity manifests detect hash mismatches |

## Key Management

!!! danger "Secret Key"
    The `secret_key` is the root of all watermark security.

    - **No default key** — must be explicitly provided
    - **Length**: Minimum 16 characters recommended
    - **Storage**: Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, environment variables)
    - **Rotation**: Rotate keys periodically; maintain old keys for verification during transition
    - **Per-deployment**: Use different keys for development, staging, and production

## Cryptographic Details

```
Algorithm:      HMAC-SHA256
Key derivation: PBKDF2-SHA256, 100,000 iterations, 32-byte output
Salt:           16 bytes CSPRNG (os.urandom), embedded in signature
Comparison:     hmac.compare_digest (constant-time, no timing side-channel)
Format:         hex(salt)[:32] + hex(signature) = 96 hex chars
```

### Signature Verification Flow

1. Read `_memmark_sig` from entry
2. If 96 chars: extract salt from first 32 hex chars, compute HMAC with derived key, compare
3. If 64 chars: legacy format (before KDF upgrade), compute bare HMAC, compare
4. Otherwise: unknown format, reject

## Security Review History

All findings from the initial security review have been remediated:

| Finding | Fix |
|---------|-----|
| Default key hardcoded | Key is now mandatory |
| No KDF before HMAC | PBKDF2-SHA256 with 100k iterations |
| Missing constant-time compare | `hmac.compare_digest` |
| Content preview PII leak | Truncated to 50 chars |
| No schema validation | Pydantic `MemoryEntry` model |
| No SAST in CI | CodeQL workflow added |
