# CLI Reference

## Global Options

```text
--key TEXT      Secret key for watermark operations [required for watermark/scan]
--format TEXT   Output format: console | json [default: console]
--output PATH   Write output to file
--help          Show help message
--version       Show version
```

## Commands

### scan

Run a full security scan on memory entries.

```bash
memmark scan <MEMORY_FILE> --key <KEY> [--format json] [--output results.json]
```

Runs: watermark detection, poisoning detection, memory forensics, provenance verification.

### watermark

Inject or verify watermarks.

```bash
# Inject watermarks into memory entries
memmark watermark inject <INPUT> --key <KEY> --output <OUTPUT>

# Detect watermarks in memory entries
memmark watermark detect <INPUT> --key <KEY>

# Verify provenance of watermarked entries
memmark watermark verify <INPUT> --key <KEY>
```

### verify

Verify memory state against an integrity manifest.

```bash
memmark verify <MEMORY_FILE> <MANIFEST_FILE>
```

### manifest

Generate an integrity manifest for a memory state.

```bash
memmark manifest generate <MEMORY_FILE> [--output manifest.json]
```

### diff

Compare two memory states.

```bash
memmark diff <ORIGINAL> <MODIFIED> [--output diff.json]
```

### generate-policy

Generate an MCPGuard-compatible security policy from a scan result.

```bash
memmark generate-policy <SCAN_RESULT> --output policy.yaml
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (file not found, invalid JSON, missing key) |
