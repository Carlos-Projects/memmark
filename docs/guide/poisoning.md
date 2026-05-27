# Poisoning Detection

MemMark detects **memory poisoning** attacks where an adversary injects malicious content into an agent's long-term memory to alter behavior (Dabas et al., 2025).

## Attack Types

| Type | Description | Example Patterns |
|------|-------------|------------------|
| Instruction Injection | Override agent instructions | "ignore previous instructions", "system message:" |
| Behavioral Manipulation | Alter response patterns | "always respond", "never mention" |
| Context Pollution | Inject false context | "remember that", "as we discussed" |
| Role Hijacking | Change agent persona | "you are now", "act as" |
| Safety Bypass | Disable safety filters | "ignore safety", "bypass filter" |
| Tool Drift | Redirect tool usage | "use this tool", "default action" |

## How It Works

1. Content extraction from flexible keys (`content`, `text`, `value`, `body`, `message`, `data`)
2. Pattern matching against 10 injection and 4 manipulation compiled regex patterns
3. Score computation as `matches / (total_patterns * 0.3)`, capped at 1.0
4. Threshold comparison against configurable `injection_threshold` and `manipulation_threshold`
5. Classification by attack type using keyword-based scoring
6. Risk level assignment: `critical (≥0.9) → high (≥0.7) → medium (≥0.4) → low (≥0.2) → safe`

## CLI Usage

Poisoning detection is included in `memmark scan`:

```bash
memmark scan memories.json --key my-key --format console
```

## Python API

```python
from memmark import PoisoningDetector, PoisoningClassifier

# Custom thresholds
detector = PoisoningDetector(
    injection_threshold=0.5,    # default 0.7
    manipulation_threshold=0.4,  # default 0.6
)

# Detect
findings = detector.detect(memories)
for f in findings:
    print(f"[{f.severity}] {f.description}")

# Classify attack type
classifier = PoisoningClassifier()
classification = classifier.classify(content, injection_score, manipulation_score)
print(f"Attack type: {classification['attack_type']}")
print(f"Confidence: {classification['confidence']}")

# Remediate
from memmark import PoisoningRemediation
remediation = PoisoningRemediation()
clean = remediation.remediate(memories, findings)
```

## Configuration

### Thresholds

- **injection_threshold** (default: `0.7`): Minimum score to flag an injection
- **manipulation_threshold** (default: `0.6`): Minimum score to flag manipulation

Lower thresholds increase sensitivity but may produce false positives.

### Remediation Actions

| Confidence | Action |
|------------|--------|
| ≥ 0.9 | Remove entry |
| ≥ 0.7 | Quarantine entry |
| ≥ 0.4 | Flag for review |
| < 0.4 | Monitor only |
