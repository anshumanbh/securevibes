# SecureVibes Evaluation Suite

> Comprehensive evaluation framework for SecureVibes AI security agents.

## Overview

This evaluation suite tests SecureVibes agents to ensure they:
- Correctly identify real vulnerabilities (true positives)
- Don't report false positives (secure code, intentional design)
- Maintain consistency across model updates
- Produce actionable findings with evidence

Based on [Anthropic's "Demystifying Evals for AI Agents"](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents).

## Quick Start

```bash
# Install eval dependencies
cd evals
pip install -e .

# Run all evals
python -m harness.runner --all

# Run specific category
python -m harness.runner --category capability

# Run single task
python -m harness.runner --task sqli-string-concatenation-001

# Run with verbose output
python -m harness.runner --all --verbose

# Run multiple trials for pass@k metrics
python -m harness.runner --all --trials 3
```

## Directory Structure

```
evals/
├── harness/          # Evaluation infrastructure
│   ├── runner.py     # Main eval execution engine
│   └── graders/      # Grading logic (code, model, human)
├── tasks/            # Individual test cases
│   ├── capability/   # Quality/capability tests
│   └── regression/   # Regression tests (should always pass)
├── fixtures/         # Test codebases
├── schemas/          # JSON validation schemas
├── rubrics/          # LLM grader prompts
└── results/          # Output from eval runs (gitignored)
```

## Task Categories

### Capability Evals
Tests what SecureVibes can do well. Start with low pass rates, improve over time.

- `vuln-detection/` - Vulnerability class detection
- `false-positive/` - Correctly rejecting secure code
- `threat-modeling/` - STRIDE analysis quality

### Regression Evals
Tests that existing functionality still works. Should have ~100% pass rate.

- `schema-validation/` - Output format correctness
- `artifact-creation/` - All files are created
- `known-vulnerabilities/` - Previously detected issues

## Writing Tasks

Each task is a YAML file with:

```yaml
id: "unique-task-id"
name: "Human-readable name"
description: "What this test verifies"
category: "capability|regression"
tags: ["sqli", "cwe-89"]

fixture:
  source: "fixtures/vulnerable-flask-app"

expected_outcome:
  vulnerabilities:
    - threat_id_pattern: "THREAT-STRIDE-\\d+"
      severity: ["CRITICAL", "HIGH"]

graders:
  - type: vulnerability_match
  - type: json_schema
    file: ".securevibes/scan_results.json"
```

See `docs/EVAL_FRAMEWORK.md` for complete documentation.

## Metrics

| Metric | Description |
|--------|-------------|
| pass@1 | Success on first try |
| pass@k | At least one success in k trials |
| pass^k | All k trials succeed |
| Precision | TP / (TP + FP) |
| Recall | TP / (TP + FN) |

## CI/CD Integration

The eval suite runs automatically:
- On every PR to `main`
- Nightly for comprehensive testing
- When models are updated

See `.github/workflows/evals.yml` for configuration.

## Contributing

1. Add tasks for bugs found in production
2. Include both positive and negative test cases
3. Calibrate LLM graders against human judgment
4. Document expected behavior clearly
