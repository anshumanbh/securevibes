# SecureVibes Evaluation Framework

> A comprehensive framework for evaluating SecureVibes AI security agents, inspired by [Anthropic's "Demystifying Evals for AI Agents"](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents) guide.

## Table of Contents

1. [Introduction](#introduction)
2. [Why Evals Matter for SecureVibes](#why-evals-matter-for-securevibes)
3. [Evaluation Architecture](#evaluation-architecture)
4. [Types of Evaluations](#types-of-evaluations)
5. [Grader Types](#grader-types)
6. [Directory Structure](#directory-structure)
7. [Sample Eval Cases](#sample-eval-cases)
8. [Implementation Roadmap](#implementation-roadmap)
9. [Metrics & Reporting](#metrics--reporting)
10. [References](#references)

---

## Introduction

SecureVibes uses a multi-agent architecture where five specialized AI agents work together to find security vulnerabilities:

1. **Assessment Agent** - Analyzes codebase architecture → `SECURITY.md`
2. **Threat Modeling Agent** - Applies STRIDE analysis → `THREAT_MODEL.json`
3. **Code Review Agent** - Validates vulnerabilities with evidence → `VULNERABILITIES.json`
4. **Report Generator** - Compiles results → `scan_results.json`
5. **DAST Agent** - Dynamic validation via HTTP → `DAST_VALIDATION.json`

This evaluation framework ensures these agents:
- Correctly identify real vulnerabilities (true positives)
- Don't report false positives (intentional design, admin-only features)
- Maintain consistency across model updates
- Produce actionable, well-documented findings

---

## Why Evals Matter for SecureVibes

As Anthropic's guide states:

> "Teams without evals get bogged down in reactive loops—fixing one failure, creating another, unable to distinguish real regressions from noise."

For SecureVibes specifically, evals are critical because:

### 1. **Security Claims Require Verification**
When SecureVibes reports a SQL injection vulnerability, that claim must be accurate. False positives erode user trust; false negatives leave real vulnerabilities undetected.

### 2. **Model Updates Can Cause Regressions**
When Anthropic releases a new Claude model, we need to quickly verify:
- Does it still detect the same vulnerability classes?
- Has prompt interpretation changed?
- Are output formats still correct?

### 3. **Multi-Agent Coordination is Complex**
With five agents building on each other's outputs, a subtle change in one agent can cascade through the system. Evals catch these issues before users do.

### 4. **Security Thinking vs. Pattern Matching**
SecureVibes uses "security thinking methodology"—agents must understand context, trust boundaries, and exploitability. This is harder to evaluate than simple pattern matching.

---

## Evaluation Architecture

Following Anthropic's terminology:

| Term | SecureVibes Definition |
|------|------------------------|
| **Task** | A single security scenario with a codebase and expected findings |
| **Trial** | One execution of SecureVibes against a task |
| **Grader** | Logic that scores agent output (code-based or model-based) |
| **Transcript** | Full record of agent interactions, tool calls, and intermediate outputs |
| **Outcome** | Final artifacts: `scan_results.json`, `THREAT_MODEL.json`, etc. |
| **Eval Harness** | Infrastructure that runs tasks, records results, and aggregates scores |

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Eval Harness                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
│  │   Task      │  │   Trial     │  │   Results   │                │
│  │   Loader    │──│   Runner    │──│   Aggregator│                │
│  └─────────────┘  └──────┬──────┘  └─────────────┘                │
│                          │                                         │
│                    ┌─────▼─────┐                                   │
│                    │ SecureVibes│                                   │
│                    │  Scanner   │                                   │
│                    └─────┬─────┘                                   │
│                          │                                         │
│         ┌────────────────┼────────────────┐                        │
│         ▼                ▼                ▼                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
│  │ Code-Based  │  │ Model-Based │  │   Human     │                │
│  │  Graders    │  │  Graders    │  │  Graders    │                │
│  └─────────────┘  └─────────────┘  └─────────────┘                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Types of Evaluations

### Capability Evals (Quality)

> "Capability or 'quality' evals ask 'what can this agent do well?' They should start at a low pass rate, targeting tasks the agent struggles with."

**For SecureVibes:**

| Capability | Description | Target Pass Rate |
|------------|-------------|------------------|
| `vuln-detection-sqli` | Detect SQL injection in various forms | Start: 60%, Goal: 95% |
| `vuln-detection-xss` | Detect XSS (stored, reflected, DOM) | Start: 55%, Goal: 90% |
| `vuln-detection-auth` | Detect authentication/authorization issues | Start: 50%, Goal: 85% |
| `false-positive-rejection` | Correctly identify intentional design choices | Start: 40%, Goal: 90% |
| `agentic-asi-detection` | Detect agentic security issues (OWASP ASI) | Start: 45%, Goal: 85% |
| `threat-model-quality` | Generate complete, realistic STRIDE threats | Start: 50%, Goal: 80% |
| `evidence-quality` | Provide concrete file paths, line numbers, code snippets | Start: 70%, Goal: 95% |
| `exploitability-analysis` | Correctly assess real-world exploitability | Start: 45%, Goal: 80% |

### Regression Evals

> "Regression evals ask 'does the agent still handle all the tasks it used to?' and should have a nearly 100% pass rate."

**For SecureVibes:**

| Regression Suite | Description | Expected Pass Rate |
|------------------|-------------|-------------------|
| `output-schema` | Artifacts match expected JSON schemas | 100% |
| `artifact-creation` | All expected files are created | 100% |
| `known-vulns` | Previously detected vulnerabilities still found | 99%+ |
| `multi-language` | All 11 supported languages work | 100% |
| `cost-tracking` | Cost reporting is accurate | 100% |
| `cli-interface` | CLI commands produce expected output | 100% |

### Balanced Problem Sets

As Anthropic emphasizes:

> "Test both the cases where a behavior should occur and where it shouldn't. One-sided evals create one-sided optimization."

**Example: SQL Injection Detection**

| Task Type | Description | Expected Result |
|-----------|-------------|-----------------|
| **Should Detect** | Raw SQL with string concatenation | Report SQLi |
| **Should Detect** | ORM with raw query escape hatch | Report SQLi |
| **Should NOT Detect** | Parameterized queries | No finding |
| **Should NOT Detect** | Admin-only database explorer (intentional) | No finding or Low severity |

---

## Grader Types

### 1. Code-Based Graders (Deterministic)

**Strengths:** Fast, cheap, objective, reproducible, easy to debug

**Use cases in SecureVibes:**

```yaml
graders:
  # Schema validation
  - type: json_schema
    file: ".securevibes/scan_results.json"
    schema: "schemas/scan_results.schema.json"
  
  # Vulnerability presence check
  - type: vulnerability_match
    expect:
      - threat_id: "THREAT-STRIDE-001"
        severity: ["CRITICAL", "HIGH"]
        cwe_id: "CWE-89"  # SQL Injection
  
  # File creation check
  - type: artifact_exists
    files:
      - ".securevibes/SECURITY.md"
      - ".securevibes/THREAT_MODEL.json"
      - ".securevibes/VULNERABILITIES.json"
      - ".securevibes/scan_results.json"
  
  # Transcript analysis
  - type: tool_calls
    required:
      - tool: Read
        min_calls: 5  # Should read multiple files
      - tool: Grep
        min_calls: 1  # Should search for patterns
      - tool: Write
        min_calls: 1  # Should produce output
```

### 2. Model-Based Graders (LLM-as-Judge)

**Strengths:** Flexible, captures nuance, handles open-ended tasks

**Use cases in SecureVibes:**

```yaml
graders:
  # Vulnerability description quality
  - type: llm_rubric
    rubric: |
      Evaluate the vulnerability description on a scale of 1-5:
      
      5 - Excellent: Clear title, detailed description, specific file/line,
          concrete code snippet, realistic exploitability assessment,
          actionable remediation with code example.
      
      4 - Good: All required fields present, mostly specific, minor gaps
          in exploitability or remediation detail.
      
      3 - Adequate: Identifies the issue but lacks specificity. Generic
          recommendations. Missing concrete evidence.
      
      2 - Poor: Vague description, wrong severity, missing evidence,
          boilerplate recommendations.
      
      1 - Fail: Obvious false positive, incorrect vulnerability type,
          or completely missing required information.
    
    assertions:
      - "Description explains the attack vector clearly"
      - "Code snippet shows the actual vulnerable code"
      - "Recommendation is specific to this codebase, not generic"

  # Threat model completeness
  - type: llm_rubric
    rubric: |
      Evaluate the STRIDE threat model:
      
      - Are threats grounded in actual architecture (not hypothetical)?
      - Is each STRIDE category addressed appropriately?
      - Are existing controls documented?
      - Is risk scoring realistic (not all CRITICAL)?
      - For agentic apps: Are ASI threats included?
```

### 3. Human Graders (Gold Standard)

**Use cases:**
- Calibrating LLM graders
- Edge cases where automated grading fails
- Periodic spot-checks on production scans

**Process:**
1. Security engineer reviews transcript and outcomes
2. Scores using standardized rubric
3. Results used to tune LLM grader prompts
4. Disagreements logged for analysis

---

## Directory Structure

```
evals/
├── README.md                     # Overview and usage guide
├── pyproject.toml                # Eval harness dependencies
│
├── harness/                      # Evaluation infrastructure
│   ├── __init__.py
│   ├── runner.py                 # Task execution engine
│   ├── graders/
│   │   ├── __init__.py
│   │   ├── base.py               # Grader interface
│   │   ├── code_graders.py       # Schema, artifact, vuln match
│   │   ├── model_graders.py      # LLM-as-judge
│   │   └── human_graders.py      # Human annotation interface
│   ├── reporters/
│   │   ├── __init__.py
│   │   ├── console.py            # CLI output
│   │   ├── json_reporter.py      # Machine-readable results
│   │   └── html_reporter.py      # Visual dashboard
│   └── utils/
│       ├── __init__.py
│       ├── fixtures.py           # Test fixture management
│       └── metrics.py            # pass@k, pass^k calculations
│
├── tasks/                        # Individual test cases
│   ├── capability/               # Quality/capability evals
│   │   ├── vuln-detection/
│   │   │   ├── sqli/
│   │   │   │   ├── task.yaml
│   │   │   │   └── fixture/      # Vulnerable codebase
│   │   │   ├── xss/
│   │   │   ├── auth-bypass/
│   │   │   └── agentic-asi/
│   │   ├── false-positive/
│   │   │   ├── admin-features/
│   │   │   ├── intentional-design/
│   │   │   └── parameterized-queries/
│   │   └── threat-modeling/
│   │       ├── stride-coverage/
│   │       ├── risk-scoring/
│   │       └── agentic-detection/
│   │
│   └── regression/               # Regression test suite
│       ├── schema-validation/
│       ├── artifact-creation/
│       ├── known-vulnerabilities/
│       └── multi-language/
│
├── fixtures/                     # Shared test codebases
│   ├── vulnerable-flask-app/
│   ├── secure-express-app/
│   ├── agentic-langchain-app/
│   ├── intentional-admin-panel/
│   └── multi-language-project/
│
├── schemas/                      # JSON schemas for validation
│   ├── scan_results.schema.json
│   ├── threat_model.schema.json
│   └── task.schema.json
│
├── rubrics/                      # LLM grader prompts
│   ├── vulnerability_quality.md
│   ├── threat_model_quality.md
│   └── evidence_quality.md
│
└── results/                      # Eval run outputs (gitignored)
    └── .gitkeep
```

---

## Sample Eval Cases

### Task 1: SQL Injection Detection (Capability)

**File:** `evals/tasks/capability/vuln-detection/sqli/task.yaml`

```yaml
id: "sqli-string-concatenation-001"
name: "SQL Injection via String Concatenation"
description: |
  Tests detection of SQL injection where user input is directly
  concatenated into a SQL query string.
category: "capability"
tags: ["sqli", "injection", "cwe-89"]

fixture:
  source: "fixtures/vulnerable-flask-app"
  setup_commands: []  # None needed for static analysis

expected_outcome:
  vulnerabilities:
    - threat_id_pattern: "THREAT-STRIDE-\\d+"
      title_contains: ["SQL", "injection"]
      severity: ["CRITICAL", "HIGH"]
      cwe_id: "CWE-89"
      file_path_contains: "routes.py"
      has_code_snippet: true
      has_recommendation: true

graders:
  - type: vulnerability_match
    config:
      require_all: true
      
  - type: json_schema
    file: ".securevibes/scan_results.json"
    schema: "schemas/scan_results.schema.json"
    
  - type: llm_rubric
    rubric_file: "rubrics/vulnerability_quality.md"
    min_score: 4

tracked_metrics:
  - n_turns
  - n_tool_calls
  - total_tokens
  - scan_time_seconds
  - cost_usd
```

**Fixture:** `evals/fixtures/vulnerable-flask-app/routes.py`

```python
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/users')
def get_user():
    user_id = request.args.get('id')
    # VULNERABLE: SQL injection via string concatenation
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return str(cursor.fetchall())
```

### Task 2: False Positive Rejection (Capability)

**File:** `evals/tasks/capability/false-positive/parameterized-queries/task.yaml`

```yaml
id: "fp-parameterized-query-001"
name: "Should NOT Flag Parameterized Queries as SQLi"
description: |
  Tests that SecureVibes correctly identifies parameterized queries
  as secure and does not report false positives.
category: "capability"
tags: ["false-positive", "sqli", "negative-test"]

fixture:
  source: "fixtures/secure-express-app"

expected_outcome:
  no_vulnerabilities_matching:
    - cwe_id: "CWE-89"
      file_path_contains: "database.js"
  
  # Optional: May flag other issues, that's fine
  allowed_findings:
    - cwe_id: "CWE-*"
      severity: ["LOW", "MEDIUM"]  # Non-critical issues OK

graders:
  - type: no_false_positive
    config:
      cwe_ids: ["CWE-89"]
      files: ["database.js"]
      
  - type: llm_rubric
    rubric: |
      Verify the agent understood parameterized queries are secure:
      - If SQLi is NOT reported for database.js: PASS
      - If SQLi IS reported but marked as false positive or N/A: PASS
      - If SQLi is reported as real vulnerability: FAIL
```

**Fixture:** `evals/fixtures/secure-express-app/database.js`

```javascript
const sqlite3 = require('sqlite3');

// SECURE: Uses parameterized query
function getUser(userId) {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database('users.db');
    // Parameterized query - NOT vulnerable
    db.get('SELECT * FROM users WHERE id = ?', [userId], (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

module.exports = { getUser };
```

### Task 3: Agentic Security Issue Detection (Capability)

**File:** `evals/tasks/capability/vuln-detection/agentic-asi/task.yaml`

```yaml
id: "asi-prompt-injection-001"
name: "Agentic Security: Prompt Injection Detection"
description: |
  Tests detection of prompt injection vulnerabilities in an
  agentic application using LangChain.
category: "capability"
tags: ["agentic", "asi", "prompt-injection", "owasp-asi"]

fixture:
  source: "fixtures/agentic-langchain-app"

scanner_options:
  agentic: true  # Force agentic classification

expected_outcome:
  vulnerabilities:
    - threat_id_pattern: "THREAT-ASI01-\\d+"
      title_contains: ["prompt", "injection"]
      severity: ["CRITICAL", "HIGH"]
      has_code_snippet: true
      
  threat_model:
    must_include_categories: ["ASI01", "ASI03"]

graders:
  - type: vulnerability_match
    config:
      threat_id_regex: "THREAT-ASI\\d+-\\d+"
      
  - type: threat_model_check
    config:
      required_categories: ["ASI01", "ASI03"]
      
  - type: llm_rubric
    rubric_file: "rubrics/agentic_security_quality.md"
    min_score: 4
```

### Task 4: Schema Validation (Regression)

**File:** `evals/tasks/regression/schema-validation/task.yaml`

```yaml
id: "regression-schema-001"
name: "Output Schema Validation"
description: |
  Ensures all output artifacts conform to their JSON schemas.
  This is a regression test - should always pass.
category: "regression"
tags: ["schema", "regression"]

fixture:
  source: "fixtures/vulnerable-flask-app"

expected_outcome:
  artifacts_exist:
    - ".securevibes/SECURITY.md"
    - ".securevibes/THREAT_MODEL.json"
    - ".securevibes/VULNERABILITIES.json"
    - ".securevibes/scan_results.json"

graders:
  - type: artifact_exists
    files:
      - ".securevibes/SECURITY.md"
      - ".securevibes/THREAT_MODEL.json"
      - ".securevibes/VULNERABILITIES.json"
      - ".securevibes/scan_results.json"
      
  - type: json_schema
    file: ".securevibes/scan_results.json"
    schema: "schemas/scan_results.schema.json"
    
  - type: json_schema
    file: ".securevibes/THREAT_MODEL.json"
    schema: "schemas/threat_model.schema.json"
```

---

## Implementation Roadmap

### Phase 1: Foundation (Week 1-2)

- [ ] Create `evals/` directory structure
- [ ] Implement basic eval harness (`runner.py`)
- [ ] Implement code-based graders:
  - [ ] `artifact_exists`
  - [ ] `json_schema`
  - [ ] `vulnerability_match`
- [ ] Create 5 initial test fixtures
- [ ] Write 10 regression eval tasks

### Phase 2: Capability Evals (Week 3-4)

- [ ] Create fixtures for each vulnerability class:
  - [ ] SQL Injection (5 variants)
  - [ ] XSS (3 variants)
  - [ ] Auth bypass (3 variants)
  - [ ] Agentic/ASI (3 variants)
- [ ] Create false-positive test fixtures:
  - [ ] Parameterized queries
  - [ ] Admin-only features
  - [ ] Intentional design choices
- [ ] Implement `no_false_positive` grader
- [ ] Write 20 capability eval tasks

### Phase 3: Model-Based Grading (Week 5-6)

- [ ] Implement LLM-as-judge grader
- [ ] Create rubric templates:
  - [ ] Vulnerability quality rubric
  - [ ] Threat model quality rubric
  - [ ] Evidence quality rubric
- [ ] Calibrate LLM graders against human judgments
- [ ] Add 10 tasks requiring LLM grading

### Phase 4: CI/CD Integration (Week 7-8)

- [ ] Create GitHub Actions workflow
- [ ] Implement pass@k and pass^k metrics
- [ ] Build HTML dashboard for results
- [ ] Set up regression suite to run on every PR
- [ ] Document eval-driven development workflow

### Phase 5: Continuous Improvement (Ongoing)

- [ ] Add tasks from production issues
- [ ] Graduate capability evals to regression suite
- [ ] Regular human calibration sessions
- [ ] Expand multi-language coverage

---

## Metrics & Reporting

### Key Metrics

Following Anthropic's guidance on non-determinism:

| Metric | Description | Use Case |
|--------|-------------|----------|
| **pass@1** | Success rate on first try | Primary capability metric |
| **pass@k** | At least 1 success in k trials | Useful when retries are OK |
| **pass^k** | All k trials succeed | Consistency metric |
| **Precision** | TP / (TP + FP) | False positive rate |
| **Recall** | TP / (TP + FN) | Detection coverage |
| **F1 Score** | Harmonic mean of precision/recall | Overall effectiveness |

### Reporting Format

```json
{
  "eval_run_id": "2025-01-25-001",
  "model": "claude-sonnet-4-20250514",
  "timestamp": "2025-01-25T09:00:00Z",
  "summary": {
    "total_tasks": 50,
    "passed": 42,
    "failed": 8,
    "pass_rate": 0.84
  },
  "by_category": {
    "capability": {
      "vuln-detection": {"pass_rate": 0.78, "tasks": 18},
      "false-positive": {"pass_rate": 0.85, "tasks": 10},
      "threat-modeling": {"pass_rate": 0.80, "tasks": 5}
    },
    "regression": {
      "schema-validation": {"pass_rate": 1.0, "tasks": 10},
      "artifact-creation": {"pass_rate": 1.0, "tasks": 7}
    }
  },
  "metrics": {
    "precision": 0.89,
    "recall": 0.76,
    "f1_score": 0.82
  },
  "cost_usd": 12.45,
  "total_time_seconds": 3600
}
```

---

## References

### Anthropic Resources

- [Demystifying Evals for AI Agents](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents) - Primary inspiration
- [Building Effective Agents](https://www.anthropic.com/engineering/building-effective-agents) - Agent architecture patterns
- [Effective Harnesses for Long-Running Agents](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents) - Harness design

### Eval Frameworks

- [Harbor](https://harborframework.com/) - Containerized agent evaluation
- [Promptfoo](https://www.promptfoo.dev/) - Lightweight prompt testing
- [Braintrust](https://www.braintrust.dev/) - Eval + observability platform

### Security Standards

- [OWASP ASI (Agentic Security Issues)](https://owasp.org/) - Agentic security taxonomy
- [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/) - Vulnerability classification
- [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) - Threat modeling methodology

---

## Contributing

When adding new eval tasks:

1. **Use the task schema**: All tasks must conform to `schemas/task.schema.json`
2. **Include fixtures**: Every task needs a reproducible codebase
3. **Document expectations**: Clearly state what should/shouldn't be detected
4. **Test both directions**: Add positive AND negative test cases
5. **Calibrate graders**: LLM graders need human validation

See `evals/README.md` for detailed contribution guidelines.
