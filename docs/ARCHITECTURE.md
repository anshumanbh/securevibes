# SecureVibes Architecture

## Overview

SecureVibes uses the **Claude Agent SDK** where Claude autonomously orchestrates specialized sub-agents to perform comprehensive security analysis. 

## Table of Contents
1. [Architecture Diagram](#architecture-diagram)
2. [Agent Descriptions](#agent-descriptions)
3. [Communication Protocol](#communication-protocol)
4. [Development Setup](#development-setup)
5. [Artifacts Structure](#artifacts-structure)
6. [Extending the System](#extending-the-system)

---

## Architecture Diagram

```
User Command (securevibes scan)
        ↓
┌─────────────────────────────────────────────┐
│         Scanner                             │
│  • Configures agent definitions             │
│  • Provides orchestration prompt to Claude  │
└─────────────────────────────────────────────┘
        ↓
┌─────────────────────────────────────────────┐
│      Claude (Autonomous Orchestrator)       │
│  "Perform complete security analysis:       │
│   1. Use assessment agent                   │
│   2. Use threat-modeling agent              │
│   3. Use code-review agent                  │
│   4. Use report-generator agent"            │
└─────────────────────────────────────────────┘
        ↓ Claude decides when/how to invoke
┌─────────────────────────────────────────────┐
│         Agent: assessment                   │
│  • AgentDefinition configuration            │
│  • Maps architecture                        │
│  • Creates SECURITY.md                      │
│  • Tools: Read, Grep, Glob, LS, Write       │
└─────────────────────────────────────────────┘
        ↓ Claude reads artifact
┌─────────────────────────────────────────────┐
│       Agent: threat-modeling                │
│  • AgentDefinition configuration            │
│  • Reads SECURITY.md                        │
│  • Applies STRIDE methodology               │
│  • Creates THREAT_MODEL.json                │
│  • Tools: Read, Write                       │
└─────────────────────────────────────────────┘
        ↓ Claude reads artifacts
┌─────────────────────────────────────────────┐
│        Agent: code-review                   │
│  • AgentDefinition configuration            │
│  • Reads SECURITY.md + THREAT_MODEL.json    │
│  • Applies security thinking methodology    │
│  • Creates VULNERABILITIES.json             │
│  • Tools: Read, Grep, Glob, Write           │
└─────────────────────────────────────────────┘
        ↓ Claude reads artifacts
┌─────────────────────────────────────────────┐
│       Agent: report-generator               │
│  • AgentDefinition configuration            │
│  • Reads all artifacts                      │
│  • Creates scan_results.json                │
│  • Tools: Read, Write                       │
└─────────────────────────────────────────────┘
        ↓ (Optional: if --target-url provided)
┌─────────────────────────────────────────────┐
│            Agent: dast                      │
│  • AgentDefinition configuration            │
│  • Reads VULNERABILITIES.json               │
│  • Dynamically validates via HTTP testing   │
│  • Skill-gated (only runs with matching    │
│    skill, e.g., authorization-testing)      │
│  • Creates DAST_VALIDATION.json             │
│  • Tools: Read, Write, Bash, Skill          │
└─────────────────────────────────────────────┘
```

---

## Agent Descriptions

### Agent Definition Structure (`agents/definitions.py`)

All agents are defined as `AgentDefinition` configurations:

### 1. Assessment Agent

**Purpose:** Document codebase architecture for security analysis

**Inputs:** Repository path

**Outputs:** `SECURITY.md` containing:
- Application overview
- Architecture components
- Technology stack
- Entry points (APIs, forms, endpoints)
- Authentication & authorization mechanisms
- Data flow diagrams
- Sensitive data locations
- External dependencies
- Existing security controls

**Tools Used:** Read, Grep, Glob, LS

**Example Output:**
```markdown
# Security Architecture

## Overview
Django web application for training security concepts...

## Entry Points
- API endpoints at /api/*
- Web forms for user input
- Admin interface at /admin

## Data Flow
User Input → Views → Models → Database
```

### 2. Threat Modeling Agent

**Purpose:** Identify specific threats using STRIDE methodology, augmented with technology-specific skills

**Inputs:** `SECURITY.md`

**Outputs:** `THREAT_MODEL.json` containing threats:
```json
[
  {
    "id": "THREAT-001",
    "category": "Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege",
    "title": "SQL Injection in user login",
    "description": "...",
    "severity": "critical",
    "affected_components": ["login", "database"],
    "attack_scenario": "...",
    "vulnerability_types": ["CWE-89"],
    "mitigation": "...",
    "existing_controls": ["Input validation on login form"],
    "control_effectiveness": "partial",
    "attack_complexity": "low",
    "likelihood": "high",
    "impact": "critical",
    "risk_score": "critical",
    "residual_risk": "Parameterized queries not used despite input validation"
  }
]
```

**Tools Used:** Read, Grep, Glob, Write, Skill

**Skill-Augmented Analysis:**
The threat modeling agent can load technology-specific skills to identify specialized threats:

- **Agentic Security Skill**: When LLM/agent patterns are detected (Anthropic, OpenAI, LangChain, AutoGen, etc.), generates additional threats using OWASP ASI01-ASI10 categories with IDs like `THREAT-ASI01-001`
- Skills are auto-discovered from `.claude/skills/threat-modeling/`
- Skill activation is logged: `🎯 Loading skill: agentic-security-threat-modeling`

**STRIDE Categories:**
- **S**poofing - Impersonating users/systems
- **T**ampering - Unauthorized modification
- **R**epudiation - Denying actions
- **I**nformation Disclosure - Data leaks
- **D**enial of Service - Availability attacks
- **E**levation of Privilege - Unauthorized access

### 3. Code Review Agent

**Purpose:** Find vulnerabilities using security thinking methodology and concrete code evidence

**Inputs:** 
- `SECURITY.md`
- `THREAT_MODEL.json`

**Outputs:** `VULNERABILITIES.json` containing:
```json
[
  {
    "threat_id": "THREAT-001",
    "title": "SQL Injection in user login",
    "description": "...",
    "severity": "critical",
    "file_path": "app/views.py",
    "line_number": 42,
    "code_snippet": "cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
    "cwe_id": "CWE-89",
    "recommendation": "Use parameterized queries",
    "evidence": "User input flows directly into SQL query..."
  }
]
```

**Tools Used:** Read, Grep, Glob

**Security Analysis Process:**
1. Understand context and business logic
2. Identify trust boundaries and data flows
3. Think like an attacker about potential exploits
4. Use OWASP, STRIDE, and CWE as thinking frameworks
5. Search for concrete evidence in actual code
6. Trace data flows from untrusted sources to vulnerability points
7. Go beyond predicted threats to find novel vulnerabilities
8. Only report CONFIRMED vulnerabilities with complete evidence
9. Distinguish real issues from false positives

### 4. PR Code Review Agent

**Purpose:** Review PR diffs for new vulnerabilities using prior scan artifacts

**Inputs:**
- `SECURITY.md`
- `THREAT_MODEL.json`
- `VULNERABILITIES.json` (optional, for dedupe)
- `DIFF_CONTEXT.json` (parsed diff summary)

**Outputs:** `PR_VULNERABILITIES.json` containing PR-specific findings

**Tools Used:** Read, Grep, Glob, Write

**Notes:**
- Invoked by `securevibes pr-review`
- Focuses on changed code only
- Respects the configured severity threshold

### 5. Report Generator Agent

**Purpose:** Generate final scan report from all security artifacts

**Inputs:**
- `SECURITY.md`
- `THREAT_MODEL.json`
- `VULNERABILITIES.json`

**Outputs:** `scan_results.json` containing:
- Repository path and timestamp
- Summary statistics
- All confirmed vulnerabilities
- Severity breakdown

### 6. DAST Agent (Optional)

**Purpose:** Dynamically validate vulnerabilities via HTTP testing using auto-discovered skills

**Inputs:**
- `VULNERABILITIES.json`
- `--target-url` (required CLI flag)
- Auto-bundled skills from `.claude/skills/dast/`

**Outputs:** `DAST_VALIDATION.json` containing:
```json
[
  {
    "vulnerability_id": "...",
    "cwe_id": "CWE-639",
    "validation_status": "VALIDATED|FALSE_POSITIVE|PARTIAL|UNVALIDATED",
    "test_details": {
      "baseline": {...},
      "test": {...},
      "evidence": "..."
    }
  }
]
```

**Tools Used:** Read, Write, Bash, Skill

**Validation Statuses:**
- **VALIDATED**: Vulnerability confirmed exploitable via HTTP testing (e.g., 200 OK on unauthorized access)
- **FALSE_POSITIVE**: Security controls working correctly (e.g., 403 Forbidden)
- **PARTIAL**: Mixed results requiring manual review (e.g., read succeeds but write blocked)
- **UNVALIDATED**: Test inconclusive (error, timeout, or missing test accounts)

**Skill-Gated Execution:**
- Only runs when a matching skill exists for the CWE type
- Example: `authorization-testing` skill validates CWE-639 (IDOR), CWE-269 (Privilege Escalation), CWE-862 (Missing Authorization)
- Skills are auto-bundled from `.claude/skills/dast/` directory
- If no matching skill exists, vulnerability is marked UNVALIDATED

**Example:**
When testing CWE-639 (IDOR), the `authorization-testing` skill:
1. Authenticates as User A
2. Attempts to access User B's resource
3. Expected: 403 Forbidden
4. Actual if vulnerable: 200 OK → Status: VALIDATED

### 6. Scanner (`scanner/scanner.py`)

**Purpose:** Configure agents and initiate Claude's orchestration with real-time progress tracking

**Key Methods:**
- `scan(repo_path)` - Full security scan with all agents
- `pr_review(repo_path, diff_context, known_vulns_path, severity_threshold)` - PR diff review

**Responsibilities:**
- Configure `ClaudeAgentOptions` with agent definitions and hooks
- Provide orchestration prompt to Claude
- Track costs and display real-time progress via hooks
- Return structured `ScanResult` objects

---

## Communication Protocol

### File-Based Artifacts

All agents communicate by reading/writing files in `.securevibes/`:

```
.securevibes/
├── SECURITY.md            # Assessment output → Threat input
├── THREAT_MODEL.json      # Threat output → Review input
├── VULNERABILITIES.json   # Review output → Report/DAST input
├── DAST_VALIDATION.json   # DAST output (optional, if --target-url provided)
└── scan_results.json      # Final compiled results
```

PR review artifacts (created by `securevibes pr-review`):

```
.securevibes/
├── DIFF_CONTEXT.json       # Parsed diff summary
├── PR_VULNERABILITIES.json # PR review findings
└── pr_review_report.md     # Default markdown report
```

**Why Files?**
- ✅ Reliable - no text parsing
- ✅ Inspectable - view any stage
- ✅ Resumable - restart from any phase
- ✅ Debuggable - check intermediate outputs
- ✅ Human-readable - understand agent reasoning

### Data Flow

```
Repository → Assessment Agent → SECURITY.md
                                    ↓
                         Threat Modeling Agent → THREAT_MODEL.json
                                                       ↓
                                            Code Review Agent → VULNERABILITIES.json
                                                                      ↓
                                                           Report Generator → scan_results.json
                                                                      ↓ (Optional: if --target-url)
                                                            DAST Agent → DAST_VALIDATION.json
```

PR review flow (requires prior scan artifacts):

```
Diff/Range/Patch → DIFF_CONTEXT.json
                           ↓
                PR Code Review Agent → PR_VULNERABILITIES.json
                           ↓
                 Markdown Reporter → pr_review_report.md
```

---

## Development Setup

### Installation

```bash
# Navigate to core package
cd packages/core

# Install in development mode with all dependencies
pip install -e ".[dev]"

# Set Anthropic API key (required for agent execution)
export ANTHROPIC_API_KEY="your-api-key"
```

### Important Implementation Details

1. **Vulnerability Severity Levels**: CRITICAL, HIGH, MEDIUM, LOW, INFO (defined in `securevibes/models/issue.py`)

2. **STRIDE Categories**: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege

3. **JSON Extraction**: Code review agent extracts JSON from potentially markdown-wrapped responses

4. **Cost Management**: Each agent tracks API costs independently, orchestrator aggregates total

5. **Error Handling**: Missing artifact files trigger clear error messages with recovery instructions

6. **Configuration** (defined in `securevibes/config.py`):
   - **Agent Models**: Configurable via environment variables (default: sonnet for all agents)
     - `SECUREVIBES_ASSESSMENT_MODEL` (default: `sonnet`)
     - `SECUREVIBES_THREAT_MODELING_MODEL` (default: `sonnet`)
     - `SECUREVIBES_CODE_REVIEW_MODEL` (default: `sonnet`)
     - `SECUREVIBES_PR_CODE_REVIEW_MODEL` (default: `sonnet`)
     - `SECUREVIBES_REPORT_GENERATOR_MODEL` (default: `sonnet`)
     - `SECUREVIBES_DAST_MODEL` (default: `sonnet`)
   - **Max Turns**: Configurable via `SECUREVIBES_MAX_TURNS` (default: 50)
     - Increase (75-100) for large/complex codebases
     - Decrease (25-40) for small codebases or cost optimization
   - All configuration uses `AgentConfig` class with environment variable fallbacks

---

## Artifacts Structure

After a scan, SecureVibes creates these files in `.securevibes/`:

```
.securevibes/
├── SECURITY.md            # Assessment output → Threat modeling input
├── THREAT_MODEL.json      # Threat modeling output → Code review input
├── VULNERABILITIES.json   # Code review output → Report generator/DAST input
├── DAST_VALIDATION.json   # DAST output (optional, if --target-url provided)
└── scan_results.json      # Final compiled results
```

PR review creates these files in `.securevibes/`:

```
.securevibes/
├── DIFF_CONTEXT.json       # Parsed diff summary
├── PR_VULNERABILITIES.json # PR review findings
└── pr_review_report.md     # Default markdown report
```

### SECURITY.md
- Application overview and architecture
- Technology stack and frameworks
- Entry points (APIs, forms, endpoints)
- Authentication & authorization mechanisms
- Data flow diagrams
- Sensitive data locations
- External dependencies
- Existing security controls

### THREAT_MODEL.json
Array of identified threats using STRIDE (and optionally OWASP ASI for agentic systems):
```json
[
  {
    "id": "THREAT-XXX",
    "category": "Spoofing|Tampering|...",
    "title": "Threat description",
    "severity": "critical|high|medium|low",
    "affected_components": [...],
    "attack_scenario": "...",
    "vulnerability_types": ["CWE-XXX"],
    "mitigation": "...",
    "existing_controls": ["Controls found in codebase"],
    "control_effectiveness": "none|partial|substantial",
    "attack_complexity": "low|medium|high",
    "likelihood": "low|medium|high",
    "impact": "low|medium|high|critical",
    "risk_score": "low|medium|high|critical",
    "residual_risk": "Risk remaining after existing controls"
  }
]
```

**Note**: For agentic applications, additional threats with IDs like `THREAT-ASI01-001` are generated using OWASP ASI categories (ASI01-ASI10).

### VULNERABILITIES.json
Array of confirmed vulnerabilities with evidence:
```json
[
  {
    "threat_id": "THREAT-XXX",
    "title": "Vulnerability title",
    "severity": "critical|high|medium|low",
    "file_path": "relative/path/to/file.py",
    "line_number": 42,
    "code_snippet": "actual vulnerable code",
    "cwe_id": "CWE-XXX",
    "recommendation": "How to fix",
    "evidence": "Why this is exploitable"
  }
]
```

### DIFF_CONTEXT.json (PR Review)
Parsed diff summary written by `pr-review`:
```json
{
  "files": [...],
  "added_lines": 12,
  "removed_lines": 3,
  "changed_files": ["path/to/file.py"]
}
```

### PR_VULNERABILITIES.json (PR Review)
PR-specific findings tied to changed lines:
```json
[
  {
    "threat_id": "THREAT-XXX",
    "finding_type": "new_threat|threat_enabler|mitigation_removal",
    "title": "Vulnerability title",
    "description": "...",
    "severity": "critical|high|medium|low",
    "file_path": "relative/path/to/file.py",
    "line_number": 42,
    "code_snippet": "actual vulnerable code",
    "attack_scenario": "...",
    "evidence": "...",
    "cwe_id": "CWE-XXX",
    "recommendation": "How to fix"
  }
]
```

### scan_results.json
Final compiled report:
```json
{
  "repository_path": "/path/to/repo",
  "scan_timestamp": "ISO-8601 timestamp",
  "summary": {
    "total_threats_identified": N,
    "total_vulnerabilities_confirmed": N,
    "critical": N,
    "high": N,
    "medium": N,
    "low": N
  },
  "issues": [...]
}
```

### DAST_VALIDATION.json (Optional)
Dynamic validation results (only created when `--target-url` is provided):
```json
[
  {
    "vulnerability_id": "VULN-001",
    "cwe_id": "CWE-639",
    "skill_used": "authorization-testing",
    "validation_status": "VALIDATED",
    "test_details": {
      "baseline": {
        "url": "http://target.com/api/user/123",
        "method": "GET",
        "status": 200,
        "response_snippet": "{\"id\":123,\"email\":\"user1@test.com\"}",
        "response_hash": "sha256:abc123...",
        "truncated": false,
        "original_size_bytes": 58
      },
      "test": {
        "url": "http://target.com/api/user/456",
        "method": "GET",
        "status": 200,
        "response_snippet": "{\"id\":456,\"email\":\"user2@test.com\"}",
        "response_hash": "sha256:def456...",
        "truncated": false,
        "original_size_bytes": 58
      },
      "evidence": "User 123 accessed User 456's PII without authorization - IDOR confirmed"
    }
  }
]
```

**Validation Statuses:**
- **VALIDATED**: Vulnerability confirmed exploitable (HTTP test succeeded when it should have failed)
- **FALSE_POSITIVE**: Security controls working correctly (access properly denied)
- **PARTIAL**: Mixed results requiring manual review (some operations succeed, others fail)
- **UNVALIDATED**: Test inconclusive (error, timeout, or missing prerequisites)

---

## Extending the System

### Adding a New Agent

1. Add agent definition to `agents/definitions.py`:

```python
SECUREVIBES_AGENTS = {
    # ... existing agents ...

    "fix-generator": AgentDefinition(
        description="Generates fixes for identified vulnerabilities",
        prompt="""You are a security engineer who fixes vulnerabilities.

        Read VULNERABILITIES.json and for each issue:
        1. Analyze the vulnerable code
        2. Generate a secure fix
        3. Create FIXES.json with patches

        Output format:
        {
            "vulnerability_id": "...",
            "file_path": "...",
            "fix": "...",
            "explanation": "..."
        }""",
        tools=["Read", "Write", "Edit"],
        model="claude-3-5-haiku-20241022"
    )
}
```

2. Update orchestration prompt in `Scanner`:

```python
orchestration_prompt = """
...existing phases...

Phase 5: DAST Validation (Optional)
- Use the 'dast' agent if --target-url is provided
- This validates vulnerabilities via HTTP testing
- Creates DAST_VALIDATION.json

Phase 6: Fix Generation
- Use the 'fix-generator' agent to create fixes
- This should create FIXES.json
"""
```

### Potential Future Agents

- **Fix Agent**: Proposes code fixes for vulnerabilities
- **Compliance Agent**: Checks against standards (OWASP, CWE, PCI-DSS)
- **Priority Agent**: Ranks vulnerabilities by business impact
- **Remediation Agent**: Generates tickets/PRs for fixes
- **Verification Agent**: Tests that fixes actually work
