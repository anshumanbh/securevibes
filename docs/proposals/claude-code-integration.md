# SecureVibes AI Agent Integration Spec

**Status:** Proposal  
**Author:** SecureVibes Team  
**Created:** 2026-01-24  
**Version:** 4.0.0 (Skill-first architecture)

---

## TL;DR

SecureVibes as a **Claude Code skill** — not an MCP server wrapping a CLI wrapping Claude. The prompts and methodology ARE the product. Claude Code handles orchestration natively.

```
Before (wrapper-on-wrapper):
Claude Code → MCP Server → SecureVibes CLI → Claude CLI
                    ↑                              ↑
              Unnecessary              Redundant Claude call

After (skill-first):
Claude Code + SecureVibes Skill → Done
```

**MCP only needed for:** Platform integration (save findings, dashboard, history)

---

## Table of Contents

1. [Why Skill-First](#1-why-skill-first)
2. [Skill Architecture](#2-skill-architecture)
3. [Skill Contents](#3-skill-contents)
4. [Orchestration Flow](#4-orchestration-flow)
5. [Platform Integration (Optional MCP)](#5-platform-integration-optional-mcp)
6. [Codex Compatibility](#6-codex-compatibility)
7. [Implementation Plan](#7-implementation-plan)
8. [Migration Path](#8-migration-path)

---

## 1. Why Skill-First

### 1.1 The Problem with MCP-First

SecureVibes CLI is essentially a Claude wrapper with prompts. Building an MCP server that calls SecureVibes CLI means:

```
Claude Code → MCP → SecureVibes CLI → Claude API
```

This is redundant. We're asking Claude to call a tool that calls Claude.

### 1.2 What SecureVibes Actually Provides

| Component | What It Is | Can Be a Skill? |
|-----------|------------|-----------------|
| Threat modeling | Prompts + STRIDE methodology | ✅ Yes |
| Code review | Prompts + security patterns | ✅ Yes |
| Assessment | Prompts + checklist | ✅ Yes |
| Orchestration | Sequential agent execution | ✅ Claude Code does this natively |
| Output format | Structured findings (JSON) | ✅ Yes (prompt instructions) |

**Conclusion:** The value is in the prompts and methodology. Package that as a skill.

### 1.3 When MCP Is Actually Needed

MCP makes sense for things Claude can't do with prompts alone:

| Feature | Needs MCP? | Why |
|---------|------------|-----|
| Run security scan | ❌ No | It's just prompts |
| Save findings to platform | ✅ Yes | External API call |
| Query scan history | ✅ Yes | External data |
| CVE/vulnerability lookup | ✅ Yes | External database |
| SBOM scanning | ✅ Yes | External tooling |

---

## 2. Skill Architecture

### 2.1 Directory Structure

```
securevibes-skill/
├── SKILL.md                    # Main entry point
├── methodology/
│   ├── threat-modeling.md      # STRIDE, attack trees, etc.
│   ├── code-review.md          # Security patterns, CWEs
│   ├── assessment.md           # Security checklist
│   └── output-format.md        # How to structure findings
├── prompts/
│   ├── threat-model-prompt.md  # Detailed prompt for threat modeling
│   ├── code-review-prompt.md   # Detailed prompt for code review
│   └── assessment-prompt.md    # Detailed prompt for assessment
├── examples/
│   ├── sample-findings.json    # Example output format
│   └── sample-threat-model.md  # Example threat model
└── reference/
    ├── cwe-top-25.md           # Common weaknesses
    ├── owasp-top-10.md         # OWASP reference
    └── severity-guide.md       # How to rate severity
```

### 2.2 SKILL.md (Entry Point)

```markdown
# SecureVibes Security Review Skill

## Description
Comprehensive security review using threat modeling, code review, and security assessment.

## When to Use
- User asks for security review
- User asks about vulnerabilities
- PR review with security focus
- Threat modeling request

## Workflow

### Quick Scan (default)
1. Read the code/PR
2. Run code-review methodology
3. Output findings in structured format

### Full Security Review
1. **Assessment**: High-level security posture
2. **Threat Modeling**: STRIDE analysis, attack surface
3. **Code Review**: Line-by-line vulnerability scan
4. **Findings**: Compiled, deduplicated, prioritized

## Output Format
Always output findings as:
- Severity: critical/high/medium/low
- CWE ID (if applicable)
- Location: file:line
- Description: What's wrong
- Remediation: How to fix
- Confidence: high/medium/low

## Sub-Methodologies
- [Threat Modeling](methodology/threat-modeling.md)
- [Code Review](methodology/code-review.md)
- [Assessment](methodology/assessment.md)
```

---

## 3. Skill Contents

### 3.1 Threat Modeling Methodology

```markdown
# Threat Modeling Methodology

## Approach: STRIDE

For each component/data flow, analyze:

| Threat | Question | Example |
|--------|----------|---------|
| **S**poofing | Can attacker impersonate? | Auth bypass, session hijacking |
| **T**ampering | Can attacker modify data? | SQL injection, file manipulation |
| **R**epudiation | Can attacker deny actions? | Missing audit logs |
| **I**nformation Disclosure | Can attacker access secrets? | Data exposure, verbose errors |
| **D**enial of Service | Can attacker disrupt service? | Resource exhaustion |
| **E**levation of Privilege | Can attacker gain access? | Privilege escalation |

## Process

1. **Identify assets**: What are we protecting?
2. **Map attack surface**: Entry points, data flows
3. **Apply STRIDE**: For each entry point
4. **Prioritize**: By impact and likelihood
5. **Document**: Threats and mitigations

## Output Format

For each threat:
```json
{
  "threat": "SQL Injection in user search",
  "stride_category": "Tampering",
  "entry_point": "GET /api/users?search=",
  "impact": "high",
  "likelihood": "medium",
  "mitigation": "Use parameterized queries"
}
```
```

### 3.2 Code Review Methodology

```markdown
# Security Code Review Methodology

## Focus Areas

### 1. Input Validation
- [ ] All user input sanitized
- [ ] SQL queries parameterized
- [ ] File paths validated
- [ ] Command injection prevented

### 2. Authentication & Authorization
- [ ] Auth checks on all endpoints
- [ ] Session management secure
- [ ] Password handling correct
- [ ] RBAC properly implemented

### 3. Data Protection
- [ ] Secrets not hardcoded
- [ ] Encryption at rest/transit
- [ ] PII handled correctly
- [ ] Logs don't leak sensitive data

### 4. Error Handling
- [ ] Errors don't leak info
- [ ] Failures are secure defaults
- [ ] Exceptions properly caught

## Output Format

For each finding:
```json
{
  "severity": "high",
  "cwe": "CWE-89",
  "title": "SQL Injection",
  "location": "api/users.py:42",
  "code": "query = f\"SELECT * FROM users WHERE name = '{name}'\"",
  "description": "User input directly concatenated into SQL query",
  "remediation": "Use parameterized query: cursor.execute('SELECT * FROM users WHERE name = ?', (name,))",
  "confidence": "high"
}
```
```

### 3.3 Output Format Specification

```markdown
# SecureVibes Output Format

## Findings Array

```json
{
  "scan_type": "full_review",
  "timestamp": "2026-01-24T10:00:00Z",
  "summary": {
    "critical": 0,
    "high": 2,
    "medium": 5,
    "low": 3
  },
  "findings": [
    {
      "id": "SV-001",
      "severity": "high",
      "cwe": "CWE-89",
      "title": "SQL Injection in user search",
      "location": {
        "file": "api/users.py",
        "line": 42,
        "snippet": "query = f\"SELECT * FROM users WHERE name = '{name}'\""
      },
      "description": "User-controlled input is directly interpolated into SQL query without sanitization.",
      "impact": "Attacker can read/modify/delete database contents",
      "remediation": {
        "description": "Use parameterized queries",
        "code": "cursor.execute('SELECT * FROM users WHERE name = ?', (name,))"
      },
      "confidence": "high",
      "references": [
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://owasp.org/www-community/attacks/SQL_Injection"
      ]
    }
  ]
}
```

## Severity Definitions

| Severity | Criteria |
|----------|----------|
| Critical | RCE, auth bypass, data breach imminent |
| High | SQLi, XSS, privilege escalation |
| Medium | Information disclosure, missing security headers |
| Low | Best practice violations, minor issues |
```

---

## 4. Orchestration Flow

Claude Code handles orchestration natively. The skill just teaches the methodology.

### 4.1 User Request → Claude Code Response

```
User: "Review this PR for security issues"

Claude Code (with SecureVibes skill):
1. Reads SKILL.md → understands workflow
2. Reads code-review.md → knows methodology  
3. Applies methodology to PR
4. Outputs findings in specified format
```

### 4.2 Full Review Flow

```
User: "Do a full security review of this codebase"

Claude Code:
1. SKILL.md says: Assessment → Threat Model → Code Review → Compile
2. Runs assessment (reads assessment.md)
3. Runs threat modeling (reads threat-modeling.md)
4. Runs code review (reads code-review.md)
5. Compiles and deduplicates findings
6. Outputs in specified format
```

### 4.3 Example Conversation

```
User: "Check src/api/ for security vulnerabilities"

Claude: I'll perform a security code review using the SecureVibes methodology.

**Scanning src/api/...**

## Findings

### 🔴 HIGH: SQL Injection (CWE-89)
**Location:** `src/api/users.py:42`
```python
query = f"SELECT * FROM users WHERE name = '{name}'"
```
**Issue:** User input directly concatenated into SQL query
**Fix:** Use parameterized query:
```python
cursor.execute('SELECT * FROM users WHERE name = ?', (name,))
```

### 🟡 MEDIUM: Missing Rate Limiting
**Location:** `src/api/auth.py:15`
**Issue:** Login endpoint has no rate limiting
**Fix:** Add rate limiting middleware (e.g., 5 attempts per minute)

---
**Summary:** 1 high, 1 medium, 0 low
```

---

## 5. Platform Integration (Optional MCP)

MCP is **only** needed for features that require external state or APIs.

### 5.1 When to Use MCP

| Feature | Implementation |
|---------|----------------|
| Save findings to SecureVibes Platform | MCP tool: `securevibes_save_findings` |
| Query scan history | MCP tool: `securevibes_history` |
| CVE/NVD lookup | MCP tool: `securevibes_cve_lookup` |
| SBOM scanning | MCP tool: `securevibes_sbom_scan` |
| Team dashboard | MCP tool: `securevibes_dashboard` |

### 5.2 MCP Tools (Platform Features Only)

```typescript
// Only for platform integration, NOT for running scans

securevibes_save_findings({
  findings: Finding[],
  project: string,
  branch?: string
}) → { scan_id: string, dashboard_url: string }

securevibes_history({
  project: string,
  limit?: number
}) → { scans: Scan[] }

securevibes_cve_lookup({
  cve_id: string
}) → { cve: CVEDetails }
```

### 5.3 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Claude Code                                                 │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ SecureVibes Skill (installed)                       │   │
│  │  → Methodology, prompts, output format              │   │
│  │  → Claude Code handles orchestration                │   │
│  └─────────────────────────────────────────────────────┘   │
│                          ↓                                  │
│            [Findings generated locally]                     │
│                          ↓                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ SecureVibes MCP (optional)                          │   │
│  │  → Save findings to platform                        │   │
│  │  → Query history                                    │   │
│  │  → CVE lookup                                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                          ↓                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ SecureVibes Platform                                │   │
│  │  → Dashboard, history, team features                │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. Codex Compatibility

### 6.1 AGENTS.md for Codex

Codex uses AGENTS.md for project-level instructions. Include SecureVibes methodology:

```markdown
# AGENTS.md

## Security Review (SecureVibes)

When reviewing code or PRs for security:

1. Follow the SecureVibes methodology:
   - Input validation (SQLi, XSS, command injection)
   - Auth & authorization checks
   - Data protection (secrets, encryption)
   - Error handling (info leakage)

2. Output findings as structured JSON with:
   - severity (critical/high/medium/low)
   - cwe (if applicable)
   - location (file:line)
   - description, remediation, confidence

3. Policy:
   - Block PRs with critical findings
   - Require acknowledgment for high findings
   - Track medium/low as tech debt
```

### 6.2 Skill Distribution

| Platform | Installation |
|----------|-------------|
| Claude Code | Install skill via marketplace or local path |
| Codex CLI | Add to AGENTS.md or $CODEX_HOME/skills/ |
| Both | Skill files are portable |

---

## 7. Implementation Plan

### Phase 1: Core Skill (Week 1-2)
- [ ] Create skill directory structure
- [ ] Write SKILL.md entry point
- [ ] Write threat-modeling.md methodology
- [ ] Write code-review.md methodology
- [ ] Write output-format.md specification
- [ ] Test with Claude Code

### Phase 2: Reference Materials (Week 2-3)
- [ ] Add CWE top 25 reference
- [ ] Add OWASP top 10 reference
- [ ] Add severity guide
- [ ] Add example findings
- [ ] Add example threat models

### Phase 3: Platform MCP (Week 3-4) — Optional
- [ ] `securevibes_save_findings` tool
- [ ] `securevibes_history` tool
- [ ] Platform API integration
- [ ] Dashboard connection

### Phase 4: Distribution (Week 4-5)
- [ ] Claude Code marketplace submission
- [ ] Codex AGENTS.md template
- [ ] Documentation
- [ ] Installation guide

---

## 8. Migration Path

### For Existing SecureVibes CLI Users

The CLI continues to work. The skill is an **additional** integration path.

```
Before: securevibes scan .
After:  Claude Code + skill (same methodology, no CLI needed)
```

### For New Users

1. Install SecureVibes skill in Claude Code
2. Ask Claude to "review this code for security"
3. Done — no CLI, no API key, no setup

### Platform Users

1. Install skill + MCP
2. Scans run locally via skill
3. Findings sync to platform via MCP
4. Dashboard shows history, trends, team data

---

## Summary

| Component | What It Is | Status |
|-----------|------------|--------|
| SecureVibes Skill | Prompts, methodology, output format | **Primary** |
| Claude Code | Orchestration, execution | Uses skill |
| SecureVibes MCP | Platform integration only | **Optional** |
| SecureVibes CLI | Legacy / standalone | Still works |
| SecureVibes Platform | Dashboard, history, teams | Separate product |

**The skill IS the product for AI agent users.**
