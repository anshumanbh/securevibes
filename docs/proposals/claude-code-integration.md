# SecureVibes Claude Code Integration Spec

**Status:** Proposal  
**Author:** SecureVibes Team  
**Created:** 2026-01-24  
**Version:** 2.0.0 (MCP-first revision)

---

## TL;DR

SecureVibes as **MCP tools** that Claude Code can invoke directly. No terminal commands needed — Claude just calls `securevibes_scan` and gets structured findings.

```typescript
// What Claude sees:
{
  securevibes_scan: (options) => Finding[],
  securevibes_findings: (scanId) => Finding[],
  securevibes_fix: (findingId) => FixSuggestion
}
```

---

## Table of Contents

1. [Overview and Motivation](#1-overview-and-motivation)
2. [MCP Tools (Primary Interface)](#2-mcp-tools-primary-interface)
3. [User Stories (MCP-First)](#3-user-stories-mcp-first)
4. [CLI Commands (Secondary)](#4-cli-commands-secondary)
5. [Architecture](#5-architecture)
6. [Implementation Roadmap](#6-implementation-roadmap)
7. [Future Enhancements](#7-future-enhancements)

---

## 1. Overview and Motivation

### 1.1 The Problem

Current workflow:
```
Developer in Claude Code → "Review my code" → Claude reviews → "Run SecureVibes" 
→ Exit Claude Code → Run securevibes CLI → Parse results → Context switch back
```

This is broken. Context-switching kills flow.

### 1.2 The Solution: MCP-Native Integration

Claude should be able to invoke SecureVibes **as a tool**, not as a terminal command:

```
Developer: "Review this PR for security issues"
Claude: 
  → Calls securevibes_scan({ pr: 123 })
  → Gets structured findings
  → Addresses them inline
  → Developer never leaves the conversation
```

**Key insight:** Claude already has tools. SecureVibes should be one of them.

### 1.3 How Greptile Does It

Greptile's Claude Code plugin:
1. User asks Claude to review code
2. Claude calls Greptile tool → gets findings
3. Claude addresses findings in its response
4. User sees integrated review + fixes

**We want the same pattern for security.**

### 1.4 Goals

| Goal | Description |
|------|-------------|
| **MCP-first** | Tools Claude can invoke, not commands to type |
| **Zero terminal** | Developer never leaves Claude Code |
| **Conversational** | "Fix this" → Claude uses securevibes_fix |
| **Claude-native** | Feels like a built-in capability |

### 1.5 Non-Goals (v1)

- Real-time continuous monitoring (future)
- IDE plugins (separate project)
- GitHub App (separate project)
- DAST (requires infrastructure)

---

## 2. MCP Tools (Primary Interface)

These are the tools Claude Code will see and can invoke.

### 2.1 Tool Definitions

```typescript
namespace SecureVibes {

  // Primary: Run a security scan
  type securevibes_scan = (_: {
    // Scan target - mutually exclusive
    path?: string,           // Local directory (default: ".")
    pr?: number,             // GitHub PR number
    diff?: string,           // Diff/patch content
    commit?: string,         // Specific commit
    
    // Options
    severity?: ("critical" | "high" | "medium" | "low")[],
    agents?: ("assessment" | "threat-modeling" | "code-review")[],
    timeout?: number,        // Max seconds (default: 300)
  }) => {
    scan_id: string,
    status: "queued" | "running" | "completed" | "failed",
    summary: {
      critical: number,
      high: number,
      medium: number,
      low: number,
    },
    findings: Finding[],
    scan_url: string,        // Link to platform dashboard
  };

  // Query findings from a completed scan
  type securevibes_findings = (_: {
    scan_id: string,
    severity?: string[],
    status?: "open" | "resolved" | "ignored",
    limit?: number,
  }) => {
    findings: Finding[],
    total: number,
  };

  // Get fix suggestion for a finding
  type securevibes_fix = (_: {
    finding_id: string,
    scan_id?: string,
    apply?: boolean,         // Claude wants to apply fix directly
  }) => {
    finding: Finding,
    suggested_fix: {
      description: string,
      code_change: {
        before: string,
        after: string,
      },
      explanation: string,
    },
    confidence: number,
  };

  // Get scan status
  type securevibes_status = (_: {
    scan_id?: string,
  }) => {
    configured: boolean,
    api_key_valid: boolean,
    recent_scans: { scan_id: string, status: string, created_at: string }[],
  };

  // Auto-fix workflow - scan, get findings, fix, re-scan
  type securevibes_auto_remediate = (_: {
    path: string,
    max_iterations?: number,  // default: 3
  }) => {
    iterations: number,
    findings_resolved: number,
    findings_remaining: number,
    final_scan_url: string,
  };
}
```

### 2.2 Example Conversation

```
User: "Review my PR #456 for security issues"

Claude (internally):
  → calls securevibes_scan({ pr: 456, agents: ["code-review"] })
  → receives 3 findings (1 critical, 2 medium)
  → shows findings to user with line numbers and descriptions
  → user says "Fix the SQL injection"
  → Claude calls securevibes_fix({ finding_id: "sv-123", apply: true })
  → Claude applies the fix
  → Claude re-runs scan to verify
```

---

## 3. User Stories (MCP-First)

### US-1: Conversational Security Review
> **As a developer**, I want to ask Claude to "check this for security issues" and have Claude invoke SecureVibes automatically.
> 
> **Acceptance:**
> - [ ] Claude calls `securevibes_scan` without terminal
> - [ ] Findings appear in conversation
> - [ ] Critical issues highlighted

### US-2: Fix What You Find
> **As a developer**, I want to say "fix this vulnerability" and have Claude apply the fix.
> 
> **Acceptance:**
> - [ ] Claude calls `securevibes_fix({ id: "sv-123", apply: true })`
> - [ ] Fix is applied to codebase
> - [ ] Claude re-scans to verify

### US-3: PR Review Automation
> **As a developer**, I want Claude to automatically scan PRs when reviewing.
> 
> **Acceptance:**
> - [ ] Claude Code triggers scan on PR open
> - [ ] Findings appear in PR review comment
> - [ ] Auto-approve if no critical findings

### US-4: Iterative Remediation
> **As a developer**, I want Claude to keep fixing until clean.
> 
> **Acceptance:**
> - [ ] Call `securevibes_auto_remediate`
> - [ ] Claude iterates: scan → fix → scan → fix
> - [ ] Returns summary of what was fixed

---

## 4. CLI Commands (Secondary)

For power users who want terminal access (optional convenience):

```bash
securevibes scan .                          # Scan current directory
securevibes scan --pr 123                   # Scan GitHub PR
securevibes scan --diff < patch_file        # Scan diff/patch
securevibes findings --scan-id <id>         # List findings
securevibes fix <finding-id>                # Generate fix
securevibes status                          # Config status
securevibes auto-remediate --path .         # Iterative fix loop
```

These CLI commands are thin wrappers around the MCP tools.

---

## 5. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Claude Code                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Claude Agent                                             │   │
│  │  → User asks for security review                        │   │
│  │  → Calls securevibes_scan MCP tool                      │   │
│  └─────────────────────────────────────────────────────────┘   │
│                          ↓                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ MCP Client (built into Claude Code)                     │   │
│  │  → SecureVibes MCP Server                               │   │
│  └─────────────────────────────────────────────────────────┘   │
│                          ↓                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ SecureVibes MCP Server (NEW)                            │   │
│  │  → Wraps existing securevibes CLI                       │   │
│  │  → Handles auth, queuing, result formatting             │   │
│  │  → Returns JSON that Claude can parse                   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                          ↓                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Existing SecureVibes Platform                           │   │
│  │  → Same scan logic, agents, findings                    │   │
│  │  → No changes needed                                    │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 5.1 MCP Server Responsibilities

1. **Tool registration** — Expose functions Claude can call
2. **Auth** — Validate API key from SecureVibes platform
3. **Queuing** — Handle scan requests, polling for completion
4. **Formatting** — Convert findings to Claude-readable JSON
5. **Error handling** — Graceful failures with actionable messages

### 5.2 Integration with Existing Codebase

Reuses existing `packages/core`:
- Scanning logic
- Agent definitions
- Finding models
- Configuration

New code:
- `packages/mcp-server/` (NEW)
  - `main.py` — MCP server entry
  - `tools.py` — Tool definitions
  - `auth.py` — API key validation
  - `formatters.py` — Finding → JSON conversion

---

## 6. Implementation Roadmap

### Phase 1: MCP Server (Weeks 1-2)
- [ ] Set up MCP server structure
- [ ] Implement `securevibes_scan` tool
- [ ] Basic auth flow
- [ ] Test with Claude Code dev mode

### Phase 2: Core Tools (Weeks 2-3)
- [ ] `securevibes_findings` tool
- [ ] `securevibes_fix` tool
- [ ] `securevibes_status` tool
- [ ] JSON schema validation

### Phase 3: Advanced Features (Weeks 3-4)
- [ ] `securevibes_auto_remediate` tool
- [ ] PR integration
- [ ] Rate limiting, caching
- [ ] Error handling polish

### Phase 4: Polish (Weeks 4-6)
- [ ] Documentation
- [ ] Publish to MCP registry
- [ ] Claude Code marketplace listing
- [ ] User testing

---

## 7. Future Enhancements

### v1.1
- Streaming responses (progress updates)
- Diff-aware scanning (only changed files)
- Custom policy enforcement

### v1.5
- Real-time monitoring mode
- Team workspaces
- Compliance reporting

### v2.0
- IDE plugins (VS Code, JetBrains)
- GitHub App integration
- Custom agent definitions
