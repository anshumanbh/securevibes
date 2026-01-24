# SecureVibes AI Agent Integration Spec

**Status:** Proposal  
**Author:** SecureVibes Team  
**Created:** 2026-01-24  
**Version:** 3.0.0 (Universal agent support: Claude Code + Codex)

---

## TL;DR

SecureVibes as **native tools** for AI coding agents. Works with both **Claude Code (MCP)** and **OpenAI Codex (Responses API)**. No terminal commands needed — agents just call `securevibes_scan` and get structured findings.

```typescript
// What AI agents see:
{
  securevibes_scan: (options) => Finding[],
  securevibes_findings: (scanId) => Finding[],
  securevibes_fix: (findingId) => FixSuggestion
}
```

**Supported Agents:**
| Agent | Protocol | Status |
|-------|----------|--------|
| Claude Code | MCP | ✅ Primary |
| Codex CLI | MCP + Responses API | ✅ Supported |
| Future agents | MCP | 🔮 Ready |

---

## Table of Contents

1. [Overview and Motivation](#1-overview-and-motivation)
2. [MCP Tools (Primary Interface)](#2-mcp-tools-primary-interface)
3. [User Stories (MCP-First)](#3-user-stories-mcp-first)
4. [CLI Commands (Secondary)](#4-cli-commands-secondary)
5. [Architecture](#5-architecture)
6. [Codex Compatibility](#6-codex-compatibility)
7. [Implementation Roadmap](#7-implementation-roadmap)
8. [Future Enhancements](#8-future-enhancements)

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
│                    AI Coding Agents                             │
│  ┌──────────────────────┐    ┌──────────────────────┐          │
│  │ Claude Code          │    │ Codex CLI            │          │
│  │  → MCP Client        │    │  → MCP + Responses   │          │
│  └──────────┬───────────┘    └──────────┬───────────┘          │
│             │                           │                       │
│             └─────────────┬─────────────┘                       │
│                           ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ SecureVibes Agent Server (NEW)                          │   │
│  │                                                          │   │
│  │  ┌─────────────────┐    ┌─────────────────────────┐     │   │
│  │  │ MCP Endpoint    │    │ Responses API Endpoint  │     │   │
│  │  │ (Claude Code)   │    │ (Codex CLI)             │     │   │
│  │  └────────┬────────┘    └────────────┬────────────┘     │   │
│  │           │                          │                   │   │
│  │           └──────────┬───────────────┘                   │   │
│  │                      ▼                                   │   │
│  │           ┌─────────────────────┐                        │   │
│  │           │ Shared Tool Layer   │                        │   │
│  │           │ • securevibes_scan  │                        │   │
│  │           │ • securevibes_fix   │                        │   │
│  │           │ • securevibes_auto  │                        │   │
│  │           └─────────────────────┘                        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                          ↓                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Existing SecureVibes Platform                           │   │
│  │  → Same scan logic, agents, findings                    │   │
│  │  → No changes needed                                    │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 5.1 Server Responsibilities

1. **Dual protocol support** — MCP for Claude Code, Responses API for Codex
2. **Tool registration** — Same tools exposed via both protocols
3. **Auth** — Validate API key from SecureVibes platform
4. **Streaming** — SSE progress updates for long-running scans
5. **Formatting** — Convert findings to agent-readable JSON

### 5.2 Integration with Existing Codebase

Reuses existing `packages/core`:
- Scanning logic
- Agent definitions
- Finding models
- Configuration

New code:
- `packages/agent-server/` (NEW)
  - `main.py` — Server entry (MCP + HTTP)
  - `mcp/` — MCP protocol handlers
  - `responses/` — Responses API handlers
  - `tools.py` — Shared tool definitions
  - `stream.py` — SSE streaming support
  - `auth.py` — API key validation

---

## 6. Codex Compatibility

OpenAI Codex CLI uses MCP tools but also supports the Responses API directly. This section covers Codex-specific integration.

**Reference:** [Unrolling the Codex Agent Loop](https://openai.com/index/unrolling-the-codex-agent-loop/)

### 6.1 AGENTS.md Integration

Codex reads `AGENTS.md` for project-level instructions. Provide a security-focused snippet:

```markdown
## Security Review (SecureVibes)

When reviewing code or PRs:
1. Run `securevibes_scan` to check for security vulnerabilities
2. Address all critical/high findings before approving
3. Use `securevibes_fix` to generate remediation suggestions

Security policy:
- No PR approval with unresolved critical findings
- High findings require explicit acknowledgment
- Medium/low can be tracked as tech debt
```

**Deliverables:**
- Ship `agents-snippet.md` template in docs/
- Include in MCP server install instructions

### 6.2 Responses API Endpoint

For native Codex integration without MCP:

```
POST /v1/responses
Authorization: Bearer <SECUREVIBES_API_KEY>

{
  "tools": [
    {
      "name": "securevibes_scan",
      "description": "Scan code for security vulnerabilities",
      "parameters": { ... }
    }
  ],
  "input": [
    { "role": "user", "content": "scan this directory for vulnerabilities" }
  ]
}
```

**Response (SSE stream):**
```
data: {"type": "response.output_item.added", "item": {"type": "function_call", "name": "securevibes_scan"}}
data: {"type": "response.function_call_arguments.delta", "delta": "{\"path\": \".\"}"}
data: {"type": "response.output_item.done", "item": {"output": "{\"findings\": [...]}"}}
```

### 6.3 Streaming Support

Both Claude Code and Codex benefit from streaming progress:

```typescript
// Streaming response
securevibes_scan() → 
  { type: "progress", percent: 10, agent: "threat-model" } →
  { type: "progress", percent: 40, agent: "code-review" } →
  { type: "finding", finding: { severity: "high", ... } } →
  { type: "complete", summary: { critical: 0, high: 1 } }
```

**Benefits:**
- Reduced perceived latency
- Findings appear as discovered
- Progress visibility for long scans

### 6.4 Auto-Remediate Loop

Codex's agent loop repeats until the model produces a final response. SecureVibes supports this pattern:

```typescript
securevibes_auto_remediate({
  path: ".",
  max_iterations: 3,
  exit_on: "no_critical_high"
})

// Loop: scan → fix → re-scan → fix → re-scan
// Exit when: no critical/high findings OR max iterations
```

### 6.5 Compatibility Matrix

| Feature | Claude Code | Codex CLI |
|---------|-------------|-----------|
| MCP tools | ✅ | ✅ |
| Responses API | ❌ | ✅ |
| AGENTS.md | ❌ | ✅ |
| Streaming | ✅ | ✅ |
| Auto-remediate | ✅ | ✅ |

---

## 7. Implementation Roadmap

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

### Phase 3: Streaming + Codex (Weeks 3-4)
- [ ] SSE streaming support
- [ ] Responses API endpoint (`/v1/responses`)
- [ ] AGENTS.md snippet and docs
- [ ] Test with Codex CLI

### Phase 4: Advanced Features (Weeks 4-5)
- [ ] `securevibes_auto_remediate` tool
- [ ] PR integration
- [ ] Rate limiting, caching
- [ ] Error handling polish

### Phase 5: Polish (Weeks 5-6)
- [ ] Documentation for both Claude Code and Codex
- [ ] Publish to MCP registry
- [ ] Marketplace listings
- [ ] User testing with both agents

---

## 8. Future Enhancements

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
