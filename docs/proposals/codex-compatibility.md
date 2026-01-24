# SecureVibes Codex Compatibility Plan

**Status:** Proposal  
**Author:** SecureVibes Team  
**Created:** 2026-01-24  
**Related:** [Claude Code Integration Spec (PR #29)](../proposals/claude-code-integration.md)

---

## Overview

This proposal extends the SecureVibes Claude Code integration (MCP-first) to also support **OpenAI Codex CLI**. The goal: SecureVibes works seamlessly with both Claude Code and Codex, becoming the universal security layer for AI coding agents.

**Reference:** [Unrolling the Codex Agent Loop](https://openai.com/index/unrolling-the-codex-agent-loop/)

---

## Why Codex Support?

| Agent | Protocol | Market |
|-------|----------|--------|
| Claude Code | MCP (Model Context Protocol) | Anthropic users |
| Codex CLI | Responses API + MCP | OpenAI users |
| Future agents | TBD | Everyone else |

Codex supports MCP tools, so our MCP server will work. But Codex also has unique patterns we should leverage:
- AGENTS.md for project-level instructions
- Responses API for direct integration
- Streaming-first architecture

---

## Implementation Plan

### Phase 1: AGENTS.md Integration (Week 1)
**Quick win — works today with existing MCP server**

Create a recommended AGENTS.md snippet users can add to their projects:

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
- [ ] Create `agents-snippet.md` template in docs/
- [ ] Add to MCP server install instructions
- [ ] Test with Codex CLI

---

### Phase 2: Streaming Support (Week 2)
**Better UX for both Claude Code and Codex**

Current: MCP server waits for full scan, then returns all findings.
Proposed: Stream progress and findings incrementally.

```typescript
// Before (blocking)
securevibes_scan() → wait 60s → { findings: [...] }

// After (streaming)
securevibes_scan() → 
  { status: "scanning", progress: 10, agent: "threat-model" } →
  { status: "scanning", progress: 40, agent: "code-review" } →
  { status: "finding", finding: { severity: "high", ... } } →
  { status: "complete", summary: { critical: 0, high: 1, ... } }
```

**Deliverables:**
- [ ] Implement SSE streaming in MCP server
- [ ] Progress updates during scan
- [ ] Emit findings as discovered (don't wait for full scan)
- [ ] Test streaming with Claude Code and Codex

---

### Phase 3: Responses API Adapter (Week 3-4)
**Native Codex integration without MCP**

For environments where MCP isn't configured, provide a Responses API compatible endpoint:

```
POST /v1/responses
{
  "tools": [{ "name": "securevibes_scan", ... }],
  "input": [{ "role": "user", "content": "scan this PR" }]
}
```

This allows SecureVibes to be used as a Responses API provider, not just a tool.

**Architecture:**
```
┌─────────────────────────────────────────────────────────┐
│ SecureVibes Server                                      │
│                                                         │
│  ┌─────────────────┐    ┌─────────────────────────┐    │
│  │ MCP Endpoint    │    │ Responses API Endpoint  │    │
│  │ (Claude Code)   │    │ (Codex CLI)             │    │
│  └────────┬────────┘    └────────────┬────────────┘    │
│           │                          │                  │
│           └──────────┬───────────────┘                  │
│                      ▼                                  │
│           ┌─────────────────────┐                       │
│           │ Shared Scan Engine  │                       │
│           │ (existing core)     │                       │
│           └─────────────────────┘                       │
└─────────────────────────────────────────────────────────┘
```

**Deliverables:**
- [ ] Responses API endpoint (`/v1/responses`)
- [ ] Tool definitions in OpenAI format
- [ ] SSE streaming response
- [ ] Auth via API key header
- [ ] Test with Codex CLI `--provider` flag

---

### Phase 4: Auto-Remediate Loop (Week 4-5)
**Codex-style iterative fixing**

Codex loops until the model produces a final response. SecureVibes should support:

```typescript
securevibes_auto_remediate({
  path: ".",
  max_iterations: 3,
  exit_on: "no_critical_high"  // or "all_clean"
})

// Returns:
{
  iterations: [
    { scan_id: "...", findings: 5, fixed: 3 },
    { scan_id: "...", findings: 2, fixed: 2 },
    { scan_id: "...", findings: 0, fixed: 0 }
  ],
  final_status: "clean",
  total_fixed: 5
}
```

**Loop logic:**
1. Scan → get findings
2. For each critical/high finding: generate fix, apply
3. Re-scan
4. Repeat until clean or max iterations

**Deliverables:**
- [ ] `securevibes_auto_remediate` tool
- [ ] Iteration tracking and reporting
- [ ] Configurable exit conditions
- [ ] Timeout/circuit breaker for runaway loops

---

## Compatibility Matrix

| Feature | Claude Code | Codex CLI | Both |
|---------|-------------|-----------|------|
| MCP tools | ✅ | ✅ | ✅ |
| AGENTS.md | ❌ | ✅ | ✅ (Codex) |
| Responses API | ❌ | ✅ | ✅ (Codex) |
| Streaming | ✅ | ✅ | ✅ |
| Auto-remediate | ✅ | ✅ | ✅ |

---

## Timeline

| Week | Phase | Deliverable |
|------|-------|-------------|
| 1 | AGENTS.md | Snippet template, docs update |
| 2 | Streaming | SSE support in MCP server |
| 3-4 | Responses API | `/v1/responses` endpoint |
| 4-5 | Auto-remediate | Iterative fix loop |
| 6 | Polish | Testing, docs, release |

---

## Success Metrics

1. **Adoption:** SecureVibes works out-of-box with both Claude Code and Codex
2. **UX:** Streaming reduces perceived latency by 50%+
3. **Automation:** Auto-remediate resolves 80%+ of findings without human intervention
4. **Docs:** Clear setup guides for both platforms

---

## Open Questions

1. Should Responses API be a separate service or same server as MCP?
2. Priority: Codex Cloud vs Codex CLI?
3. Do we need VS Code extension for non-CLI users?

---

## References

- [Unrolling the Codex Agent Loop](https://openai.com/index/unrolling-the-codex-agent-loop/)
- [Codex CLI GitHub](https://github.com/openai/codex)
- [MCP Specification](https://modelcontextprotocol.io/)
- [SecureVibes Claude Code Integration (PR #29)](../proposals/claude-code-integration.md)
