# Design: Threat-Aware Incremental Scanning

## Status: Proposed

## Problem

The incremental scanner treats every commit equally. A docs-only changelog update gets the same deep Sonnet review (~600s) as a change to the sandbox exec boundary. With a high-velocity repo like OpenClaw (20-30 commits per hour), the scanner falls behind permanently — the backlog grows faster than we can process it.

**Current numbers (OpenClaw, Feb 2026):**
- ~600s per chunk with Sonnet
- Agent session SIGTERM'd after ~20 min → 2-3 chunks per 30-min cron cycle
- Backlog: 146 commits / 58 chunks ≈ 9.7 hours to clear
- New commits arrive faster than we scan

## Solution: Three-Tier Risk-Based Triage

Use the baseline scan artifacts (THREAT_MODEL.json, SECURITY.md, VULNERABILITIES.json) indexed in qmd as a security-aware lens. Before any LLM call, classify each chunk by what it touches.

### Tier 1 — Critical (Opus, deep review + threat context injection)

Files touching security-critical components: auth, exec, sandbox, secrets, gateway, pairing, device-auth, credential handling, permission boundaries.

- Full review with Opus
- `before_model_call` hook injects relevant threats from qmd: "This file is part of the device auth component. Known threats: unsigned platform fields, scope escalation via shared tokens."
- ~600s per chunk, but these are the chunks that matter

### Tier 2 — Moderate (Sonnet, standard review)

Files touching config, routing, plugins, API handlers, session management, browser relay.

- Standard review with Sonnet
- No extra context injection
- ~300s per chunk

### Tier 3 — Skip (no LLM call)

Docs, tests, CI config, changelog, package.json version bumps, README, comments-only changes.

- Log the skip, advance anchor, move on
- ~0s

### Projected impact

Using OpenClaw's current commit distribution as a benchmark:

| Tier | Chunks | Time per chunk | Total |
|------|--------|---------------|-------|
| Critical (Opus) | ~10 | 600s | 6,000s |
| Moderate (Sonnet) | ~15 | 300s | 4,500s |
| Skip | ~33 | 0s | 0s |
| **Total** | **58** | | **~2.9 hours** |

vs current: 58 × 600s = **9.7 hours**

~70% reduction. More importantly, critical findings surface in the first pass instead of being queued behind docs updates.

## Implementation

### Phase 1: File-to-Component Mapping + Risk Scoring

**In the wrapper (`incremental_scan.py`):**

1. On each run, before chunking:
   - Get changed files: `git diff --name-only base..head`
   - For each file, query qmd: `qmd search "security component for <filepath>"` against indexed THREAT_MODEL.json
   - Score each file by matched component's risk level

2. Classify the chunk:
   - Any file matches a critical component → Tier 1
   - Any file matches a moderate component → Tier 2
   - All files are docs/tests/CI → Tier 3

3. Route to appropriate model:
   - Tier 1: `--model opus`
   - Tier 2: `--model sonnet`
   - Tier 3: skip, log, advance anchor

**Component risk mapping (seeded from THREAT_MODEL.json):**

```json
{
  "critical": [
    "src/agents/sandbox*",
    "src/agents/pi-auth*",
    "src/gateway/credentials*",
    "src/gateway/device-auth*",
    "src/gateway/server-http*",
    "src/secrets/*",
    "src/security/*",
    "src/infra/exec*",
    "src/infra/boundary*",
    "src/agents/bash-tools.exec*"
  ],
  "moderate": [
    "src/config/*",
    "src/routing/*",
    "src/plugins/*",
    "src/browser/*",
    "src/channels/*",
    "src/gateway/server-methods/*",
    "extensions/*/src/*"
  ],
  "skip": [
    "docs/*",
    "*.test.ts",
    "*test-harness*",
    "CHANGELOG.md",
    "package.json",
    "README.md",
    "scripts/*",
    "*.md"
  ]
}
```

Note: `*.test.ts` in skip is for test-only commits. If a commit touches both `sandbox.ts` and `sandbox.test.ts`, the non-test file drives the tier.

### Phase 2: Context Injection via Claude Agent SDK Hooks

**In `securevibes pr-review`:**

1. Accept a `--context-file` or use `before_model_call` hook in the Agent SDK
2. Before each review call, query qmd for:
   - Relevant threats from THREAT_MODEL.json
   - Previous findings for the same component
   - Decision traces (see Phase 4)
3. Inject as system context: "You are reviewing changes to the device auth component. Known threats: [list]. Previous findings: [list]. Accepted risks: [list with conditions]."

**Hook implementation:**

```python
@agent.hook("before_model_call")
def inject_threat_context(context):
    changed_files = context.get("changed_files", [])
    components = qmd_search(changed_files)
    threats = get_threats_for_components(components)
    findings_history = get_previous_findings(components)
    
    context["system_prompt"] += f"\n\n## Security Context\n{threats}\n{findings_history}"
    return context
```

### Phase 3: Smart Chunking by Risk Tier

Replace the current adaptive chunking (which groups by file count / line count) with risk-aware grouping:

1. Group commits by dominant risk tier
2. Within each tier, apply existing adaptive chunking (max files / max lines)
3. Process Tier 1 chunks first (findings surface faster)
4. Tier 3 chunks are batched and skipped as a group

### Phase 4: Decision Traces — Institutional Triage Memory

When a finding is triaged (false positive, accepted risk, mitigated elsewhere), record a **decision trace**:

```json
{
  "finding_hash": "sha256_of_title_file_severity",
  "verdict": "accepted_risk",
  "rationale": "Auth handled upstream by gateway middleware",
  "mitigated_by": "src/gateway/auth.ts:42",
  "conditions": ["gateway auth middleware is enabled", "allowlist is not bypassed"],
  "decided_by": "anshuman",
  "decided_at": "2026-02-26T12:00:00Z",
  "component": "device-auth"
}
```

**Condition-aware re-triggering:** When someone accepts a risk because "the allowlist handles it," and then a commit changes the allowlist code, the decision automatically gets flagged for re-review. The `conditions` field maps to file patterns — if a conditioned file changes, the accepted risk is surfaced again.

**Storage:** `.securevibes/decision_traces/` indexed in qmd. Injected via `before_model_call` alongside threat context.

**Flow:**
```
Finding surfaces → Human reviews → Decision trace recorded
                                    ↓
                              Indexed in qmd
                                    ↓
                   Available for future reviews via before_model_call
                                    ↓
              "Do NOT re-flag this unless the allowlist implementation has changed"
                                    ↓
                   Commit changes allowlist → decision re-surfaced
```

### Phase 5: Compounding Knowledge Loop

After each scan:
- `after_model_call` hook logs which threats were surfaced vs which findings were generated
- Track relevance scores: did injecting threat X actually lead to finding Y?
- Prune low-relevance threat context over time (keeps prompts lean)
- Feed scan results back into qmd index for future runs

## Migration Path

1. **Phase 1 first** — biggest ROI, no changes to core securevibes needed. Pure wrapper change.
2. **Phase 2** — requires Agent SDK hook support in securevibes core.
3. **Phase 3** — wrapper refactor, depends on Phase 1.
4. **Phase 4** — needs a triage UI/CLI flow + qmd integration.
5. **Phase 5** — metrics collection, can be added incrementally.

## Open Questions

- Should the risk mapping be per-repo (stored in `.securevibes/risk_map.json`) or derived from THREAT_MODEL.json automatically?
- What's the right granularity for qmd queries — per-file or per-directory?
- Should Tier 3 skips be configurable? Some teams may want to scan tests too.
- How to handle files that don't match any component mapping? Default to Tier 2?
