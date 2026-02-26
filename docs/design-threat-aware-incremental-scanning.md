# Design: Threat-Aware Incremental Scanning

## Status
Proposed — PR #43

## Problem

Current incremental scanning treats all code changes equally. A 1-line change to `src/agents/sandbox.ts` (code execution boundary) gets the same review depth and budget as a 30-file documentation update. This leads to:

1. **Wasted spend** — $5 reviewing docs, CI configs, and test formatting
2. **Shallow coverage** — high-risk changes get the same shallow pass as everything else
3. **No memory** — each review starts from zero context, unaware of known threats, past findings, or the codebase's security architecture
4. **Can't keep up** — on high-velocity repos (OpenClaw: 20-30 commits/hour), the scanner falls permanently behind

**Current numbers (OpenClaw, Feb 2026):**
- ~600s per chunk with Sonnet, every chunk treated equally
- 146 commits / 58 chunks ≈ 9.7 hours to clear
- New commits arrive faster than we scan — backlog grows indefinitely

## Solution

Use baseline scan artifacts (THREAT_MODEL.json, SECURITY.md, VULNERABILITIES.json) indexed in qmd as a **security-aware lens**. Before any LLM call, classify each chunk by what it touches and route to the appropriate model and review depth.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Baseline Artifacts                     │
│  SECURITY.md · THREAT_MODEL.json · VULNERABILITIES.json  │
└──────────────────────┬──────────────────────────────────┘
                       │ qmd index + embed
                       ▼
              ┌─────────────────┐
              │   qmd (memory)  │
              │  BM25 + vectors │
              └────────┬────────┘
                       │
    ┌──────────────────┼──────────────────┐
    │                  │                  │
    ▼                  ▼                  ▼
┌──────────┐   ┌──────────────┐   ┌─────────────┐
│  File →   │   │  Threat ctx  │   │   Past       │
│ Component │   │  injection   │   │  findings    │
│  mapping  │   │  per chunk   │   │  retrieval   │
└──────────┘   └──────────────┘   └─────────────┘
    │                  │                  │
    └──────────────────┼──────────────────┘
                       ▼
              ┌─────────────────┐
              │ Risk-weighted   │
              │ chunk pipeline  │
              └─────────────────┘
```

## Three-Tier Risk-Based Triage

### Tier 1 — Critical (Opus, deep review + threat context injection)

Files touching security-critical components: auth, exec, sandbox, secrets, gateway, pairing, device-auth, credential handling, permission boundaries.

- Full review with **Opus**
- `before_model_call` hook injects relevant threats from qmd
- Previous findings and decision traces injected as context
- ~600s per chunk, but these are the chunks that matter

### Tier 2 — Moderate (Sonnet, standard review)

Files touching config, routing, plugins, API handlers, session management, browser relay, channels.

- Standard review with **Sonnet**
- No extra context injection
- ~300s per chunk

### Tier 3 — Skip (no LLM call)

Docs, tests, CI config, changelog, package.json version bumps, README, comments-only changes.

- Log the skip, advance anchor, move on
- ~0s

### Component Risk Mapping

Seeded from THREAT_MODEL.json, with file pattern overrides per repo (stored in `.securevibes/risk_map.json`):

```json
{
  "critical": [
    "src/agents/sandbox*",
    "src/agents/pi-auth*",
    "src/agents/bash-tools.exec*",
    "src/gateway/credentials*",
    "src/gateway/device-auth*",
    "src/gateway/server-http*",
    "src/secrets/*",
    "src/security/*",
    "src/infra/exec*",
    "src/infra/boundary*"
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
    "scripts/*"
  ]
}
```

**Note:** If a commit touches both `sandbox.ts` and `sandbox.test.ts`, the non-test file drives the tier. The highest-risk file in a chunk determines the tier for the entire chunk.

**Unmapped files** default to Tier 2 (moderate) and get flagged for threat model update.

### Projected Impact

Using OpenClaw's current commit distribution as a benchmark:

| Tier | Chunks | Model | Time/chunk | Total |
|------|--------|-------|-----------|-------|
| Critical (Opus) | ~10 | Opus | 600s | 6,000s |
| Moderate (Sonnet) | ~15 | Sonnet | 300s | 4,500s |
| Skip | ~33 | — | 0s | 0s |
| **Total** | **58** | | | **~2.9 hours** |

**vs current:** 58 × 600s = **9.7 hours** (all Sonnet, no triage)

~70% time reduction. Critical findings surface in the first pass instead of being queued behind docs updates.

## Implementation Plan

### Phase 1: Index Baseline Artifacts in qmd

After a full scan completes, index `.securevibes/` into qmd:

```bash
qmd add securevibes-artifacts .securevibes/**/*.{json,md}
qmd update && qmd embed
```

This gives semantic search over components, threat models, known vulnerabilities, and architecture.

### Phase 2: File → Component Mapping + Risk Scoring

**In the wrapper (`ops/incremental_scan.py`):**

1. On each run, before chunking:
   - Get changed files: `git diff --name-only base..head`
   - Match against `.securevibes/risk_map.json` patterns (fast, no LLM)
   - For unmapped files, query qmd: `qmd search "security relevance of <filepath>"` against indexed artifacts
   - Score each file by matched component's risk level

2. Classify the chunk by highest-risk file:
   - Any file matches critical → Tier 1
   - Any file matches moderate → Tier 2
   - All files are skip-tier → Tier 3

3. Route to appropriate model and depth.

**New module: `ops/risk_scorer.py`**
- Parse THREAT_MODEL.json for component definitions + risk levels
- Map file paths to components using directory patterns + qmd semantic matching
- Output: `list[FileRisk]` with file, component, tier, relevant_threats

### Phase 3: Risk-Weighted Chunking

Replace flat chunking with tiered processing:

- Group commits by dominant risk tier
- Within each tier, apply existing adaptive chunking (max files / max lines)
- Process Tier 1 chunks first (findings surface faster)
- Tier 3 chunks are batched and skipped as a group

### Phase 4: Context Injection via Claude Agent SDK Hooks

**In `securevibes pr-review` (packages/core change):**

Use `before_model_call` hook to inject threat context dynamically:

```python
@agent.hook("before_model_call")
def inject_threat_context(context):
    changed_files = context.get("changed_files", [])
    components = qmd_search(changed_files)
    threats = get_threats_for_components(components)
    findings_history = get_previous_findings(components)
    decisions = get_decision_traces(components)

    context["system_prompt"] += f"""

## Security Context for [{component_name}]

Known threats:
{threats}

Previous findings:
{findings_history}

Triage decisions (do not re-flag unless conditions changed):
{decisions}
"""
    return context
```

`after_model_call` hook logs which threats were surfaced vs findings generated — feedback loop for relevance tuning.

### Phase 5: Decision Traces — Institutional Triage Memory

When a finding is triaged (false positive, accepted risk, mitigated elsewhere), record a **decision trace**:

```json
{
  "finding_id": "sv-2026-0225-007",
  "title": "Exec obfuscation detector gaps",
  "component": "Sandbox/Exec",
  "severity": "HIGH",
  "verdict": "accepted_risk",
  "rationale": "Single-variable indirection is low-exploitability because exec allowlist restricts to known binaries.",
  "conditions": "Revisit if exec allowlist implementation changes",
  "mitigated_by": ["src/agents/pi-tools.safe-bins.ts", "src/agents/sandbox-tool-policy.ts"],
  "decided_by": "anshuman",
  "decided_at": "2026-02-26",
  "related_findings": ["sv-2026-0225-004"]
}
```

**Verdict types:**

| Verdict | Meaning | Revisit When |
|---------|---------|-------------|
| `false_positive` | Not a real vulnerability | Same code pattern appears (low priority) |
| `accepted_risk` | Real risk, accepted with rationale | Conditions change (e.g., component refactored) |
| `mitigated_by` | Risk exists but compensating controls handle it | Linked mitigating code changes |
| `deferred` | Will fix later | Deferred deadline passes |
| `fixed` | Addressed in code | Regression detected |

**Condition-aware re-triggering:** When `mitigated_by` files are changed in a diff, the decision is automatically flagged for re-review. Decisions older than a configurable threshold (e.g., 90 days) get surfaced for re-validation.

**Impact:**
- Repeat findings drop to zero — triaged findings don't resurface unless conditions change
- Triage cost compounds downward — each human decision permanently reduces future noise
- Institutional knowledge survives personnel changes
- Accepted risks automatically resurface when compensating controls change

### Phase 6: Compounding Knowledge Loop

After each scan:
1. New findings written to VULNERABILITIES.json (already happens with `--update-artifacts`)
2. Re-index: `qmd update && qmd embed`
3. `after_model_call` tracks relevance: did injecting threat X lead to finding Y?
4. Prune low-relevance threat context over time (keeps prompts lean)
5. Flag decisions whose `mitigated_by` files changed for re-review

## Cost Model

Assuming a repo like OpenClaw (~5,300 files):

| Scenario | Current | With Threat-Aware |
|----------|---------|------------------|
| 3 commits, 22 files (mixed risk) | $4.50 (reviews everything equally) | ~$2.00 (deep on 5 critical files, skip 10 docs) |
| 1 commit, 1 doc file | $0.45 (full review) | ~$0.05 (skip tier) |
| 5 commits, 8 files all in sandbox | $4.50 (no extra context) | ~$3.50 (deep + injected threats, better findings) |

## Migration Path

1. **Phase 1-2** — biggest ROI, pure wrapper change. No changes to core securevibes needed.
2. **Phase 3** — wrapper refactor, depends on Phase 2.
3. **Phase 4** — requires Agent SDK hook support in securevibes core.
4. **Phase 5** — needs a triage CLI flow + qmd integration.
5. **Phase 6** — metrics collection, added incrementally.

## Dependencies

- **qmd** — BM25 + vector search CLI
- **THREAT_MODEL.json** — must exist from baseline scan
- **Baseline artifacts** — SECURITY.md, VULNERABILITIES.json
- **Claude Agent SDK** — `before_model_call` / `after_model_call` hooks (Phase 4)

## Open Questions

1. Should risk tiers be configurable per repo? E.g., some teams want docs reviewed if docs contain security guidance.
2. How to handle new files not in the threat model? Default to Tier 2 and flag for threat model update.
3. Should qmd be required or optional? If optional, fall back to file-path pattern matching only.
4. Multi-repo support? Each repo gets its own qmd collection, but threat models could reference shared components.
5. What's the right granularity for qmd queries — per-file or per-directory?
