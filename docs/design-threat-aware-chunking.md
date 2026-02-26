# Design: Threat-Aware Incremental Scanning (v2)

## Status
Proposed — discussion in PR #43

## Problem

Current incremental scanning treats all code changes equally. A 1-line change to `src/agents/sandbox.ts` (code execution boundary) gets the same review depth and budget as a 30-file documentation update. This leads to:

1. **Wasted spend** — $5 reviewing docs, CI configs, and test formatting
2. **Shallow coverage** — high-risk changes get the same shallow pass as everything else
3. **No memory** — each review starts from zero context, unaware of known threats, past findings, or the codebase's security architecture

## Proposal

Use baseline scan artifacts as a **security-aware lens** for incremental reviews. Index them with qmd (BM25 + vectors) to create a persistent memory layer that informs chunking, prioritization, and context injection.

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

### Phase 1: Index Baseline Artifacts

After a full scan completes, index `.securevibes/` into qmd:

```bash
qmd add securevibes-artifacts .securevibes/**/*.{json,md}
qmd update && qmd embed
```

This gives semantic search over:
- **Components** — what the codebase is made of (gateway, sandbox, plugins, channels)
- **Threat model** — attack surfaces, trust boundaries, data flows
- **Known vulnerabilities** — past findings with severity and affected files
- **Architecture** — how components interact, where sensitive operations happen

### Phase 2: File → Component Mapping

When an incremental scan runs:

1. Get changed files from `git diff --name-only base..head`
2. For each file, query qmd: `qmd search "security relevance of <filepath>"` against the indexed artifacts
3. Map each file to its threat model component(s) and retrieve the risk score

Example:
```
src/agents/sandbox.ts        → Component: Sandbox/Exec  | Risk: CRITICAL
src/gateway/server-methods/  → Component: Gateway API    | Risk: HIGH
src/commands/onboard-*.ts    → Component: Onboarding     | Risk: MEDIUM
docs/install/docker.md       → Component: Documentation  | Risk: LOW
CHANGELOG.md                 → Component: None           | Risk: SKIP
```

### Phase 3: Risk-Weighted Chunking

Replace flat chunking with risk-tiered processing:

| Tier | Risk Level | Review Depth | Context Injection | Budget |
|------|-----------|-------------|-------------------|--------|
| **Critical** | Exec, Auth, Sandbox, Crypto | Deep multi-pass with full threat context | All relevant threats + past findings | Uncapped |
| **High** | Gateway, Plugins, Pairing | Standard review with component threats | Top 5 relevant threats | Standard |
| **Medium** | CLI, Config, Channels | Single pass, focused on regressions | Component summary only | Reduced |
| **Low** | Docs, Tests, CI, Formatting | Skip or single-pass triage | None | Minimal |

Chunks are grouped by component, not by commit count or diff size. A single commit touching both `sandbox.ts` and `CHANGELOG.md` gets split into two chunks at different tiers.

### Phase 4: Context Injection

For each chunk, inject relevant security context into the pr-review prompt:

```
You are reviewing changes to the [Sandbox/Exec] component.

Known threats for this component:
- Exec obfuscation detector gaps (single-variable indirection, compile()+exec())
- Plugin loading executes in-process with full OS access
- Docker sandbox symlink TOCTOU

Previous findings in this area:
- [HIGH] Exec obfuscation detector gaps (2026-02-25)

Focus your review on: code execution boundaries, input validation,
privilege escalation, and sandbox escape vectors.
```

This gives the LLM *domain-specific knowledge* about what to look for, rather than relying on generic security review heuristics.

### Phase 5: Findings Memory

After each incremental scan:
1. New findings are written to `VULNERABILITIES.json` (already happens with `--update-artifacts`)
2. Re-index: `qmd update && qmd embed`
3. Future reviews of the same component automatically get the accumulated findings history

This creates a **compounding knowledge loop** — the scanner gets smarter about the codebase over time.

## Implementation Plan

### Step 1: qmd integration in wrapper (ops/incremental_scan.py)
- Add `--use-qmd` flag
- Post-baseline: auto-index artifacts into qmd collection `securevibes-<repo-hash>`
- Add `query_component_risk()` function that maps files → components via qmd search

### Step 2: Risk scoring (new module: ops/risk_scorer.py)
- Parse THREAT_MODEL.json for component definitions + risk levels
- Map file paths to components using directory patterns + qmd semantic matching
- Output: `list[FileRisk]` with file, component, tier, relevant_threats

### Step 3: Tiered chunking (extend compute_chunks_adaptive)
- Group files by risk tier
- Generate separate chunks per tier with appropriate depth settings
- Critical/High chunks include injected threat context

### Step 4: Context injection via Claude Agent SDK hooks (packages/core change)
- Use `before_model_call` hook in the Agent SDK to inject threat context dynamically
- The hook queries qmd for relevant threats/findings for the current chunk's components
- Prepends component-specific security context to the system prompt before each LLM call
- No CLI flag needed — the hook fires automatically when qmd index exists
- `after_model_call` hook can log which threats were surfaced vs. which findings were generated (feedback loop for relevance tuning)

### Step 5: Decision Traces — Institutional Triage Memory

Findings that get triaged by humans carry valuable institutional knowledge. This needs to be captured, indexed, and fed back into future reviews.

#### Decision Trace Schema

```json
{
  "finding_id": "sv-2026-0225-007",
  "title": "Exec obfuscation detector gaps",
  "component": "Sandbox/Exec",
  "severity": "HIGH",
  "verdict": "accepted_risk",
  "rationale": "Single-variable indirection is low-exploitability because exec allowlist restricts to known binaries. The obfuscation path requires chaining with an allowlist bypass which is tracked separately.",
  "conditions": "Revisit if exec allowlist implementation changes or new bypass vectors are discovered",
  "mitigated_by": ["src/agents/pi-tools.safe-bins.ts", "src/agents/sandbox-tool-policy.ts"],
  "decided_by": "anshuman",
  "decided_at": "2026-02-26",
  "related_findings": ["sv-2026-0225-004"]
}
```

#### Verdict Types

| Verdict | Meaning | Revisit When |
|---------|---------|-------------|
| `false_positive` | Not a real vulnerability | Same code pattern appears (low priority) |
| `accepted_risk` | Real risk, accepted with rationale | Conditions change (e.g., component refactored) |
| `mitigated_by` | Risk exists but compensating controls handle it | Linked mitigating code changes |
| `deferred` | Will fix later | Deferred deadline passes |
| `fixed` | Addressed in code | Regression detected |

#### How It Works

1. **Capture:** After a scan, human reviews findings. Decisions are recorded in `.securevibes/decisions/` as JSON files, one per finding.
2. **Index:** Decision traces are indexed in qmd alongside threat model and findings.
3. **Inject:** `before_model_call` hook queries qmd for decision history on the current chunk's components. Injects relevant decisions into the review prompt:
   ```
   Previous triage decisions for [Sandbox/Exec]:
   - [HIGH] Exec obfuscation detector gaps → ACCEPTED_RISK
     Rationale: "Allowlist restricts to known binaries"
     Conditions: "Revisit if exec allowlist changes"
     DO NOT re-flag unless conditions are met.
   ```
4. **Condition monitoring:** When `mitigated_by` files are changed in a diff, the `after_model_call` hook flags the relevant decisions for re-review. "This change touches src/agents/pi-tools.safe-bins.ts which is a compensating control for finding sv-2026-0225-007. Re-evaluate."
5. **Decay:** Decisions older than a configurable threshold (e.g., 90 days) get surfaced for re-validation rather than silently trusted.

#### Impact

- **Repeat findings drop to zero** — triaged findings don't resurface unless conditions change
- **Triage cost compounds downward** — each human decision permanently reduces future noise
- **Institutional knowledge survives** — rationale is preserved even when the person who triaged leaves
- **Condition-aware re-triggering** — accepted risks automatically resurface when compensating controls change

### Step 6: Post-scan reindex
- After each scan, update qmd index with new findings + decision traces
- Prune stale findings when vulnerabilities are resolved
- Flag decisions whose `mitigated_by` files were changed for re-review
- Surface decisions older than decay threshold for re-validation

## Cost Model

Assuming a repo like OpenClaw (~5,300 files):

| Scenario | Current | With Threat-Aware |
|----------|---------|------------------|
| 3 commits, 22 files (mixed risk) | $4.50 (reviews everything equally) | ~$2.00 (deep on 5 critical files, skip 10 docs) |
| 1 commit, 1 doc file | $0.45 (full review) | ~$0.05 (skip tier) |
| 5 commits, 8 files all in sandbox | $4.50 (no extra context) | ~$3.50 (deep + injected threats, better findings) |

The savings come from **not reviewing low-risk changes** and the quality improvement comes from **injecting threat context** for high-risk ones.

## Dependencies

- **qmd** — BM25 + vector search CLI (already used in Sage's architecture)
- **THREAT_MODEL.json** — must exist from baseline scan
- **Baseline artifacts** — SECURITY.md, VULNERABILITIES.json

## Open Questions

1. **Should risk tiers be configurable?** E.g., a user might want docs reviewed if their docs contain security guidance
2. **How to handle new files not in the threat model?** Default to MEDIUM tier and flag for threat model update?
3. **Should qmd be a required dependency or optional?** If optional, fall back to file-path heuristics only
4. **Multi-repo support?** Each repo gets its own qmd collection, but threat models could reference shared components
