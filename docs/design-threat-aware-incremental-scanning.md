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
- Threat context, design decisions, and decision traces injected during prompt assembly (see Phase 5)
- ~600s per chunk, but these are the chunks that matter

### Tier 2 — Moderate (Sonnet, standard review)

Files touching config, routing, plugins, API handlers, session management, browser relay, channels.

- Standard review with **Sonnet**
- No extra context injection
- ~300s per chunk

### Tier 3 — Skip (no LLM call)

Docs, tests, CI config, changelog, package.json version bumps, README, comments-only changes.

- Log skip classification first, then advance anchor only after invariant checks pass (see Safety Invariants)
- Skip tier remains no-LLM, but fail-closed safeguards can promote a chunk to Tier 2
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

#### qmd Availability

- Phases 1-3 MUST work without qmd using only `risk_map.json` glob pattern matching.
- qmd is required starting Phase 4 for semantic search over design decisions and decision traces.
- When qmd is configured but unavailable (process down or query timeout > 5s):
  - Fall back to `risk_map.json` pattern matching only.
  - Log a degradation warning: `"qmd unavailable, falling back to pattern-only triage"`.
  - Do NOT fail the scan; degraded triage is better than no scan.
- qmd query results are cached per scan run (keyed by file path) to avoid redundant queries.

#### Component Mapping Quality

- The existing `_derive_components_from_file_path()` in `packages/core/securevibes/scanner/artifacts.py` produces coarse mappings (for example, `src/auth/user.py -> src:py`) and is insufficient for tier decisions.
- Tier classification MUST use `risk_map.json` glob patterns as the primary mechanism.
- For unmapped files, default to Tier 2 and log for threat model update.
- `_derive_components_from_file_path()` is NOT used for tier decisions in Phases 1-3.
- Future improvement: enhance component derivation to use multi-level path segments; this is not a blocker for Phases 1-3.

### Phase 3: Risk-Weighted Chunking

Replace flat chunking with tiered processing:

- Chunks are processed in commit order (same anchor model as today); tier determines review depth, not processing sequence.
- For Phases 1-3, model routing is chunk-level: the highest-risk file in the chunk chooses the model (`critical -> Opus`, `moderate -> Sonnet`, `skip -> no LLM`, subject to skip safeguards).
- Mixed-tier chunks are processed as a single unit at the highest required depth to preserve anchor safety and avoid split-range gaps.
- Skip-tier classification is recorded before anchor advancement (see Safety Invariants / Anchor Advancement Invariant).
- Tier 3 batching: consecutive all-skip chunks can be batched for execution efficiency, but each constituent commit must be individually recorded as classified.

### Phase 4: Security Design Decisions — Proactive Intent Declaration

Decision traces (Phase 5) are reactive — they capture triage after a finding surfaces. Design decisions are proactive — they tell the scanner what's intentional **before** it runs, preventing false positives entirely.

#### The Problem

The scanner flagged "Scope Escalation via Self-Declared Scopes on Shared-Token Operator Connections" as HIGH. Investigation revealed this was an intentional fix (#27494) — shared gateway token holders are fully trusted operators, so preserving their scopes is by design. The scanner wasted time flagging it, a human wasted time investigating it, and on the next scan of a different repo with similar patterns, it'll happen again.

#### Design Decision Schema

Stored in `.securevibes/design_decisions.json`, version-controlled with the repo:

```json
[
  {
    "id": "DD-001",
    "component": "gateway/auth",
    "decision": "Shared gateway token holders are fully trusted operators. Self-declared scopes are preserved for token-authenticated connections.",
    "rationale": "Gateway token is the operator-level shared secret. Restricting scopes for token holders broke headless API workflows (#27494). If an attacker has the gateway token, scope restrictions are meaningless.",
    "references": [
      "src/gateway/server/ws-connection/message-handler.ts",
      "src/gateway/server/ws-connection/auth-context.ts"
    ],
    "accepted_behaviors": [
      "Token-authenticated operators retain self-declared scopes",
      "No scope clearing when sharedAuthOk is true"
    ],
    "invalidation_conditions": [
      "Introduction of tiered/scoped gateway tokens with different trust levels",
      "Gateway token shared with untrusted third parties"
    ],
    "decided_by": "kevin-shenghui",
    "decided_at": "2026-02-26",
    "issue_ref": "#27494"
  }
]
```

#### How It Works

1. **Developers write design decisions** when they make intentional security trade-offs. This is the natural point — they already write commit messages explaining "why." This captures it in a structured, machine-readable format.

2. **Indexed in qmd** alongside threat model and vulnerability data:
   ```bash
   qmd add securevibes-decisions .securevibes/design_decisions.json
   qmd update && qmd embed
   ```

3. **Injected during prompt assembly** for every review of the affected component:
   ```
   ## Design Decisions for [Gateway Auth]
   
   DD-001: Shared gateway token holders are fully trusted operators.
   Self-declared scopes are preserved for token-authenticated connections.
   Rationale: Gateway token is the operator-level shared secret.
   
   DO NOT flag behaviors listed as accepted unless invalidation
   conditions are met:
   - Introduction of tiered/scoped gateway tokens
   - Gateway token shared with untrusted third parties
   ```

4. **Invalidation monitoring:** When files in `references` are changed, check whether the change affects any `invalidation_conditions`. If so, surface the design decision for re-review.

#### Comparison with Other Layers

| | Design Decisions | Decision Traces (Phase 5) | Threat Model Annotations |
|---|---|---|---|
| **When created** | Proactively by dev team | After first false positive | During baseline scan |
| **Prevents first FP?** | ✅ Yes | ❌ No (reactive) | ✅ Yes |
| **Granularity** | Per architectural decision | Per finding instance | Per component behavior |
| **Who writes it** | Developer/architect | Security reviewer | Security + dev together |
| **Lives where** | `.securevibes/design_decisions.json` | `.securevibes/decisions/` | `THREAT_MODEL.json` |
| **Survives personnel changes** | ✅ Version-controlled | ✅ Indexed | ✅ Version-controlled |

#### Threat Model Annotations (Lightweight Alternative)

For teams that don't want to maintain a full design decisions file, the THREAT_MODEL.json can be extended with an `accepted_behaviors` field per component:

```json
{
  "component": "Gateway Auth",
  "risk": "HIGH",
  "attack_surfaces": ["ws-connection", "http-api"],
  "accepted_behaviors": [
    "Token-authenticated operators retain self-declared scopes",
    "V2 device signatures do not include platform/deviceFamily fields"
  ]
}
```

This is lighter weight — just a list of "this is not a bug" — but lacks the rationale, invalidation conditions, and traceability of full design decisions.

#### Why This Matters for SecureVibes

No other scanner lets developers declare design intent that the AI reviewer actually understands. Traditional SAST/DAST tools have suppression comments (`// nosec`, `@SuppressWarnings`) that silence findings blindly. Design decisions are the opposite — they explain *why* a behavior is intentional, under what conditions the decision should be revisited, and they feed the reviewer context that makes it smarter, not quieter.

### Phase 5: Context Injection via Prompt Assembly

**In `securevibes pr-review` (packages/core change):**

Context injection extends the existing prompt assembly path in `scanner.py` (`pr_review()` and `_prepare_pr_review_context()`), which already injects:

- `architecture_context`
- `threat_context_summary`
- `vuln_context_summary`
- `security_adjacent_files`

No new SDK hooks are required for Phase 5.

Append new context sections to `contextualized_prompt`:

- `## Design Decisions for [{component}]`
  - Source: `.securevibes/design_decisions.json`
  - Filter: decisions matching affected component(s)
- `## Decision Traces for [{component}]`
  - Source: `.securevibes/decisions/`
  - Filter: traces matching affected component(s), excluding `fixed` verdicts
- `## Relevant Past Findings`
  - Source: `VULNERABILITIES.json`
  - Filter: findings matching affected component(s) and changed paths (extends existing `vuln_context_summary`)

Feedback loop happens after each scan run: log which design decisions/traces were injected and whether findings were produced for the same component(s). This replaces the prior hook-based relevance-tracking concept.

### Phase 6: Decision Traces — Institutional Triage Memory

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

### Phase 7: Compounding Knowledge Loop

After each scan:
1. New findings written to VULNERABILITIES.json (already happens with `--update-artifacts`)
2. Re-index: `qmd update && qmd embed`
3. Post-scan telemetry tracks relevance: did injected threat/decision context for component X lead to finding Y?
4. Prune low-relevance threat context over time (keeps prompts lean)
5. Flag decisions whose `mitigated_by` files changed for re-review

## Cost Model

Assuming a repo like OpenClaw (~5,300 files):

| Scenario | Current | With Threat-Aware |
|----------|---------|------------------|
| 3 commits, 22 files (mixed risk) | $4.50 (reviews everything equally) | ~$2.00 (deep on 5 critical files, skip 10 docs) |
| 1 commit, 1 doc file | $0.45 (full review) | ~$0.05 (skip tier) |
| 5 commits, 8 files all in sandbox | $4.50 (no extra context) | ~$3.50 (deep + injected threats, better findings) |

## Safety Invariants

### Policy File Trust Boundary

- `risk_map.json`, `design_decisions.json`, and `THREAT_MODEL.json` MUST be loaded from merge-base or default-branch state, never from PR head state.
- Any PR that modifies these files is auto-classified as Tier 1 (Critical), regardless of other file content.
- The risk scorer loads policy via trusted git object reads (for example, `git show <merge-base>:.securevibes/risk_map.json`) rather than working-tree reads.
- Decision traces under `.securevibes/decisions/` follow the same trust rule and are loaded from trusted base state.

### Anchor Advancement Invariant

- Hard invariant: anchor may only advance to commit `N` when every commit `<= N` has been classified, including Tier 3 skips.
- Tiering controls review depth, not processing order; chunks are visited in commit order.
- "Process Tier 1 first" applies only to parallel implementations. Sequential runs must preserve commit order.
- Skip-tier chunks must record a classification entry (`tier=skip`, `files=[...]`, `reason="all files matched skip patterns"`) before anchor advances past them.
- Reference point: current greedy anchor progression in `ops/incremental_scan.py` (around `last_successful_anchor`) requires explicit classification guarantees to prevent unclassified gaps.

### Skip Tier Safeguards

Tier 3 still means no LLM call, but these fail-closed checks run before any skip is accepted:

| Check | Trigger | Action |
|---|---|---|
| New file in skip path | File status is Added (not Modified) | Bump to Tier 2 |
| Dependency file change | `package.json`, `requirements.txt`, `*.lock`, `Cargo.toml` | Run lightweight supply-chain diff check (no LLM): flag newly added/changed dependencies |
| Deleted security test | `*.test.*` or `*.spec.*` file deleted | Log warning and bump to Tier 2 |
| Extensionless file | No extension outside `docs/` | Bump to Tier 2 (matches existing fail-closed triage behavior) |
| Script with exec/eval | `scripts/*` contains `exec`, `eval`, or `child_process` patterns | Bump to Tier 2 |

These safeguards are deterministic pattern/regex checks, not LLM-based checks.

## Migration Path

1. **Phase 1-2** — biggest ROI, pure wrapper change. No changes to core securevibes needed.
2. **Phase 3** — wrapper refactor, depends on Phase 2.
3. **Phase 4** — design decisions file schema + qmd indexing. Low effort, high impact on false positive reduction. Can be adopted incrementally per repo.
4. **Phase 5** — extends existing prompt assembly in securevibes core to inject design decisions + decision traces + past findings context.
5. **Phase 6** — decision traces for reactive triage. Needs a CLI flow + qmd integration.
6. **Phase 7** — metrics collection, added incrementally.

## Dependencies

- **qmd** — BM25 + vector search CLI
- **THREAT_MODEL.json** — must exist from baseline scan
- **Baseline artifacts** — SECURITY.md, VULNERABILITIES.json
- **Prompt assembly path** — `pr_review()` in `packages/core/securevibes/scanner/scanner.py` (Phase 5 extension point)
- **design_decisions.json** — optional, created by dev team (Phase 4)

## Resolved Decisions

1. **Risk tiers configurable per repo?** Yes. `risk_map.json` is per-repo; teams can promote paths (including `docs/*`) to moderate when docs carry security guidance.
2. **How to handle new files not in threat model?** Default to Tier 2 and log for threat model update.
3. **Is qmd required?** Optional with graceful degradation for triage (pattern-only fallback).
4. **Multi-repo support?** Each repo has its own `risk_map.json` and qmd collection; cross-repo references are out of scope.
5. **qmd query granularity?** Per-file for triage classification, per-component for context injection; cache results per scan run.
