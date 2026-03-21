# Design: Threat-Aware Incremental Scanning

## Status
Partially implemented — PR #43

## Implementation Status Snapshot (March 18, 2026)

- [x] Phase 1: derive or load `.securevibes/risk_map.json` from `THREAT_MODEL.json`
- [x] Phase 2: deterministic file/chunk risk scoring with `critical` / `moderate` / `skip`
- [x] Skip-tier safeguards and dependency-change promotion
- [x] Policy/context file changes promote a chunk to Tier 1
- [~] Phase 3: risk-weighted chunk routing exists in `ops/incremental_scan.py`, but the core `securevibes incremental` orchestrator does not exist yet
- [ ] Phase 3A: range-aware commit synopsis and baseline-guided hypothesis routing
- [~] Prompt assembly now carries richer baseline-aware PR-review context, but it does not use qmd semantic retrieval
- [~] Wrapper anchor-preservation and fail-closed behavior exist, but trusted merge-base policy reads are not implemented yet
- [ ] Phase 4: `design_decisions.json` loading, matching, and prompt injection
- [ ] Phase 5: qmd indexing, semantic retrieval, and intra-run refresh
- [ ] Phase 6: decision traces and Agent Trace provenance
- [ ] Phase 7: compounding knowledge loop and artifact re-indexing
- [ ] Phase 8: interactive post-scan feedback loop

### Built In This PR Outside The Original Phase Breakdown

- PR-review timeout propagation and attempt-loop hardening
- Structured changed-code reasoning and prompt assembly improvements
- Baseline-sink composition and exact unchanged-sink adjudication for PR review

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

Use baseline scan artifacts (THREAT_MODEL.json, SECURITY.md, VULNERABILITIES.json) as a **security-aware lens**. Before any LLM call, classify each chunk by what it touches and route to the appropriate model and review depth. Triage uses exact glob matching against `risk_map.json` (no external dependencies). Context injection uses qmd for semantic search to find relevant threats and findings for the code under review.

For high-velocity repositories, the analysis unit cannot be "one giant raw diff." Incremental mode must accept a **commit range** and decompose it into smaller, evidence-preserving review units. The intended model is:

1. **Pass A: commit synopsis / surface delta**
   - Cheap LLM or deterministic pass over commit metadata, changed files, file stats, and compact diff anchors/snippets
   - Produces a structured synopsis of what each commit appears to change:
     - new or modified capabilities
     - new or modified trust boundaries
     - new or modified privileged sinks
     - likely new component / feature introduction
     - likely regression or threat-enabler against an existing component
2. **Pass B: baseline-guided hypothesis routing**
   - Compare those synopses against baseline `THREAT_MODEL.json`, `VULNERABILITIES.json`, and `risk_map.json`
   - Group commits into **security review clusters** by affected component, attack surface, and baseline overlap
   - Decide whether each cluster requires:
     - targeted code review only
     - incremental threat modeling + code review
     - dependency / supply-chain review
     - skip / defer
3. **Pass C: targeted code validation**
   - Only now read concrete code and diff content for the selected cluster
   - Review evidence must still come from code, not from summaries
   - The synopsis is a routing artifact, not a finding artifact

This keeps SecureVibes useful on repos like OpenClaw where even a 30-minute window may contain too many changed files for classic PR review.

## Commit-Range Processing Model

### Why commit ranges matter

Reviewing only the single vulnerability-introducing commit is a good benchmark approximation for "catch it at introduction time," but it is not sufficient for real-world high-velocity repositories. In practice:

- operators often run SecureVibes on a timer (`every 15m`, `every 30m`, hourly)
- the resulting window may include many commits
- that window may be too large for direct PR-review ingestion even when every individual commit is "reasonable"
- vulnerability-relevant context may span multiple commits in the same window

So incremental mode must support **range intake** while refusing to send an arbitrarily large raw diff directly into `pr-review`.

### Three-pass hierarchical review

The core orchestration model for `securevibes incremental` should be:

```text
commit range
  -> commit synopses
  -> baseline-aware hypothesis routing
  -> targeted review clusters
  -> code-grounded validation
  -> artifact updates
```

#### Pass A: commit synopsis

Input:
- commit SHAs in the active range
- commit subject/body
- changed file list
- insertions / deletions / rename metadata
- compact diff anchors and hunk snippets

Output:
- `.securevibes/incremental_synopsis.json`

Each commit synopsis captures:
- affected files and inferred components
- whether the change appears to introduce a new feature / surface
- whether the change modifies existing auth, policy, config, network, secrets, sandbox, plugin, or execution paths
- whether the change touches files with prior baseline findings
- coarse security intent:
  - `new_surface`
  - `existing_surface_delta`
  - `dependency_change`
  - `likely_non_security`

Important constraint:
- synopsis generation must stay cheap
- it may use compact diff summaries, but it must not attempt full vulnerability analysis
- synopsis output is advisory routing metadata only

#### Pass B: baseline-guided hypothesis routing

Input:
- commit synopses
- baseline `THREAT_MODEL.json`
- baseline `VULNERABILITIES.json`
- derived `risk_map.json`
- optional design decisions / decision traces when present

Output:
- `.securevibes/incremental_hypotheses.json`

This pass clusters commits into review units such as:
- "existing gateway auth surface changed across commits A,B,C"
- "new plugin installation surface introduced in commits D,E"
- "dependency-only changes in commits F,G"

For each cluster, the router chooses one of:
- `targeted_pr_review`
- `incremental_threat_model_then_review`
- `supply_chain_review`
- `skip`

The router also determines the evidence set for Pass C:
- file subset
- adjacent baseline files
- relevant baseline threats/findings
- changed-code anchors

#### Pass C: targeted code validation

Input:
- one routed cluster
- only the files and diff slices needed for that cluster
- baseline summaries and component context

Output:
- findings backed by concrete code evidence

Pass C is the only pass allowed to emit findings. It may:
- call existing PR-review prompt assembly on a synthetic diff slice
- run incremental threat modeling before PR review when the cluster is `new_surface`
- update `THREAT_MODEL.json` and `VULNERABILITIES.json` after validated findings

### Key invariants

- A large commit range is an **ingest unit**, not a review unit.
- Commit summaries are never treated as final evidence.
- Findings must remain grounded in concrete code reads and diff snippets.
- New attack surfaces trigger threat-model expansion before final review.
- Existing attack surfaces are reviewed against baseline threats and findings before broad exploration.
- Artifact updates from one cluster must be visible to later clusters in the same run.

## Mandatory Prerequisites (Per Repository)

Threat-aware incremental scanning is only valid after a baseline scan has been completed for that repository and branch.

1. Baseline run order is fixed:
   - `assessment -> threat-modeling -> code-review -> report-generator`
2. Required baseline artifacts:
   - `.securevibes/SECURITY.md`
   - `.securevibes/THREAT_MODEL.json`
   - `.securevibes/VULNERABILITIES.json`
3. Threat modeling is produced by the **`threat-modeling` subagent** (fixed subagent contract, even when invoked ad hoc per chunk).
4. For agentic applications, threat modeling must include OWASP ASI threats (via agentic threat-modeling skills); orchestration must pass repository/app profile so this path is auto-applied by the subagent.
5. If prerequisites are missing or invalid, incremental mode fails closed and instructs the operator to run baseline scan.
6. Canonical finding artifact name is `VULNERABILITIES.json`.
7. Baseline threat outputs must include code-grounded validation status from baseline code-review:
   - each threat is marked `validated`, `invalidated`, or `needs_followup`
   - each status includes code evidence (file paths and rationale) captured during the baseline run

### Baseline Quality Contract (Blocking)

Baseline quality is a hard gate because baseline artifacts are the source of truth for incremental learning, tiering, and memory.

Incremental mode is allowed only when baseline outputs satisfy all checks:

- Architecture assessment captures core components, key data flows, trust boundaries, authn/authz paths, and external integrations relevant to security.
- Architecture assessment completion is phase-complete (no omitted SecureVibes assessment phases for that repository profile).
- Threat modeling is in-depth for the repository domain and includes agentic-specific threats when the app is agentic.
- Baseline code-review explicitly validates/invalidates modeled threats against real code and carries unresolved items as `needs_followup`.
- `VULNERABILITIES.json` remains the canonical findings artifact name (not `volunteers.json`).

If quality checks fail, incremental mode fails closed with explicit remediation guidance to rerun baseline.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Baseline Artifacts                     │
│  SECURITY.md · THREAT_MODEL.json · VULNERABILITIES.json  │
│  risk_map.json · design_decisions.json · decisions/      │
└──────────────────────┬──────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
  ┌──────────────┐         ┌──────────────┐
  │   Triage     │         │   qmd index  │
  │  (Phases 1-3)│         │  (Phase 5+7) │
  │  glob match  │         │  BM25+vector │
  └──────┬───────┘         └──────┬───────┘
         │                        │
         ▼                        ▼
  ┌──────────────┐         ┌──────────────┐
  │  File → Tier │         │  Semantic    │
  │  assignment  │         │  context     │
  │              │         │  retrieval   │
  └──────┬───────┘         └──────┬───────┘
         │                        │
         └───────────┬────────────┘
                     ▼
            ┌─────────────────┐
            │ Risk-weighted   │
            │ chunk pipeline  │
            │ (tier + context)│
            └─────────────────┘
```

Runtime ownership: incremental orchestration lives in a core command (`securevibes incremental`) that enforces deterministic safety invariants. During migration, `ops/incremental_scan.py` is a compatibility shim that delegates to this command.

## Severity Handling Policy

- Persist findings across all severities in artifacts to preserve longitudinal learning.
- Surface only `high` and `critical` findings to end users by default.
- Display filtering must not discard stored `medium`/`low` findings.
- This policy applies to both baseline and incremental flows.

## Three-Tier Risk-Based Triage

### Tier 1 — Critical (Opus, deep review + threat context injection)

Files touching security-critical components: auth, exec, sandbox, secrets, gateway, pairing, device-auth, credential handling, permission boundaries.

- Full review with **Opus**
- Threat context, design decisions, and decision traces injected during prompt assembly (see Phase 5)
- ~600s per chunk, but these are the chunks that matter

### Tier 2 — Moderate (Sonnet, standard review + context injection for unmapped files)

Files touching config, routing, plugins, API handlers, session management, browser relay, channels. Also the default tier for unmapped files not in the risk map.

- Standard review with **Sonnet**
- ~300s per chunk

**Context injection for unmapped files:** When a chunk contains files not matched by any `risk_map.json` pattern, the reviewer receives existing threat model context via qmd so it can assess how the new code interacts with the system's known attack surfaces. This is critical for new attack surface detection — a new `src/secrets/` directory reviewed without knowing about existing credential handling threats produces a blind review.

**New attack surface detection:** When unmapped files introduce an entirely new component (new top-level directory, new module with security-relevant patterns like auth, crypto, exec, secrets, network), the chunk is flagged for **incremental threat modeling** in addition to code review:

1. The threat model subagent runs against the new component with the existing `THREAT_MODEL.json` as context
2. New threats are appended to `THREAT_MODEL.json`
3. `risk_map.json` is regenerated to include the new component
4. Future scans classify the component at the correct tier

This means the first review of a new attack surface is more expensive (threat modeling + code review), but all subsequent reviews are properly classified and contextualized.

### Dependency Change Detection (cross-tier)

Dependency manifest and lockfile changes (`package.json`, `requirements.txt`, `*.lock`, `Cargo.toml`, `pyproject.toml`) trigger a lightweight supply-chain diff check **regardless of tier**. This is not a skip-tier safeguard — it runs during Phase 2 risk scoring for any chunk containing manifest/lockfile changes:

- Parse the diff to identify added, removed, and changed dependencies
- Flag new or changed dependencies in the chunk metadata
- If the chunk would otherwise be Tier 3 (all files match skip patterns), **promote to Tier 2** so the dependency change gets a Sonnet review
- If the chunk contains **only** manifest/lockfile changes (no source code), it receives a **supply-chain summary** injected into the prompt instead of broad qmd threat/finding context. This avoids injecting irrelevant application-level threats for a pure dependency update.
- If the chunk also contains source code, the dependency flags are appended to whatever context injection the tier already provides.

### Tier 3 — Skip (no LLM call)

Docs, tests, CI config, changelog, README, comments-only changes.

- Log skip classification first, then advance anchor only after invariant checks pass (see Safety Invariants)
- Skip tier remains no-LLM, but fail-closed safeguards can promote a chunk to Tier 2
- ~0s

### Component Risk Mapping

`risk_map.json` is **derived from THREAT_MODEL.json**, not hand-authored. The threat model is the source of truth for what is security-critical.

#### Derivation from Threat Model

Each threat in `THREAT_MODEL.json` has a `severity` (critical/high/medium/low) and `affected_components`. The risk map generation step:

1. **Extracts components and severities** from all threats in the threat model.
2. **Resolves components to file paths.** The threat model's `affected_components` field contains function/class names (e.g., `["process_request()", "LLMChain"]`), not file paths. Resolution uses:
   - Grep/AST search to find which files define or contain those components
   - Directory-level rollup: if multiple files in `src/gateway/credentials/` are matched, the glob becomes `src/gateway/credentials*`
3. **Maps severity to tier:**
   - `critical` or `high` severity threats → Tier 1 (critical)
   - `medium` severity threats → Tier 2 (moderate)
   - `low` severity threats → no entry (falls through to Tier 2 default for unmapped files)
4. **Adds static skip patterns** for known non-security paths (docs, tests, CI config). These are not derived from the threat model — they're a fixed baseline.
5. **Writes `.securevibes/risk_map.json`** with the merged result.

Human overrides can be layered on top (promoting or demoting paths), but the base always comes from the threat model. When the threat model is updated (new baseline scan, new threats discovered), the risk map should be regenerated and overrides re-applied.

#### Generated Output

Example `risk_map.json` (generated from OpenClaw's threat model):

```json
{
  "critical": [
    "src/agents/sandbox*",
    "src/agents/pi-auth*",
    "src/agents/bash-tools.exec*",
    "src/gateway/credentials*",
    "src/gateway/device-auth*",
    "src/gateway/server-http*",
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
  ],
  "_meta": {
    "generated_from": "THREAT_MODEL.json",
    "generated_at": "2026-02-26T14:30:00Z",
    "overrides_applied": false
  }
}
```

**Note:** If a commit touches both `sandbox.ts` and `sandbox.test.ts`, the non-test file drives the tier. The highest-risk file in a chunk determines the tier for the entire chunk.

**Override precedence:** `risk_map.json` provides the initial tier, but two mechanisms can override it: (1) the cross-tier Dependency Change Detection promotes dep-containing chunks out of skip, and (2) skip-tier safeguards can bump individual files to Tier 2.

**Unmapped files** default to Tier 2 (moderate) with context injection via qmd. If they introduce a new attack surface, they also trigger incremental threat modeling (see Tier 2 description).

## Implementation Plan

### Phase 1: Risk Map Generation

After a baseline scan produces `THREAT_MODEL.json`, generate `.securevibes/risk_map.json` (see Component Risk Mapping / Derivation from Threat Model above). This is a one-time step per baseline scan, re-run when the threat model is updated.

### Phase 2: File → Component Mapping + Risk Scoring

**In the core incremental orchestrator (`securevibes incremental`):**

1. On each run, before chunking:
   - Get changed files: `git diff --name-only base..head`
   - Match against `.securevibes/risk_map.json` glob patterns (fast, no LLM)
   - Unmapped files default to Tier 2
   - Score each file by matched tier

2. Detect new attack surfaces among unmapped files:
   - If unmapped files introduce a new component (new top-level directory or module with security-relevant patterns: auth, crypto, exec, secrets, network, permissions), flag the chunk for incremental threat modeling (see Tier 2 description)
   - Otherwise, log unmapped files for threat model update on next baseline scan

3. Classify the chunk by highest-risk file:
   - Any file matches critical → Tier 1
   - Any file matches moderate → Tier 2
   - All files are skip-tier → Tier 3

4. Route to appropriate model and depth.

**New module: `packages/core/securevibes/scanner/risk_scorer.py`**
- Input: `risk_map.json` + list of changed files
- Match file paths against glob patterns from the risk map
- Output: `list[FileRisk]` with file, component, tier, relevant_threats

#### Component Mapping Quality

- The existing `_derive_components_from_file_path()` in `packages/core/securevibes/scanner/artifacts.py` produces coarse mappings (for example, `src/auth/user.py -> src:py`) and is insufficient for tier decisions.
- Tier classification MUST use `risk_map.json` glob patterns as the primary mechanism.
- For unmapped files, default to Tier 2 and log for threat model update.
- `_derive_components_from_file_path()` is NOT used for tier decisions in Phases 1-3.
- Future improvement: enhance component derivation to use multi-level path segments; this is not a blocker for Phases 1-3.

### Phase 3: Risk-Weighted Chunking + Ad Hoc Subagent Routing

Replace flat chunking with tiered processing:

- Chunks are processed in commit order (same anchor model as today); tier determines review depth, not processing sequence.
- For Phases 1-3, model routing is chunk-level: the highest-risk file in the chunk chooses the model (`critical -> Opus`, `moderate -> Sonnet`, `skip -> no LLM`), subject to cross-tier dependency-detection promotion and skip safeguards.
- Mixed-tier chunks are processed as a single unit at the highest required depth to preserve anchor safety and avoid split-range gaps.
- Subagent routing is not fixed to a global sequential pipeline. The orchestrator may invoke an ad hoc subset per chunk while preserving dependency order and anchor safety.
- Threat modeling for new attack surfaces MUST be executed by the `threat-modeling` subagent, then handed off to `pr-code-review` with updated threat context.
- Skip-tier classification is recorded before anchor advancement (see Safety Invariants / Anchor Advancement Invariant).
- Tier 3 batching: consecutive all-skip chunks can be batched for execution efficiency, but each constituent commit must be individually recorded as classified.

### Phase 3A: Commit Synopsis + Hypothesis Routing

Add a hierarchical preprocessing layer before targeted review execution.

**Inputs**
- active commit range (`last_successful_anchor..HEAD`)
- changed file metadata per commit
- compact diff anchors / hunk snippets
- baseline artifacts (`THREAT_MODEL.json`, `VULNERABILITIES.json`, `risk_map.json`)

**New runtime artifacts**
- `.securevibes/incremental_synopsis.json`
- `.securevibes/incremental_hypotheses.json`

**Step 1: commit synopsis**
- Generate a cheap structured synopsis for each commit
- Prefer deterministic metadata first, with optional low-cost LLM enrichment when needed
- Capture:
  - changed files and inferred components
  - whether the commit introduces a new surface or changes an existing one
  - whether it appears to touch trust boundaries, authz, config, routing, execution, sandbox, plugin, or secrets paths

**Step 2: baseline-guided hypothesis routing**
- Compare commit synopses against baseline threats, findings, and risk-map ownership
- Group related commits into security review clusters
- Label each cluster as:
  - `existing_surface_delta`
  - `new_surface`
  - `dependency_change`
  - `likely_non_security`

**Step 3: route clusters to review strategies**
- `existing_surface_delta`
  - targeted PR/code review with strong baseline hypothesis injection
- `new_surface`
  - incremental threat-modeling subagent first, then targeted code review
- `dependency_change`
  - supply-chain review path
- `likely_non_security`
  - skip or defer with invariant-checked logging

**Step 4: execute targeted validation**
- Review only the code slices selected by the router
- Reuse existing PR-review prompt machinery, but on cluster-sized inputs rather than the whole raw range
- Merge validated findings across clusters and update artifacts incrementally

**Implementation note**
- This phase is intentionally designed to solve the "OpenClaw problem": frequent scans over high-velocity ranges without requiring SecureVibes to ingest the entire raw diff in a single PR-review request.

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

2. **Matched by exact + semantic relevance.** During prompt assembly, design decisions are first filtered by exact `component` and `references` matches against changed files. Then qmd semantic search supplements this by surfacing relevant decisions when relationships are not captured in explicit path/component fields. Exact matches take precedence; semantic matches are supplemental context.

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
| **Survives personnel changes** | ✅ Version-controlled | ✅ Version-controlled | ✅ Version-controlled |

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

### Phase 5: Context Injection via Prompt Assembly + qmd

**In `securevibes incremental` / `securevibes pr-review` prompt assembly (packages/core change):**

Context injection extends the existing prompt assembly path in `scanner.py` (`pr_review()` and `_prepare_pr_review_context()`), which already injects:

- `architecture_context`
- `threat_context_summary`
- `vuln_context_summary`
- `security_adjacent_files`

No new SDK hooks are required for Phase 5.

#### Matching: Exact + Semantic

Context retrieval uses two mechanisms:

1. **Exact matching** — design decisions are matched by their `references` (file paths) and `component` fields. Decision traces are matched by `component` and `mitigated_by` paths. This handles cases where the relationship between changed files and context is explicitly recorded.

2. **qmd semantic search** — for finding relevant threats, past findings, and design decisions where the relationship is NOT captured in explicit path references. Example: a PR changes `src/gateway/server/http-handler.ts`, and the threat model has a threat about "API request smuggling via malformed headers" with `affected_components: ["HttpServer", "requestParser"]`. The file path doesn't appear in the threat entry. qmd bridges this gap by searching indexed artifacts for content relevant to the changed files.

qmd is indexed after each baseline scan and re-indexed after artifact updates (see Phase 7):

```bash
qmd add securevibes-artifacts .securevibes/**/*.{json,md}
qmd update && qmd embed
```

#### Intra-Run qmd Freshness

When a chunk produces artifact updates during a scan run (e.g., incremental threat modeling in chunk N appends new threats to `THREAT_MODEL.json`), qmd MUST be re-indexed before context retrieval for chunk N+1. This ensures later chunks see threats/findings produced by earlier chunks in the same run. The re-index is incremental (`qmd update && qmd embed` on changed files only) to minimize overhead.

#### Context Sections

Append new context sections to `contextualized_prompt`:

- `## Design Decisions for [{component}]`
  - Source: `.securevibes/design_decisions.json`
  - Matching: exact path/component match + qmd semantic match against decision text
- `## Decision Traces for [{component}]`
  - Source: `.securevibes/decisions/`
  - Matching: exact component/path match, excluding `fixed` verdicts
- `## Relevant Threats`
  - Source: `THREAT_MODEL.json`
  - Matching: qmd semantic search from changed file paths against indexed threats (extends existing `threat_context_summary`)
- `## Relevant Past Findings`
  - Source: `VULNERABILITIES.json`
  - Matching: exact path match + qmd semantic match against indexed findings (extends existing `vuln_context_summary`)
  - Trust rule: load from trusted base state when version-controlled; if local-only artifact, treat as advisory context and never use it to reduce review depth

#### Context Injection Scope by Tier

| Tier | Context Injected |
|------|-----------------|
| Tier 1 (Critical) | Full: design decisions + decision traces + relevant threats + past findings via qmd |
| Tier 2 (Mapped) | None — these are known moderate-risk paths with established threat coverage |
| Tier 2 (Unmapped) | Relevant threats + past findings via qmd — the reviewer needs system context to assess how new code interacts with existing attack surfaces |
| Tier 2 (Dep-only) | Supply-chain summary only (new/changed deps) — no broad qmd threat/finding injection |
| Tier 3 (Skip) | None — no LLM call |

Feedback loop happens after each scan run: log which context was injected and whether findings were produced for the same component(s).

### Phase 6: Decision Traces — Institutional Triage Memory

When a finding is triaged (false positive, accepted risk, mitigated elsewhere), record a **decision trace**.

Decision traces use **Agent Trace** for provenance and attribution (conversation/model/code-range lineage), while SecureVibes-specific fields remain canonical for security triage semantics.

Reference standard:
- https://agent-trace.dev/
- https://github.com/cursor/agent-trace

Decision trace record (SecureVibes schema + Agent Trace envelope):

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
  "related_findings": ["sv-2026-0225-004"],
  "agent_trace": {
    "id": "at_01HXYZ...",
    "standard_version": "1.0",
    "vcs_revision": "abc1234",
    "conversation_url": "https://example.ai/c/123",
    "contributor": "codex",
    "model": "claude-sonnet-4.5",
    "files": [
      {
        "path": "src/agents/sandbox-tool-policy.ts",
        "ranges": [{"start": 42, "end": 73}]
      }
    ]
  }
}
```

**Mapping rule:** Agent Trace fields capture provenance (`who/what/where`); SecureVibes fields capture security decision behavior (`verdict/conditions/mitigated_by`). Agent Trace does not replace verdict semantics.

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
2. If threat model was updated (new attack surface detected in Phase 2), regenerate `risk_map.json`
3. Re-index artifacts in qmd: `qmd update && qmd embed` — keeps Phase 5 context injection current
4. Post-scan telemetry tracks relevance: did injected context for component X lead to finding Y?
5. Prune low-relevance threat context over time (keeps prompts lean)
6. Flag decisions whose `mitigated_by` files changed for re-review

### Phase 8: Post-Baseline Findings Review + User Feedback Loop

After baseline (and on each incremental run), findings are presented to the user with default visibility filtering:

- Surface only `high` and `critical` findings by default.
- Keep `medium`/`low` persisted and queryable for longitudinal risk tracking.

Interactive review flow:

1. User opens a finding (or set of findings) in conversational mode.
2. System provides supporting context: threat entry, code evidence, prior decisions, and related artifacts.
3. User can submit feedback (confirm issue, dispute issue, accepted risk, request more evidence, defer).
4. Feedback updates decision traces and triage state for future runs.
5. If user feedback invalidates prior assumptions, mark affected threat/finding context for re-validation on next scan.

Feedback outcomes are written to decision traces with Agent Trace provenance so future reviewers can audit why a verdict changed and which conversation/code context drove the change.

## Cost Model

Assuming a repo like OpenClaw (~5,300 files):

| Scenario | Current | With Threat-Aware |
|----------|---------|------------------|
| 3 commits, 22 files (mixed risk) | $4.50 (reviews everything equally) | ~$2.00 (deep on 5 critical files, skip 10 docs) |
| 1 commit, 1 doc file | $0.45 (full review) | ~$0.05 (skip tier) |
| 5 commits, 8 files all in sandbox | $4.50 (no extra context) | ~$3.50 (deep + injected threats, better findings) |

## Safety Invariants

### Policy File Trust Boundary

- `risk_map.json`, `design_decisions.json`, `THREAT_MODEL.json`, and `VULNERABILITIES.json` (when version-controlled) MUST be loaded from merge-base or default-branch state, never from PR head state.
- Any PR that modifies these version-controlled policy/context files is auto-classified as Tier 1 (Critical), regardless of other file content.
- The risk scorer loads policy via trusted git object reads (for example, `git show <merge-base>:.securevibes/risk_map.json`) rather than working-tree reads.
- Decision traces under `.securevibes/decisions/` follow the same trust rule and are loaded from trusted base state.
- Agent Trace metadata linked from decision traces follows the same trust rule; provenance references from untrusted PR head state are advisory-only and cannot suppress review depth.
- If `VULNERABILITIES.json` is local-only (not version-controlled), it may be used as advisory context but MUST NOT lower tiering decisions or suppress review depth.

### Anchor Advancement Invariant

- Hard invariant: anchor may only advance to commit `N` when every commit `<= N` has been classified, including Tier 3 skips.
- Failed classification does NOT count as classified.
- If tier decision fails (for example, unreadable/corrupt trusted policy input) or review execution fails (timeout, LLM/infrastructure error), anchor remains at the last successfully classified commit.
- The failed chunk/range is retried on the next run; no commit beyond the failure point is considered classified.
- Tiering controls review depth, not processing order; chunks are visited in commit order.
- "Process Tier 1 first" applies only to parallel implementations. Sequential runs must preserve commit order.
- Skip-tier chunks must record a classification entry (`tier=skip`, `files=[...]`, `reason="all files matched skip patterns"`) before anchor advances past them.
- Reference implementation during migration: legacy wrapper behavior around `last_successful_anchor` in `ops/incremental_scan.py` remains the parity baseline until deprecation is complete.

### Skip Tier Safeguards

Tier 3 still means no LLM call, but these fail-closed checks run before any skip is accepted:

| Check | Trigger | Action |
|---|---|---|
| New file in skip path | File status is Added (not Modified) | Bump to Tier 2 |
| Deleted security test | `*.test.*` or `*.spec.*` file deleted | Log warning and bump to Tier 2 |
| Extensionless file | No extension outside `docs/` | Bump to Tier 2 (matches existing fail-closed triage behavior) |
| Script with exec/eval | `scripts/*` contains `exec`, `eval`, or `child_process` patterns | Bump to Tier 2 |

These safeguards are deterministic pattern/regex checks, not LLM-based checks.

**Note:** Dependency file changes are handled by the cross-tier Dependency Change Detection (see Three-Tier Risk-Based Triage section), not by skip safeguards.

## Migration Path

1. **Step 1 (core orchestrator)** — implement `securevibes incremental` in core with deterministic state/anchor/chunk invariants and tier-aware subagent routing.
2. **Step 2 (compatibility shim)** — keep `ops/incremental_scan.py` as a thin delegating shim to preserve existing cron/ops entrypoints while parity tests run.
3. **Step 3 (deprecation)** — remove wrapper-owned orchestration after parity and soak period; keep behavior contract and logs in the core command.
4. **Step 4 (context + memory layers)** — roll out Phases 4-8 (design decisions, context injection, decision traces, compounding telemetry, user feedback loop) incrementally.

### Recommended Implementation Order For Phases 4-8

To preserve deterministic routing, Phases 4-8 should be implemented as review-context and memory layers only. They must not affect tier classification, skip decisions, or anchor advancement.

1. **Phase 4 first, exact-match only** — add `design_decisions.json` loading, validation, exact path/component matching, and prompt injection. Do not add semantic retrieval yet.
2. **Phase 6 second, exact-match only** — add decision trace storage under `.securevibes/decisions/`, exact matching by changed paths/components/`mitigated_by`, and prompt injection. Do not block this on Agent Trace support.
3. **Introduce a retrieval abstraction** — add a shared retrieval layer that returns relevant threats, findings, design decisions, and decision traces. Start with exact-match providers only so `scanner.py` depends on an interface rather than a qmd-specific implementation.
4. **Phase 5 after the abstraction exists** — add qmd-backed semantic retrieval behind the retrieval layer. Use it only for contextual retrieval during prompt assembly, not for tiering or review-depth suppression.
5. **Phase 7 next** — add freshness/reindexing and compounding-memory mechanics: refresh contextual artifacts after updates, re-surface traces when `mitigated_by` files change, and record minimal context-injection telemetry.
6. **Phase 8 last** — add a simple user-feedback flow that writes decision traces from explicit triage actions (`false_positive`, `accepted_risk`, `mitigated_by`, `deferred`, `fixed`). Start with a narrow CLI-backed flow rather than a full conversational UX.

**Agent Trace sequencing:** add Agent Trace provenance as a follow-up enrichment to Phase 6 once the core decision-trace model is stable. It should extend trace provenance, not block the first usable memory layer.

## Dependencies

- **THREAT_MODEL.json** — must exist from baseline scan (source of truth for risk map generation)
- **Baseline artifacts** — SECURITY.md, VULNERABILITIES.json
- **Core incremental command** — `securevibes incremental` owns orchestration and routing behavior
- **qmd** — BM25 + vector search CLI (Phase 5 context injection, Phase 7 re-indexing). Not required for triage (Phases 1-3).
- **Prompt assembly path** — `pr_review()` in `packages/core/securevibes/scanner/scanner.py` (Phase 5 extension point)
- **design_decisions.json** — optional, created by dev team (Phase 4)
- **Agent Trace metadata** — provenance envelope for decision traces (Phase 6); SecureVibes verdict semantics remain canonical

## Resolved Decisions

1. **Risk tiers configurable per repo?** Yes. `risk_map.json` is per-repo; teams can promote paths (including `docs/*`) to moderate when docs carry security guidance.
2. **How to handle new files not in threat model?** Default to Tier 2 and log for threat model update.
3. **Where is qmd used?** Phase 5 (context injection) and Phase 7 (re-indexing). qmd provides semantic search to find relevant threats, findings, and design decisions where the relationship between changed files and context is not captured in explicit path references. Not used for triage (Phases 1-3) — tier classification uses exact glob matching against `risk_map.json`.
4. **Threat modeling execution model?** Threat updates are produced by the `threat-modeling` subagent (including agentic skill augmentation), not by ad hoc prompt fragments inside other reviewers.
5. **Ad hoc subagent routing supported?** Yes. Incremental orchestration supports per-chunk subagent subsets (not only fixed sequential runs), while preserving dependency and anchor invariants.
6. **Wrapper future?** Wrapper-owned orchestration is being deprecated in favor of a core command; wrapper remains temporary compatibility shim.
7. **Severity visibility policy?** Track all severities in artifacts; default user-facing output shows only high/critical.
8. **Multi-repo support?** Each repo has its own `risk_map.json` and artifact set; cross-repo references are out of scope.
9. **Does baseline quality block incremental eligibility?** Yes. Baseline quality contract is an explicit hard gate.
10. **Is post-baseline interactive user conversation/feedback flow included in this design?** Yes. Included as Phase 8.
11. **Canonical findings artifact name?** `VULNERABILITIES.json` (not `volunteers.json`).
12. **Should Agent Trace be used for decision traces?** Yes. Agent Trace is the provenance standard; SecureVibes retains canonical security verdict fields.
