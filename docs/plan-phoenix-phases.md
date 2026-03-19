# Phoenix Phases 1–8: Implementation Plan (v2)

> **Status:** Plan document — no code changes.
> **Design doc:** `docs/design-threat-aware-incremental-scanning.md`
> **Scope contract:** Context brief `phoenix-phases-1-3/context-brief.md`
> **Revision:** v2 — addresses reviewer feedback from review-r1.md

---

## Changelog from v1

| # | Review Finding | Resolution |
|---|---------------|------------|
| 1 | Missing re-classification after threat-model update | **Accepted.** Phase 3 gap now requires `determine_chunk_risk()` re-run after successful threat-model update, before `run_scan()`. |
| 2 | No idempotency/dedup for incremental threat-model invocation | **Accepted.** Added per-run `threat_model_invoked_components: set[str]` keyed by normalized top-level directory. |
| 3 | Threat-model failure policy too permissive | **Accepted.** Changed from fail-open to security fallback: force Tier 1/Opus + `degraded_security_context=true` in run record. |
| 4 | qmd refresh too expensive | **Accepted.** Replaced per-chunk refresh with debounced strategy: max once per run, only when artifact hash changes, with strict timeout. |
| 5 | Chunk metadata lacks validation | **Accepted.** Added explicit schema validation rules for `--chunk-tier` and `--chunk-metadata`. |
| 6 | Phase 6 proposes already-implemented `POLICY_CONTEXT_PATTERNS` change | **Accepted.** Removed — already exists in `risk_scorer.py`. |
| 7 | Prompt budget section lacks global cap + priority order | **Accepted.** Added global hard cap per tier, section priority order, and deterministic truncation policy. |
| 8 | Test coverage gaps | **Accepted.** Added all 6 requested test cases to relevant phases. |
| 9 | New CLI command vs reuse decision matrix | **Accepted.** Added brief justification in Phase 3 gap section. |

---

## Executive Summary

Phases 1–2 are **complete**. Phase 3 is **mostly complete** with one gap: incremental threat modeling invocation when `new_attack_surface=True`. Phases 4–8 are **not started**. This plan maps each phase to concrete file paths, function-level changes, dependencies, and acceptance criteria.

### Recommended Implementation Order

```
Phase 3 gap (threat modeling invocation)     ← smallest delta, unblocks Phase 7
Phase 4   (design decisions — exact match)   ← no external deps
Phase 6   (decision traces — exact match)    ← no external deps
Phase 5   (qmd context injection)            ← requires qmd CLI
Phase 7   (compounding knowledge loop)       ← requires Phases 3-gap + 5
Phase 8   (interactive feedback loop)        ← requires Phase 6
```

This follows the design doc's recommended order (§ Recommended Implementation Order For Phases 4-8) and front-loads work with no external dependencies.

### Architectural Decisions

**1. Where new code goes:** New context-injection modules should be extracted from `scanner.py` (~4800+ lines). Each phase gets its own module under `packages/core/securevibes/scanner/`:
- `design_decisions.py` (Phase 4)
- `decision_traces.py` (Phase 6)
- `context_retrieval.py` (Phase 5 — retrieval abstraction)

The prompt assembly function `_build_contextualized_pr_review_prompt()` stays in `scanner.py` but gains new keyword arguments for the new context sections.

**2. Incremental threat modeling invocation (Phase 3 gap):** New CLI command `securevibes threat-model-incremental` that the wrapper can subprocess, preserving the existing subprocess boundary pattern. See Phase 3 section for decision matrix justifying this over reusing existing subagent invocation.

**3. Prompt budget management (Phases 4–6):** Global hard cap per tier with section priority ordering and deterministic truncation. Details in Cross-Cutting Concerns section.

---

## Phase 1: Risk Map Generation

### Status: COMPLETE

**Files:**
- `packages/core/securevibes/scanner/risk_scorer.py` — `build_risk_map_from_threat_model()`, `load_threat_model_entries()`, `resolve_component_globs()`, `save_risk_map()`, `load_risk_map()`
- `ops/prepare_risk_map.py` — CLI entrypoint

**Tests:** `packages/core/tests/test_risk_scorer.py`, `ops/tests/test_prepare_risk_map.py`

**No work needed.**

---

## Phase 2: File/Chunk Risk Scoring

### Status: COMPLETE

**Files:**
- `packages/core/securevibes/scanner/risk_scorer.py` — `classify_chunk()`, `ChangedFile`, `FileRisk`, `ChunkRisk`, all 4 skip-tier safeguards, dependency detection, new attack surface detection, `POLICY_CONTEXT_PATTERNS`, `SECURITY_KEYWORDS`

**Tests:** `packages/core/tests/test_risk_scorer.py`

**No work needed.**

---

## Phase 3: Risk-Weighted Chunk Routing

### Status: PARTIAL (one gap)

**What's done:**
- `ops/incremental_scan.py` — full chunk processing loop (lines ~1657–1870): loads risk map, calls `determine_chunk_risk()` per chunk, skip-tier recording + anchor advance, non-skip routing to `run_scan()` with tier-determined model, fallback per-commit chunking with risk scoring
- `ChunkRiskDecision` dataclass, `resolve_prepared_risk_map_path()`, `load_risk_map_or_raise()`

**What's missing:**

#### Gap 3a: Incremental Threat Modeling Invocation

When `chunk_risk.new_attack_surface == True`, the wrapper currently records this flag in run records but takes no action. The design doc requires:
1. Invoke `threat-modeling` subagent on the new component
2. Append results to `THREAT_MODEL.json`
3. Regenerate `risk_map.json`
4. **Re-classify the current chunk** against the updated risk map before scanning
5. Future scans classify the component at the correct tier

##### CLI Command Decision Matrix

| Option | Pros | Cons | Verdict |
|--------|------|------|---------|
| New `securevibes threat-model-incremental` command | Preserves subprocess boundary; clear single-purpose interface; testable in isolation | Adds CLI surface area | **Selected** |
| Reuse `securevibes scan --subagent threat-modeling` | No new command | Overloaded semantics; `scan` implies full scan flow; would require flag gymnastics to scope to specific files; existing `scan` command has side effects we don't want | Rejected |
| Direct Python import from wrapper | Simplest invocation | Breaks subprocess boundary pattern; couples wrapper to core internals; makes version mismatches dangerous | Rejected |

**Recommendation:** New CLI command `securevibes threat-model-incremental`. This preserves the subprocess boundary pattern already used by `run_scan()` → `securevibes pr-review`.

##### Files to Create

| File | Purpose |
|------|---------|
| `packages/core/securevibes/cli/main.py` | Add `threat-model-incremental` CLI command |

##### Files to Modify

| File | Changes |
|------|---------|
| `packages/core/securevibes/scanner/scanner.py` | Add `threat_model_incremental()` method on `Scanner` class — loads existing `THREAT_MODEL.json`, invokes `threat-modeling` agent definition with scope limited to the new component paths, merges new threats into existing model, saves updated `THREAT_MODEL.json` |
| `packages/core/securevibes/cli/main.py` | Add `@cli.command("threat-model-incremental")` — accepts `--repo`, `--files` (comma-separated new component files), `--existing-threat-model` path; calls `Scanner.threat_model_incremental()` |
| `ops/incremental_scan.py` | Add `run_incremental_threat_model()` function (similar pattern to `run_scan()`); add per-run dedup set; add re-classification logic after successful update |
| `packages/core/securevibes/scanner/risk_scorer.py` | Add `merge_threat_model_entries(existing: list, new: list) -> list` — deduplicates by component+title, appends genuinely new threats |

##### Specific Code Changes in `ops/incremental_scan.py`

**Per-run dedup set** (initialized before chunk loop):

```python
# Track which top-level components have already had threat modeling invoked
# Keyed by normalized top-level directory (e.g., "src/payments")
threat_model_invoked_components: set[str] = set()
```

In the chunk loop (after line ~1700, where `chunk_risk.tier == "skip"` is handled), add a block **before** `run_scan()`:

```python
if chunk_risk.new_attack_surface and chunk_risk.unmapped_files:
    # Dedupe: normalize unmapped files to top-level component directories
    novel_components = {
        _normalize_to_component_dir(f) for f in chunk_risk.unmapped_files
    } - threat_model_invoked_components

    if novel_components:
        novel_files = [
            f for f in chunk_risk.unmapped_files
            if _normalize_to_component_dir(f) in novel_components
        ]
        tm_result = run_incremental_threat_model(
            repo, novel_files, securevibes_dir, timeout=per_chunk_timeout
        )
        threat_model_invoked_components.update(novel_components)

        if tm_result.success:
            # Regenerate risk map from updated threat model
            threats = load_threat_model_entries(securevibes_dir / "THREAT_MODEL.json")
            new_risk_map = build_risk_map_from_threat_model(threats, component_resolver=...)
            save_risk_map(securevibes_dir / "risk_map.json", new_risk_map)
            risk_map = load_risk_map(securevibes_dir / "risk_map.json")

            # Re-classify current chunk against updated risk map
            chunk_risk = determine_chunk_risk(chunk, risk_map, ...)
            model_for_chunk = RISK_MODEL_BY_TIER.get(chunk_risk.tier, default_model)
        else:
            # Security fallback: force Tier 1/Opus for uncharacterized attack surface
            model_for_chunk = "opus"
            chunk_risk_record["degraded_security_context"] = True
            chunk_risk_record["threat_model_failure_reason"] = tm_result.error

    # Proceed to run_scan() — code review always happens
```

Helper function:

```python
def _normalize_to_component_dir(file_path: str) -> str:
    """Normalize a file path to its top-level component directory.

    e.g., "src/payments/processor.py" → "src/payments"
    """
    parts = Path(file_path).parts
    return str(Path(*parts[:2])) if len(parts) > 1 else parts[0]
```

##### Atomic Writes for THREAT_MODEL.json

`merge_threat_model_entries()` must use atomic write (write-to-temp + rename) to avoid partial writes if the process is interrupted. The existing `save_risk_map()` pattern should be followed.

##### Dependencies
- None (Phases 1–2 are complete)

##### Acceptance Criteria
1. When a chunk has `new_attack_surface=True`, the `threat-modeling` subagent is invoked via subprocess
2. New threats are appended to `THREAT_MODEL.json` (not overwriting existing entries) via atomic write
3. `risk_map.json` is regenerated after threat model update
4. **Current chunk is re-classified** against updated risk map — model selection may change
5. Subsequent chunks in the same run use the updated risk map
6. If incremental threat modeling fails, the chunk is **forced to Tier 1/Opus** and `degraded_security_context=true` is recorded in run record
7. Same component across multiple chunks invokes threat modeling **at most once per run**
8. Run record includes threat modeling invocation metadata

##### Test Cases (new in v2)
1. Test that successful threat-model update re-classifies current chunk and can change model selection from Sonnet to Opus
2. Test dedup: same new component across multiple chunks invokes subagent exactly once
3. Test threat-model failure fallback: forced Tier 1 + `degraded_security_context` flag set

##### Complexity: M

#### Gap 3b: Tier 3 Batching (Optional/Deferred)

Design doc mentions consecutive all-skip chunks can be batched. Currently each skip chunk is individually recorded + anchor advanced. Since skip chunks have no LLM call, the per-chunk cost is negligible (just a dict append + anchor write). **Recommendation: defer.** The optimization is marginal and adds complexity to the chunk loop.

##### Complexity: S (if implemented)

---

## Phase 4: Security Design Decisions

### Status: NOT STARTED

#### Overview
Load `.securevibes/design_decisions.json`, match against changed files by exact path/component, inject matched decisions into prompt assembly. Invalidation monitoring when `references` files change.

#### Files to Create

| File | Purpose |
|------|---------|
| `packages/core/securevibes/scanner/design_decisions.py` | New module: schema validation, loading, matching, prompt section formatting |

#### Files to Modify

| File | Changes |
|------|---------|
| `packages/core/securevibes/scanner/scanner.py` | Modify `_prepare_pr_baseline_context()` to call design decision loader; modify `_build_contextualized_pr_review_prompt()` to accept and inject `design_decisions_section` parameter |

#### Module: `design_decisions.py`

##### Types/Dataclasses

```python
@dataclass(frozen=True)
class DesignDecision:
    id: str
    component: str
    decision: str
    rationale: str
    references: tuple[str, ...]
    accepted_behaviors: tuple[str, ...]
    invalidation_conditions: tuple[str, ...]
    decided_by: str
    decided_at: str
    issue_ref: str | None

@dataclass(frozen=True)
class MatchedDesignDecision:
    decision: DesignDecision
    match_type: Literal["reference_path", "component"]
    invalidation_triggered: bool  # True if a references file was changed
```

##### Functions

1. **`load_design_decisions(path: Path) -> list[DesignDecision]`**
   - Parse `.securevibes/design_decisions.json`
   - Validate schema: required fields `id`, `component`, `decision`, `rationale`, `references`, `accepted_behaviors`
   - Return empty list if file doesn't exist (graceful degradation)
   - Raise on malformed JSON

2. **`match_decisions_to_changed_files(decisions: list[DesignDecision], changed_files: list[str]) -> list[MatchedDesignDecision]`**
   - Exact match: any file in `changed_files` appears in `decision.references`
   - Component match: normalize `decision.component` to path segments, match against changed file path prefixes (e.g., `gateway/auth` matches `src/gateway/auth-context.ts`)
   - Set `invalidation_triggered=True` when a matched file is in `references`

3. **`format_design_decisions_section(matched: list[MatchedDesignDecision], max_tokens: int = 2000) -> str`**
   - Format as `## Design Decisions for [{component}]` sections
   - Include: decision text, rationale, accepted behaviors, invalidation conditions
   - Append `DO NOT flag behaviors listed as accepted unless invalidation conditions are met` instruction
   - Truncate to budget

##### Changes to `scanner.py`

In `_prepare_pr_baseline_context()` (line ~3903):
- After existing context preparation, call `load_design_decisions()` and `match_decisions_to_changed_files()`
- Add `design_decisions_section` field to `_PRBaselineContext` dataclass

In `_build_contextualized_pr_review_prompt()` (line ~1420):
- Add `design_decisions_section: str` parameter
- Insert section after `_build_pr_prompt_baseline_context_section()` call

#### Dependencies
- None (no qmd required — exact matching only)

#### Acceptance Criteria
1. When `.securevibes/design_decisions.json` exists and contains decisions matching changed files, the matched decisions appear in the PR review prompt
2. When the file doesn't exist, PR review proceeds normally (no error)
3. When a `references` file is changed, `invalidation_triggered` is set to `True` and the prompt flags it
4. Decisions are matched by both exact path and component prefix
5. Context section respects token budget (truncation with marker)
6. Schema validation rejects malformed entries with clear error messages

#### Complexity: M

---

## Phase 5: Context Injection via qmd

### Status: NOT STARTED

#### Overview
Add qmd semantic retrieval to supplement exact matching. Introduce a retrieval abstraction so `scanner.py` depends on an interface, not qmd directly. Implement tier-scoped context injection rules.

#### Prerequisite
- Phase 4 (design decisions exact matching)
- Phase 6 (decision traces exact matching) — can be implemented in parallel but the retrieval abstraction should accommodate both
- `qmd` CLI tool available in the environment

#### Files to Create

| File | Purpose |
|------|---------|
| `packages/core/securevibes/scanner/context_retrieval.py` | Retrieval abstraction: `ContextRetriever` protocol, `ExactMatchRetriever`, `QmdRetriever`, `CompositeRetriever` |

#### Files to Modify

| File | Changes |
|------|---------|
| `packages/core/securevibes/scanner/scanner.py` | Modify `_prepare_pr_baseline_context()` to use `ContextRetriever`; add tier-scoped injection logic |
| `packages/core/securevibes/scanner/design_decisions.py` | Refactor matching to implement `ContextRetriever` protocol |
| `packages/core/securevibes/scanner/decision_traces.py` | Refactor matching to implement `ContextRetriever` protocol (if Phase 6 is done) |
| `ops/incremental_scan.py` | Pass tier metadata through to `run_scan()` so core can apply tier-scoped injection rules |

#### Module: `context_retrieval.py`

##### Protocol

```python
class ContextRetriever(Protocol):
    def retrieve(
        self,
        changed_files: Sequence[str],
        tier: RiskTier,
        *,
        max_tokens: int = 4000,
    ) -> RetrievedContext: ...

@dataclass(frozen=True)
class RetrievedContext:
    design_decisions_section: str
    decision_traces_section: str
    relevant_threats_section: str
    relevant_findings_section: str
    total_tokens_estimate: int
```

##### Implementations

1. **`ExactMatchRetriever`** — wraps Phase 4 + Phase 6 exact matching. No external deps. Always available.

2. **`QmdRetriever`** — calls `qmd search` subprocess for semantic retrieval against indexed artifacts. Returns relevant threats and findings that exact matching misses.

3. **`CompositeRetriever`** — combines exact + qmd results. Exact matches take precedence; qmd supplements. Deduplicates.

##### Tier-Scoped Injection Rules (from design doc)

| Tier | Context Injected |
|------|-----------------|
| Tier 1 (Critical) | Full: design decisions + decision traces + threats + findings |
| Tier 2 (Mapped) | None additional |
| Tier 2 (Unmapped) | Threats + findings via qmd |
| Tier 2 (Dep-only) | Supply-chain summary only |
| Tier 3 (Skip) | None (no LLM call) |

##### Passing Tier to Core

Currently `ops/incremental_scan.py` calls `run_scan()` which subprocesses `securevibes pr-review`. The tier is known in the wrapper but not passed to core.

**Change:** Add `--chunk-tier` and `--chunk-metadata` flags to `securevibes pr-review` CLI command. The wrapper passes these; core uses them to select context injection scope.

```
securevibes pr-review . --range base..head --model opus \
    --chunk-tier critical \
    --chunk-metadata '{"dependency_only":false,"unmapped_files":["src/new/foo.ts"]}'
```

##### Chunk Metadata Validation (new in v2)

The `--chunk-tier` and `--chunk-metadata` flags constitute a subprocess boundary — input must be validated strictly:

1. **`--chunk-tier`**: Must be one of `{"critical", "moderate", "skip"}`. Reject any other value with a clear error.
2. **`--chunk-metadata` JSON schema**:
   - `dependency_only: bool` (required)
   - `unmapped_files: list[str]` (optional, max 100 entries)
   - All file paths must be repo-relative, normalized (no `..`, no absolute paths, no null bytes)
   - Reject paths containing `..` segments or starting with `/`
   - Unknown keys are silently ignored (forward-compatible)
3. **Validation function**: `validate_chunk_metadata(tier: str, metadata_json: str) -> ChunkMetadata` in `context_retrieval.py` — raises `ValueError` on invalid input.

##### Intra-Run qmd Freshness (revised in v2)

~~Per-chunk `qmd update && qmd embed` after artifact updates.~~ Replaced with debounced strategy:

```python
# In ops/incremental_scan.py — state tracked across chunk loop
_last_qmd_refresh_hash: str | None = None  # hash of artifact files at last refresh
_qmd_refresh_count: int = 0

def _maybe_refresh_qmd(securevibes_dir: Path, repo: Path, *, max_refreshes: int = 3) -> None:
    """Refresh qmd index if artifacts have changed since last refresh.

    Constraints:
    - Max N refreshes per run (default 3)
    - Only refreshes when artifact content hash has changed
    - Strict 60s timeout per refresh operation
    """
    current_hash = _hash_artifact_files(securevibes_dir)
    if current_hash == _last_qmd_refresh_hash:
        return  # No artifact changes
    if _qmd_refresh_count >= max_refreshes:
        log.warning("qmd refresh budget exhausted (%d/%d)", _qmd_refresh_count, max_refreshes)
        return

    subprocess.run(["qmd", "update"], cwd=repo, check=False, timeout=60)
    subprocess.run(["qmd", "embed"], cwd=repo, check=False, timeout=60)
    _last_qmd_refresh_hash = current_hash
    _qmd_refresh_count += 1
```

##### Graceful Degradation

If `qmd` is not installed or fails:
- Log warning
- Fall back to `ExactMatchRetriever` only
- Never fail the scan because qmd is unavailable

#### Dependencies
- Phase 4 (design decisions)
- Phase 6 (decision traces) — for full retrieval, but can ship without
- `qmd` CLI tool (external)

#### Acceptance Criteria
1. `ContextRetriever` protocol allows swapping exact-only vs qmd-backed retrieval
2. Tier-scoped injection rules are enforced: Tier 1 gets full context, Tier 2 mapped gets none, etc.
3. `--chunk-tier` flag is accepted by `securevibes pr-review` and drives injection scope
4. `--chunk-tier` rejects values outside `{critical, moderate, skip}`
5. `--chunk-metadata` validates JSON schema: path normalization, bounded list sizes, no `..`/absolute paths
6. When qmd is unavailable, scan proceeds with exact matching only (warning logged)
7. Intra-run qmd refresh is debounced: max 3 per run, only on artifact hash change, 60s timeout
8. Each context section respects its token budget cap
9. Existing prompt assembly tests pass (no regression in baseline context injection)

#### Test Cases (new in v2)
1. Test strict validation of `--chunk-tier` rejects invalid values
2. Test `--chunk-metadata` rejects paths with `..`, absolute paths, null bytes
3. Test `--chunk-metadata` rejects lists exceeding max size
4. Test qmd refresh debounce: no refresh when artifact hash unchanged
5. Test qmd refresh budget: stops after max refreshes

#### Complexity: L

---

## Phase 6: Decision Traces

### Status: NOT STARTED

#### Overview
Store triage decisions (false_positive, accepted_risk, mitigated_by, deferred, fixed) under `.securevibes/decisions/`. Match against changed files during prompt assembly. Condition-aware re-triggering when `mitigated_by` files change.

#### Files to Create

| File | Purpose |
|------|---------|
| `packages/core/securevibes/scanner/decision_traces.py` | New module: schema, loading, matching, prompt formatting, writing |

#### Files to Modify

| File | Changes |
|------|---------|
| `packages/core/securevibes/scanner/scanner.py` | Modify `_prepare_pr_baseline_context()` to load and match decision traces; modify `_build_contextualized_pr_review_prompt()` to inject `decision_traces_section` |

> **Note (v2):** v1 proposed modifying `risk_scorer.py` to add `.securevibes/decisions/*` to `POLICY_CONTEXT_PATTERNS`. This is already implemented — no change needed.

#### Module: `decision_traces.py`

##### Types/Dataclasses

```python
VERDICT_TYPES = ("false_positive", "accepted_risk", "mitigated_by", "deferred", "fixed")

@dataclass(frozen=True)
class DecisionTrace:
    finding_id: str
    title: str
    component: str
    severity: str
    verdict: str  # one of VERDICT_TYPES
    rationale: str
    conditions: str
    mitigated_by: tuple[str, ...]
    decided_by: str
    decided_at: str
    related_findings: tuple[str, ...]
    agent_trace: dict | None  # opaque Agent Trace envelope — stored, not interpreted

@dataclass(frozen=True)
class MatchedDecisionTrace:
    trace: DecisionTrace
    match_type: Literal["component", "mitigated_by_changed"]
    re_review_triggered: bool  # True when mitigated_by file was changed
```

##### Functions

1. **`load_decision_traces(decisions_dir: Path) -> list[DecisionTrace]`**
   - Load all `.json` files from `.securevibes/decisions/`
   - Validate schema per file
   - Skip `fixed` verdicts (they don't need re-injection)
   - Return empty list if directory doesn't exist

2. **`match_traces_to_changed_files(traces: list[DecisionTrace], changed_files: list[str]) -> list[MatchedDecisionTrace]`**
   - Component match: normalize `trace.component` → path prefix match against changed files
   - Mitigated-by match: any file in `trace.mitigated_by` appears in `changed_files` → `re_review_triggered=True`
   - Exclude `fixed` verdicts
   - **Path normalization (v2):** All paths in `mitigated_by` and `component` are normalized to repo-relative form. Reject references containing `..` or absolute paths during `load_decision_traces()` validation.

3. **`format_decision_traces_section(matched: list[MatchedDecisionTrace], max_tokens: int = 2000) -> str`**
   - Format as `## Decision Traces for [{component}]`
   - Include: title, verdict, rationale, conditions
   - When `re_review_triggered`: add `⚠ REVIEW REQUIRED: mitigated_by file changed` warning
   - Truncate to budget

4. **`write_decision_trace(decisions_dir: Path, trace: DecisionTrace) -> Path`**
   - Write trace JSON to `.securevibes/decisions/{finding_id}.json`
   - Create directory if needed
   - Used by Phase 8 (feedback loop)

##### Agent Trace Handling

Agent Trace provenance is stored as an opaque `agent_trace` field in the JSON. Phase 6 does NOT interpret Agent Trace fields — it stores them and passes them through. Agent Trace interpretation/enrichment is a follow-up after the core decision-trace model is stable (per design doc).

##### Changes to `scanner.py`

In `_prepare_pr_baseline_context()`:
- Call `load_decision_traces()` and `match_traces_to_changed_files()`
- Add `decision_traces_section` field to `_PRBaselineContext`

In `_build_contextualized_pr_review_prompt()`:
- Add `decision_traces_section: str` parameter
- Insert section after design decisions section

#### Dependencies
- None for exact matching
- Phase 5 for qmd-backed semantic matching (enhancement, not blocker)

#### Acceptance Criteria
1. Decision traces under `.securevibes/decisions/` are loaded, validated, and matched against changed files
2. `fixed` verdicts are excluded from injection
3. When a `mitigated_by` file is changed, the trace is flagged for re-review in the prompt
4. Component-based matching works (normalized path prefix)
5. Agent Trace envelope is preserved in storage without interpretation
6. Missing decisions directory is handled gracefully (empty list)
7. `write_decision_trace()` creates valid JSON files that can be loaded back
8. Path normalization rejects `..` segments and absolute paths in `mitigated_by` references

#### Test Cases (new in v2)
1. Test path normalization rejects decision trace references outside repo scope (`..`, absolute paths)

#### Complexity: M

---

## Phase 7: Compounding Knowledge Loop

### Status: NOT STARTED

#### Overview
After each scan run: regenerate risk map if threat model was updated, re-index qmd artifacts, track context-injection telemetry, flag aged decision traces for re-review.

#### Files to Modify

| File | Changes |
|------|---------|
| `ops/incremental_scan.py` | Add post-run artifact refresh logic after chunk loop completes |
| `packages/core/securevibes/scanner/decision_traces.py` | Add `find_stale_traces(traces, max_age_days=90) -> list[DecisionTrace]` |
| `packages/core/securevibes/scanner/risk_scorer.py` | No changes needed — `build_risk_map_from_threat_model()` already exists |

#### Specific Code Changes

##### In `ops/incremental_scan.py` — Post-Run Refresh

After the chunk loop completes (after line ~1870), add a post-run phase:

```python
# --- Post-run artifact refresh ---
if threat_model_updated_this_run:
    # Risk map was already regenerated per-chunk in Phase 3 gap fix,
    # but do a final regeneration to ensure consistency
    threats = load_threat_model_entries(securevibes_dir / "THREAT_MODEL.json")
    fresh_map = build_risk_map_from_threat_model(threats, component_resolver=...)
    save_risk_map(securevibes_dir / "risk_map.json", fresh_map)

# qmd refresh uses the same debounced strategy from Phase 5
# (one final refresh if artifacts changed and budget not exhausted)
_maybe_refresh_qmd(securevibes_dir, repo)

# Flag stale decision traces
stale = find_stale_traces(
    load_decision_traces(securevibes_dir / "decisions"),
    max_age_days=90,
)
if stale:
    run_record["stale_decision_traces"] = [t.finding_id for t in stale]
```

##### Telemetry

Add to each chunk's run record:
- `context_injected: dict` — which context sections were injected and their token counts
- `findings_produced: list[str]` — finding IDs produced for this chunk

This enables post-hoc analysis: did injected context for component X lead to finding Y?

##### Decision Re-Review Triggering

In `decision_traces.py`, add:

```python
def find_stale_traces(
    traces: list[DecisionTrace],
    max_age_days: int = 90,
    reference_date: date | None = None,
) -> list[DecisionTrace]:
    """Find traces older than max_age_days for re-validation."""
```

#### Dependencies
- Phase 3 gap (incremental threat modeling — triggers risk map regeneration)
- Phase 5 (qmd — for re-indexing, uses debounced `_maybe_refresh_qmd()`)
- Phase 6 (decision traces — for staleness checking)

#### Acceptance Criteria
1. Risk map is regenerated after any threat model update in a run
2. qmd is re-indexed using debounced strategy (not unconditionally)
3. Decision traces older than 90 days are flagged in run records
4. Context injection telemetry is recorded per chunk in run records
5. Post-run phase doesn't fail the scan if qmd is unavailable
6. Post-run phase has a timeout cap (doesn't block indefinitely)

#### Complexity: M

---

## Phase 8: Post-Baseline Findings Review + User Feedback Loop

### Status: NOT STARTED

#### Overview
Interactive CLI flow for reviewing findings, submitting feedback (confirm, dispute, accept risk, defer), and writing feedback to decision traces. Severity-based display filtering.

#### Files to Create

| File | Purpose |
|------|---------|
| `packages/core/securevibes/cli/findings_review.py` | CLI commands for interactive findings review |

#### Files to Modify

| File | Changes |
|------|---------|
| `packages/core/securevibes/cli/main.py` | Register new CLI commands: `securevibes findings list`, `securevibes findings review`, `securevibes findings triage` |
| `packages/core/securevibes/scanner/decision_traces.py` | `write_decision_trace()` already exists from Phase 6; add `create_trace_from_feedback()` helper |
| `packages/core/securevibes/scanner/artifacts.py` | Add helper to load and filter `VULNERABILITIES.json` by severity |

#### Module: `findings_review.py`

##### CLI Commands

1. **`securevibes findings list`**
   - `--severity` filter (default: `high,critical`)
   - `--include-triaged` to show already-triaged findings
   - Loads `VULNERABILITIES.json`, displays findings with severity, component, title
   - Shows triage status if a matching decision trace exists

2. **`securevibes findings review <finding-id>`**
   - Displays full finding details: title, severity, description, code evidence, affected files
   - Shows related context: threat model entry, existing decision traces, design decisions
   - Shows triage options

3. **`securevibes findings triage <finding-id> --verdict <verdict>`**
   - `--verdict`: one of `false_positive`, `accepted_risk`, `mitigated_by`, `deferred`, `fixed`
   - `--rationale`: required for `accepted_risk` and `false_positive`
   - `--mitigated-by`: required for `mitigated_by` verdict (comma-separated file paths)
   - `--conditions`: optional re-review conditions
   - Writes decision trace to `.securevibes/decisions/{finding_id}.json`
   - Records Agent Trace provenance (conversation context if available)

##### Feedback → Decision Trace Mapping

```python
def create_trace_from_feedback(
    finding: dict,
    verdict: str,
    rationale: str,
    *,
    mitigated_by: Sequence[str] = (),
    conditions: str = "",
    decided_by: str = "",
) -> DecisionTrace:
    """Create a DecisionTrace from user feedback on a finding."""
```

##### Display Filtering

- Default: show only `high` and `critical` severity findings
- `--severity all` shows everything
- Persisted `medium`/`low` findings remain in `VULNERABILITIES.json` (never deleted)
- Triaged findings (with matching decision trace) shown with `[triaged: {verdict}]` label

#### Dependencies
- Phase 6 (decision traces — for writing feedback)
- `VULNERABILITIES.json` must exist (from baseline scan)

#### Acceptance Criteria
1. `securevibes findings list` displays high/critical findings by default
2. `securevibes findings review <id>` shows full finding context
3. `securevibes findings triage <id> --verdict accepted_risk --rationale "..."` creates a valid decision trace
4. Created decision traces are loadable by Phase 6's `load_decision_traces()`
5. Severity filtering doesn't delete lower-severity findings from artifacts
6. Already-triaged findings show their verdict status
7. CLI commands work without qmd (no dependency on semantic retrieval)

#### Complexity: M

---

## Cross-Cutting Concerns

### Prompt Budget Management (revised in v2)

As Phases 4–6 add context sections, prompt size grows. The v1 plan lacked a global hard cap and priority truncation order. Revised strategy:

#### Global Hard Caps by Tier

| Tier | Global Cap (all injected sections combined) |
|------|---------------------------------------------|
| Tier 1 (Critical) | 12K tokens |
| Tier 2 (Unmapped) | 6K tokens |
| Tier 2 (Dep-only) | 2K tokens |
| Tier 2 (Mapped) | 0 (no additional context) |
| Tier 3 (Skip) | 0 (no LLM call) |

These caps cover only the **new** context sections introduced by Phases 4–6. Existing baseline sections (architecture, threats, vulns) have their own existing budgets and are not affected.

#### Section Priority Order (truncate lowest priority first)

When total injected context exceeds the global cap, sections are truncated in this order (last = first truncated):

| Priority | Section | Per-Section Soft Cap |
|----------|---------|---------------------|
| 1 (highest) | Architecture context | existing |
| 2 | Threat context summary | existing |
| 3 | Design decisions (Phase 4) | 2K tokens |
| 4 | Decision traces (Phase 6) | 2K tokens |
| 5 | qmd threats (Phase 5) | 2K tokens |
| 6 | qmd findings (Phase 5) | 2K tokens |
| 7 (lowest) | Supply-chain summary | 1K tokens |

**Truncation algorithm:**
1. Each `format_*_section()` function enforces its per-section soft cap
2. After all sections are assembled, `enforce_global_budget(sections, global_cap)` checks total
3. If over budget: truncate sections in reverse priority order (7 → 6 → 5 → ...) until under cap
4. Truncated sections get `...[truncated for prompt budget]` marker

**Token estimation:** `len(text) // 4` as fast approximation. This is deliberately conservative (overestimates) — better to truncate slightly early than blow the context window.

**Implementation location:** `context_retrieval.py` owns the budget constants and `enforce_global_budget()` function.

### scanner.py Extraction Strategy

`scanner.py` is ~4800+ lines. New modules reduce growth:

| Module | Owns |
|--------|------|
| `design_decisions.py` | Loading, matching, formatting design decisions |
| `decision_traces.py` | Loading, matching, formatting, writing decision traces |
| `context_retrieval.py` | Retrieval abstraction, qmd integration, tier-scoped injection, budget enforcement |
| `scanner.py` | Prompt assembly orchestration (calls into new modules) |

The `_prepare_pr_baseline_context()` method stays in `scanner.py` but delegates to the new modules. The `_build_contextualized_pr_review_prompt()` function gains new parameters but its structure (list of section builders joined by `\n\n`) is unchanged.

### Test Strategy

Each new module gets its own test file:
- `packages/core/tests/test_design_decisions.py`
- `packages/core/tests/test_decision_traces.py`
- `packages/core/tests/test_context_retrieval.py`
- `packages/core/tests/test_findings_review.py`

Integration tests in `ops/tests/test_incremental_scan.py` for:
- Incremental threat modeling subprocess invocation (Phase 3 gap)
- **Current-chunk re-classification after threat model update (v2)**
- **Per-run dedup of threat model invocations (v2)**
- **Threat model failure → forced Tier 1 + degraded flag (v2)**
- Tier metadata passing to `pr-review` subprocess (Phase 5)
- **Chunk metadata validation rejects invalid input (v2)**
- Post-run artifact refresh (Phase 7)
- **qmd refresh debounce/timeout behavior (v2)**
- **Decision trace path normalization rejects out-of-repo references (v2)**

---

## Dependency Graph

```
Phase 1 (COMPLETE) ──→ Phase 2 (COMPLETE) ──→ Phase 3 (PARTIAL)
                                                    │
                                                    ├──→ Phase 3 gap (threat model invocation)
                                                    │         │
                                                    │         └──→ Phase 7 (compounding loop)
                                                    │
                                                    ├──→ Phase 4 (design decisions)
                                                    │         │
                                                    │         └──→ Phase 5 (qmd + retrieval abstraction)
                                                    │                   │
                                                    │                   └──→ Phase 7
                                                    │
                                                    └──→ Phase 6 (decision traces)
                                                              │
                                                              ├──→ Phase 5 (semantic matching enhancement)
                                                              │
                                                              └──→ Phase 8 (feedback loop)
```

### Phase Sizing Summary

| Phase | Status | Complexity | Key Blocker |
|-------|--------|-----------|-------------|
| 1 | Complete | — | — |
| 2 | Complete | — | — |
| 3 gap | Partial | M | None |
| 4 | Not Started | M | None |
| 5 | Not Started | L | qmd CLI, Phases 4+6 |
| 6 | Not Started | M | None |
| 7 | Not Started | M | Phases 3-gap, 5, 6 |
| 8 | Not Started | M | Phase 6 |

---

## Verdict

**AGREE** — All 9 review findings were valid and have been incorporated. No pushback needed. The plan is ready for implementation.
