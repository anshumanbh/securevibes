# PR #48 Focused Debug Workflow

This workflow is optimized for practical debugging to reach 10/10 benchmark detection.

## Detection Protocol

Tier 1 gate:
- `tier1_detected_from_new_commits == true` in `cases/<GHSA>/detectability.json`.

Tier 2 gate (manual adjudication):
- Human reviewer checks `intro_pr_review.json` findings against `cases/<GHSA>/analysis.md`.
- Pass if at least one finding matches either:
  - same vulnerability category/CWE family, or
  - same vulnerable code path/function/root-cause behavior.

## 1) Run Initial Sweep (latest-first)

Optional: prime baseline cache first to avoid re-running expensive baseline scans:

```bash
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/run_sweep.py \
  --openclaw-repo ../openclaw \
  --securevibes-repo . \
  --model sonnet \
  --severity medium \
  --permission-mode bypassPermissions \
  --baseline-only \
  --parallel 2
```

In `--baseline-only` mode, the sweep dedupes cases by `baseline_commit`, so each unique
baseline is scanned once.

Use SecureVibes from current repo HEAD and run all 10 cases in parallel:

```bash
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/run_sweep.py \
  --openclaw-repo ../openclaw \
  --securevibes-repo . \
  --model sonnet \
  --severity medium \
  --permission-mode bypassPermissions \
  --parallel 2
```

Output summary:
- `docs/benchmarks/openclaw-ghsa-batch1/debug/sweeps/<timestamp>.json`

For intro-only campaign runs (baseline + intro PR review, skip fix PR review):

```bash
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/run_case.py \
  --ghsa GHSA-qrq5-wjgg-rvqw \
  --openclaw-repo ../openclaw \
  --securevibes-repo . \
  --model sonnet \
  --severity medium \
  --permission-mode bypassPermissions \
  --intro-only
```

`--baseline-only` and `--intro-only` are mutually exclusive.

Per-case artifacts:
- `docs/benchmarks/openclaw-ghsa-batch1/cases/<GHSA>/runs/<timestamp>/...`
- `docs/benchmarks/openclaw-ghsa-batch1/cases/<GHSA>/detectability.json`

## 2) Triage Misses

For any Tier-1 miss, classify exactly one cause in `misses_analysis.md`:
- `no_finding_generated`
- `finding_generated_but_not_root_cause`
- `severity_filtered_out`
- `range_or_context_gap`
- `triage_skip_or_routing_loss`

## 3) Apply Small Fixes First

Preferred tuning order:
1. `packages/core/securevibes/prompts/agents/pr_code_review.txt`
2. `packages/core/securevibes/prompts/agents/_shared/security_rules.txt`
3. Small context assembly tweaks in `packages/core/securevibes/scanner/scanner.py`
4. Risk routing changes only for `triage_skip_or_routing_loss`

Track each change in `tuning_log.md`.

## 4) Regression Controls (after each tuning change)

Always rerun:
- failed GHSA
- `GHSA-qrq5-wjgg-rvqw`
- `GHSA-gv46-4xfq-jv58`

Example:

```bash
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/run_sweep.py \
  --openclaw-repo ../openclaw \
  --securevibes-repo . \
  --model sonnet --severity medium --permission-mode bypassPermissions --parallel 1 \
  --ghsa GHSA-<failed> \
  --ghsa GHSA-qrq5-wjgg-rvqw \
  --ghsa GHSA-gv46-4xfq-jv58
```

## 5) Replay Only Missed Cases on Older PR #48 Commits

Behavior commits:
- `50bca799ef54f849a167722396911d89531c3afc`
- `ee5f5356755947806fcb12a6858ac82607d4a9ef`
- `aa0aada223b374118cfb2caff5dac2c37463a907`

Replay command (example):

```bash
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/run_sweep.py \
  --openclaw-repo ../openclaw \
  --securevibes-repo . \
  --securevibes-commit 50bca799ef54f849a167722396911d89531c3afc \
  --model sonnet --severity medium --permission-mode bypassPermissions --parallel 1 \
  --ghsa GHSA-<missed-1> \
  --ghsa GHSA-<missed-2>
```

## Notes

- `run_case.py` is the default runner for each case; manual commands are for deep debugging of misses.
- Baseline artifact sanity is captured in detectability under:
  `baseline_scan.artifact_validation`.
- Phase escalation (from `docs/design-threat-aware-incremental-scanning.md`) should happen only if prompt/context tuning cannot clear remaining misses.
