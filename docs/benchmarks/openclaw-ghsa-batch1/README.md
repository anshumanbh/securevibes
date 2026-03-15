# OpenClaw GHSA Batch-1 Benchmark Corpus

This corpus captures the first 10 OpenClaw advisory cases for SecureVibes efficacy testing:
- all critical advisories first,
- then high advisories selected by highest CVSS (tie-break: latest publish date).

As of 2026-03-03 advisory snapshot:
- `critical=3`
- `high=70`
- `medium=144`
- `low=28`

## Corpus Layout

- `manifest.json` - corpus snapshot + selected case summary
- `selection.json` - severity counts and selection ranking evidence
- `summary.md` - compact baseline/intro/fix table
- `cases/<GHSA>/advisory.json` - normalized advisory data
- `cases/<GHSA>/timeline.json` - baseline/introducing/fix commit mapping
- `cases/<GHSA>/verification.json` - commit/range correctness checks
- `cases/<GHSA>/detectability.json` - empirical run status/results
- `cases/<GHSA>/analysis.md` - human-readable case analysis
- `scripts/build_corpus.py` - regenerate all corpus artifacts
- `scripts/materialize_case.py` - export baseline/vulnerable/fixed trees for a case
- `scripts/run_case.py` - run empirical SecureVibes scan + PR reviews for one case
- `scripts/run_sweep.py` - run multiple benchmark cases in parallel
- `scripts/validate_corpus.py` - structural and semantic validation
- `debug/README.md` - focused debug and replay workflow for PR #48 style tuning
- `debug/misses_analysis.md` - miss classification log
- `debug/tuning_log.md` - tuning decision/change log

## Rebuild

```bash
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/build_corpus.py \
  --openclaw-repo ../openclaw \
  --advisories-file /tmp/openclaw_advisories_all.json
```

Without `--advisories-file`, the script pulls advisories via `gh api --paginate`.

## Materialize Snapshots

```bash
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/materialize_case.py \
  --ghsa GHSA-g55j-c2v4-pjcg \
  --openclaw-repo ../openclaw \
  --workspace /tmp/openclaw-ghsa-batch1 \
  --force
```

## Run Empirical Efficacy

Run a single case:

```bash
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/run_case.py \
  --ghsa GHSA-g55j-c2v4-pjcg \
  --openclaw-repo ../openclaw \
  --securevibes-repo . \
  --model sonnet \
  --severity medium \
  --permission-mode bypassPermissions
```

This updates `cases/<GHSA>/detectability.json` and stores run logs under `cases/<GHSA>/runs/<timestamp>/`.

Run all manifest cases in parallel (latest-first sweep):

```bash
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/run_sweep.py \
  --openclaw-repo ../openclaw \
  --securevibes-repo . \
  --model sonnet \
  --severity medium \
  --permission-mode bypassPermissions \
  --parallel 2
```

Prime baseline cache first (one baseline scan per case run; cache hits skip repeats):

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

Baseline cache is stored under:
- `docs/benchmarks/openclaw-ghsa-batch1/baseline-cache/`
- In `--baseline-only` mode, `run_sweep.py` automatically dedupes by `baseline_commit`
  so each unique baseline is scanned once.

Run intro-only PR review mode (baseline + introducing PR review, skip fix PR review):

```bash
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/run_case.py \
  --ghsa GHSA-g55j-c2v4-pjcg \
  --openclaw-repo ../openclaw \
  --securevibes-repo . \
  --model sonnet \
  --severity medium \
  --permission-mode bypassPermissions \
  --intro-only
```

Optional for new-attack-surface debugging: refresh threat model at intro head before
intro PR review:

```bash
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/run_case.py \
  --ghsa GHSA-g55j-c2v4-pjcg \
  --openclaw-repo ../openclaw \
  --securevibes-repo . \
  --model sonnet \
  --severity medium \
  --permission-mode bypassPermissions \
  --intro-only \
  --intro-threat-model-refresh
```

`--baseline-only` and `--intro-only` are mutually exclusive in both `run_case.py`
and `run_sweep.py`.

Replay only missed cases on an older SecureVibes commit:

```bash
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/run_sweep.py \
  --openclaw-repo ../openclaw \
  --securevibes-repo . \
  --securevibes-commit 50bca799ef54f849a167722396911d89531c3afc \
  --model sonnet \
  --severity medium \
  --permission-mode bypassPermissions \
  --parallel 1 \
  --ghsa GHSA-<missed-1> \
  --ghsa GHSA-<missed-2>
```

See `debug/README.md` for Tier-1/Tier-2 adjudication and tuning loop details.

## Validate

```bash
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/validate_corpus.py
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/validate_corpus.py --strict
```
