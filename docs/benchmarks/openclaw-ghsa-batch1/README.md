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
- `scripts/validate_corpus.py` - structural and semantic validation

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

```bash
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/run_case.py \
  --ghsa GHSA-g55j-c2v4-pjcg \
  --openclaw-repo ../openclaw \
  --model sonnet \
  --severity high
```

This updates `cases/<GHSA>/detectability.json` and stores run logs under `cases/<GHSA>/runs/<timestamp>/`.

## Validate

```bash
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/validate_corpus.py
python3 docs/benchmarks/openclaw-ghsa-batch1/scripts/validate_corpus.py --strict
```
