# GHSA-r5fq-947m-xm57

## Vulnerability
- Severity: `high`
- Summary: Path traversal in apply_patch could write/delete files outside the workspace
- CWE: CWE-22
- Advisory: https://github.com/openclaw/openclaw/security/advisories/GHSA-r5fq-947m-xm57
- Affected range: `<=2026.2.13`
- Patched range: `>=2026.2.14`

## Baseline Commit
- Baseline (pre-introduction): `221c0b4cf8410261e5424dde4cbf7de88805a4bd`

## Vulnerable Introducing Commit(s)
- `8b4bdaa8a473e6e14cab866a916a407e86ab861a` (2026-01-12T03:42:56Z) feat: add apply_patch tool (exec-gated)

## Fix Commit(s)
- `5544646a09c0121fca7d7093812dc2de8437c7f1` (2026-02-14T19:11:12Z) security: block apply_patch path traversal outside workspace (#16405)

## Verification
- Overall: `pass`
- Confidence: `high`
- Notes: Vulnerability is anchored to initial apply_patch tool implementation lacking workspace containment in non-sandbox mode.

- [PASS] `baseline_is_parent_of_earliest_intro`: baseline=221c0b4cf8410261e5424dde4cbf7de88805a4bd earliest_intro=8b4bdaa8a473e6e14cab866a916a407e86ab861a
- [PASS] `baseline_ancestor_of_all_intro`: baseline should precede introducing commits
- [PASS] `baseline_ancestor_of_all_fix`: baseline should precede fix commits
- [PASS] `intro_precedes_patched_release`: intro=8b4bdaa8a473e6e14cab866a916a407e86ab861a patched_tag_commit=b5ab92eef4e4f6099c98817e0917c99ec9e03045
- [PASS] `fix_at_or_before_patched_release`: fix_head=5544646a09c0121fca7d7093812dc2de8437c7f1 patched_tag_commit=b5ab92eef4e4f6099c98817e0917c99ec9e03045
- [PASS] `intro_at_or_before_affected_upper`: intro=8b4bdaa8a473e6e14cab866a916a407e86ab861a affected_upper_commit=e91d957d7089d2ca9589255245eead0edddc16d5

## SecureVibes Efficacy
- See `detectability.json` for empirical-run status and findings mapping.
