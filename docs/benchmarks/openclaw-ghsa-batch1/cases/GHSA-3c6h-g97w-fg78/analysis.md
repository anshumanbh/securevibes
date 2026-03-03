# GHSA-3c6h-g97w-fg78

## Vulnerability
- Severity: `high`
- Summary: tools.exec.safeBins sort long-option abbreviation bypass can skip exec approval in allowlist mode
- CWE: CWE-184, CWE-863
- Advisory: https://github.com/openclaw/openclaw/security/advisories/GHSA-3c6h-g97w-fg78
- Affected range: `<= 2026.2.22-2`
- Patched range: `>=2026.2.23`

## Baseline Commit
- Baseline (pre-introduction): `0e85380e56345d21bab8242d09674c77ea8ad5ea`

## Vulnerable Introducing Commit(s)
- `2d485cd47a539b083c460f88061fe584deaeb064` (2026-02-19T14:28:03+01:00) refactor(security): extract safe-bin policy and dedupe tests
- `89aad7b922835e40b4df54a9e6195a5f8ee2e5b6` (2026-02-21T19:24:23+01:00) refactor: tighten safe-bin policy model and docs parity

## Fix Commit(s)
- `3b8e33037ae2e12af7beb56fcf0346f1f8cbde6f` (2026-02-23T23:58:58Z) fix(security): harden safeBins long-option validation

## Verification
- Overall: `pass`
- Confidence: `high`
- Notes: Safe-bin policy refactors introduced long-option abbreviation handling gap fixed by targeted deny-path hardening.

- [PASS] `baseline_is_parent_of_earliest_intro`: baseline=0e85380e56345d21bab8242d09674c77ea8ad5ea earliest_intro=2d485cd47a539b083c460f88061fe584deaeb064
- [PASS] `baseline_ancestor_of_all_intro`: baseline should precede introducing commits
- [PASS] `baseline_ancestor_of_all_fix`: baseline should precede fix commits
- [PASS] `intro_precedes_patched_release`: intro=89aad7b922835e40b4df54a9e6195a5f8ee2e5b6 patched_tag_commit=b817600533129771ace2801d7c05901c7f850fb8
- [PASS] `fix_at_or_before_patched_release`: fix_head=3b8e33037ae2e12af7beb56fcf0346f1f8cbde6f patched_tag_commit=b817600533129771ace2801d7c05901c7f850fb8

## SecureVibes Efficacy
- See `detectability.json` for empirical-run status and findings mapping.
