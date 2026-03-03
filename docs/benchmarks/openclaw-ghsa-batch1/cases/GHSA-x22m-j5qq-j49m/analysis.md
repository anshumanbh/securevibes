# GHSA-x22m-j5qq-j49m

## Vulnerability
- Severity: `high`
- Summary: Two SSRF via sendMediaFeishu and markdown image fetching in Feishu extension
- CWE: CWE-918
- Advisory: https://github.com/openclaw/openclaw/security/advisories/GHSA-x22m-j5qq-j49m
- Affected range: `< 2026.2.14`
- Patched range: `>= 2026.2.14`

## Baseline Commit
- Baseline (pre-introduction): `02842bef9179e65ac3c8174091a4facfcd0a4083`

## Vulnerable Introducing Commit(s)
- `2267d58afcc70fe19408b8f0dce108c340f3426d` (2026-02-06T09:32:10+09:00) feat(feishu): replace built-in SDK with community plugin

## Fix Commit(s)
- `5b4121d6011a48c71e747e3c18197f180b872c5d` (2026-02-14T16:42:35+01:00) fix: harden Feishu media URL fetching (#16285) (thanks @mbelinky)

## Verification
- Overall: `pass`
- Confidence: `high`
- Notes: SSRF surface appears when Feishu media/docx paths start fetching remote URLs without hardened fetch guards.

- [PASS] `baseline_is_parent_of_earliest_intro`: baseline=02842bef9179e65ac3c8174091a4facfcd0a4083 earliest_intro=2267d58afcc70fe19408b8f0dce108c340f3426d
- [PASS] `baseline_ancestor_of_all_intro`: baseline should precede introducing commits
- [PASS] `baseline_ancestor_of_all_fix`: baseline should precede fix commits
- [PASS] `intro_precedes_patched_release`: intro=2267d58afcc70fe19408b8f0dce108c340f3426d patched_tag_commit=b5ab92eef4e4f6099c98817e0917c99ec9e03045
- [PASS] `fix_at_or_before_patched_release`: fix_head=5b4121d6011a48c71e747e3c18197f180b872c5d patched_tag_commit=b5ab92eef4e4f6099c98817e0917c99ec9e03045
- [PASS] `intro_at_or_before_affected_upper`: intro=2267d58afcc70fe19408b8f0dce108c340f3426d affected_upper_commit=b5ab92eef4e4f6099c98817e0917c99ec9e03045

## SecureVibes Efficacy
- See `detectability.json` for empirical-run status and findings mapping.
