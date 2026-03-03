# GHSA-gv46-4xfq-jv58

## Vulnerability
- Severity: `critical`
- Summary: Remote Code Execution via Node Invoke Approval Bypass in Gateway
- CWE: CWE-20, CWE-441, CWE-863
- Advisory: https://github.com/openclaw/openclaw/security/advisories/GHSA-gv46-4xfq-jv58
- Affected range: `< 2026.2.14`
- Patched range: `>= 2026.2.14`

## Baseline Commit
- Baseline (pre-introduction): `b347d5d9ccbb8ccf008c887fc03cdc3410710afd`

## Vulnerable Introducing Commit(s)
- `2f8206862a684d14f7ca92e9fe0dbce627c5d82b` (2026-01-19T10:08:29Z) refactor: remove bridge protocol

## Fix Commit(s)
- `318379cdba1804eb840896f6ebd4dd6dd0fb53cb` (2026-02-14T13:27:45+01:00) fix(gateway): bind system.run approvals to exec approvals
- `0af76f5f0e93540efbdf054895216c398692afcd` (2026-02-14T13:27:45+01:00) refactor(gateway): centralize node.invoke param sanitization
- `01b3226ecbea6f5aa2a433237dae87d181d8790f` (2026-02-14T19:22:37+01:00) fix(gateway): block node.invoke exec approvals

## Verification
- Overall: `pass`
- Confidence: `medium`
- Notes: Advisory lists three SHAs that do not resolve via GitHub API; equivalent public fix sequence was resolved by file history and commit messages.

- [PASS] `baseline_is_parent_of_earliest_intro`: baseline=b347d5d9ccbb8ccf008c887fc03cdc3410710afd earliest_intro=2f8206862a684d14f7ca92e9fe0dbce627c5d82b
- [PASS] `baseline_ancestor_of_all_intro`: baseline should precede introducing commits
- [PASS] `baseline_ancestor_of_all_fix`: baseline should precede fix commits
- [PASS] `intro_precedes_patched_release`: intro=2f8206862a684d14f7ca92e9fe0dbce627c5d82b patched_tag_commit=b5ab92eef4e4f6099c98817e0917c99ec9e03045
- [PASS] `fix_at_or_before_patched_release`: fix_head=01b3226ecbea6f5aa2a433237dae87d181d8790f patched_tag_commit=b5ab92eef4e4f6099c98817e0917c99ec9e03045
- [PASS] `intro_at_or_before_affected_upper`: intro=2f8206862a684d14f7ca92e9fe0dbce627c5d82b affected_upper_commit=b5ab92eef4e4f6099c98817e0917c99ec9e03045

## SecureVibes Efficacy
- See `detectability.json` for empirical-run status and findings mapping.
