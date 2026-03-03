# GHSA-qrq5-wjgg-rvqw

## Vulnerability
- Severity: `critical`
- Summary: Path Traversal in Plugin Installation
- CWE: CWE-22
- Advisory: https://github.com/openclaw/openclaw/security/advisories/GHSA-qrq5-wjgg-rvqw
- Affected range: `>= 2026.1.29-beta.1, < 2026.2.1`
- Patched range: `>= 2026.2.1`

## Baseline Commit
- Baseline (pre-introduction): `a6ea74f8e6ffae13f1de88736b0d47a004b98e54`

## Vulnerable Introducing Commit(s)
- `2f4a248314fdd754b8344d955842fdd47f828fab` (2026-01-12T01:16:39Z) feat: plugin system + voice-call
- `3a6ee5ee00176c88aee32bb8bfd543780014c079` (2026-01-17T07:08:04Z) feat: unify hooks installs and webhooks

## Fix Commit(s)
- `d03eca8450dc493b198a88b105fd180895238e57` (2026-02-02T02:07:47-08:00) fix: harden plugin and hook install paths

## Verification
- Overall: `pass`
- Confidence: `high`
- Notes: Plugin install path logic introduced during plugin system bootstrap and hook/plugin install unification.

- [PASS] `baseline_is_parent_of_earliest_intro`: baseline=a6ea74f8e6ffae13f1de88736b0d47a004b98e54 earliest_intro=2f4a248314fdd754b8344d955842fdd47f828fab
- [PASS] `baseline_ancestor_of_all_intro`: baseline should precede introducing commits
- [PASS] `baseline_ancestor_of_all_fix`: baseline should precede fix commits
- [PASS] `intro_precedes_patched_release`: intro=3a6ee5ee00176c88aee32bb8bfd543780014c079 patched_tag_commit=d842b28a1517f95aae2a5bcd97f2f726e42b93d8
- [PASS] `fix_at_or_before_patched_release`: fix_head=d03eca8450dc493b198a88b105fd180895238e57 patched_tag_commit=d842b28a1517f95aae2a5bcd97f2f726e42b93d8
- [PASS] `intro_at_or_before_affected_upper`: intro=3a6ee5ee00176c88aee32bb8bfd543780014c079 affected_upper_commit=d842b28a1517f95aae2a5bcd97f2f726e42b93d8

## SecureVibes Efficacy
- See `detectability.json` for empirical-run status and findings mapping.
