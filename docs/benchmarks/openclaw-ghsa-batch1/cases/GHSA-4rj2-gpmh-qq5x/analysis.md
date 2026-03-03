# GHSA-4rj2-gpmh-qq5x

## Vulnerability
- Severity: `critical`
- Summary: Inbound allowlist policy bypass in voice-call extension (empty caller ID + suffix matching)
- CWE: CWE-287
- Advisory: https://github.com/openclaw/openclaw/security/advisories/GHSA-4rj2-gpmh-qq5x
- Affected range: `<= 2026.2.1`
- Patched range: `>= 2026.2.2`

## Baseline Commit
- Baseline (pre-introduction): `3467b0ba074cba456cf20d2178faff96bacaeafb`

## Vulnerable Introducing Commit(s)
- `42c17adb5e4d3ea1f9b1d2fd921b9abc183b79df` (2026-01-12T21:44:19Z) feat: restore voice-call plugin parity

## Fix Commit(s)
- `f8dfd034f5d9235c5485f492a9e4ccc114e97fdb` (2026-02-03T09:33:25-08:00) fix(voice-call): harden inbound policy

## Verification
- Overall: `pass`
- Confidence: `high`
- Notes: Inbound allowlist logic is introduced in the voice-call manager parity commit and hardened in the fix commit.

- [PASS] `baseline_is_parent_of_earliest_intro`: baseline=3467b0ba074cba456cf20d2178faff96bacaeafb earliest_intro=42c17adb5e4d3ea1f9b1d2fd921b9abc183b79df
- [PASS] `baseline_ancestor_of_all_intro`: baseline should precede introducing commits
- [PASS] `baseline_ancestor_of_all_fix`: baseline should precede fix commits
- [PASS] `intro_precedes_patched_release`: intro=42c17adb5e4d3ea1f9b1d2fd921b9abc183b79df patched_tag_commit=95cd2210f93d6ab2acc5e29dbad6065294365863
- [PASS] `fix_at_or_before_patched_release`: fix_head=f8dfd034f5d9235c5485f492a9e4ccc114e97fdb patched_tag_commit=95cd2210f93d6ab2acc5e29dbad6065294365863
- [PASS] `intro_at_or_before_affected_upper`: intro=42c17adb5e4d3ea1f9b1d2fd921b9abc183b79df affected_upper_commit=d842b28a1517f95aae2a5bcd97f2f726e42b93d8

## SecureVibes Efficacy
- See `detectability.json` for empirical-run status and findings mapping.
