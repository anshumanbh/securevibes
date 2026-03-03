# GHSA-g55j-c2v4-pjcg

## Vulnerability
- Severity: `high`
- Summary: Unauthenticated Local RCE via WebSocket config.apply
- CWE: CWE-20, CWE-78, CWE-306
- Advisory: https://github.com/openclaw/openclaw/security/advisories/GHSA-g55j-c2v4-pjcg
- Affected range: `< 2026.1.20`
- Patched range: `>= 2026.1.20`

## Baseline Commit
- Baseline (pre-introduction): `47d1f23d5552c6ae186249e61d845e4b955486ff`

## Vulnerable Introducing Commit(s)
- `73e9e787b4df7705556f199f5f3e00580fab38c3` (2026-01-19T10:07:56Z) feat: unify device auth + pairing

## Fix Commit(s)
- `9dbc1435a6cac576d5fd71f4e4bff11a5d9d43ba` (2026-01-20T09:24:01Z) fix: enforce ws3 roles + node allowlist

## Verification
- Overall: `pass`
- Confidence: `high`
- Notes: Gateway ws config.apply + unsafe cliPath flow is introduced in the device-auth/pairing unification and fixed by role and allowlist hardening.

- [PASS] `baseline_is_parent_of_earliest_intro`: baseline=47d1f23d5552c6ae186249e61d845e4b955486ff earliest_intro=73e9e787b4df7705556f199f5f3e00580fab38c3
- [PASS] `baseline_ancestor_of_all_intro`: baseline should precede introducing commits
- [PASS] `baseline_ancestor_of_all_fix`: baseline should precede fix commits
- [PASS] `intro_precedes_patched_release`: intro=73e9e787b4df7705556f199f5f3e00580fab38c3 patched_tag_commit=9a14267dfa5238188a30636bd60eed08f05a7255
- [PASS] `fix_at_or_before_patched_release`: fix_head=9dbc1435a6cac576d5fd71f4e4bff11a5d9d43ba patched_tag_commit=9a14267dfa5238188a30636bd60eed08f05a7255
- [PASS] `intro_at_or_before_affected_upper`: intro=73e9e787b4df7705556f199f5f3e00580fab38c3 affected_upper_commit=9a14267dfa5238188a30636bd60eed08f05a7255

## SecureVibes Efficacy
- See `detectability.json` for empirical-run status and findings mapping.
