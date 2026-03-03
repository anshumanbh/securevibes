# GHSA-g8p2-7wf7-98mq

## Vulnerability
- Severity: `high`
- Summary: 1-Click RCE via Authentication Token Exfiltration From gatewayUrl
- CWE: CWE-200
- Advisory: https://github.com/openclaw/openclaw/security/advisories/GHSA-g8p2-7wf7-98mq
- Affected range: `<=v2026.1.28`
- Patched range: `v2026.1.29`

## Baseline Commit
- Baseline (pre-introduction): `51dfd6efdb013cfc7e269e0bedf3a9bef0ed7023`

## Vulnerable Introducing Commit(s)
- `c74551c2ae0611f3ef0e691dc93a38372f366765` (2026-01-20T16:35:02-08:00) fix(ui): parse gatewayUrl from URL params for remote gateway access

## Fix Commit(s)
- `a7534dc22382c42465f3676724536a014ce0cbf7` (2026-01-28T13:32:10-08:00) fix(ui): gateway URL confirmation modal (based on #2880) (#3578)

## Verification
- Overall: `pass`
- Confidence: `high`
- Notes: UI auto-connect trust boundary issue is introduced by query-param based gatewayUrl parsing.

- [PASS] `baseline_is_parent_of_earliest_intro`: baseline=51dfd6efdb013cfc7e269e0bedf3a9bef0ed7023 earliest_intro=c74551c2ae0611f3ef0e691dc93a38372f366765
- [PASS] `baseline_ancestor_of_all_intro`: baseline should precede introducing commits
- [PASS] `baseline_ancestor_of_all_fix`: baseline should precede fix commits
- [PASS] `intro_precedes_patched_release`: intro=c74551c2ae0611f3ef0e691dc93a38372f366765 patched_tag_commit=77e703c69b07a236c2f0962bd195e03aae1b8da0
- [PASS] `fix_at_or_before_patched_release`: fix_head=a7534dc22382c42465f3676724536a014ce0cbf7 patched_tag_commit=77e703c69b07a236c2f0962bd195e03aae1b8da0

## SecureVibes Efficacy
- See `detectability.json` for empirical-run status and findings mapping.
