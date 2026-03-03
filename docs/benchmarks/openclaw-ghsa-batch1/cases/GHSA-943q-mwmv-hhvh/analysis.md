# GHSA-943q-mwmv-hhvh

## Vulnerability
- Severity: `high`
- Summary: OC-02: Gateway /tools/invoke tool escalation + ACP permission auto-approval
- CWE: CWE-78
- Advisory: https://github.com/openclaw/openclaw/security/advisories/GHSA-943q-mwmv-hhvh
- Affected range: `<2026.2.14`
- Patched range: `>=2026.2.14`

## Baseline Commit
- Baseline (pre-introduction): `68d79e56c2ef91555ccd596cf520a85dd34c83fb`

## Vulnerable Introducing Commit(s)
- `9809b47d4545b394a5e49624796297147a8253cb` (2026-01-18T08:27:37Z) feat(acp): add interactive client harness
- `f1083cd52cf43c7312ae09cf0aa696ba9c95282c` (2026-01-24T09:29:32Z) gateway: add /tools/invoke HTTP endpoint

## Fix Commit(s)
- `749e28dec796f77697398acbfc7a64d4439d7cad` (2026-02-13T14:30:06+01:00) fix(security): block dangerous tools from HTTP gateway and fix ACP auto-approval (OC-02)
- `ee31cd47b49f4b2f128a69a2a3745ca9db68b3be` (2026-02-13T14:30:06+01:00) fix: close OC-02 gaps in ACP permission + gateway HTTP deny config (#15390) (thanks @aether-ai-agent)
- `539689a2f2897c317be4d6064f8ee10883907efa` (2026-02-14T12:48:02+01:00) feat(security): warn when gateway.tools.allow re-enables dangerous HTTP tools
- `bb1c3dfe10766fd996ef220ff9d3f967eb717faa` (2026-02-14T12:53:27+01:00) fix(acp): prompt for non-read/search permissions
- `153a7644eabc5f0214c9e51dd42cba5276e9bc3e` (2026-02-14T13:18:49+01:00) fix(acp): tighten safe kind inference

## Verification
- Overall: `pass`
- Confidence: `high`
- Notes: Issue combines two independently introduced paths: HTTP /tools/invoke surface and ACP auto-approval logic.

- [PASS] `baseline_is_parent_of_earliest_intro`: baseline=68d79e56c2ef91555ccd596cf520a85dd34c83fb earliest_intro=9809b47d4545b394a5e49624796297147a8253cb
- [PASS] `baseline_ancestor_of_all_intro`: baseline should precede introducing commits
- [PASS] `baseline_ancestor_of_all_fix`: baseline should precede fix commits
- [PASS] `intro_precedes_patched_release`: intro=f1083cd52cf43c7312ae09cf0aa696ba9c95282c patched_tag_commit=b5ab92eef4e4f6099c98817e0917c99ec9e03045
- [PASS] `fix_at_or_before_patched_release`: fix_head=153a7644eabc5f0214c9e51dd42cba5276e9bc3e patched_tag_commit=b5ab92eef4e4f6099c98817e0917c99ec9e03045
- [PASS] `intro_at_or_before_affected_upper`: intro=f1083cd52cf43c7312ae09cf0aa696ba9c95282c affected_upper_commit=b5ab92eef4e4f6099c98817e0917c99ec9e03045

## SecureVibes Efficacy
- See `detectability.json` for empirical-run status and findings mapping.
