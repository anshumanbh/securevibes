# GHSA-mc68-q9jw-2h3v

## Vulnerability
- Severity: `high`
- Summary: Command Injection in Clawdbot Docker Execution via PATH Environment Variable
- CWE: CWE-78
- Advisory: https://github.com/openclaw/openclaw/security/advisories/GHSA-mc68-q9jw-2h3v
- Affected range: `<= 2026.1.24`
- Patched range: `v2026.1.29`

## Baseline Commit
- Baseline (pre-introduction): `7a839e7eb62b9711188cadc88f90b1d8a9a29113`

## Vulnerable Introducing Commit(s)
- `eaace34233fdf454c526d23cd2fd49de3be8eb32` (2026-01-15T02:58:20Z) fix: restore docker binds and PATH in sandbox exec (#873)

## Fix Commit(s)
- `771f23d36b95ec2204cc9a0054045f5d8439ea75` (2026-01-27T04:00:22Z) fix(exec): prevent PATH injection in docker sandbox

## Verification
- Overall: `pass`
- Confidence: `high`
- Notes: PATH handling weakness is introduced by docker sandbox exec PATH restoration and corrected in dedicated fix commit.

- [PASS] `baseline_is_parent_of_earliest_intro`: baseline=7a839e7eb62b9711188cadc88f90b1d8a9a29113 earliest_intro=eaace34233fdf454c526d23cd2fd49de3be8eb32
- [PASS] `baseline_ancestor_of_all_intro`: baseline should precede introducing commits
- [PASS] `baseline_ancestor_of_all_fix`: baseline should precede fix commits
- [PASS] `intro_precedes_patched_release`: intro=eaace34233fdf454c526d23cd2fd49de3be8eb32 patched_tag_commit=77e703c69b07a236c2f0962bd195e03aae1b8da0
- [PASS] `fix_at_or_before_patched_release`: fix_head=771f23d36b95ec2204cc9a0054045f5d8439ea75 patched_tag_commit=77e703c69b07a236c2f0962bd195e03aae1b8da0
- [PASS] `intro_at_or_before_affected_upper`: intro=eaace34233fdf454c526d23cd2fd49de3be8eb32 affected_upper_commit=bcedeb4e1f620a50b6e99f1e2b25cc692f0d7bab

## SecureVibes Efficacy
- See `detectability.json` for empirical-run status and findings mapping.
