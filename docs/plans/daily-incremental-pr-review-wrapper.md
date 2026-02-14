# Daily Incremental SecureVibes Wrapper (Cron-Driven, No SecureVibes Code Changes)

## Summary

Build an external wrapper script that runs every 30 minutes, tracks `last_seen_sha`, computes new commit windows on `origin/main`, and invokes `securevibes pr-review` with adaptive chunking for reliability. This avoids scanning every PR while preserving vuln-chain detection quality under bursty commit traffic.

## Public Interfaces / Types / Contracts

- New executable script (outside core SecureVibes code), e.g. `ops/securevibes_incremental_scan.sh`.
- New local state file, e.g. `.securevibes/incremental_state.json`:
  - `repo`
  - `branch`
  - `last_seen_sha`
  - `last_run_utc`
  - `last_success_utc`
- New optional log output file, e.g. `.securevibes/incremental_scan.log`.
- No changes to SecureVibes CLI/API internals.

## Wrapper Behavior (Decision-Complete)

1. Preflight
- Validate `git`, `jq` (or Python fallback), and `securevibes` are installed.
- `cd` into target repo.
- Acquire lock (e.g., `flock` or PID lockfile) to prevent overlapping cron runs.
- Ensure branch is `main` (or configured branch).

2. Sync
- Run `git fetch origin main`.
- Resolve `new_head=$(git rev-parse origin/main)`.

3. Initialize State
- If state file missing:
  - Set `last_seen_sha=new_head`.
  - Write state and exit without scanning (bootstrap mode).
- If state exists:
  - Load `last_seen_sha`.

4. Validate History
- If `last_seen_sha == new_head`, log "no new commits" and exit success.
- If `last_seen_sha` is not ancestor of `new_head` (force-push/rewrite):
  - Fallback to safe mode:
    - Run one date-bounded scan (`--since` current date in Pacific), or
    - Reset `last_seen_sha=new_head` and emit warning (configurable policy; default: reset+warn).
  - Exit with non-zero only if configured strict mode.

5. Build Commit List
- `commits=git rev-list --reverse ${last_seen_sha}..${new_head}`.
- Count commits `N`.

6. Adaptive Chunking (selected policy)
- If `N <= 8`: one range scan on full window.
- If `9 <= N <= 25`: split into chunks of 5 commits each.
- If `N > 25`: scan per commit (`sha^..sha`).
- Before each scan, remove transient PR artifacts:
  - Prefer `securevibes pr-review ... --clean-pr-artifacts`.
- Command shape:
  - `securevibes pr-review <repo> --range <base>..<head> --model sonnet --debug --update-artifacts --clean-pr-artifacts`
  - For per-commit: `--range <sha>^..<sha>`.

7. Result Handling
- Collect exit codes and failed chunks.
- Consider run successful if all chunks completed.
- On full success:
  - Update `last_seen_sha=new_head`.
  - Set `last_success_utc`.
- On partial failure:
  - Do not advance `last_seen_sha` beyond last successful contiguous chunk.
  - Persist failure metadata for retry next cron tick.

8. Reporting
- Emit concise run summary:
  - total new commits
  - chunk strategy chosen
  - scans run / failed
  - final anchored SHA
- Keep logs append-only with timestamps.

## Cron Setup

Run every 30 minutes:

`*/30 * * * * /path/to/ops/securevibes_incremental_scan.sh >> /path/to/repo/.securevibes/incremental_scan.log 2>&1`

## Failure Modes and Guardrails

- Network/git transient failure: retry once in-script, then fail and keep old anchor.
- SecureVibes non-zero on findings: treat as "scan completed" (not infra failure); continue chunk pipeline.
- SecureVibes execution error: treat as infra failure; stop and preserve anchor.
- Overlap protection: lock prevents duplicate concurrent runs.
- Force-push: detected via ancestry check; safe fallback path triggered.

## Test Cases / Scenarios

1. Bootstrap with no state file initializes anchor and does not scan.
2. No new commits exits cleanly without invoking `pr-review`.
3. 1-8 commits runs single range and updates anchor.
4. 9-25 commits runs chunked ranges of 5 and updates anchor on full success.
5. >25 commits runs per-commit scans.
6. Mid-run failure leaves anchor at last successful contiguous point.
7. Force-push/rewrite triggers fallback behavior and warning.
8. Concurrent invocations: second run exits due to lock.
9. Findings exit codes (1/2) do not block anchor advancement when scan completed.

## Assumptions and Defaults Chosen

- Branch: `main`.
- Interval: every 30 minutes.
- Model: `sonnet`.
- Chunk policy: adaptive (`<=8` single range, `9-25` chunk size 5, `>25` per-commit).
- Artifact hygiene: always pass `--clean-pr-artifacts`.
- Baseline SecureVibes artifacts already exist in `.securevibes/`.
- State file location: `.securevibes/incremental_state.json`.
