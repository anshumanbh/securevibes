# Implementation Plan: Daily Incremental SecureVibes Wrapper

## Context

SecureVibes needs automated continuous scanning of new commits on `main` without manual PR-per-PR invocations. This wrapper runs every 30 minutes via cron, tracks the last scanned SHA, computes new commit windows, and invokes `securevibes pr-review` with adaptive chunking. Commit traffic is bursty (up to 21 commits/day), so adaptive chunking prevents timeouts on large windows.

No changes to SecureVibes core code. Python implementation for TDD compatibility with existing pytest infrastructure.

---

## Files to Create

| File | Purpose |
|---|---|
| `ops/incremental_scan.py` | Main wrapper script (executable, argparse CLI) |
| `ops/incremental_scan.sh` | Thin shell launcher for cron ergonomics |
| `ops/__init__.py` | Empty, enables test imports |
| `ops/tests/__init__.py` | Empty, enables test discovery |
| `ops/tests/conftest.py` | Shared fixtures (tmp repo, mock state, mock subprocess) |
| `ops/tests/test_incremental_scan.py` | Unit + integration tests (TDD — written first) |

No files modified. No changes to `packages/core/` or `pyproject.toml`.

---

## CLI Contract: `ops/incremental_scan.py`

```
python ops/incremental_scan.py [options]

--repo PATH                 Repository path (default: .)
--branch NAME               Branch to track (default: main)
--remote NAME               Git remote (default: origin)
--model NAME                Claude model for pr-review (default: sonnet)
--severity LEVEL            Min severity: critical|high|medium|low (default: medium)
--state-file PATH           State file path (default: .securevibes/incremental_state.json)
--log-file PATH             Log file path (default: .securevibes/incremental_scan.log)
--chunk-small-max INT       Max commits for single-range scan (default: 8)
--chunk-medium-max INT      Max commits for chunked scan (default: 25)
--chunk-medium-size INT     Chunk size for medium windows (default: 5)
--retry-network INT         Network retry count for git fetch (default: 1)
--rewrite-policy POLICY     Force-push policy: reset_warn|since_date|strict_fail (default: reset_warn)
--strict                    Return non-zero on infra failures
--debug                     Forward --debug to pr-review
```

Built with `argparse` (stdlib only, no Click dependency needed for this standalone script).

---

## State Schema: `.securevibes/incremental_state.json`

```json
{
  "repo": "/abs/path/to/repo",
  "branch": "main",
  "remote": "origin",
  "last_seen_sha": "abc123...",
  "last_run_utc": "2026-02-18T10:00:00Z",
  "last_success_utc": "2026-02-18T10:00:45Z",
  "last_status": "success|partial|failed|bootstrap|no_change|rewrite_reset",
  "last_run_id": "20260218T100000Z-3f2a1d",
  "last_failure": {
    "phase": "fetch|chunk_run|state_write",
    "reason": "error message string",
    "failed_chunk_index": 2
  }
}
```

---

## Structured Run Records: `.securevibes/incremental_runs/`

Each run writes: `.securevibes/incremental_runs/<run_id>.json`

Contains: run_id, timestamps, commit window, strategy chosen, per-chunk results (exit code, output file path, stderr snippet), final anchor, overall status.

Also used for **scan completion validation** — see below.

---

## Module Design: `ops/incremental_scan.py`

### Functions (in dependency order)

1. **`load_state(state_path: Path) -> dict | None`** — Parse state JSON; return None if missing; treat corrupt JSON as None + log warning (auto-recovery)
2. **`save_state(state_path: Path, state: dict) -> None`** — Atomic write: `tempfile.NamedTemporaryFile` + `fsync` + `os.replace`
3. **`generate_run_id() -> str`** — Format: `YYYYMMDDTHHMMSSZ-<6hex>`
4. **`git_fetch(repo: Path, remote: str, branch: str, retries: int) -> None`** — `git fetch <remote> <branch>` with configurable retry count; raise on final failure
5. **`resolve_head(repo: Path, remote: str, branch: str) -> str`** — `git rev-parse <remote>/<branch>`, return full SHA
6. **`is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool`** — `git merge-base --is-ancestor`
7. **`get_commit_list(repo: Path, base: str, head: str) -> list[str]`** — `git rev-list --reverse base..head`
8. **`compute_chunks(commits: list[str], base_sha: str, small_max: int, medium_max: int, medium_size: int) -> list[tuple[str, str]]`** — Adaptive chunking; returns list of `(range_base, range_head)` tuples
9. **`classify_scan_result(exit_code: int, output_path: Path | None) -> str`** — Returns `"completed"` or `"infra_failure"`. **Critical**: exit code 0/1/2 alone is NOT sufficient — must also verify output file exists and parses as valid JSON with expected fields. Exit code 1 is ambiguous (high findings OR runtime error).
10. **`run_scan(repo: Path, base: str, head: str, model: str, severity: str, debug: bool, output_path: Path) -> tuple[int, str]`** — Invoke `securevibes pr-review <repo> --range <base>..<head> --model <model> --severity <severity> --format json --output <output_path> --update-artifacts --clean-pr-artifacts [--debug]`. Returns `(exit_code, classification)`.
11. **`handle_rewrite(repo: Path, state: dict, new_head: str, policy: str) -> dict`** — Implements `reset_warn`, `since_date`, `strict_fail` policies
12. **`run(args: argparse.Namespace) -> int`** — Full orchestration (see flow below)

### Orchestration Flow (`run()`)

```
 1. Resolve repo path, validate it's a git repo
 2. Ensure .securevibes/ exists; verify SECURITY.md + THREAT_MODEL.json exist
 3. Ensure .securevibes/incremental_runs/ exists
 4. Acquire flock on .securevibes/.incremental_scan.lock (non-blocking; exit 0 if locked)
 5. generate_run_id()
 6. git_fetch(remote, branch, retries=retry_network)
 7. new_head = resolve_head(remote, branch)
 8. state = load_state(state_path)  [None = missing or corrupt]
 9. If no state → save_state(last_seen_sha=new_head, status="bootstrap"), exit 0
10. If last_seen_sha == new_head → save_state(status="no_change"), exit 0
11. If not is_ancestor(last_seen_sha, new_head) → handle_rewrite(policy)
12. commits = get_commit_list(last_seen_sha, new_head)
13. chunks = compute_chunks(commits, last_seen_sha, ...)
14. For each chunk[i] = (base, head):
    - output_path = .securevibes/incremental_runs/<run_id>-chunk-<i>.json
    - (exit_code, classification) = run_scan(...)
    - If classification == "completed": record success, track last_successful_head = head
    - If classification == "infra_failure": record failure, STOP loop
15. Determine overall status:
    - All completed → status="success", anchor=new_head
    - Partial → status="partial", anchor=last_successful_head
    - None → status="failed", anchor unchanged
16. save_state atomically
17. Write run record JSON to .securevibes/incremental_runs/<run_id>.json
18. Append summary line to log file
19. Release lock
20. Return 0 if success/no_change/bootstrap, 1 if partial/failed (when --strict)
```

### Scan Completion Classification (Critical Detail)

`pr-review` exit code 1 is **ambiguous** — it can mean "high severity findings" OR "runtime error". Relying on exit code alone would cause the wrapper to incorrectly advance the anchor after a failed scan.

**Classification logic in `classify_scan_result()`:**
- `"completed"` if: exit code in {0, 1, 2} AND output file exists AND output parses as valid JSON with expected top-level fields
- `"infra_failure"` if: exit code > 2, OR output file missing, OR output doesn't parse, OR subprocess exception

### Root Commit Edge Case

When building chunk ranges, `c_first^` may not exist if the chunk starts at the repo's root commit. Handle by checking `git rev-parse <sha>^` — if it fails, use `--last 1` mode or generate a temp patch via `git show` + `--diff` fallback for that single root commit.

### Locking

`fcntl.flock(fd, LOCK_EX | LOCK_NB)` on `.securevibes/.incremental_scan.lock`. If `BlockingIOError`, log "overlap prevented" and exit 0.

### Atomic State Writes

`tempfile.NamedTemporaryFile(dir=same_dir)` → write → `fd.flush()` → `os.fsync(fd)` → `os.replace(tmp, final)`. The `fsync` ensures data hits disk before rename.

---

## Shell Launcher: `ops/incremental_scan.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_DIR"
exec python3 "$SCRIPT_DIR/incremental_scan.py" --repo "$REPO_DIR" "$@"
```

Cron entry: `*/30 * * * * /path/to/ops/incremental_scan.sh >> /path/to/.securevibes/incremental_scan.log 2>&1`

---

## TDD Test Plan: `ops/tests/test_incremental_scan.py`

### Fixtures (`conftest.py`)

- **`mock_repo(tmp_path)`** — tmp dir with `.securevibes/` containing dummy `SECURITY.md` + `THREAT_MODEL.json`, and `incremental_runs/` subdir
- **`state_path(mock_repo)`** — Returns `.securevibes/incremental_state.json` path
- **`sample_state()`** — Returns valid state dict with all fields
- **`fake_commits()`** — Returns list of 40 fake SHA strings for chunking tests

### Unit Tests (written first)

| # | Test | Validates |
|---|---|---|
| 1 | `test_load_state_returns_none_when_missing` | Non-existent file → None |
| 2 | `test_load_state_returns_dict` | Valid JSON → dict with expected keys |
| 3 | `test_load_state_corrupt_json_returns_none` | Corrupt file → None + no crash (auto-recovery) |
| 4 | `test_save_state_creates_file` | File created with valid JSON |
| 5 | `test_save_state_atomic_uses_fsync_and_replace` | Verify tmp file + fsync + os.replace sequence via mocks |
| 6 | `test_generate_run_id_format` | Matches `YYYYMMDDTHHMMSSZ-<6hex>` pattern |
| 7 | `test_compute_chunks_small_window` | N<=8 → single range `[(base, last_commit)]` |
| 8 | `test_compute_chunks_medium_window` | 9<=N<=25 → chunks of 5 |
| 9 | `test_compute_chunks_large_window` | N>25 → per-commit `[(commits[i-1], commits[i])]` |
| 10 | `test_compute_chunks_exact_boundaries` | N=8, N=9, N=25, N=26 edge cases |
| 11 | `test_compute_chunks_custom_thresholds` | Non-default small_max/medium_max/medium_size |
| 12 | `test_classify_scan_completed` | Exit 0/1/2 + valid JSON output → "completed" |
| 13 | `test_classify_scan_exit_1_no_output_is_infra_failure` | Exit 1 + missing output → "infra_failure" (the ambiguous case) |
| 14 | `test_classify_scan_exit_1_invalid_json_is_infra_failure` | Exit 1 + corrupt output → "infra_failure" |
| 15 | `test_classify_scan_high_exit_code` | Exit 127 → "infra_failure" |
| 16 | `test_run_scan_builds_correct_command` | Subprocess args match expected CLI shape |
| 17 | `test_run_scan_includes_debug_flag` | `--debug` present when debug=True |
| 18 | `test_run_scan_includes_severity` | `--severity <level>` present in command |
| 19 | `test_handle_rewrite_reset_warn` | Resets anchor + sets status "rewrite_reset" |
| 20 | `test_handle_rewrite_strict_fail` | Leaves anchor unchanged + raises/returns error |

### Integration Tests (mocked subprocess + git)

| # | Test | Scenario |
|---|---|---|
| 21 | `test_bootstrap_initializes_state_no_scan` | No state file → state created with HEAD, status="bootstrap", no scan invoked |
| 22 | `test_no_new_commits_exits_clean` | `last_seen_sha == new_head` → exit 0, status="no_change" |
| 23 | `test_small_window_single_scan` | 5 commits → 1 scan call, anchor=new_head |
| 24 | `test_medium_window_chunked_scans` | 12 commits → 3 chunk scans (5+5+2), anchor=new_head |
| 25 | `test_large_window_per_commit_scans` | 30 commits → 30 scan calls, anchor=new_head |
| 26 | `test_partial_failure_anchors_at_last_success` | 3 chunks, chunk 2 infra failure → anchor at end of chunk 1 |
| 27 | `test_force_push_resets_anchor_default_policy` | `is_ancestor` False → anchor reset, status="rewrite_reset" |
| 28 | `test_concurrent_run_exits_cleanly` | Lock held → exit 0, no scan, log "overlap prevented" |
| 29 | `test_findings_exit_codes_advance_anchor` | Scan returns 1 with valid JSON → anchor advances |
| 30 | `test_exit_1_without_output_halts_pipeline` | Scan returns 1 without JSON output → treated as infra failure |
| 31 | `test_infra_failure_stops_remaining_chunks` | Scan returns 127 → remaining chunks skipped, anchor partial |
| 32 | `test_run_record_written_with_chunk_results` | Run record JSON exists with per-chunk results |
| 33 | `test_corrupt_state_triggers_bootstrap` | Corrupt state file → treated as bootstrap, re-initialized |

---

## Implementation Order (TDD, dependency-driven)

1. Create directory structure: `ops/`, `ops/tests/`, `__init__.py` files
2. Write `conftest.py` with fixtures
3. **Tests 1-6** → implement `load_state`, `save_state`, `generate_run_id`
4. **Tests 7-11** → implement `compute_chunks`
5. **Tests 12-15** → implement `classify_scan_result`
6. **Tests 16-18** → implement `run_scan`
7. **Tests 19-20** → implement `handle_rewrite`
8. **Tests 21-33** → implement `run()` orchestration + `argparse` CLI
9. Create `ops/incremental_scan.sh` launcher
10. Add shebang + `if __name__ == "__main__"` to `incremental_scan.py`
11. Run full test suite to confirm green

## Verification

1. `python -m pytest ops/tests/ -v --tb=short` — all 33 tests pass
2. `cd packages/core && python -m pytest tests/ -v --tb=short` — existing tests unaffected
3. Manual dry run on the repo:
   - `python ops/incremental_scan.py --repo . --debug` → bootstrap, state file created
   - Run again → "no new commits"
   - After a new commit on main → scan invoked with correct range
