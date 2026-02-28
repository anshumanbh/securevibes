# Incremental Scan Wrapper Notes

`ops/incremental_scan.py` is a cron-friendly wrapper for `securevibes pr-review`.
It tracks an anchor commit in `.securevibes/incremental_state.json`, scans new commit windows,
and writes structured run records under `.securevibes/incremental_runs/`.

## Operational guarantees

- Uses a non-blocking file lock at `.securevibes/.incremental_scan.lock` to prevent overlap.
- Writes state atomically (`fsync` + `os.replace`) to avoid partial state corruption.
- Treats scan completion as:
  - exit code in `{0,1,2}` and
  - valid JSON output with required top-level fields.
- Supports per-command timeouts to prevent indefinite hangs:
  - `--git-timeout-seconds` (default `60`)
  - `--scan-timeout-seconds` (default `900`)
- Threads PR review budget flags through to `securevibes pr-review`:
  - `--pr-attempts` — override PR review retry count (default from env or `4`)
  - `--pr-timeout` — override per-attempt timeout in seconds (default from env or `240`)
  - `--auto-triage` — deterministic triage pre-filter to reduce budget for low-risk diffs (docs, tests, config-only changes)
- Maintains a threat-aware `risk_map.json`:
  - Loads `.securevibes/risk_map.json` when present.
  - Generates it from `THREAT_MODEL.json` when missing.
- Scores each chunk by risk tier before invoking `securevibes pr-review`:
  - `critical` → routes to `opus`
  - `moderate` → routes to `sonnet`
  - `skip` → records classification and advances anchor without an LLM call
- Applies deterministic safeguards:
  - dependency manifest/lockfile changes promote skip chunks to moderate
  - policy/context file edits under `.securevibes/` force critical tier

## Rewrite policy behavior

When `last_seen_sha` is not an ancestor of the new remote head:

- `reset_warn`: reset anchor to new head and continue.
- `strict_fail`: fail and keep current anchor.
- `since_date`: run a `--since <Pacific-today>` scan for visibility, but keep the previous
  anchor to avoid skipping commits after a history rewrite.

The `since_date` path is intentionally conservative; it may require explicit operator action
(e.g., switching policy to `reset_warn`) to re-anchor.

## CLI

```bash
python ops/incremental_scan.py --repo . --help
```

Launcher for cron:

```bash
ops/incremental_scan.sh
```

## Validation commands

```bash
pytest ops/tests/test_incremental_scan.py -q
pytest ops/tests/test_incremental_scan.py --cov=ops.incremental_scan --cov-report=term-missing -q
ruff check ops/incremental_scan.py ops/tests/test_incremental_scan.py ops/tests/conftest.py
black --check ops/incremental_scan.py ops/tests/test_incremental_scan.py ops/tests/conftest.py
```
