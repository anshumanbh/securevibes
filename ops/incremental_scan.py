#!/usr/bin/env python3
"""Cron-friendly incremental SecureVibes PR review wrapper."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore[assignment]

REQUIRED_REPORT_FIELDS = (
    "repository_path",
    "files_scanned",
    "scan_time_seconds",
    "issues",
)
COMPLETED = "completed"
INFRA_FAILURE = "infra_failure"
DIFF_TOO_LARGE = "diff_too_large"
DEFAULT_GIT_TIMEOUT_SECONDS = 60
DEFAULT_SCAN_TIMEOUT_SECONDS = 900
DIFF_TOO_LARGE_MARKERS = (
    "exceeds safe analysis limits",
    "diff context exceeds",
)
RUN_RECORD_NAME_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}\.json$")


@dataclass
class RunContext:
    """Mutable context shared with signal handlers for graceful cleanup."""

    run_id: str | None = None
    current_chunk_index: int = 0
    last_successful_anchor: str | None = None
    interrupted: bool = False
    interrupted_signal: int | None = None
    _child_process: subprocess.Popen | None = None  # type: ignore[type-arg]

    def reset(self) -> None:
        """Reset context to avoid leakage between runs/tests."""
        self.run_id = None
        self.current_chunk_index = 0
        self.last_successful_anchor = None
        self.interrupted = False
        self.interrupted_signal = None
        self._child_process = None

    def mark_interrupted(self, signum: int | None = None) -> None:
        """Mark run as interrupted and terminate any active child process."""
        self.interrupted = True
        self.interrupted_signal = signum
        if self._child_process is not None:
            try:
                self._child_process.kill()
            except OSError:
                pass


# Global run context for signal handler access
_run_ctx = RunContext()


def _signal_handler(signum: int, frame: Any) -> None:
    """Handle SIGTERM/SIGINT with graceful cleanup."""
    del frame
    sig_name = (
        signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
    )
    print(
        f"\n[incremental-scan] Received {sig_name}, cleaning up...",
        file=sys.stderr,
        flush=True,
    )
    _run_ctx.mark_interrupted(signum)


@dataclass
class ScanCommandResult:
    """Result of one wrapper-invoked SecureVibes command."""

    command: list[str]
    exit_code: int
    classification: str
    stderr_tail: str
    output_path: Path


@dataclass
class RewriteOutcome:
    """Decision object for history-rewrite handling."""

    action: str
    reason: str
    since_date: str | None = None


def utc_timestamp() -> str:
    """Return UTC timestamp in ISO-8601 with Z suffix."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def generate_run_id() -> str:
    """Create stable run id used for logs and output artifacts."""
    return (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + f"-{secrets.token_hex(3)}"
    )


def positive_int(value: str) -> int:
    """Parse positive integer argparse values."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for incremental wrapper."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Repository path")
    parser.add_argument("--branch", default="main", help="Branch to track")
    parser.add_argument("--remote", default="origin", help="Git remote")
    parser.add_argument("--model", default="sonnet", help="SecureVibes model")
    parser.add_argument(
        "--severity",
        default="medium",
        choices=("critical", "high", "medium", "low"),
        help="Minimum severity for pr-review",
    )
    parser.add_argument(
        "--state-file",
        default=".securevibes/incremental_state.json",
        help="State file path",
    )
    parser.add_argument(
        "--log-file",
        default=".securevibes/incremental_scan.log",
        help="Log file path",
    )
    parser.add_argument("--chunk-small-max", type=int, default=8)
    parser.add_argument("--chunk-medium-max", type=int, default=25)
    parser.add_argument("--chunk-medium-size", type=int, default=5)
    parser.add_argument("--retry-network", type=int, default=1)
    parser.add_argument(
        "--rewrite-policy",
        default="reset_warn",
        choices=("reset_warn", "since_date", "strict_fail"),
    )
    parser.add_argument(
        "--git-timeout-seconds",
        type=positive_int,
        default=DEFAULT_GIT_TIMEOUT_SECONDS,
        help="Timeout for each git command invocation",
    )
    parser.add_argument(
        "--scan-timeout-seconds",
        type=positive_int,
        default=DEFAULT_SCAN_TIMEOUT_SECONDS,
        help="Timeout for each securevibes pr-review invocation",
    )
    parser.add_argument(
        "--pr-attempts",
        type=positive_int,
        default=None,
        help="Override number of PR review retry attempts (passed to securevibes pr-review)",
    )
    parser.add_argument(
        "--pr-timeout",
        type=positive_int,
        default=None,
        help="Override per-attempt timeout in seconds (passed to securevibes pr-review)",
    )
    parser.add_argument(
        "--auto-triage",
        action="store_true",
        default=False,
        help="Enable deterministic triage to reduce budget for low-risk diffs",
    )
    parser.add_argument(
        "--no-fallback",
        action="store_true",
        default=False,
        help="Disable per-commit fallback when a chunk exceeds diff size limits",
    )
    parser.add_argument(
        "--max-diff-files",
        type=positive_int,
        default=15,
        help="Max files per chunk before splitting (adaptive chunking)",
    )
    parser.add_argument(
        "--max-diff-lines",
        type=positive_int,
        default=500,
        help="Max total lines changed per chunk before splitting (adaptive chunking)",
    )
    parser.add_argument(
        "--no-adaptive",
        action="store_true",
        default=False,
        help="Disable adaptive diff-aware chunking; use count-based chunking instead",
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args(argv)


def resolve_repo_path(repo: Path, candidate: str) -> Path:
    """Resolve candidate path relative to repo root when needed."""
    path = Path(candidate)
    if path.is_absolute():
        return path
    return repo / path


def load_state(state_path: Path) -> dict[str, Any] | None:
    """Load state file from disk and return dict when valid."""
    if not state_path.exists():
        return None
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def save_state(state_path: Path, state: dict[str, Any]) -> None:
    """Persist state atomically to avoid partial writes."""
    state_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(state_path.parent), prefix=f".{state_path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, state_path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def save_json(path: Path, payload: dict[str, Any]) -> None:
    """Write JSON payload to disk with parent mkdir and deterministic encoding."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def append_log(log_file: Path, message: str) -> None:
    """Append one line to text log with UTC prefix."""
    log_file.parent.mkdir(parents=True, exist_ok=True)
    timestamp = utc_timestamp()
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(f"[{timestamp}] {message}\n")


def ensure_dependencies() -> None:
    """Verify required binaries are available on PATH."""
    for binary in ("git", "securevibes"):
        if shutil.which(binary):
            continue
        raise RuntimeError(f"Missing required dependency: {binary}")


def ensure_repo(repo: Path, timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS) -> None:
    """Ensure repository exists and is a git worktree."""
    if not repo.exists() or not repo.is_dir():
        raise RuntimeError(f"Repository path does not exist: {repo}")

    result = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if result.returncode != 0 or result.stdout.strip() != "true":
        stderr = result.stderr.strip() or "not a git repository"
        raise RuntimeError(f"Invalid repository: {stderr}")


def ensure_baseline_artifacts(repo: Path) -> None:
    """Ensure baseline artifacts required by securevibes pr-review exist."""
    securevibes_dir = repo / ".securevibes"
    required = [
        securevibes_dir / "SECURITY.md",
        securevibes_dir / "THREAT_MODEL.json",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        joined = ", ".join(missing)
        raise RuntimeError(f"Missing baseline artifacts for pr-review: {joined}")


def git_fetch(
    repo: Path,
    remote: str,
    branch: str,
    retries: int,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> None:
    """Fetch remote branch with retry on transient failure."""
    attempts = max(0, retries) + 1
    last_error = ""
    for attempt in range(1, attempts + 1):
        try:
            result = subprocess.run(
                ["git", "fetch", remote, branch],
                cwd=repo,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            last_error = f"git fetch timed out after {timeout_seconds}s"
            if attempt < attempts:
                time.sleep(1)
            continue
        if result.returncode == 0:
            return
        last_error = result.stderr.strip() or "git fetch failed"
        if attempt < attempts:
            time.sleep(1)
    raise RuntimeError(last_error)


def resolve_head(
    repo: Path,
    remote: str,
    branch: str,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> str:
    """Resolve the latest commit SHA for remote branch."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", f"{remote}/{branch}"],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"git rev-parse timed out after {timeout_seconds}s") from exc
    if result.returncode != 0:
        stderr = result.stderr.strip() or "unable to resolve head"
        raise RuntimeError(stderr)
    head = result.stdout.strip()
    if not head:
        raise RuntimeError("Empty git head SHA")
    return head


def is_ancestor(
    repo: Path,
    ancestor: str,
    descendant: str,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> bool:
    """Return True when ancestor is reachable from descendant."""
    try:
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"git merge-base timed out after {timeout_seconds}s"
        ) from exc
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    stderr = result.stderr.strip() or "merge-base check failed"
    raise RuntimeError(stderr)


def get_commit_list(
    repo: Path,
    base: str,
    head: str,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> list[str]:
    """Collect commits in base..head ordered oldest-to-newest."""
    try:
        result = subprocess.run(
            ["git", "rev-list", "--reverse", f"{base}..{head}"],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"git rev-list timed out after {timeout_seconds}s") from exc
    if result.returncode != 0:
        stderr = result.stderr.strip() or "rev-list failed"
        raise RuntimeError(stderr)
    return [line for line in result.stdout.splitlines() if line.strip()]


def get_diff_stats(
    repo: Path,
    base: str,
    head: str,
    timeout_seconds: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> tuple[int, int]:
    """Return (file_count, total_lines_changed) for a range."""
    try:
        result = subprocess.run(
            ["git", "diff", "--numstat", f"{base}..{head}"],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"git diff --numstat timed out after {timeout_seconds}s"
        ) from exc
    if result.returncode != 0:
        stderr = result.stderr.strip() or "git diff --numstat failed"
        raise RuntimeError(stderr)
    file_count = 0
    total_lines = 0
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        added, deleted = parts[0], parts[1]
        file_count += 1
        # Binary files show "-" for additions/deletions
        if added == "-" or deleted == "-":
            continue
        try:
            total_lines += int(added) + int(deleted)
        except ValueError:
            pass
    return (file_count, total_lines)


def compute_chunks_by_count(
    commits: list[str],
    base_sha: str,
    small_max: int,
    medium_max: int,
    medium_size: int,
) -> list[tuple[str, str]]:
    """Compute adaptive pr-review ranges as (base, head) tuples."""
    if not commits:
        return []

    total = len(commits)
    if total <= small_max:
        return [(base_sha, commits[-1])]

    if total <= medium_max:
        chunks: list[tuple[str, str]] = []
        start = 0
        size = max(1, medium_size)
        while start < total:
            end = min(start + size, total)
            range_base = base_sha if start == 0 else commits[start - 1]
            range_head = commits[end - 1]
            chunks.append((range_base, range_head))
            start = end
        return chunks

    return [
        (base_sha if idx == 0 else commits[idx - 1], commit)
        for idx, commit in enumerate(commits)
    ]


# Backward-compatible alias
compute_chunks = compute_chunks_by_count


def compute_chunks_adaptive(
    commits: list[str],
    base_sha: str,
    repo: Path,
    max_files: int = 15,
    max_lines: int = 500,
    git_timeout: int = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> list[tuple[str, str]]:
    """Compute chunks using diff-size awareness.

    Splits commit ranges so each chunk stays within *max_files* and
    *max_lines* thresholds measured via ``git diff --numstat``.
    """
    if not commits:
        return []

    # Fast path: full range fits within limits
    fc, tl = get_diff_stats(repo, base_sha, commits[-1], git_timeout)
    if fc <= max_files and tl <= max_lines:
        return [(base_sha, commits[-1])]

    # Greedy: walk commits, accumulate diff stats per chunk
    chunks: list[tuple[str, str]] = []
    chunk_base = base_sha
    chunk_start_idx = 0

    for i, commit in enumerate(commits):
        fc, tl = get_diff_stats(repo, chunk_base, commit, git_timeout)
        if fc > max_files or tl > max_lines:
            if i > chunk_start_idx:
                # Cut chunk at previous commit
                chunks.append((chunk_base, commits[i - 1]))
                chunk_base = commits[i - 1]
                chunk_start_idx = i
            else:
                # Single commit exceeds limits; include as its own chunk
                chunks.append((chunk_base, commit))
                chunk_base = commit
                chunk_start_idx = i + 1

    # Remaining commits
    if chunk_start_idx < len(commits):
        chunks.append((chunk_base, commits[-1]))

    return chunks


def determine_chunk_strategy(
    total_commits: int,
    small_max: int,
    medium_max: int,
    adaptive: bool = False,
) -> str:
    """Describe selected adaptive chunk strategy for run summaries."""
    if adaptive:
        return "adaptive_diff_size"
    if total_commits <= small_max:
        return "single_range"
    if total_commits <= medium_max:
        return "chunked"
    return "per_commit"


def _is_valid_report_json(path: Path) -> bool:
    """Check that a securevibes JSON output file is present and minimally valid."""
    if not path.exists() or not path.is_file():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    return all(field in payload for field in REQUIRED_REPORT_FIELDS)


def _stderr_indicates_diff_too_large(stderr: str) -> bool:
    """Return True when stderr shows the fail-closed diff size guardrail."""
    haystack = stderr.lower()
    return any(marker in haystack for marker in DIFF_TOO_LARGE_MARKERS)


def classify_scan_result(
    exit_code: int, output_path: Path | None, stderr: str = ""
) -> str:
    """Classify command outcome into completed, diff_too_large, or infrastructure failure."""
    if exit_code not in {0, 1, 2}:
        return INFRA_FAILURE
    if output_path is None or not _is_valid_report_json(output_path):
        if exit_code == 1 and _stderr_indicates_diff_too_large(stderr):
            return DIFF_TOO_LARGE
        return INFRA_FAILURE
    return COMPLETED


def _stderr_tail(stderr: str, max_lines: int = 8) -> str:
    """Trim stderr to a short diagnostic snippet."""
    lines = [line for line in stderr.splitlines() if line.strip()]
    if not lines:
        return ""
    return "\n".join(lines[-max_lines:])


def _run_subprocess_with_progress(
    command: list[str],
    timeout_seconds: int,
    label: str = "",
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    """Run subprocess with periodic progress heartbeats to stdout.

    Prints a dot every 30 seconds so callers know the process is alive.
    Stores the child process in _run_ctx so signal handlers can kill it.
    """
    start = time.monotonic()
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **kwargs,
    )
    _run_ctx._child_process = proc

    # Heartbeat thread prints progress while subprocess runs
    stop_event = threading.Event()

    def _heartbeat() -> None:
        interval = 30
        while not stop_event.wait(interval):
            elapsed = int(time.monotonic() - start)
            print(
                f"[incremental-scan] {label} still running ({elapsed}s elapsed)...",
                file=sys.stderr,
                flush=True,
            )

    heartbeat_thread = threading.Thread(target=_heartbeat, daemon=True)
    heartbeat_thread.start()

    try:
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        _run_ctx._child_process = None
        stop_event.set()
        raise
    finally:
        _run_ctx._child_process = None
        stop_event.set()

    return subprocess.CompletedProcess(
        args=command,
        returncode=proc.returncode,
        stdout=stdout,
        stderr=stderr,
    )


def run_scan(
    repo: Path,
    base: str,
    head: str,
    model: str,
    severity: str,
    debug: bool,
    output_path: Path,
    timeout_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS,
    pr_attempts: int | None = None,
    pr_timeout: int | None = None,
    auto_triage: bool = False,
) -> ScanCommandResult:
    """Run securevibes pr-review for an explicit commit range."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "securevibes",
        "pr-review",
        str(repo),
        "--range",
        f"{base}..{head}",
        "--model",
        model,
        "--severity",
        severity,
        "--format",
        "json",
        "--output",
        str(output_path),
        "--update-artifacts",
        "--clean-pr-artifacts",
    ]
    if pr_attempts is not None:
        command.extend(["--pr-attempts", str(pr_attempts)])
    if pr_timeout is not None:
        command.extend(["--pr-timeout", str(pr_timeout)])
    if auto_triage:
        command.append("--auto-triage")
    if debug:
        command.append("--debug")

    label = f"pr-review {base[:8]}..{head[:8]}"
    print(f"[incremental-scan] Starting {label}", file=sys.stderr, flush=True)

    try:
        result = _run_subprocess_with_progress(
            command,
            timeout_seconds,
            label=label,
        )
    except subprocess.TimeoutExpired:
        print(
            f"[incremental-scan] TIMEOUT {label} after {timeout_seconds}s",
            file=sys.stderr,
            flush=True,
        )
        return ScanCommandResult(
            command=command,
            exit_code=124,
            classification=INFRA_FAILURE,
            stderr_tail=f"scan timed out after {timeout_seconds}s",
            output_path=output_path,
        )

    tail = _stderr_tail(result.stderr)
    classification = classify_scan_result(result.returncode, output_path, result.stderr)
    print(
        f"[incremental-scan] Finished {label} → {classification} (exit={result.returncode})",
        file=sys.stderr,
        flush=True,
    )
    return ScanCommandResult(
        command=command,
        exit_code=result.returncode,
        classification=classification,
        stderr_tail=tail,
        output_path=output_path,
    )


def run_since_date_scan(
    repo: Path,
    since_date: str,
    model: str,
    severity: str,
    debug: bool,
    output_path: Path,
    timeout_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS,
    pr_attempts: int | None = None,
    pr_timeout: int | None = None,
    auto_triage: bool = False,
) -> ScanCommandResult:
    """Run securevibes pr-review using --since date fallback mode."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "securevibes",
        "pr-review",
        str(repo),
        "--since",
        since_date,
        "--model",
        model,
        "--severity",
        severity,
        "--format",
        "json",
        "--output",
        str(output_path),
        "--update-artifacts",
        "--clean-pr-artifacts",
    ]
    if pr_attempts is not None:
        command.extend(["--pr-attempts", str(pr_attempts)])
    if pr_timeout is not None:
        command.extend(["--pr-timeout", str(pr_timeout)])
    if auto_triage:
        command.append("--auto-triage")
    if debug:
        command.append("--debug")

    label = f"pr-review --since {since_date}"
    print(f"[incremental-scan] Starting {label}", file=sys.stderr, flush=True)

    try:
        result = _run_subprocess_with_progress(
            command,
            timeout_seconds,
            label=label,
        )
    except subprocess.TimeoutExpired:
        print(
            f"[incremental-scan] TIMEOUT {label} after {timeout_seconds}s",
            file=sys.stderr,
            flush=True,
        )
        return ScanCommandResult(
            command=command,
            exit_code=124,
            classification=INFRA_FAILURE,
            stderr_tail=f"scan timed out after {timeout_seconds}s",
            output_path=output_path,
        )

    tail = _stderr_tail(result.stderr)
    classification = classify_scan_result(result.returncode, output_path, result.stderr)
    print(
        f"[incremental-scan] Finished {label} → {classification} (exit={result.returncode})",
        file=sys.stderr,
        flush=True,
    )
    return ScanCommandResult(
        command=command,
        exit_code=result.returncode,
        classification=classification,
        stderr_tail=tail,
        output_path=output_path,
    )


def pacific_today() -> str:
    """Return current date in America/Los_Angeles timezone for --since fallback."""
    if ZoneInfo is None:
        return datetime.now().strftime("%Y-%m-%d")
    return datetime.now(ZoneInfo("America/Los_Angeles")).strftime("%Y-%m-%d")


def handle_rewrite(policy: str) -> RewriteOutcome:
    """Decide behavior when tracked anchor is not ancestor of current head."""
    if policy == "reset_warn":
        return RewriteOutcome(
            action="reset", reason="last_seen_sha is not ancestor of new head"
        )
    if policy == "since_date":
        return RewriteOutcome(
            action="since_date",
            reason="history rewrite detected; scanning current Pacific date window",
            since_date=pacific_today(),
        )
    return RewriteOutcome(action="strict_fail", reason="history rewrite detected")


def _build_state(
    *,
    repo: Path,
    branch: str,
    remote: str,
    anchor: str,
    run_id: str,
    status: str,
    failure: dict[str, Any] | None = None,
    previous_success_utc: str | None = None,
) -> dict[str, Any]:
    """Create persisted state payload for current run."""
    now = utc_timestamp()
    payload: dict[str, Any] = {
        "repo": str(repo),
        "branch": branch,
        "remote": remote,
        "last_seen_sha": anchor,
        "last_run_utc": now,
        "last_status": status,
        "last_run_id": run_id,
    }
    if status in {"success", "rewrite_reset", "bootstrap", "no_change"}:
        payload["last_success_utc"] = now
    elif previous_success_utc:
        payload["last_success_utc"] = previous_success_utc

    if failure:
        payload["last_failure"] = failure
    return payload


@contextmanager
def file_lock(lock_path: Path) -> Iterator[bool]:
    """Acquire non-blocking lock, yielding whether lock was acquired."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    acquired = False
    try:
        if fcntl is None:  # pragma: no cover
            acquired = True
            yield True
            return

        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
            yield True
        except BlockingIOError:
            yield False
    finally:
        if acquired and fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _is_primary_run_record(path: Path) -> bool:
    """Return True for top-level run record files only."""
    return bool(RUN_RECORD_NAME_RE.fullmatch(path.name))


def _recover_stale_runs(runs_dir: Path, log_file: Path) -> None:
    """Detect and mark run records that lack finished_utc as stale.

    This happens when a previous process was killed mid-run.
    We don't delete anything — just annotate the record so it's clear what happened.
    """
    if not runs_dir.exists():
        return
    for path in runs_dir.glob("*.json"):
        if not _is_primary_run_record(path):
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(record, dict):
            continue
        # If it has finished_utc or is already marked stale, skip
        if record.get("finished_utc") or record.get("status") == "stale_recovered":
            continue
        # This is an unfinished run — mark it
        record["status"] = "stale_recovered"
        record["finished_utc"] = utc_timestamp()
        record["failure"] = record.get("failure") or {
            "phase": "unknown",
            "reason": "process killed before completion (recovered on next run)",
        }
        try:
            save_json(path, record)
            run_id = record.get("run_id", path.stem)
            append_log(
                log_file,
                f"run_id={run_id} status=stale_recovered (previous run did not complete)",
            )
            print(
                f"[incremental-scan] Recovered stale run: {run_id}",
                file=sys.stderr,
                flush=True,
            )
        except Exception:
            pass


def _write_run_record(run_record_path: Path, run_record: dict[str, Any]) -> None:
    """Persist structured run record."""
    save_json(run_record_path, run_record)


def _strict_exit(status: str, strict: bool) -> int:
    """Return process exit code based on wrapper strictness."""
    if strict and status in {"partial", "failed"}:
        return 1
    return 0


def run(args: argparse.Namespace) -> int:
    """Run incremental scan wrapper end-to-end."""
    repo = Path(args.repo).resolve()
    git_timeout = max(
        1, int(getattr(args, "git_timeout_seconds", DEFAULT_GIT_TIMEOUT_SECONDS))
    )
    scan_timeout = max(
        1, int(getattr(args, "scan_timeout_seconds", DEFAULT_SCAN_TIMEOUT_SECONDS))
    )
    pr_attempts: int | None = getattr(args, "pr_attempts", None)
    pr_timeout: int | None = getattr(args, "pr_timeout", None)
    auto_triage: bool = getattr(args, "auto_triage", False)

    # Per-chunk timeout: cap individual chunk runs so one hung chunk can't
    # consume the entire scan budget.  When pr_timeout and pr_attempts are
    # known we allow 2x the expected max wall-clock per attempt; otherwise
    # fall back to the lesser of scan_timeout and 600s (10 min).
    if pr_timeout is not None and pr_attempts is not None:
        per_chunk_timeout = max(60, pr_timeout * pr_attempts * 2)
    else:
        per_chunk_timeout = min(scan_timeout, 600)
    no_fallback: bool = getattr(args, "no_fallback", False)

    ensure_dependencies()
    ensure_repo(repo, git_timeout)
    ensure_baseline_artifacts(repo)

    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir(parents=True, exist_ok=True)

    state_path = resolve_repo_path(repo, args.state_file)
    log_file = resolve_repo_path(repo, args.log_file)
    lock_path = securevibes_dir / ".incremental_scan.lock"
    runs_dir = securevibes_dir / "incremental_runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    with file_lock(lock_path) as locked:
        if not locked:
            append_log(
                log_file, "overlap prevented: another incremental scan is in progress"
            )
            return 0

        _run_ctx.reset()

        # Detect stale/interrupted runs from previous invocations
        _recover_stale_runs(runs_dir, log_file)

        run_id = generate_run_id()
        run_record_path = runs_dir / f"{run_id}.json"
        state = load_state(state_path)
        previous_success_utc = (
            state.get("last_success_utc") if isinstance(state, dict) else None
        )

        run_record: dict[str, Any] = {
            "run_id": run_id,
            "repo": str(repo),
            "branch": args.branch,
            "remote": args.remote,
            "started_utc": utc_timestamp(),
            "status": "failed",
            "old_anchor": (
                state.get("last_seen_sha") if isinstance(state, dict) else None
            ),
            "new_head": None,
            "strategy": None,
            "total_new_commits": 0,
            "chunks": [],
            "failure": None,
        }

        # Wire up global run context for signal handler cleanup
        _run_ctx.run_id = run_id

        print(
            f"[incremental-scan] Run {run_id} started",
            file=sys.stderr,
            flush=True,
        )

        try:
            git_fetch(repo, args.remote, args.branch, args.retry_network, git_timeout)
            new_head = resolve_head(repo, args.remote, args.branch, git_timeout)
            run_record["new_head"] = new_head

            if not state or not isinstance(state.get("last_seen_sha"), str):
                new_state = _build_state(
                    repo=repo,
                    branch=args.branch,
                    remote=args.remote,
                    anchor=new_head,
                    run_id=run_id,
                    status="bootstrap",
                    previous_success_utc=previous_success_utc,
                )
                save_state(state_path, new_state)
                run_record["status"] = "bootstrap"
                run_record["finished_utc"] = utc_timestamp()
                _write_run_record(run_record_path, run_record)
                append_log(
                    log_file, f"run_id={run_id} status=bootstrap anchor={new_head}"
                )
                return 0

            current_anchor = state["last_seen_sha"]
            if current_anchor == new_head:
                new_state = _build_state(
                    repo=repo,
                    branch=args.branch,
                    remote=args.remote,
                    anchor=current_anchor,
                    run_id=run_id,
                    status="no_change",
                    previous_success_utc=previous_success_utc,
                )
                save_state(state_path, new_state)
                run_record["status"] = "no_change"
                run_record["finished_utc"] = utc_timestamp()
                _write_run_record(run_record_path, run_record)
                append_log(
                    log_file,
                    f"run_id={run_id} status=no_change anchor={current_anchor}",
                )
                return 0

            if not is_ancestor(repo, current_anchor, new_head, git_timeout):
                rewrite = handle_rewrite(args.rewrite_policy)
                if rewrite.action == "reset":
                    new_state = _build_state(
                        repo=repo,
                        branch=args.branch,
                        remote=args.remote,
                        anchor=new_head,
                        run_id=run_id,
                        status="rewrite_reset",
                        previous_success_utc=previous_success_utc,
                        failure={
                            "phase": "history_validation",
                            "reason": rewrite.reason,
                        },
                    )
                    save_state(state_path, new_state)
                    run_record["status"] = "rewrite_reset"
                    run_record["failure"] = {
                        "phase": "history_validation",
                        "reason": rewrite.reason,
                    }
                    run_record["finished_utc"] = utc_timestamp()
                    _write_run_record(run_record_path, run_record)
                    append_log(
                        log_file,
                        f"run_id={run_id} status=rewrite_reset old={current_anchor} new={new_head}",
                    )
                    return 0

                if rewrite.action == "strict_fail":
                    failure = {"phase": "history_validation", "reason": rewrite.reason}
                    new_state = _build_state(
                        repo=repo,
                        branch=args.branch,
                        remote=args.remote,
                        anchor=current_anchor,
                        run_id=run_id,
                        status="failed",
                        previous_success_utc=previous_success_utc,
                        failure=failure,
                    )
                    save_state(state_path, new_state)
                    run_record["status"] = "failed"
                    run_record["failure"] = failure
                    run_record["finished_utc"] = utc_timestamp()
                    _write_run_record(run_record_path, run_record)
                    append_log(
                        log_file,
                        f"run_id={run_id} status=failed reason={rewrite.reason}",
                    )
                    return 1

                since_date = rewrite.since_date or pacific_today()
                since_output = runs_dir / f"{run_id}-rewrite-since.json"
                since_result = run_since_date_scan(
                    repo,
                    since_date,
                    args.model,
                    args.severity,
                    args.debug,
                    since_output,
                    scan_timeout,
                    pr_attempts=pr_attempts,
                    pr_timeout=pr_timeout,
                    auto_triage=auto_triage,
                )
                run_record["chunks"].append(
                    {
                        "index": 1,
                        "mode": "since_date",
                        "since_date": since_date,
                        "exit_code": since_result.exit_code,
                        "classification": since_result.classification,
                        "output_path": str(since_output),
                        "stderr_tail": since_result.stderr_tail,
                        "command": since_result.command,
                    }
                )
                if since_result.classification == COMPLETED:
                    failure = {
                        "phase": "history_validation",
                        "reason": (
                            "history rewrite detected; completed since-date scan but "
                            "anchor preserved to avoid skipping commits"
                        ),
                    }
                    new_state = _build_state(
                        repo=repo,
                        branch=args.branch,
                        remote=args.remote,
                        anchor=current_anchor,
                        run_id=run_id,
                        status="partial",
                        previous_success_utc=previous_success_utc,
                        failure=failure,
                    )
                    save_state(state_path, new_state)
                    run_record["status"] = "partial"
                    run_record["strategy"] = "rewrite_since_date"
                    run_record["final_anchor"] = current_anchor
                    run_record["failure"] = failure
                    run_record["finished_utc"] = utc_timestamp()
                    _write_run_record(run_record_path, run_record)
                    append_log(
                        log_file,
                        (
                            f"run_id={run_id} status=partial strategy=rewrite_since_date "
                            f"anchor={current_anchor}"
                        ),
                    )
                    return _strict_exit("partial", args.strict)

                failure = {
                    "phase": "chunk_run",
                    "reason": "rewrite since-date fallback failed",
                    "failed_chunk_index": 1,
                }
                new_state = _build_state(
                    repo=repo,
                    branch=args.branch,
                    remote=args.remote,
                    anchor=current_anchor,
                    run_id=run_id,
                    status="failed",
                    previous_success_utc=previous_success_utc,
                    failure=failure,
                )
                save_state(state_path, new_state)
                run_record["status"] = "failed"
                run_record["failure"] = failure
                run_record["finished_utc"] = utc_timestamp()
                _write_run_record(run_record_path, run_record)
                append_log(
                    log_file,
                    f"run_id={run_id} status=failed reason=rewrite since fallback",
                )
                return _strict_exit("failed", args.strict)

            commits = get_commit_list(repo, current_anchor, new_head, git_timeout)
            run_record["total_new_commits"] = len(commits)
            if not commits:
                new_state = _build_state(
                    repo=repo,
                    branch=args.branch,
                    remote=args.remote,
                    anchor=current_anchor,
                    run_id=run_id,
                    status="no_change",
                    previous_success_utc=previous_success_utc,
                )
                save_state(state_path, new_state)
                run_record["status"] = "no_change"
                run_record["finished_utc"] = utc_timestamp()
                _write_run_record(run_record_path, run_record)
                append_log(
                    log_file,
                    f"run_id={run_id} status=no_change anchor={current_anchor}",
                )
                return 0

            no_adaptive: bool = getattr(args, "no_adaptive", False)
            max_diff_files: int = getattr(args, "max_diff_files", 15)
            max_diff_lines: int = getattr(args, "max_diff_lines", 500)

            if no_adaptive:
                strategy = determine_chunk_strategy(
                    len(commits),
                    args.chunk_small_max,
                    args.chunk_medium_max,
                )
                chunks = compute_chunks_by_count(
                    commits,
                    current_anchor,
                    args.chunk_small_max,
                    args.chunk_medium_max,
                    args.chunk_medium_size,
                )
            else:
                strategy = determine_chunk_strategy(
                    len(commits),
                    args.chunk_small_max,
                    args.chunk_medium_max,
                    adaptive=True,
                )
                chunks = compute_chunks_adaptive(
                    commits,
                    current_anchor,
                    repo,
                    max_files=max_diff_files,
                    max_lines=max_diff_lines,
                    git_timeout=git_timeout,
                )
            run_record["strategy"] = strategy
            run_record["chunk_count"] = len(chunks)
            if not no_adaptive:
                run_record["max_diff_files"] = max_diff_files
                run_record["max_diff_lines"] = max_diff_lines

            last_successful_anchor = current_anchor
            _run_ctx.last_successful_anchor = current_anchor
            failed_chunk_index: int | None = None
            fallback_triggered = False
            failure_reason = ""
            failure_phase = "chunk_run"
            oversized_commit_sha: str | None = None

            print(
                f"[incremental-scan] Processing {len(commits)} commits in {len(chunks)} chunks "
                f"(strategy={strategy})",
                file=sys.stderr,
                flush=True,
            )
            append_log(
                log_file,
                f"run_id={run_id} starting chunks={len(chunks)} commits={len(commits)} "
                f"strategy={strategy}",
            )

            for idx, (base, head) in enumerate(chunks, start=1):
                if _run_ctx.interrupted:
                    failed_chunk_index = idx
                    failure_phase = "interrupted"
                    failure_reason = "process received termination signal"
                    break

                _run_ctx.current_chunk_index = idx
                if no_adaptive:
                    fc, tl = (0, 0)
                else:
                    fc, tl = get_diff_stats(repo, base, head, git_timeout)
                print(
                    f"[incremental-scan] Chunk {idx}/{len(chunks)}: "
                    f"{base[:8]}..{head[:8]} ({fc} files, {tl} lines)",
                    file=sys.stderr,
                    flush=True,
                )
                append_log(
                    log_file,
                    f"run_id={run_id} chunk={idx}/{len(chunks)} "
                    f"range={base[:8]}..{head[:8]} files={fc} lines={tl}",
                )

                chunk_output = runs_dir / f"{run_id}-chunk-{idx}.json"
                result = run_scan(
                    repo,
                    base,
                    head,
                    args.model,
                    args.severity,
                    args.debug,
                    chunk_output,
                    per_chunk_timeout,
                    pr_attempts=pr_attempts,
                    pr_timeout=pr_timeout,
                    auto_triage=auto_triage,
                )
                run_record["chunks"].append(
                    {
                        "index": idx,
                        "base": base,
                        "head": head,
                        "exit_code": result.exit_code,
                        "classification": result.classification,
                        "output_path": str(chunk_output),
                        "stderr_tail": result.stderr_tail,
                        "command": result.command,
                    }
                )
                if result.classification == COMPLETED:
                    last_successful_anchor = head
                    _run_ctx.last_successful_anchor = head
                    continue

                if _run_ctx.interrupted:
                    failed_chunk_index = idx
                    failure_phase = "interrupted"
                    failure_reason = "process received termination signal"
                    break

                if result.classification == DIFF_TOO_LARGE and not no_fallback:
                    sub_commits = get_commit_list(repo, base, head, git_timeout)
                    if len(sub_commits) <= 1:
                        oversized_commit_sha = head
                        failure_reason = (
                            "single commit exceeds safe diff analysis limits"
                        )
                        failed_chunk_index = idx
                        break
                    fallback_triggered = True
                    for sub_idx, sub_sha in enumerate(sub_commits, start=1):
                        sub_base = base if sub_idx == 1 else sub_commits[sub_idx - 2]
                        sub_output = (
                            runs_dir / f"{run_id}-chunk-{idx}-sub-{sub_idx}.json"
                        )
                        sub_result = run_scan(
                            repo,
                            sub_base,
                            sub_sha,
                            args.model,
                            args.severity,
                            args.debug,
                            sub_output,
                            per_chunk_timeout,
                            pr_attempts=pr_attempts,
                            pr_timeout=pr_timeout,
                            auto_triage=auto_triage,
                        )
                        run_record["chunks"].append(
                            {
                                "index": idx,
                                "sub_index": sub_idx,
                                "mode": "fallback_per_commit",
                                "base": sub_base,
                                "head": sub_sha,
                                "exit_code": sub_result.exit_code,
                                "classification": sub_result.classification,
                                "output_path": str(sub_output),
                                "stderr_tail": sub_result.stderr_tail,
                                "command": sub_result.command,
                            }
                        )
                        if sub_result.classification == COMPLETED:
                            last_successful_anchor = sub_sha
                            _run_ctx.last_successful_anchor = sub_sha
                        elif sub_result.classification == DIFF_TOO_LARGE:
                            oversized_commit_sha = sub_sha
                            failure_reason = (
                                "single commit exceeds safe diff analysis limits"
                            )
                            append_log(
                                log_file,
                                f"run_id={run_id} single commit too large, stopping at {sub_sha}",
                            )
                            failed_chunk_index = idx
                            break
                        else:
                            if _run_ctx.interrupted:
                                failure_phase = "interrupted"
                                failure_reason = "process received termination signal"
                            else:
                                failure_reason = "fallback per-commit scan failed"
                            failed_chunk_index = idx
                            break
                    if failed_chunk_index is not None:
                        break
                    continue

                if result.classification == DIFF_TOO_LARGE and no_fallback:
                    failure_reason = "chunk exceeds safe diff analysis limits and fallback is disabled"
                elif not failure_reason:
                    failure_reason = "chunk scan failed"
                failed_chunk_index = idx
                break

            all_completed = failed_chunk_index is None
            if all_completed:
                status = "success"
                anchor = new_head
                failure: dict[str, Any] | None = None
            elif _run_ctx.interrupted:
                if last_successful_anchor != current_anchor:
                    status = "partial"
                    anchor = last_successful_anchor
                else:
                    status = "failed"
                    anchor = current_anchor
                failure = {
                    "phase": "interrupted",
                    "reason": "process received termination signal",
                    "failed_chunk_index": failed_chunk_index,
                    "last_successful_anchor": last_successful_anchor,
                }
            elif last_successful_anchor != current_anchor:
                status = "partial"
                anchor = last_successful_anchor
                failure = {
                    "phase": failure_phase,
                    "reason": failure_reason or "chunk scan failed",
                    "failed_chunk_index": failed_chunk_index,
                }
            else:
                status = "failed"
                anchor = current_anchor
                failure = {
                    "phase": failure_phase,
                    "reason": failure_reason or "first chunk scan failed",
                    "failed_chunk_index": failed_chunk_index,
                }
            if failure is not None and oversized_commit_sha:
                failure["oversized_commit_sha"] = oversized_commit_sha
                failure["oversized_commit_action"] = "stopped_without_skipping"

            new_state = _build_state(
                repo=repo,
                branch=args.branch,
                remote=args.remote,
                anchor=anchor,
                run_id=run_id,
                status=status,
                previous_success_utc=previous_success_utc,
                failure=failure,
            )
            if all_completed:
                new_state["last_success_utc"] = utc_timestamp()
            save_state(state_path, new_state)

            run_record["status"] = status
            run_record["final_anchor"] = anchor
            run_record["failure"] = failure
            if fallback_triggered:
                run_record["fallback_triggered"] = True
            run_record["finished_utc"] = utc_timestamp()
            _write_run_record(run_record_path, run_record)
            append_log(
                log_file,
                (
                    f"run_id={run_id} status={status} commits={len(commits)} strategy={strategy} "
                    f"chunks={len(chunks)} failed_chunk={failed_chunk_index or 0} "
                    f"anchor={anchor}"
                ),
            )
            if _run_ctx.interrupted:
                return 128 + int(_run_ctx.interrupted_signal or signal.SIGINT)
            return _strict_exit(status, args.strict)

        except Exception as exc:
            failure = {"phase": "orchestration", "reason": str(exc)}
            fallback_anchor = (
                state.get("last_seen_sha")
                if isinstance(state, dict)
                else run_record.get("new_head")
            )
            if isinstance(fallback_anchor, str):
                error_state = _build_state(
                    repo=repo,
                    branch=args.branch,
                    remote=args.remote,
                    anchor=fallback_anchor,
                    run_id=run_id,
                    status="failed",
                    previous_success_utc=previous_success_utc,
                    failure=failure,
                )
                save_state(state_path, error_state)
            run_record["status"] = "failed"
            run_record["failure"] = failure
            run_record["finished_utc"] = utc_timestamp()
            _write_run_record(run_record_path, run_record)
            append_log(log_file, f"run_id={run_id} status=failed reason={exc}")
            raise
        finally:
            _run_ctx.reset()


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    # Install signal handlers for graceful cleanup
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    args = parse_args(argv)
    try:
        return run(args)
    except Exception as exc:  # pragma: no cover - wrapper for user-facing CLI failures
        print(f"[incremental-scan] ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
