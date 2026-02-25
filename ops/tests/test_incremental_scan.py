"""Tests for ops.incremental_scan wrapper."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ops import incremental_scan as inc


def build_args(repo_dir: Path, **overrides: Any) -> argparse.Namespace:
    """Build argument namespace with wrapper defaults."""
    payload: dict[str, Any] = {
        "repo": str(repo_dir),
        "branch": "main",
        "remote": "origin",
        "model": "sonnet",
        "severity": "medium",
        "state_file": ".securevibes/incremental_state.json",
        "log_file": ".securevibes/incremental_scan.log",
        "chunk_small_max": 8,
        "chunk_medium_max": 25,
        "chunk_medium_size": 5,
        "retry_network": 1,
        "rewrite_policy": "reset_warn",
        "git_timeout_seconds": 60,
        "scan_timeout_seconds": 900,
        "strict": False,
        "debug": False,
    }
    payload.update(overrides)
    return argparse.Namespace(**payload)


def _noop(*_args: Any, **_kwargs: Any) -> None:
    """Utility no-op function for monkeypatching."""


def _valid_result(
    command: list[str], output_path: Path, exit_code: int = 0
) -> inc.ScanCommandResult:
    """Create a command result classified as completed."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            {
                "repository_path": "/tmp/repo",
                "files_scanned": 1,
                "scan_time_seconds": 1,
                "issues": [],
            }
        ),
        encoding="utf-8",
    )
    return inc.ScanCommandResult(
        command=command,
        exit_code=exit_code,
        classification=inc.COMPLETED,
        stderr_tail="",
        output_path=output_path,
    )


def test_load_state_returns_none_when_missing(state_path: Path) -> None:
    assert inc.load_state(state_path) is None


def test_load_state_returns_dict(
    state_path: Path, sample_state: dict[str, object]
) -> None:
    state_path.write_text(json.dumps(sample_state), encoding="utf-8")
    loaded = inc.load_state(state_path)
    assert loaded == sample_state


def test_load_state_corrupt_json_returns_none(state_path: Path) -> None:
    state_path.write_text("{bad-json", encoding="utf-8")
    assert inc.load_state(state_path) is None


def test_save_state_creates_file(
    state_path: Path, sample_state: dict[str, object]
) -> None:
    inc.save_state(state_path, sample_state)
    loaded = json.loads(state_path.read_text(encoding="utf-8"))
    assert loaded["last_seen_sha"] == "abc123"


def test_generate_run_id_format() -> None:
    run_id = inc.generate_run_id()
    assert re.match(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$", run_id)


def test_positive_int_validation() -> None:
    assert inc.positive_int("7") == 7
    with pytest.raises(argparse.ArgumentTypeError):
        inc.positive_int("0")


def test_parse_args_defaults_include_timeouts() -> None:
    args = inc.parse_args([])
    assert args.git_timeout_seconds == inc.DEFAULT_GIT_TIMEOUT_SECONDS
    assert args.scan_timeout_seconds == inc.DEFAULT_SCAN_TIMEOUT_SECONDS


def test_compute_chunks_small_window() -> None:
    commits = ["c1", "c2", "c3"]
    chunks = inc.compute_chunks(commits, "base", 8, 25, 5)
    assert chunks == [("base", "c3")]


def test_compute_chunks_medium_window() -> None:
    commits = [f"c{i}" for i in range(1, 13)]
    chunks = inc.compute_chunks(commits, "base", 8, 25, 5)
    assert chunks == [("base", "c5"), ("c5", "c10"), ("c10", "c12")]


def test_compute_chunks_large_window(fake_commits: list[str]) -> None:
    commits = fake_commits[:30]
    chunks = inc.compute_chunks(commits, "base", 8, 25, 5)
    assert len(chunks) == 30
    assert chunks[0] == ("base", "sha01")
    assert chunks[1] == ("sha01", "sha02")
    assert chunks[-1] == ("sha29", "sha30")


def test_compute_chunks_exact_boundaries() -> None:
    c8 = [f"c{i}" for i in range(1, 9)]
    c9 = [f"c{i}" for i in range(1, 10)]
    c25 = [f"c{i}" for i in range(1, 26)]
    c26 = [f"c{i}" for i in range(1, 27)]

    assert len(inc.compute_chunks(c8, "base", 8, 25, 5)) == 1
    assert len(inc.compute_chunks(c9, "base", 8, 25, 5)) == 2
    assert len(inc.compute_chunks(c25, "base", 8, 25, 5)) == 5
    assert len(inc.compute_chunks(c26, "base", 8, 25, 5)) == 26


def test_compute_chunks_custom_thresholds() -> None:
    commits = [f"c{i}" for i in range(1, 11)]
    chunks = inc.compute_chunks(commits, "base", 3, 10, 4)
    assert chunks == [("base", "c4"), ("c4", "c8"), ("c8", "c10")]


def test_classify_scan_completed(
    report_path: Path, valid_report_payload: dict[str, object]
) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(valid_report_payload), encoding="utf-8")
    assert inc.classify_scan_result(1, report_path) == inc.COMPLETED


@pytest.fixture
def report_path(tmp_path: Path) -> Path:
    return tmp_path / "report.json"


def test_classify_scan_exit_1_no_output_is_infra_failure(report_path: Path) -> None:
    assert inc.classify_scan_result(1, report_path) == inc.INFRA_FAILURE


def test_classify_scan_exit_1_invalid_json_is_infra_failure(report_path: Path) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("not-json", encoding="utf-8")
    assert inc.classify_scan_result(1, report_path) == inc.INFRA_FAILURE


def test_classify_scan_high_exit_code(
    report_path: Path, valid_report_payload: dict[str, object]
) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(valid_report_payload), encoding="utf-8")
    assert inc.classify_scan_result(127, report_path) == inc.INFRA_FAILURE


def test_run_scan_builds_correct_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(command: list[str], **_kwargs: Any) -> SimpleNamespace:
        seen["command"] = command
        output_idx = command.index("--output") + 1
        output_path = Path(command[output_idx])
        output_path.write_text(
            json.dumps(
                {
                    "repository_path": "/tmp/repo",
                    "files_scanned": 1,
                    "scan_time_seconds": 1,
                    "issues": [],
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(inc.subprocess, "run", fake_run)
    out = tmp_path / "result.json"
    result = inc.run_scan(Path("/repo"), "base", "head", "sonnet", "high", False, out)

    assert result.classification == inc.COMPLETED
    assert seen["command"][:3] == ["securevibes", "pr-review", "/repo"]
    assert "--range" in seen["command"]
    assert "base..head" in seen["command"]
    assert "--severity" in seen["command"]
    assert "high" in seen["command"]


def test_run_scan_includes_debug_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(command: list[str], **_kwargs: Any) -> SimpleNamespace:
        seen["command"] = command
        output_path = Path(command[command.index("--output") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "repository_path": "/tmp/repo",
                    "files_scanned": 1,
                    "scan_time_seconds": 1,
                    "issues": [],
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(inc.subprocess, "run", fake_run)
    out = tmp_path / "debug.json"
    inc.run_scan(Path("/repo"), "base", "head", "sonnet", "medium", True, out)
    assert "--debug" in seen["command"]


def test_run_scan_timeout_returns_infra_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        raise subprocess.TimeoutExpired(cmd=["securevibes"], timeout=3)

    monkeypatch.setattr(inc.subprocess, "run", fake_run)
    out = tmp_path / "timeout.json"
    result = inc.run_scan(
        Path("/repo"),
        "base",
        "head",
        "sonnet",
        "medium",
        False,
        out,
        timeout_seconds=3,
    )
    assert result.classification == inc.INFRA_FAILURE
    assert result.exit_code == 124
    assert "timed out" in result.stderr_tail


def test_run_since_date_scan_timeout_returns_infra_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        raise subprocess.TimeoutExpired(cmd=["securevibes"], timeout=4)

    monkeypatch.setattr(inc.subprocess, "run", fake_run)
    out = tmp_path / "since-timeout.json"
    result = inc.run_since_date_scan(
        Path("/repo"),
        "2026-01-01",
        "sonnet",
        "medium",
        False,
        out,
        timeout_seconds=4,
    )
    assert result.classification == inc.INFRA_FAILURE
    assert result.exit_code == 124
    assert "timed out" in result.stderr_tail


def test_git_fetch_retries_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def fake_run(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        calls["n"] += 1
        if calls["n"] == 1:
            return SimpleNamespace(returncode=1, stderr="temporary fetch error")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(inc.subprocess, "run", fake_run)
    monkeypatch.setattr(inc.time, "sleep", _noop)

    inc.git_fetch(Path("/repo"), "origin", "main", retries=1, timeout_seconds=3)
    assert calls["n"] == 2


def test_git_fetch_timeout_raises_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        raise subprocess.TimeoutExpired(cmd=["git", "fetch"], timeout=2)

    monkeypatch.setattr(inc.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="timed out"):
        inc.git_fetch(Path("/repo"), "origin", "main", retries=0, timeout_seconds=2)


def test_resolve_head_timeout_raises_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        raise subprocess.TimeoutExpired(cmd=["git", "rev-parse"], timeout=2)

    monkeypatch.setattr(inc.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="timed out"):
        inc.resolve_head(Path("/repo"), "origin", "main", timeout_seconds=2)


def test_is_ancestor_timeout_raises_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        raise subprocess.TimeoutExpired(cmd=["git", "merge-base"], timeout=2)

    monkeypatch.setattr(inc.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="timed out"):
        inc.is_ancestor(Path("/repo"), "a", "b", timeout_seconds=2)


def test_get_commit_list_timeout_raises_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        raise subprocess.TimeoutExpired(cmd=["git", "rev-list"], timeout=2)

    monkeypatch.setattr(inc.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="timed out"):
        inc.get_commit_list(Path("/repo"), "a", "b", timeout_seconds=2)


def test_determine_chunk_strategy_variants() -> None:
    assert inc.determine_chunk_strategy(2, 8, 25) == "single_range"
    assert inc.determine_chunk_strategy(10, 8, 25) == "chunked"
    assert inc.determine_chunk_strategy(30, 8, 25) == "per_commit"


def test_strict_exit_behavior() -> None:
    assert inc._strict_exit("partial", strict=True) == 1
    assert inc._strict_exit("failed", strict=True) == 1
    assert inc._strict_exit("success", strict=True) == 0


def test_handle_rewrite_reset_warn() -> None:
    outcome = inc.handle_rewrite("reset_warn")
    assert outcome.action == "reset"
    assert "not ancestor" in outcome.reason


def test_handle_rewrite_strict_fail() -> None:
    outcome = inc.handle_rewrite("strict_fail")
    assert outcome.action == "strict_fail"


def test_bootstrap_initializes_state_no_scan(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
    state_path: Path,
) -> None:
    args = build_args(repo_dir)
    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)
    monkeypatch.setattr(inc, "git_fetch", _noop)
    monkeypatch.setattr(inc, "resolve_head", lambda *_args: "head123")
    monkeypatch.setattr(inc, "generate_run_id", lambda: "RUN123")

    def should_not_run_scan(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("run_scan should not be called during bootstrap")

    monkeypatch.setattr(inc, "run_scan", should_not_run_scan)

    exit_code = inc.run(args)
    assert exit_code == 0
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["last_status"] == "bootstrap"
    assert state["last_seen_sha"] == "head123"


def test_no_new_commits_exits_clean(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
    state_path: Path,
    write_state,
    sample_state: dict[str, object],
) -> None:
    args = build_args(repo_dir)
    write_state(sample_state)
    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)
    monkeypatch.setattr(inc, "git_fetch", _noop)
    monkeypatch.setattr(inc, "resolve_head", lambda *_args: "abc123")
    monkeypatch.setattr(inc, "generate_run_id", lambda: "RUN124")

    exit_code = inc.run(args)
    assert exit_code == 0
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["last_status"] == "no_change"


def test_small_window_single_scan(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
    state_path: Path,
    write_state,
    sample_state: dict[str, object],
) -> None:
    args = build_args(repo_dir)
    write_state(sample_state)
    calls: list[tuple[str, str]] = []

    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)
    monkeypatch.setattr(inc, "git_fetch", _noop)
    monkeypatch.setattr(inc, "resolve_head", lambda *_args: "newhead")
    monkeypatch.setattr(inc, "is_ancestor", lambda *_args: True)
    monkeypatch.setattr(
        inc, "get_commit_list", lambda *_args: ["c1", "c2", "c3", "c4", "c5"]
    )
    monkeypatch.setattr(inc, "generate_run_id", lambda: "RUN125")

    def fake_run_scan(
        repo: Path,
        base: str,
        head: str,
        model: str,
        severity: str,
        debug: bool,
        output_path: Path,
        timeout_seconds: int,
        **_kwargs: Any,
    ) -> inc.ScanCommandResult:
        calls.append((base, head))
        return _valid_result(["securevibes"], output_path)

    monkeypatch.setattr(inc, "run_scan", fake_run_scan)

    exit_code = inc.run(args)
    assert exit_code == 0
    assert calls == [("abc123", "c5")]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["last_seen_sha"] == "newhead"
    assert state["last_status"] == "success"


def test_medium_window_chunked_scans(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
    state_path: Path,
    write_state,
    sample_state: dict[str, object],
) -> None:
    args = build_args(repo_dir)
    write_state(sample_state)
    calls: list[tuple[str, str]] = []
    commits = [f"c{i}" for i in range(1, 13)]

    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)
    monkeypatch.setattr(inc, "git_fetch", _noop)
    monkeypatch.setattr(inc, "resolve_head", lambda *_args: "newhead")
    monkeypatch.setattr(inc, "is_ancestor", lambda *_args: True)
    monkeypatch.setattr(inc, "get_commit_list", lambda *_args: commits)
    monkeypatch.setattr(inc, "generate_run_id", lambda: "RUN126")

    def fake_run_scan(
        repo: Path,
        base: str,
        head: str,
        model: str,
        severity: str,
        debug: bool,
        output_path: Path,
        timeout_seconds: int,
        **_kwargs: Any,
    ) -> inc.ScanCommandResult:
        calls.append((base, head))
        return _valid_result(["securevibes"], output_path)

    monkeypatch.setattr(inc, "run_scan", fake_run_scan)

    exit_code = inc.run(args)
    assert exit_code == 0
    assert calls == [("abc123", "c5"), ("c5", "c10"), ("c10", "c12")]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["last_status"] == "success"


def test_large_window_per_commit_scans(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
    state_path: Path,
    write_state,
    sample_state: dict[str, object],
) -> None:
    args = build_args(repo_dir)
    write_state(sample_state)
    calls: list[tuple[str, str]] = []
    commits = [f"c{i}" for i in range(1, 31)]

    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)
    monkeypatch.setattr(inc, "git_fetch", _noop)
    monkeypatch.setattr(inc, "resolve_head", lambda *_args: "newhead")
    monkeypatch.setattr(inc, "is_ancestor", lambda *_args: True)
    monkeypatch.setattr(inc, "get_commit_list", lambda *_args: commits)
    monkeypatch.setattr(inc, "generate_run_id", lambda: "RUN127")

    def fake_run_scan(
        repo: Path,
        base: str,
        head: str,
        model: str,
        severity: str,
        debug: bool,
        output_path: Path,
        timeout_seconds: int,
        **_kwargs: Any,
    ) -> inc.ScanCommandResult:
        calls.append((base, head))
        return _valid_result(["securevibes"], output_path)

    monkeypatch.setattr(inc, "run_scan", fake_run_scan)

    exit_code = inc.run(args)
    assert exit_code == 0
    assert len(calls) == 30
    assert calls[0] == ("abc123", "c1")
    assert calls[-1] == ("c29", "c30")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["last_seen_sha"] == "newhead"


def test_partial_failure_anchors_at_last_success(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
    state_path: Path,
    write_state,
    sample_state: dict[str, object],
) -> None:
    args = build_args(repo_dir, strict=True)
    write_state(sample_state)
    commits = [f"c{i}" for i in range(1, 13)]
    call_count = {"n": 0}

    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)
    monkeypatch.setattr(inc, "git_fetch", _noop)
    monkeypatch.setattr(inc, "resolve_head", lambda *_args: "newhead")
    monkeypatch.setattr(inc, "is_ancestor", lambda *_args: True)
    monkeypatch.setattr(inc, "get_commit_list", lambda *_args: commits)
    monkeypatch.setattr(inc, "generate_run_id", lambda: "RUN128")

    def fake_run_scan(
        repo: Path,
        base: str,
        head: str,
        model: str,
        severity: str,
        debug: bool,
        output_path: Path,
        timeout_seconds: int,
        **_kwargs: Any,
    ) -> inc.ScanCommandResult:
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _valid_result(["securevibes"], output_path)
        return inc.ScanCommandResult(
            command=["securevibes"],
            exit_code=1,
            classification=inc.INFRA_FAILURE,
            stderr_tail="failed",
            output_path=output_path,
        )

    monkeypatch.setattr(inc, "run_scan", fake_run_scan)

    exit_code = inc.run(args)
    assert exit_code == 1
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["last_status"] == "partial"
    assert state["last_seen_sha"] == "c5"


def test_force_push_resets_anchor_default_policy(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
    state_path: Path,
    write_state,
    sample_state: dict[str, object],
) -> None:
    args = build_args(repo_dir, rewrite_policy="reset_warn")
    write_state(sample_state)

    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)
    monkeypatch.setattr(inc, "git_fetch", _noop)
    monkeypatch.setattr(inc, "resolve_head", lambda *_args: "newhead")
    monkeypatch.setattr(inc, "is_ancestor", lambda *_args: False)
    monkeypatch.setattr(inc, "generate_run_id", lambda: "RUN129")

    exit_code = inc.run(args)
    assert exit_code == 0
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["last_status"] == "rewrite_reset"
    assert state["last_seen_sha"] == "newhead"


def test_strict_fail_on_force_push(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
    state_path: Path,
    write_state,
    sample_state: dict[str, object],
) -> None:
    args = build_args(repo_dir, rewrite_policy="strict_fail")
    write_state(sample_state)

    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)
    monkeypatch.setattr(inc, "git_fetch", _noop)
    monkeypatch.setattr(inc, "resolve_head", lambda *_args: "newhead")
    monkeypatch.setattr(inc, "is_ancestor", lambda *_args: False)
    monkeypatch.setattr(inc, "generate_run_id", lambda: "RUN130")

    exit_code = inc.run(args)
    assert exit_code == 1
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["last_status"] == "failed"
    assert state["last_seen_sha"] == "abc123"


def test_since_date_policy_success(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
    state_path: Path,
    write_state,
    sample_state: dict[str, object],
) -> None:
    args = build_args(repo_dir, rewrite_policy="since_date")
    write_state(sample_state)

    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)
    monkeypatch.setattr(inc, "git_fetch", _noop)
    monkeypatch.setattr(inc, "resolve_head", lambda *_args: "newhead")
    monkeypatch.setattr(inc, "is_ancestor", lambda *_args: False)
    monkeypatch.setattr(inc, "generate_run_id", lambda: "RUN131")

    def fake_run_since(
        repo: Path,
        since_date: str,
        model: str,
        severity: str,
        debug: bool,
        output_path: Path,
        timeout_seconds: int,
        **_kwargs: Any,
    ) -> inc.ScanCommandResult:
        return _valid_result(["securevibes"], output_path)

    monkeypatch.setattr(inc, "run_since_date_scan", fake_run_since)

    exit_code = inc.run(args)
    assert exit_code == 0
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["last_status"] == "partial"
    assert state["last_seen_sha"] == "abc123"


def test_since_date_policy_strict_returns_nonzero(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
    state_path: Path,
    write_state,
    sample_state: dict[str, object],
) -> None:
    args = build_args(repo_dir, rewrite_policy="since_date", strict=True)
    write_state(sample_state)

    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)
    monkeypatch.setattr(inc, "git_fetch", _noop)
    monkeypatch.setattr(inc, "resolve_head", lambda *_args: "newhead")
    monkeypatch.setattr(inc, "is_ancestor", lambda *_args: False)
    monkeypatch.setattr(inc, "generate_run_id", lambda: "RUN131B")

    def fake_run_since(
        repo: Path,
        since_date: str,
        model: str,
        severity: str,
        debug: bool,
        output_path: Path,
        timeout_seconds: int,
        **_kwargs: Any,
    ) -> inc.ScanCommandResult:
        return _valid_result(["securevibes"], output_path)

    monkeypatch.setattr(inc, "run_since_date_scan", fake_run_since)

    exit_code = inc.run(args)
    assert exit_code == 1
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["last_status"] == "partial"
    assert state["last_seen_sha"] == "abc123"


def test_concurrent_run_exits_cleanly(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
) -> None:
    args = build_args(repo_dir)
    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)

    @contextmanager
    def fake_lock(_path: Path):
        yield False

    monkeypatch.setattr(inc, "file_lock", fake_lock)

    def should_not_fetch(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("git_fetch should not run when lock acquisition fails")

    monkeypatch.setattr(inc, "git_fetch", should_not_fetch)

    exit_code = inc.run(args)
    assert exit_code == 0


def test_findings_exit_codes_advance_anchor(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
    state_path: Path,
    write_state,
    sample_state: dict[str, object],
) -> None:
    args = build_args(repo_dir)
    write_state(sample_state)

    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)
    monkeypatch.setattr(inc, "git_fetch", _noop)
    monkeypatch.setattr(inc, "resolve_head", lambda *_args: "newhead")
    monkeypatch.setattr(inc, "is_ancestor", lambda *_args: True)
    monkeypatch.setattr(inc, "get_commit_list", lambda *_args: ["c1"])
    monkeypatch.setattr(inc, "generate_run_id", lambda: "RUN132")

    def fake_run_scan(
        repo: Path,
        base: str,
        head: str,
        model: str,
        severity: str,
        debug: bool,
        output_path: Path,
        timeout_seconds: int,
        **_kwargs: Any,
    ) -> inc.ScanCommandResult:
        return _valid_result(["securevibes"], output_path, exit_code=1)

    monkeypatch.setattr(inc, "run_scan", fake_run_scan)

    exit_code = inc.run(args)
    assert exit_code == 0
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["last_status"] == "success"
    assert state["last_seen_sha"] == "newhead"


def test_exit_1_without_output_halts_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
    state_path: Path,
    write_state,
    sample_state: dict[str, object],
) -> None:
    args = build_args(repo_dir, strict=True)
    write_state(sample_state)

    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)
    monkeypatch.setattr(inc, "git_fetch", _noop)
    monkeypatch.setattr(inc, "resolve_head", lambda *_args: "newhead")
    monkeypatch.setattr(inc, "is_ancestor", lambda *_args: True)
    monkeypatch.setattr(inc, "get_commit_list", lambda *_args: ["c1", "c2"])
    monkeypatch.setattr(inc, "generate_run_id", lambda: "RUN133")

    def fake_run_scan(
        repo: Path,
        base: str,
        head: str,
        model: str,
        severity: str,
        debug: bool,
        output_path: Path,
        timeout_seconds: int,
        **_kwargs: Any,
    ) -> inc.ScanCommandResult:
        return inc.ScanCommandResult(
            command=["securevibes"],
            exit_code=1,
            classification=inc.INFRA_FAILURE,
            stderr_tail="missing output",
            output_path=output_path,
        )

    monkeypatch.setattr(inc, "run_scan", fake_run_scan)

    exit_code = inc.run(args)
    assert exit_code == 1
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["last_status"] == "failed"
    assert state["last_seen_sha"] == "abc123"


def test_run_record_written_with_chunk_results(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
    write_state,
    sample_state: dict[str, object],
) -> None:
    args = build_args(repo_dir)
    write_state(sample_state)

    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)
    monkeypatch.setattr(inc, "git_fetch", _noop)
    monkeypatch.setattr(inc, "resolve_head", lambda *_args: "newhead")
    monkeypatch.setattr(inc, "is_ancestor", lambda *_args: True)
    monkeypatch.setattr(inc, "get_commit_list", lambda *_args: ["c1", "c2", "c3"])
    monkeypatch.setattr(inc, "generate_run_id", lambda: "RUN134")

    def fake_run_scan(
        repo: Path,
        base: str,
        head: str,
        model: str,
        severity: str,
        debug: bool,
        output_path: Path,
        timeout_seconds: int,
        **_kwargs: Any,
    ) -> inc.ScanCommandResult:
        return _valid_result(["securevibes", "pr-review"], output_path)

    monkeypatch.setattr(inc, "run_scan", fake_run_scan)

    exit_code = inc.run(args)
    assert exit_code == 0
    run_record = repo_dir / ".securevibes" / "incremental_runs" / "RUN134.json"
    payload = json.loads(run_record.read_text(encoding="utf-8"))
    assert payload["status"] == "success"
    assert len(payload["chunks"]) == 1


def test_corrupt_state_triggers_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
    state_path: Path,
) -> None:
    args = build_args(repo_dir)
    state_path.write_text("{broken-json", encoding="utf-8")

    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)
    monkeypatch.setattr(inc, "git_fetch", _noop)
    monkeypatch.setattr(inc, "resolve_head", lambda *_args: "head456")
    monkeypatch.setattr(inc, "generate_run_id", lambda: "RUN135")

    exit_code = inc.run(args)
    assert exit_code == 0
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["last_status"] == "bootstrap"
    assert state["last_seen_sha"] == "head456"


def test_main_returns_error_code_on_exception(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(inc, "parse_args", lambda _argv=None: argparse.Namespace())

    def _boom(_args: argparse.Namespace) -> int:
        raise RuntimeError("boom")

    monkeypatch.setattr(inc, "run", _boom)
    assert inc.main([]) == 1
    assert "ERROR: boom" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Auto-triage integration tests
# ---------------------------------------------------------------------------


def test_parse_args_auto_triage_flag() -> None:
    """--auto-triage should set args.auto_triage to True."""
    args = inc.parse_args(["--auto-triage"])
    assert args.auto_triage is True


def test_parse_args_auto_triage_default_false() -> None:
    """auto_triage should default to False."""
    args = inc.parse_args([])
    assert args.auto_triage is False


def test_run_scan_appends_auto_triage_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """run_scan with auto_triage=True should append --auto-triage to the command."""
    seen: dict[str, Any] = {}

    def fake_run(command: list[str], **_kwargs: Any) -> SimpleNamespace:
        seen["command"] = command
        output_idx = command.index("--output") + 1
        output_path = Path(command[output_idx])
        output_path.write_text(
            json.dumps(
                {
                    "repository_path": "/tmp/repo",
                    "files_scanned": 1,
                    "scan_time_seconds": 1,
                    "issues": [],
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(inc.subprocess, "run", fake_run)
    out = tmp_path / "triage-scan.json"
    inc.run_scan(
        Path("/repo"), "base", "head", "sonnet", "medium", False, out,
        auto_triage=True,
    )
    assert "--auto-triage" in seen["command"]


def test_run_since_date_scan_appends_auto_triage_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """run_since_date_scan with auto_triage=True should append --auto-triage."""
    seen: dict[str, Any] = {}

    def fake_run(command: list[str], **_kwargs: Any) -> SimpleNamespace:
        seen["command"] = command
        output_idx = command.index("--output") + 1
        output_path = Path(command[output_idx])
        output_path.write_text(
            json.dumps(
                {
                    "repository_path": "/tmp/repo",
                    "files_scanned": 1,
                    "scan_time_seconds": 1,
                    "issues": [],
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(inc.subprocess, "run", fake_run)
    out = tmp_path / "triage-since.json"
    inc.run_since_date_scan(
        Path("/repo"), "2026-01-01", "sonnet", "medium", False, out,
        auto_triage=True,
    )
    assert "--auto-triage" in seen["command"]


def test_run_threads_auto_triage_to_run_scan(
    monkeypatch: pytest.MonkeyPatch,
    repo_dir: Path,
    state_path: Path,
    write_state,
    sample_state: dict[str, object],
) -> None:
    """run() should pass auto_triage through to run_scan."""
    args = build_args(repo_dir, auto_triage=True)
    write_state(sample_state)
    scan_kwargs: dict[str, Any] = {}

    monkeypatch.setattr(inc, "ensure_dependencies", _noop)
    monkeypatch.setattr(inc, "ensure_repo", _noop)
    monkeypatch.setattr(inc, "ensure_baseline_artifacts", _noop)
    monkeypatch.setattr(inc, "git_fetch", _noop)
    monkeypatch.setattr(inc, "resolve_head", lambda *_args: "newhead")
    monkeypatch.setattr(inc, "is_ancestor", lambda *_args: True)
    monkeypatch.setattr(inc, "get_commit_list", lambda *_args: ["c1"])
    monkeypatch.setattr(inc, "generate_run_id", lambda: "RUN_TRIAGE")

    def fake_run_scan(
        repo: Path,
        base: str,
        head: str,
        model: str,
        severity: str,
        debug: bool,
        output_path: Path,
        timeout_seconds: int,
        **kwargs: Any,
    ) -> inc.ScanCommandResult:
        scan_kwargs.update(kwargs)
        return _valid_result(["securevibes"], output_path)

    monkeypatch.setattr(inc, "run_scan", fake_run_scan)

    exit_code = inc.run(args)
    assert exit_code == 0
    assert scan_kwargs.get("auto_triage") is True
