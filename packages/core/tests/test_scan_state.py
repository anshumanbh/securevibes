"""Tests for scan state tracking helpers."""

from pathlib import Path

from securevibes.scanner.state import (
    build_full_scan_entry,
    build_pr_review_entry,
    get_repo_branch,
    get_repo_head_commit,
    get_last_full_scan_commit,
    load_scan_state,
    scan_state_branch_matches,
    update_scan_state,
)


def test_load_scan_state_missing_returns_none(tmp_path: Path):
    state_path = tmp_path / "scan_state.json"

    assert load_scan_state(state_path) is None


def test_update_scan_state_writes_full_scan(tmp_path: Path):
    state_path = tmp_path / "scan_state.json"
    full_scan = build_full_scan_entry(
        commit="abc123",
        branch="main",
        timestamp="2026-02-02T10:00:00Z",
    )

    state = update_scan_state(state_path, full_scan=full_scan)

    assert state_path.exists()
    assert state["last_full_scan"]["commit"] == "abc123"
    assert state["last_full_scan"]["branch"] == "main"


def test_update_scan_state_merges_pr_review(tmp_path: Path):
    state_path = tmp_path / "scan_state.json"
    full_scan = build_full_scan_entry(
        commit="abc123",
        branch="main",
        timestamp="2026-02-02T10:00:00Z",
    )
    update_scan_state(state_path, full_scan=full_scan)

    pr_review = build_pr_review_entry(
        commit="def456",
        commits_reviewed=["def456", "ghi789"],
        timestamp="2026-02-02T15:00:00Z",
    )
    state = update_scan_state(state_path, pr_review=pr_review)

    assert state["last_full_scan"]["commit"] == "abc123"
    assert state["last_pr_review"]["commit"] == "def456"
    assert state["last_pr_review"]["commits_reviewed"] == ["def456", "ghi789"]


def test_scan_state_branch_matches(tmp_path: Path):
    state_path = tmp_path / "scan_state.json"
    full_scan = build_full_scan_entry(
        commit="abc123",
        branch="main",
        timestamp="2026-02-02T10:00:00Z",
    )
    state = update_scan_state(state_path, full_scan=full_scan)

    assert scan_state_branch_matches(state, "main") is True
    assert scan_state_branch_matches(state, "dev") is False


def test_get_last_full_scan_commit(tmp_path: Path):
    state_path = tmp_path / "scan_state.json"
    full_scan = build_full_scan_entry(
        commit="abc123",
        branch="main",
        timestamp="2026-02-02T10:00:00Z",
    )
    state = update_scan_state(state_path, full_scan=full_scan)

    assert get_last_full_scan_commit(state) == "abc123"


def test_get_repo_head_commit_parses_output(monkeypatch):
    """get_repo_head_commit should parse git rev-parse output."""

    class DummyResult:
        returncode = 0
        stdout = "abc123\n"
        stderr = ""

    def fake_run(*_args, **_kwargs):
        return DummyResult()

    monkeypatch.setattr("securevibes.scanner.state.subprocess.run", fake_run)

    assert get_repo_head_commit(Path(".")) == "abc123"


def test_get_repo_branch_parses_output(monkeypatch):
    """get_repo_branch should parse git branch output."""

    class DummyResult:
        returncode = 0
        stdout = "main\n"
        stderr = ""

    def fake_run(*_args, **_kwargs):
        return DummyResult()

    monkeypatch.setattr("securevibes.scanner.state.subprocess.run", fake_run)

    assert get_repo_branch(Path(".")) == "main"
