"""Tests for scan state tracking helpers."""

import json
from datetime import datetime, timezone
from pathlib import Path

from securevibes.scanner.state import (
    build_full_scan_entry,
    build_pr_review_entry,
    get_repo_branch,
    get_repo_head_commit,
    get_last_full_scan_commit,
    load_scan_state,
    scan_state_branch_matches,
    utc_timestamp,
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
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["last_full_scan"]["commit"] == "abc123"


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


def test_load_scan_state_invalid_json_returns_none(tmp_path: Path):
    state_path = tmp_path / "scan_state.json"
    state_path.write_text("{not-valid-json", encoding="utf-8")

    assert load_scan_state(state_path) is None


def test_load_scan_state_non_dict_returns_none(tmp_path: Path):
    state_path = tmp_path / "scan_state.json"
    state_path.write_text('["not", "a", "dict"]', encoding="utf-8")

    assert load_scan_state(state_path) is None


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


def test_get_repo_head_commit_nonzero_returns_none(monkeypatch):
    class DummyResult:
        returncode = 1
        stdout = ""
        stderr = "fatal: not a git repository"

    def fake_run(*_args, **_kwargs):
        return DummyResult()

    monkeypatch.setattr("securevibes.scanner.state.subprocess.run", fake_run)

    assert get_repo_head_commit(Path(".")) is None


def test_get_repo_head_commit_oserror_returns_none(monkeypatch):
    def fake_run(*_args, **_kwargs):
        raise OSError("git missing")

    monkeypatch.setattr("securevibes.scanner.state.subprocess.run", fake_run)

    assert get_repo_head_commit(Path(".")) is None


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


def test_get_repo_branch_nonzero_returns_none(monkeypatch):
    class DummyResult:
        returncode = 1
        stdout = ""
        stderr = "fatal: ambiguous argument"

    def fake_run(*_args, **_kwargs):
        return DummyResult()

    monkeypatch.setattr("securevibes.scanner.state.subprocess.run", fake_run)

    assert get_repo_branch(Path(".")) is None


def test_get_repo_branch_oserror_returns_none(monkeypatch):
    def fake_run(*_args, **_kwargs):
        raise OSError("git missing")

    monkeypatch.setattr("securevibes.scanner.state.subprocess.run", fake_run)

    assert get_repo_branch(Path(".")) is None


def test_utc_timestamp_is_utc_zulu():
    timestamp = utc_timestamp()

    assert timestamp.endswith("Z")
    parsed = timestamp.replace("Z", "+00:00")
    dt = datetime.fromisoformat(parsed)
    assert dt.tzinfo == timezone.utc
