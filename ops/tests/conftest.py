"""Shared fixtures for incremental wrapper tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def repo_dir(tmp_path: Path) -> Path:
    """Create a temporary repository-like directory with baseline artifacts."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()
    (securevibes_dir / "SECURITY.md").write_text("# baseline", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    return repo


@pytest.fixture
def state_path(repo_dir: Path) -> Path:
    """Return default incremental state path."""
    return repo_dir / ".securevibes" / "incremental_state.json"


@pytest.fixture
def sample_state(repo_dir: Path) -> dict[str, object]:
    """Return a representative persisted state payload."""
    return {
        "repo": str(repo_dir),
        "branch": "main",
        "remote": "origin",
        "last_seen_sha": "abc123",
        "last_run_utc": "2026-02-18T10:00:00Z",
        "last_success_utc": "2026-02-18T10:00:00Z",
        "last_status": "success",
        "last_run_id": "20260218T100000Z-a1b2c3",
    }


@pytest.fixture
def valid_report_payload() -> dict[str, object]:
    """Return a minimal valid securevibes JSON report payload."""
    return {
        "repository_path": "/tmp/repo",
        "files_scanned": 1,
        "scan_time_seconds": 1,
        "issues": [],
    }


@pytest.fixture
def fake_commits() -> list[str]:
    """Return deterministic fake commit SHAs for chunk tests."""
    return [f"sha{i:02d}" for i in range(1, 41)]


@pytest.fixture
def write_state(state_path: Path):
    """Helper to write arbitrary state JSON to disk."""

    def _write(payload: dict[str, object]) -> None:
        state_path.write_text(json.dumps(payload), encoding="utf-8")

    return _write
