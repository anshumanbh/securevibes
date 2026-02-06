"""Scan state tracking helpers."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Mapping, Optional


def load_scan_state(state_path: Path) -> Optional[Dict[str, object]]:
    """Load scan state from disk.

    Args:
        state_path: Path to scan_state.json.

    Returns:
        Parsed state dict or None if missing/invalid.
    """
    if not state_path.exists():
        return None

    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(data, dict):
        return None

    return data


def update_scan_state(
    state_path: Path,
    *,
    full_scan: Optional[Mapping[str, object]] = None,
    pr_review: Optional[Mapping[str, object]] = None,
) -> Dict[str, object]:
    """Update scan state on disk with new entries.

    Args:
        state_path: Path to scan_state.json.
        full_scan: Optional last_full_scan entry.
        pr_review: Optional last_pr_review entry.

    Returns:
        Updated state dict.
    """
    state = load_scan_state(state_path) or {}

    if full_scan is not None:
        state["last_full_scan"] = dict(full_scan)
    if pr_review is not None:
        state["last_pr_review"] = dict(pr_review)

    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    return state


def build_full_scan_entry(*, commit: str, branch: str, timestamp: str) -> Dict[str, object]:
    """Build a last_full_scan entry.

    Args:
        commit: Commit hash of the full scan.
        branch: Branch name used for the scan.
        timestamp: ISO timestamp.

    Returns:
        Dict with full scan metadata.
    """
    return {"commit": commit, "timestamp": timestamp, "branch": branch}


def build_pr_review_entry(
    *, commit: str, commits_reviewed: list[str], timestamp: str
) -> Dict[str, object]:
    """Build a last_pr_review entry.

    Args:
        commit: Commit hash of the PR review (HEAD).
        commits_reviewed: List of commits reviewed.
        timestamp: ISO timestamp.

    Returns:
        Dict with PR review metadata.
    """
    return {
        "commit": commit,
        "timestamp": timestamp,
        "commits_reviewed": list(commits_reviewed),
    }


def scan_state_branch_matches(state: Mapping[str, object], branch: str) -> bool:
    """Check if scan state belongs to the provided branch."""
    entry = state.get("last_full_scan")
    if not isinstance(entry, dict):
        return False
    state_branch = entry.get("branch")
    return isinstance(state_branch, str) and state_branch == branch


def get_last_full_scan_commit(state: Mapping[str, object]) -> Optional[str]:
    """Extract last_full_scan commit hash from state."""
    entry = state.get("last_full_scan")
    if not isinstance(entry, dict):
        return None
    commit = entry.get("commit")
    return commit if isinstance(commit, str) else None


def get_repo_head_commit(repo: Path) -> Optional[str]:
    """Get the current HEAD commit hash for a repo."""
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    commit = result.stdout.strip()
    return commit if commit else None


def get_repo_branch(repo: Path) -> Optional[str]:
    """Get the current branch name for a repo."""
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    branch = result.stdout.strip()
    return branch if branch else None


def utc_timestamp() -> str:
    """Return current UTC timestamp in ISO format."""
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return timestamp.replace("+00:00", "Z")
