"""Diff extraction helpers."""

from pathlib import Path
import re
import subprocess

# Git ref validation pattern: allows alphanumeric, dots, slashes, hyphens, underscores,
# tildes (for parent refs like HEAD~1), and carets (for commit refs like HEAD^2).
# Blocks shell metacharacters and other potentially dangerous characters.
GIT_REF_PATTERN = re.compile(r"^[\w./@^~-]+$")


def _validate_git_ref(ref: str) -> None:
    """Validate a git ref to prevent command injection.

    Args:
        ref: Git reference (branch name, commit hash, range like abc123~1..def456)

    Raises:
        ValueError: If the ref contains invalid characters
    """
    if not ref:
        raise ValueError("Git ref cannot be empty")
    # Handle commit ranges (e.g., abc123~1..def456 or base...head)
    parts = re.split(r"\.{2,3}", ref)
    for part in parts:
        if not part:
            continue
        if part.startswith("-"):
            raise ValueError(f"Invalid git ref: {ref!r} (option-style refs are not allowed)")
        if not GIT_REF_PATTERN.match(part):
            raise ValueError(f"Invalid git ref: {ref!r} (contains invalid characters)")


def _run_git_diff(repo: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", "diff", "--no-color", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or "Unknown git diff error"
        raise RuntimeError(f"git diff failed: {stderr}")
    return result.stdout


def _run_git_rev_list(repo: Path, args: list[str]) -> list[str]:
    result = subprocess.run(
        ["git", "rev-list", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or "Unknown git rev-list error"
        raise RuntimeError(f"git rev-list failed: {stderr}")
    return [line for line in result.stdout.splitlines() if line]


def _get_parent_commit(repo: Path, commit: str) -> str | None:
    _validate_git_ref(commit)
    result = subprocess.run(
        ["git", "rev-parse", f"{commit}^"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    parent = result.stdout.strip()
    return parent if parent else None


def get_commits_since(repo: Path, since: str) -> list[str]:
    """Get commits since a given time (inclusive)."""
    if not since:
        raise ValueError("since must be provided")
    return _run_git_rev_list(repo, ["--reverse", f"--since={since}", "HEAD"])


def get_commits_after(repo: Path, base_commit: str) -> list[str]:
    """Get commits after a base commit (exclusive)."""
    _validate_git_ref(base_commit)
    return _run_git_rev_list(repo, ["--reverse", f"{base_commit}..HEAD"])


def get_commits_between(repo: Path, base: str, head: str) -> list[str]:
    """Get commits between base and head (exclusive of base)."""
    _validate_git_ref(base)
    _validate_git_ref(head)
    return _run_git_rev_list(repo, ["--reverse", f"{base}..{head}"])


def get_commits_for_range(repo: Path, commit_range: str) -> list[str]:
    """Get commits for an explicit range expression."""
    _validate_git_ref(commit_range)
    return _run_git_rev_list(repo, ["--reverse", commit_range])


def get_last_n_commits(repo: Path, count: int) -> list[str]:
    """Get the last N commits (oldest to newest)."""
    if count <= 0:
        raise ValueError("count must be positive")
    return _run_git_rev_list(repo, ["--reverse", f"--max-count={count}", "HEAD"])


def get_diff_from_commit_list(repo: Path, commits: list[str]) -> str:
    """Get a combined diff for a list of commits."""
    if not commits:
        return ""

    oldest = commits[0]
    _validate_git_ref(oldest)
    base_commit = _get_parent_commit(repo, oldest)
    if base_commit:
        return _run_git_diff(repo, [f"{base_commit}..HEAD"])
    return _run_git_diff(repo, ["--root", "HEAD"])


def get_diff_from_git_range(repo: Path, base: str, head: str) -> str:
    """Get diff between two branches/commits."""
    _validate_git_ref(base)
    _validate_git_ref(head)
    return _run_git_diff(repo, [f"{base}...{head}"])


def get_diff_from_commits(repo: Path, commit_range: str) -> str:
    """Get diff from commit range (e.g., abc123~1..abc123)."""
    _validate_git_ref(commit_range)
    return _run_git_diff(repo, [commit_range])


def get_diff_from_file(patch_path: Path) -> str:
    """Read diff from patch file."""
    return patch_path.read_text(encoding="utf-8")
