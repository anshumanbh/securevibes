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
        if part and not GIT_REF_PATTERN.match(part):
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
