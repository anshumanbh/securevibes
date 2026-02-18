"""Diff extraction helpers."""

from pathlib import Path
import re
import subprocess

# Git ref validation pattern: allows alphanumeric, dots, slashes, hyphens, underscores,
# tildes (for parent refs like HEAD~1), and carets (for commit refs like HEAD^2).
# Blocks shell metacharacters and other potentially dangerous characters.
GIT_REF_PATTERN = re.compile(r"^[\w./@^~-]+$")
_SINCE_PATTERN = re.compile(r"^[0-9T:+\- ]+$")


def _validate_single_git_ref(ref: str, original_ref: str) -> None:
    """Validate one git ref token (non-range)."""
    if ref.startswith("-"):
        raise ValueError(f"Invalid git ref: {original_ref!r} (option-style refs are not allowed)")
    if not GIT_REF_PATTERN.match(ref):
        raise ValueError(f"Invalid git ref: {original_ref!r} (contains invalid characters)")


def validate_git_ref(ref: str) -> None:
    """Validate a git ref to prevent command injection.

    Args:
        ref: Git reference (branch name, commit hash, range like abc123~1..def456)

    Raises:
        ValueError: If the ref contains invalid characters
    """
    if not ref:
        raise ValueError("Git ref cannot be empty")
    # Handle commit ranges (e.g., abc123~1..def456 or base...head).
    # Require exactly two non-empty endpoints when a range separator is present.
    if "...." in ref:
        raise ValueError(f"Invalid git ref: {ref!r} (malformed range syntax)")

    has_three_dot_range = "..." in ref
    has_two_dot_range = ".." in ref

    if has_three_dot_range:
        parts = ref.split("...")
        if len(parts) != 2 or not all(parts):
            raise ValueError(f"Invalid git ref: {ref!r} (malformed range syntax)")
        for part in parts:
            if ".." in part:
                raise ValueError(f"Invalid git ref: {ref!r} (malformed range syntax)")
            _validate_single_git_ref(part, ref)
        return

    if has_two_dot_range:
        parts = ref.split("..")
        if len(parts) != 2 or not all(parts):
            raise ValueError(f"Invalid git ref: {ref!r} (malformed range syntax)")
        for part in parts:
            _validate_single_git_ref(part, ref)
        return

    _validate_single_git_ref(ref, ref)


# Backward-compatible alias for older imports/tests.
def _validate_git_ref(ref: str) -> None:
    validate_git_ref(ref)


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
    validate_git_ref(commit)
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
    if any(ch in since for ch in ("\x00", "\n", "\r")):
        raise ValueError("since must not contain control characters")
    if not _SINCE_PATTERN.match(since):
        raise ValueError("since contains invalid characters")
    return _run_git_rev_list(repo, ["--reverse", f"--since={since}", "HEAD"])


def get_commits_after(repo: Path, base_commit: str) -> list[str]:
    """Get commits after a base commit (exclusive)."""
    validate_git_ref(base_commit)
    return _run_git_rev_list(repo, ["--reverse", f"{base_commit}..HEAD"])


def get_commits_between(repo: Path, base: str, head: str) -> list[str]:
    """Get commits between base and head (exclusive of base)."""
    validate_git_ref(base)
    validate_git_ref(head)
    return _run_git_rev_list(repo, ["--reverse", f"{base}..{head}"])


def get_commits_for_range(repo: Path, commit_range: str) -> list[str]:
    """Get commits for an explicit range expression."""
    validate_git_ref(commit_range)
    return _run_git_rev_list(repo, ["--reverse", commit_range])


def get_last_n_commits(repo: Path, count: int) -> list[str]:
    """Get the last N commits (oldest to newest)."""
    if count <= 0:
        raise ValueError("count must be positive")
    return _run_git_rev_list(repo, ["--reverse", f"--max-count={count}", "HEAD"])


def get_diff_from_commit_list(repo: Path, commits: list[str]) -> str:
    """Get a combined diff for the provided commit list window."""
    if not commits:
        return ""

    oldest = commits[0]
    newest = commits[-1]
    validate_git_ref(oldest)
    validate_git_ref(newest)
    base_commit = _get_parent_commit(repo, oldest)
    if base_commit:
        return _run_git_diff(repo, [f"{base_commit}..{newest}"])
    return _run_git_diff(repo, ["--root", newest])


def get_diff_from_git_range(repo: Path, base: str, head: str) -> str:
    """Get diff between two branches/commits."""
    validate_git_ref(base)
    validate_git_ref(head)
    return _run_git_diff(repo, [f"{base}...{head}"])


def get_diff_from_commits(repo: Path, commit_range: str) -> str:
    """Get diff from commit range (e.g., abc123~1..abc123)."""
    validate_git_ref(commit_range)
    return _run_git_diff(repo, [commit_range])


def get_diff_from_file(patch_path: Path) -> str:
    """Read diff from patch file."""
    return patch_path.read_text(encoding="utf-8")
