"""Diff extraction helpers."""

from pathlib import Path
import subprocess


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
    return _run_git_diff(repo, [f"{base}...{head}"])


def get_diff_from_commits(repo: Path, commit_range: str) -> str:
    """Get diff from commit range (e.g., abc123~1..abc123)."""
    return _run_git_diff(repo, [commit_range])


def get_diff_from_file(patch_path: Path) -> str:
    """Read diff from patch file."""
    return patch_path.read_text(encoding="utf-8")
