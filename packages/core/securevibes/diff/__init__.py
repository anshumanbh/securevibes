"""Diff parsing and context helpers for PR review."""

from securevibes.diff.parser import (
    DiffContext,
    DiffFile,
    DiffHunk,
    DiffLine,
    parse_unified_diff,
    extract_changed_code_with_context,
)
from securevibes.diff.extractor import (
    get_commits_after,
    get_commits_between,
    get_commits_for_range,
    get_commits_since,
    get_diff_from_commit_list,
    get_diff_from_commits,
    get_diff_from_file,
    get_diff_from_git_range,
    get_last_n_commits,
)
from securevibes.diff.context import (
    extract_relevant_architecture,
    filter_relevant_threats,
    check_vuln_overlap,
)

__all__ = [
    "DiffContext",
    "DiffFile",
    "DiffHunk",
    "DiffLine",
    "parse_unified_diff",
    "extract_changed_code_with_context",
    "get_commits_after",
    "get_commits_between",
    "get_commits_for_range",
    "get_commits_since",
    "get_diff_from_commit_list",
    "get_diff_from_commits",
    "get_diff_from_file",
    "get_diff_from_git_range",
    "get_last_n_commits",
    "extract_relevant_architecture",
    "filter_relevant_threats",
    "check_vuln_overlap",
]
