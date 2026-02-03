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
    get_diff_from_commits,
    get_diff_from_file,
    get_diff_from_git_range,
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
    "get_diff_from_commits",
    "get_diff_from_file",
    "get_diff_from_git_range",
    "extract_relevant_architecture",
    "filter_relevant_threats",
    "check_vuln_overlap",
]
