"""Unified diff parsing utilities for PR review."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Dict, List, Optional, Sequence, Tuple


HUNK_HEADER_RE = re.compile(
    r"@@\s+-(?P<old_start>\d+)(?:,(?P<old_count>\d+))?\s+\+(?P<new_start>\d+)"
    r"(?:,(?P<new_count>\d+))?\s+@@"
)


@dataclass
class DiffLine:
    """Represents a single line inside a diff hunk."""

    type: str  # "add", "remove", "context"
    content: str
    old_line_num: Optional[int]
    new_line_num: Optional[int]


@dataclass
class DiffHunk:
    """Represents a diff hunk."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: List[DiffLine]


@dataclass
class DiffFile:
    """Represents a file touched by the diff."""

    old_path: Optional[str]
    new_path: Optional[str]
    hunks: List[DiffHunk]
    is_new: bool
    is_deleted: bool
    is_renamed: bool


@dataclass
class DiffContext:
    """Parsed diff with summary statistics."""

    files: List[DiffFile]
    added_lines: int
    removed_lines: int
    changed_files: List[str]

    def to_json(self) -> dict:
        """Serialize diff context to JSON-safe dict."""
        return {
            "files": [
                {
                    "old_path": f.old_path,
                    "new_path": f.new_path,
                    "is_new": f.is_new,
                    "is_deleted": f.is_deleted,
                    "is_renamed": f.is_renamed,
                    "hunks": [
                        {
                            "old_start": h.old_start,
                            "old_count": h.old_count,
                            "new_start": h.new_start,
                            "new_count": h.new_count,
                            "lines": [
                                {
                                    "type": line.type,
                                    "content": line.content,
                                    "old_line_num": line.old_line_num,
                                    "new_line_num": line.new_line_num,
                                }
                                for line in h.lines
                            ],
                        }
                        for h in f.hunks
                    ],
                }
                for f in self.files
            ],
            "added_lines": self.added_lines,
            "removed_lines": self.removed_lines,
            "changed_files": self.changed_files,
        }


def _strip_diff_prefix(path: str) -> Optional[str]:
    path = path.split("\t", 1)[0].strip()
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]
    if path in ("/dev/null", "dev/null"):
        return None
    return path or None


def _parse_hunk_header(line: str) -> Tuple[int, int, int, int]:
    match = HUNK_HEADER_RE.search(line)
    if not match:
        return 0, 0, 0, 0
    old_start = int(match.group("old_start"))
    old_count = int(match.group("old_count") or 1)
    new_start = int(match.group("new_start"))
    new_count = int(match.group("new_count") or 1)
    return old_start, old_count, new_start, new_count


def parse_unified_diff(diff_content: str) -> DiffContext:
    """Parse unified diff content into structured context.

    Args:
        diff_content: Git diff output string.

    Returns:
        DiffContext describing all file changes.
    """
    files: List[DiffFile] = []
    added_lines = 0
    removed_lines = 0

    current_file: Optional[DiffFile] = None
    current_hunk: Optional[DiffHunk] = None
    old_line_num: Optional[int] = None
    new_line_num: Optional[int] = None

    for line in diff_content.splitlines():
        if line.startswith("diff --git"):
            if current_file:
                files.append(current_file)
            parts = line.split()
            old_path = _strip_diff_prefix(parts[2]) if len(parts) > 2 else None
            new_path = _strip_diff_prefix(parts[3]) if len(parts) > 3 else None
            current_file = DiffFile(
                old_path=old_path,
                new_path=new_path,
                hunks=[],
                is_new=False,
                is_deleted=False,
                is_renamed=False,
            )
            current_hunk = None
            old_line_num = None
            new_line_num = None
            continue

        if current_file is None:
            continue

        if line.startswith("new file mode"):
            current_file.is_new = True
            continue
        if line.startswith("deleted file mode"):
            current_file.is_deleted = True
            continue
        if line.startswith("rename from "):
            current_file.old_path = line[len("rename from ") :].strip() or current_file.old_path
            current_file.is_renamed = True
            continue
        if line.startswith("rename to "):
            current_file.new_path = line[len("rename to ") :].strip() or current_file.new_path
            current_file.is_renamed = True
            continue

        if line.startswith("--- "):
            current_file.old_path = _strip_diff_prefix(line[4:]) or current_file.old_path
            if current_file.old_path is None:
                current_file.is_new = True
            continue
        if line.startswith("+++ "):
            current_file.new_path = _strip_diff_prefix(line[4:]) or current_file.new_path
            if current_file.new_path is None:
                current_file.is_deleted = True
            continue

        if line.startswith("@@"):
            old_start, old_count, new_start, new_count = _parse_hunk_header(line)
            current_hunk = DiffHunk(
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                lines=[],
            )
            current_file.hunks.append(current_hunk)
            old_line_num = old_start
            new_line_num = new_start
            continue

        if current_hunk is None:
            continue

        if line.startswith("\\ No newline at end of file"):
            continue

        prefix = line[:1]
        content = line[1:] if len(line) > 0 else ""

        if prefix == "+":
            current_hunk.lines.append(
                DiffLine("add", content, old_line_num=None, new_line_num=new_line_num)
            )
            added_lines += 1
            if new_line_num is not None:
                new_line_num += 1
        elif prefix == "-":
            current_hunk.lines.append(
                DiffLine("remove", content, old_line_num=old_line_num, new_line_num=None)
            )
            removed_lines += 1
            if old_line_num is not None:
                old_line_num += 1
        else:
            if prefix == " ":
                content = line[1:]
            current_hunk.lines.append(
                DiffLine("context", content, old_line_num=old_line_num, new_line_num=new_line_num)
            )
            if old_line_num is not None:
                old_line_num += 1
            if new_line_num is not None:
                new_line_num += 1

    if current_file:
        files.append(current_file)

    changed_files: List[str] = []
    seen = set()
    for file in files:
        path = file.new_path or file.old_path
        if not path or path in seen:
            continue
        seen.add(path)
        changed_files.append(path)

    return DiffContext(
        files=files,
        added_lines=added_lines,
        removed_lines=removed_lines,
        changed_files=changed_files,
    )


def _merge_ranges(ranges: Sequence[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not ranges:
        return []
    sorted_ranges = sorted(ranges, key=lambda r: r[0])
    merged = [sorted_ranges[0]]
    for start, end in sorted_ranges[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end + 1:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def extract_changed_code_with_context(
    diff: DiffContext,
    repo_path: Path,
    context_lines: int = 10,
) -> Dict[str, str]:
    """Extract changed code with surrounding context lines.

    Args:
        diff: Parsed diff context.
        repo_path: Repository root path.
        context_lines: Number of context lines before/after each change.

    Returns:
        Mapping of file path to context snippet.
    """
    snippets: Dict[str, str] = {}

    for diff_file in diff.files:
        if diff_file.is_deleted or not diff_file.new_path:
            continue

        file_path = repo_path / diff_file.new_path
        if not file_path.exists():
            continue

        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        ranges: List[Tuple[int, int]] = []
        for hunk in diff_file.hunks:
            for line in hunk.lines:
                if line.type != "add" or not line.new_line_num:
                    continue
                start = max(1, line.new_line_num - context_lines)
                end = min(len(lines), line.new_line_num + context_lines)
                ranges.append((start, end))

        merged = _merge_ranges(ranges)
        if not merged:
            continue

        snippet_lines: List[str] = []
        for idx, (start, end) in enumerate(merged):
            if idx > 0:
                snippet_lines.append("...")
            for line_no in range(start, end + 1):
                snippet_lines.append(f"{line_no:>4}: {lines[line_no - 1]}")

        snippets[diff_file.new_path] = "\n".join(snippet_lines)

    return snippets
