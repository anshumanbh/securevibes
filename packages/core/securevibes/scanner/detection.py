"""Deterministic agentic application detection.

This module is intentionally lightweight and conservative: it is used to decide
whether we should REQUIRE OWASP ASI threats in THREAT_MODEL.json.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


MAX_BYTES_TO_SCAN = 200_000
MAX_SIGNALS_REPORTED = 25


@dataclass(frozen=True)
class AgenticDetectionResult:
    """Result of deterministic agentic detection."""

    is_agentic: bool
    matched_categories: frozenset[str]
    strong_categories: frozenset[str]
    signals: tuple[str, ...]


# Categories whose presence is a strong indicator of an AI/agentic system.
STRONG_CATEGORIES = frozenset({"llm_apis", "agent_frameworks", "tool_execution"})


AGENTIC_PATTERNS: dict[str, Sequence[str]] = {
    "llm_apis": (
        r"\banthropic\b",
        r"\bopenai\b",
        r"\bclaude\b",
        r"\bgpt-\d\b",
        r"messages\.create",
        r"chat\.completions",
    ),
    "agent_frameworks": (
        r"\blangchain\b",
        r"\bautogen\b",
        r"\bcrewai\b",
        r"\bclaude_agent_sdk\b",
        r"\bclaude-agent-sdk\b",
        r"\bsemantic_kernel\b",
    ),
    "tool_execution": (
        r"\bfunction_call\b",
        r"\btool\.use\b",
        r"\bbash\.tool\b",
        r"\bbrowser\.tool\b",
        r"\btools\s*[:=]\s*\[",
        r"\@tool\b",
    ),
    # Weaker signals (commonly appear in non-agentic codebases too)
    "agent_patterns": (
        r"class\s+\w*Agent\b",
        r"class\s+\w*Runner\b",
        r"class\s+\w*Executor\b",
        r"\bBaseAgent\b",
        r"\bAgentExecutor\b",
    ),
    "mcp_patterns": (
        r"\bMCPServer\b",
        r"\bMCPClient\b",
        r"\bmcp\b",
    ),
}


def detect_agentic_patterns(
    repo: Path,
    files: Sequence[Path],
    *,
    max_signals: int = MAX_SIGNALS_REPORTED,
) -> AgenticDetectionResult:
    """Detect whether a repository contains agentic application patterns.

    Detection is based on matching 2+ distinct pattern categories across the
    provided files. This reduces false positives from generic terms like
    "Agent".

    Args:
        repo: Repository root path.
        files: Files to scan (should already exclude vendored/infrastructure dirs).
        max_signals: Maximum number of matched signals to include in the result.

    Returns:
        AgenticDetectionResult with boolean classification and matched signals.
    """

    compiled: dict[str, Sequence[re.Pattern[str]]] = {
        category: tuple(re.compile(p, re.IGNORECASE) for p in patterns)
        for category, patterns in AGENTIC_PATTERNS.items()
    }

    matched_categories: set[str] = set()
    strong_categories: set[str] = set()
    signals: list[str] = []

    def _read_prefix(path: Path) -> str:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            return f.read(MAX_BYTES_TO_SCAN)

    for file_path in files:
        try:
            if not file_path.is_file():
                continue
        except OSError:
            continue

        try:
            content = _read_prefix(file_path)
        except OSError:
            continue

        for category, patterns in compiled.items():
            # Avoid scanning categories we already have if we have enough signals.
            if category in matched_categories and len(signals) >= max_signals:
                continue

            for pat in patterns:
                if pat.search(content) is None:
                    continue

                matched_categories.add(category)
                if category in STRONG_CATEGORIES:
                    strong_categories.add(category)

                if len(signals) < max_signals:
                    try:
                        rel = file_path.relative_to(repo)
                        where = str(rel)
                    except ValueError:
                        where = file_path.name
                    signals.append(f"{category}:{pat.pattern} in {where}")

                break

        # Early exit once we have 2+ categories (the classification threshold)
        if len(matched_categories) >= 2:
            break

    is_agentic = len(matched_categories) >= 2

    return AgenticDetectionResult(
        is_agentic=is_agentic,
        matched_categories=frozenset(matched_categories),
        strong_categories=frozenset(strong_categories),
        signals=tuple(signals),
    )


def collect_agentic_detection_files(
    repo: Path,
    code_files: Sequence[Path],
    *,
    exclude_dirs: Iterable[str],
) -> list[Path]:
    """Collect files for agentic detection.

    This is a helper for the scanner to include dependency manifests in
    detection without scanning large infrastructure directories.

    Args:
        repo: Repository root.
        code_files: Code files already filtered for exclusions.
        exclude_dirs: Directory names to exclude.

    Returns:
        List of files to scan.
    """

    exclude = set(exclude_dirs)

    def _should_include(p: Path) -> bool:
        return not any(excluded in p.parts for excluded in exclude)

    candidates: list[Path] = list(code_files)

    manifest_names = {
        "package.json",
        "requirements.txt",
        "pyproject.toml",
        "Pipfile",
        "poetry.lock",
    }

    for name in manifest_names:
        p = repo / name
        if p.exists() and p.is_file() and _should_include(p):
            candidates.append(p)

    return candidates
