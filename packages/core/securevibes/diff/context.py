"""Context extraction helpers for PR review."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import re
from typing import Dict, Iterable, List, Sequence, Tuple

logger = logging.getLogger(__name__)

# Truncation limits for context extraction.
# These limits prevent excessively large prompts while still providing
# meaningful context to the LLM for security analysis.
# - DEFAULT_CONTEXT_LIMIT: Used when no relevant sections are found (fallback)
# - MATCHED_SECTIONS_LIMIT: Used when matching sections are extracted (allows more content)
DEFAULT_CONTEXT_LIMIT = 4000
MATCHED_SECTIONS_LIMIT = 8000

MAX_RELEVANT_THREATS = 12
MAX_RELEVANT_VULNERABILITIES = 12
MAX_CONTEXT_SUMMARY_CHARS = 3500


IGNORE_TOKENS = {
    "src",
    "lib",
    "tests",
    "test",
    "package",
    "packages",
    "core",
    "main",
    "index",
}

SECURITY_ADJACENT_TOKENS = (
    "auth",
    "authorize",
    "policy",
    "permission",
    "guard",
    "access",
    "middleware",
    "server",
    "route",
    "gateway",
    "websocket",
    "ws",
    "rpc",
    "config",
)

CODE_FILE_SUFFIXES = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".go",
    ".java",
    ".rb",
    ".rs",
    ".php",
    ".cs",
    ".cpp",
    ".c",
}


def normalize_repo_path(path: object) -> str:
    """Normalize repository-relative paths for consistent matching."""
    if not isinstance(path, str):
        return ""
    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = re.sub(r"/+", "/", normalized)
    return normalized


def _tokenize_path(path: str) -> List[str]:
    tokens: List[str] = []
    for part in Path(path).parts:
        base = part.rsplit(".", 1)[0] if "." in part else part
        for chunk in re.split(r"[-_.]", base):
            chunk = chunk.strip()
            if not chunk:
                continue
            tokens.append(chunk.lower())
        if base:
            tokens.append(base.lower())
    return tokens


def _build_tokens(changed_files: Iterable[str]) -> List[str]:
    tokens: List[str] = []
    for path in changed_files:
        tokens.extend(_tokenize_path(path))
    return [t for t in tokens if len(t) >= 2 and t not in IGNORE_TOKENS]


def _safe_text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _clip_text(value: object, max_chars: int = 220) -> str:
    text = _safe_text(value)
    if len(text) <= max_chars:
        return text
    return f"{text[: max_chars - 3].rstrip()}..."


def _path_parts(path: str) -> Tuple[str, ...]:
    normalized = normalize_repo_path(path)
    return tuple(part for part in normalized.split("/") if part)


def _max_path_relevance(candidate_paths: Sequence[str], changed_files: Sequence[str]) -> int:
    if not candidate_paths or not changed_files:
        return 0

    normalized_changed = [
        normalize_repo_path(path) for path in changed_files if normalize_repo_path(path)
    ]
    changed_parts = [set(_path_parts(path)) for path in normalized_changed]

    best = 0
    for candidate in candidate_paths:
        candidate_norm = normalize_repo_path(candidate)
        if not candidate_norm:
            continue

        candidate_parts = _path_parts(candidate_norm)
        candidate_parent = "/".join(candidate_parts[:-1])

        for idx, changed_norm in enumerate(normalized_changed):
            changed_path_parts = _path_parts(changed_norm)
            changed_parent = "/".join(changed_path_parts[:-1])

            score = 0
            if candidate_norm == changed_norm:
                score = 100
            elif candidate_norm.endswith(f"/{changed_norm}") or changed_norm.endswith(
                f"/{candidate_norm}"
            ):
                score = 90
            elif candidate_parent and candidate_parent == changed_parent:
                score = 80
            elif (
                candidate_parts
                and changed_path_parts
                and candidate_parts[0] == changed_path_parts[0]
            ):
                score = 35

            overlap = len(set(candidate_parts) & changed_parts[idx])
            score += min(overlap, 5) * 4
            best = max(best, score)

    return best


def _entry_text(entry: Dict[str, object], text_keys: Sequence[str]) -> str:
    parts: List[str] = []
    for key in text_keys:
        value = entry.get(key)
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            parts.extend(str(item) for item in value)
        elif value is not None:
            parts.append(str(value))
    return " ".join(parts).lower()


def _entry_path_candidates(entry: Dict[str, object]) -> List[str]:
    candidates: List[str] = []

    file_path = entry.get("file_path")
    if isinstance(file_path, str):
        normalized = normalize_repo_path(file_path)
        if normalized:
            candidates.append(normalized)

    affected_files = entry.get("affected_files")
    if isinstance(affected_files, list):
        for item in affected_files:
            if isinstance(item, dict):
                nested_path = normalize_repo_path(item.get("file_path"))
                if nested_path:
                    candidates.append(nested_path)
            elif isinstance(item, str):
                normalized = normalize_repo_path(item)
                if normalized:
                    candidates.append(normalized)
    elif isinstance(affected_files, str):
        normalized = normalize_repo_path(affected_files)
        if normalized:
            candidates.append(normalized)

    deduped: List[str] = []
    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        deduped.append(candidate)
    return deduped


def _rank_relevant_entries(
    entries: Sequence[Dict[str, object]],
    changed_files: Sequence[str],
    *,
    text_keys: Sequence[str],
    max_items: int,
) -> List[Dict[str, object]]:
    if max_items <= 0:
        return []

    tokens = _build_tokens(changed_files)
    ranked: List[Tuple[int, str, Dict[str, object]]] = []

    for entry in entries:
        path_score = _max_path_relevance(_entry_path_candidates(entry), changed_files)
        text = _entry_text(entry, text_keys)
        token_hits = 0
        if tokens and text:
            token_hits = sum(1 for token in set(tokens) if token in text)
        token_score = min(token_hits, 8) * 5
        score = path_score + token_score
        if score <= 0:
            continue

        sort_key = (
            _safe_text(entry.get("id"))
            or _safe_text(entry.get("threat_id"))
            or _safe_text(entry.get("title"))
            or "zzz"
        )
        ranked.append((score, sort_key.lower(), entry))

    ranked.sort(key=lambda item: (-item[0], item[1]))
    return [item[2] for item in ranked[:max_items]]


def _summarize_entries(
    entries: Sequence[Dict[str, object]],
    *,
    id_key: str,
    max_chars: int,
) -> str:
    if not entries:
        return "- None"

    lines: List[str] = []
    used_chars = 0
    for entry in entries:
        entry_id = _safe_text(entry.get(id_key)) or _safe_text(entry.get("id")) or "UNKNOWN"
        title = _clip_text(entry.get("title"), max_chars=120) or "Untitled"
        severity = _safe_text(entry.get("severity")) or "unknown"
        file_path = normalize_repo_path(entry.get("file_path")) or "unknown"
        cwe = _safe_text(entry.get("cwe_id")) or _safe_text(entry.get("cwe")) or "n/a"
        description = _clip_text(entry.get("description"), max_chars=180)

        line = f"- [{entry_id}] {title} | severity={severity} | file={file_path} | cwe={cwe}"
        if description:
            line = f"{line} | desc={description}"

        projected = used_chars + len(line) + 1
        if projected > max_chars:
            if not lines:
                lines.append(_clip_text(line, max_chars=max_chars))
            break
        lines.append(line)
        used_chars = projected

    if not lines:
        return "- None"
    return "\n".join(lines)


def extract_relevant_architecture(security_md_path: Path, changed_files: List[str]) -> str:
    """Extract SECURITY.md sections relevant to changed files."""
    if not security_md_path.exists():
        return ""

    text = security_md_path.read_text(encoding="utf-8", errors="ignore")
    if not text.strip():
        return ""

    tokens = _build_tokens(changed_files)
    if not tokens:
        return text[:DEFAULT_CONTEXT_LIMIT].strip()

    sections: List[Dict[str, str]] = []
    current_heading = ""
    current_lines: List[str] = []
    for line in text.splitlines():
        if line.startswith("#"):
            if current_lines:
                sections.append(
                    {"heading": current_heading, "content": "\n".join(current_lines).strip()}
                )
                current_lines = []
            current_heading = line.strip()
        else:
            current_lines.append(line)
    if current_lines:
        sections.append({"heading": current_heading, "content": "\n".join(current_lines).strip()})

    matched_sections: List[str] = []
    for section in sections:
        combined = f"{section['heading']}\n{section['content']}".lower()
        if any(token in combined for token in tokens):
            matched_sections.append(f"{section['heading']}\n{section['content']}".strip())

    if not matched_sections:
        return text[:DEFAULT_CONTEXT_LIMIT].strip()

    combined_text = "\n\n".join(matched_sections).strip()
    return combined_text[:MATCHED_SECTIONS_LIMIT].strip()


def _load_threat_model(threat_model_path: Path) -> List[Dict[str, object]]:
    raw = threat_model_path.read_text(encoding="utf-8", errors="ignore")
    if not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.warning("Failed to parse threat model at %s: %s", threat_model_path, e)
        return []
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("threats", "threat_model", "vulnerabilities", "issues"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def filter_relevant_threats(
    threat_model_path: Path,
    changed_files: List[str],
    *,
    max_items: int = MAX_RELEVANT_THREATS,
) -> List[Dict[str, object]]:
    """Filter and rank THREAT_MODEL.json entries relevant to changed files."""
    if not threat_model_path.exists():
        return []

    threats = _load_threat_model(threat_model_path)
    if not threats:
        return []

    return _rank_relevant_entries(
        threats,
        changed_files,
        text_keys=(
            "id",
            "threat_id",
            "title",
            "description",
            "category",
            "affected_components",
            "affected_files",
        ),
        max_items=max_items,
    )


def filter_relevant_vulnerabilities(
    vulnerabilities: Sequence[Dict[str, object]],
    changed_files: List[str],
    *,
    max_items: int = MAX_RELEVANT_VULNERABILITIES,
) -> List[Dict[str, object]]:
    """Filter and rank baseline vulnerabilities relevant to changed files."""
    return _rank_relevant_entries(
        [item for item in vulnerabilities if isinstance(item, dict)],
        changed_files,
        text_keys=(
            "threat_id",
            "title",
            "description",
            "cwe_id",
            "file_path",
            "attack_scenario",
            "evidence",
            "recommendation",
        ),
        max_items=max_items,
    )


def summarize_threats_for_prompt(
    threats: Sequence[Dict[str, object]],
    *,
    max_chars: int = MAX_CONTEXT_SUMMARY_CHARS,
) -> str:
    """Build a compact threat summary for prompt injection."""
    return _summarize_entries(threats, id_key="id", max_chars=max_chars)


def summarize_vulnerabilities_for_prompt(
    vulnerabilities: Sequence[Dict[str, object]],
    *,
    max_chars: int = MAX_CONTEXT_SUMMARY_CHARS,
) -> str:
    """Build a compact vulnerability summary for prompt injection."""
    return _summarize_entries(vulnerabilities, id_key="threat_id", max_chars=max_chars)


def suggest_security_adjacent_files(
    repo_root: Path,
    changed_files: Sequence[str],
    *,
    max_items: int = 15,
) -> List[str]:
    """Suggest nearby security-sensitive files that should be inspected for exploit chains."""
    if max_items <= 0:
        return []
    try:
        repo_root_resolved = repo_root.resolve()
    except OSError:
        return []

    changed_set = {
        normalize_repo_path(path)
        for path in changed_files
        if isinstance(path, str) and normalize_repo_path(path)
    }
    if not changed_set:
        return []

    scores: Dict[str, int] = {}

    for changed in changed_set:
        changed_abs = (repo_root / changed).resolve()
        for directory in {changed_abs.parent, changed_abs.parent.parent}:
            if not directory.exists() or not directory.is_dir():
                continue
            try:
                directory.relative_to(repo_root_resolved)
            except (ValueError, OSError):
                continue

            try:
                entries = list(directory.iterdir())
            except (OSError, PermissionError) as exc:
                logger.debug("Skipping unreadable adjacent directory %s: %s", directory, exc)
                continue

            for entry in entries:
                try:
                    if not entry.is_file():
                        continue
                    if entry.suffix and entry.suffix.lower() not in CODE_FILE_SUFFIXES:
                        continue
                    entry_lower_name = entry.name.lower()
                    if any(token in entry_lower_name for token in ("test", "spec")):
                        continue

                    rel_path = normalize_repo_path(str(entry.relative_to(repo_root)))
                except (ValueError, OSError, PermissionError) as exc:
                    logger.debug("Skipping unreadable adjacent path %s: %s", entry, exc)
                    continue
                if not rel_path or rel_path in changed_set:
                    continue
                if rel_path.startswith(".securevibes/"):
                    continue

                lower = rel_path.lower()
                if "/test/" in lower or "/tests/" in lower or "/__tests__/" in lower:
                    continue
                token_hits = sum(1 for token in SECURITY_ADJACENT_TOKENS if token in lower)
                if token_hits == 0:
                    continue

                score = 100 if entry.parent == changed_abs.parent else 70
                score += token_hits * 12
                scores[rel_path] = max(scores.get(rel_path, 0), score)

    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    return [path for path, _score in ranked[:max_items]]


def check_vuln_overlap(vulns_path: Path, changed_files: List[str]) -> List[Dict[str, object]]:
    """Check if diff affects files with known vulnerabilities."""
    if not vulns_path.exists():
        return []
    raw = vulns_path.read_text(encoding="utf-8", errors="ignore")
    if not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.warning("Failed to parse vulnerabilities at %s: %s", vulns_path, e)
        return []
    if not isinstance(data, list):
        return []
    changed_normalized = {normalize_repo_path(path) for path in changed_files}
    return [
        vuln
        for vuln in data
        if isinstance(vuln, dict)
        and normalize_repo_path(vuln.get("file_path")) in changed_normalized
    ]
