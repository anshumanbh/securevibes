"""Context extraction helpers for PR review."""

from __future__ import annotations

import logging
from pathlib import Path
import json
import re
from typing import Dict, Iterable, List

logger = logging.getLogger(__name__)

# Truncation limits for context extraction.
# These limits prevent excessively large prompts while still providing
# meaningful context to the LLM for security analysis.
# - DEFAULT_CONTEXT_LIMIT: Used when no relevant sections are found (fallback)
# - MATCHED_SECTIONS_LIMIT: Used when matching sections are extracted (allows more content)
DEFAULT_CONTEXT_LIMIT = 4000
MATCHED_SECTIONS_LIMIT = 8000


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


def _threat_matches_tokens(threat: Dict[str, object], tokens: List[str]) -> bool:
    if not tokens:
        return False

    text_fields: List[str] = []
    for key in ("title", "description", "category", "id", "threat_id"):
        value = threat.get(key)
        if isinstance(value, str):
            text_fields.append(value)

    affected_components = threat.get("affected_components")
    if isinstance(affected_components, list):
        text_fields.extend([str(c) for c in affected_components])
    elif isinstance(affected_components, str):
        text_fields.append(affected_components)

    affected_files = threat.get("affected_files")
    if isinstance(affected_files, list):
        for item in affected_files:
            if isinstance(item, dict):
                file_path = item.get("file_path")
                if file_path:
                    text_fields.append(str(file_path))
            elif isinstance(item, str):
                text_fields.append(item)

    combined = " ".join(text_fields).lower()
    return any(token in combined for token in tokens)


def filter_relevant_threats(
    threat_model_path: Path, changed_files: List[str]
) -> List[Dict[str, object]]:
    """Filter THREAT_MODEL.json to threats affecting changed components."""
    if not threat_model_path.exists():
        return []

    threats = _load_threat_model(threat_model_path)
    if not threats:
        return []

    tokens = _build_tokens(changed_files)
    relevant: List[Dict[str, object]] = []
    for threat in threats:
        file_path = threat.get("file_path")
        if file_path and file_path in changed_files:
            relevant.append(threat)
            continue
        if _threat_matches_tokens(threat, tokens):
            relevant.append(threat)

    return relevant


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
    return [v for v in data if isinstance(v, dict) and v.get("file_path") in changed_files]
