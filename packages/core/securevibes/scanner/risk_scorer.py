"""Threat-aware file and chunk risk scoring for incremental scans."""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Literal, Mapping, Sequence

RiskTier = Literal["critical", "moderate", "skip"]

RISK_MODEL_BY_TIER: dict[RiskTier, str | None] = {
    "critical": "opus",
    "moderate": "sonnet",
    "skip": None,
}

STATIC_SKIP_PATTERNS: tuple[str, ...] = (
    "docs/*",
    "doc/*",
    "tests/*",
    "test/*",
    "*.test.*",
    "*.spec.*",
    "CHANGELOG.md",
    "README.md",
    ".github/*",
    "scripts/*",
)

POLICY_CONTEXT_PATTERNS: tuple[str, ...] = (
    ".securevibes/risk_map.json",
    ".securevibes/design_decisions.json",
    ".securevibes/THREAT_MODEL.json",
    ".securevibes/VULNERABILITIES.json",
    ".securevibes/decisions/*",
)

DEPENDENCY_FILE_NAMES: frozenset[str] = frozenset(
    {
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "requirements.txt",
        "poetry.lock",
        "pipfile",
        "pipfile.lock",
        "cargo.toml",
        "cargo.lock",
        "pyproject.toml",
        "go.mod",
        "go.sum",
        "gemfile",
        "gemfile.lock",
        "composer.json",
        "composer.lock",
    }
)

SECURITY_KEYWORDS: tuple[str, ...] = (
    "auth",
    "crypto",
    "exec",
    "secret",
    "network",
    "permission",
    "gateway",
    "credential",
)

_SCRIPT_EXEC_RE = re.compile(r"\b(exec|eval|child_process)\b", re.IGNORECASE)


@dataclass(frozen=True)
class ChangedFile:
    """Changed-file metadata used for deterministic chunk scoring."""

    path: str
    status: str = "M"
    added_lines: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class FileRisk:
    """Per-file risk classification."""

    file_path: str
    tier: RiskTier
    matched_pattern: str | None
    is_unmapped: bool
    is_dependency_file: bool


@dataclass(frozen=True)
class ChunkRisk:
    """Chunk-level risk classification and routing metadata."""

    tier: RiskTier
    model: str | None
    file_risks: tuple[FileRisk, ...]
    reasons: tuple[str, ...]
    dependency_files: tuple[str, ...]
    dependency_only: bool
    unmapped_files: tuple[str, ...]
    new_attack_surface: bool


def normalize_path(path: str) -> str:
    """Normalize repository-relative paths to forward-slash format."""
    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = re.sub(r"/+", "/", normalized)
    return normalized.strip("/")


def is_dependency_file(path: str) -> bool:
    """Return True when a path is a dependency manifest or lockfile."""
    normalized = normalize_path(path).lower()
    name = Path(normalized).name.lower()
    if name in DEPENDENCY_FILE_NAMES:
        return True
    return name.endswith(".lock")


def _matches(path: str, patterns: Sequence[str]) -> str | None:
    for pattern in patterns:
        normalized_pattern = normalize_path(pattern)
        if normalized_pattern and fnmatch.fnmatch(path, normalized_pattern):
            return normalized_pattern
    return None


def _collect_mapped_top_levels(risk_map: Mapping[str, object]) -> set[str]:
    top_levels: set[str] = set()
    for bucket in ("critical", "moderate"):
        raw = risk_map.get(bucket, [])
        if not isinstance(raw, list):
            continue
        for item in raw:
            if not isinstance(item, str):
                continue
            normalized = normalize_path(item)
            if not normalized:
                continue
            first = normalized.split("/", 1)[0]
            if first and "*" not in first and "?" not in first and "[" not in first:
                top_levels.add(first)
    return top_levels


def _is_security_test_path(path: str) -> bool:
    name = Path(path).name.lower()
    return ".test." in name or ".spec." in name


def _is_extensionless_non_doc(path: str) -> bool:
    if path.startswith("docs/") or path.startswith("doc/"):
        return False
    return Path(path).suffix == ""


def _is_policy_context_path(path: str) -> bool:
    return _matches(path, POLICY_CONTEXT_PATTERNS) is not None


def _match_file_tier(
    path: str, risk_map: Mapping[str, object]
) -> tuple[RiskTier, str | None, bool]:
    critical = risk_map.get("critical", [])
    moderate = risk_map.get("moderate", [])
    skip = risk_map.get("skip", [])
    critical_patterns = critical if isinstance(critical, list) else []
    moderate_patterns = moderate if isinstance(moderate, list) else []
    skip_patterns = skip if isinstance(skip, list) else []

    match = _matches(path, [p for p in critical_patterns if isinstance(p, str)])
    if match:
        return ("critical", match, False)

    match = _matches(path, [p for p in moderate_patterns if isinstance(p, str)])
    if match:
        return ("moderate", match, False)

    match = _matches(path, [p for p in skip_patterns if isinstance(p, str)])
    if match:
        return ("skip", match, False)

    return ("moderate", None, True)


def classify_chunk(
    changed_files: Sequence[ChangedFile],
    risk_map: Mapping[str, object],
) -> ChunkRisk:
    """Classify a chunk into critical/moderate/skip tiers."""
    if not changed_files:
        return ChunkRisk(
            tier="skip",
            model=None,
            file_risks=(),
            reasons=("empty_chunk",),
            dependency_files=(),
            dependency_only=False,
            unmapped_files=(),
            new_attack_surface=False,
        )

    file_risks: list[FileRisk] = []
    reasons: list[str] = []
    dependency_files: list[str] = []
    unmapped_files: list[str] = []
    has_critical = False
    has_moderate = False
    force_critical = False

    for changed_file in changed_files:
        normalized = normalize_path(changed_file.path)
        if not normalized:
            continue

        tier, pattern, is_unmapped = _match_file_tier(normalized, risk_map)
        dep_file = is_dependency_file(normalized)

        if tier == "critical":
            has_critical = True
        elif tier == "moderate":
            has_moderate = True

        if dep_file:
            dependency_files.append(normalized)
        if is_unmapped:
            unmapped_files.append(normalized)
        if _is_policy_context_path(normalized):
            force_critical = True

        file_risks.append(
            FileRisk(
                file_path=normalized,
                tier=tier,
                matched_pattern=pattern,
                is_unmapped=is_unmapped,
                is_dependency_file=dep_file,
            )
        )

    if force_critical:
        chunk_tier: RiskTier = "critical"
        reasons.append("policy_file_changed")
    elif has_critical:
        chunk_tier = "critical"
        reasons.append("critical_pattern_match")
    elif has_moderate:
        chunk_tier = "moderate"
        reasons.append("moderate_or_unmapped_file_present")
    else:
        chunk_tier = "skip"
        reasons.append("all_files_matched_skip_patterns")

    dependency_only = bool(file_risks) and all(
        file_risk.is_dependency_file for file_risk in file_risks
    )
    if chunk_tier == "skip" and dependency_files:
        chunk_tier = "moderate"
        reasons.append("dependency_change_promotion")

    if chunk_tier == "skip":
        if any(changed.status.upper().startswith("A") for changed in changed_files):
            chunk_tier = "moderate"
            reasons.append("skip_safeguard:new_file_in_skip_path")
        elif any(
            changed.status.upper().startswith("D")
            and _is_security_test_path(normalize_path(changed.path))
            for changed in changed_files
        ):
            chunk_tier = "moderate"
            reasons.append("skip_safeguard:deleted_security_test")
        elif any(
            _is_extensionless_non_doc(normalize_path(changed.path))
            for changed in changed_files
        ):
            chunk_tier = "moderate"
            reasons.append("skip_safeguard:extensionless_file")
        elif any(
            normalize_path(changed.path).startswith("scripts/")
            and any(_SCRIPT_EXEC_RE.search(line) for line in changed.added_lines)
            for changed in changed_files
        ):
            chunk_tier = "moderate"
            reasons.append("skip_safeguard:script_exec_eval_signal")

    mapped_top_levels = _collect_mapped_top_levels(risk_map)
    new_attack_surface = False
    for changed_file in changed_files:
        path = normalize_path(changed_file.path)
        if not path or path not in unmapped_files:
            continue
        top_level = path.split("/", 1)[0] if "/" in path else path
        has_security_keyword = any(
            keyword in path.lower() for keyword in SECURITY_KEYWORDS
        )
        if changed_file.status.upper().startswith("A") and (
            top_level not in mapped_top_levels or has_security_keyword
        ):
            new_attack_surface = True
            reasons.append("unmapped_new_attack_surface")
            break

    return ChunkRisk(
        tier=chunk_tier,
        model=RISK_MODEL_BY_TIER[chunk_tier],
        file_risks=tuple(file_risks),
        reasons=tuple(dict.fromkeys(reasons)),
        dependency_files=tuple(sorted(set(dependency_files))),
        dependency_only=dependency_only,
        unmapped_files=tuple(sorted(set(unmapped_files))),
        new_attack_surface=new_attack_surface,
    )


def load_threat_model_entries(threat_model_path: Path) -> list[dict[str, object]]:
    """Load THREAT_MODEL.json entries from list or wrapped ``{"threats": [...]}``."""
    raw = threat_model_path.read_text(encoding="utf-8")
    parsed = json.loads(raw)
    if isinstance(parsed, dict) and isinstance(parsed.get("threats"), list):
        parsed = parsed["threats"]
    if not isinstance(parsed, list):
        raise ValueError(
            "THREAT_MODEL.json must be a JSON array or an object with 'threats'."
        )
    return [entry for entry in parsed if isinstance(entry, dict)]


def resolve_component_globs(
    repo_root: Path,
    component: str,
    *,
    max_matches: int = 24,
) -> list[str]:
    """Resolve non-path component names to file globs using lightweight path matching."""
    token = component.strip().lower().replace("()", "")
    if not token:
        return []

    matches: list[str] = []
    for candidate in repo_root.rglob("*"):
        if not candidate.is_file():
            continue
        rel_path = normalize_path(str(candidate.relative_to(repo_root)))
        if token in rel_path.lower():
            matches.append(rel_path)
        if len(matches) >= max_matches:
            break

    globs: set[str] = set()
    for rel_path in matches:
        parts = rel_path.split("/")
        if len(parts) >= 2:
            globs.add(f"{parts[0]}/{parts[1]}*")
        elif parts:
            globs.add(f"{parts[0]}*")
    return sorted(globs)


def _iter_components(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                yield item


def _normalize_component_pattern(component: str) -> str:
    normalized = normalize_path(component)
    if normalized.endswith("()"):
        normalized = normalized[:-2]
    return normalized


def build_risk_map_from_threat_model(
    threats: Sequence[Mapping[str, object]],
    *,
    component_resolver: Callable[[str], Sequence[str]] | None = None,
    generated_at: str | None = None,
) -> dict[str, object]:
    """Build ``risk_map.json`` data from threat-model entries."""
    critical: set[str] = set()
    moderate: set[str] = set()

    for threat in threats:
        severity = str(threat.get("severity", "")).strip().lower()
        if severity not in {"critical", "high", "medium"}:
            continue
        target_bucket = critical if severity in {"critical", "high"} else moderate

        for component in _iter_components(threat.get("affected_components")):
            normalized = _normalize_component_pattern(component)
            if not normalized:
                continue

            resolved_patterns: list[str] = []
            if "/" in normalized or "*" in normalized:
                resolved_patterns.append(normalized)
            elif component_resolver is not None:
                resolved_patterns.extend(
                    normalize_path(item)
                    for item in component_resolver(normalized)
                    if normalize_path(item)
                )

            for pattern in resolved_patterns:
                target_bucket.add(pattern)

    timestamp = (
        generated_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    )
    if timestamp.endswith("+00:00"):
        timestamp = timestamp.replace("+00:00", "Z")

    return {
        "critical": sorted(critical),
        "moderate": sorted(moderate),
        "skip": sorted(set(STATIC_SKIP_PATTERNS)),
        "_meta": {
            "generated_from": "THREAT_MODEL.json",
            "generated_at": timestamp,
            "overrides_applied": False,
        },
    }


def load_risk_map(risk_map_path: Path) -> dict[str, object]:
    """Load and validate ``risk_map.json`` from disk."""
    raw = risk_map_path.read_text(encoding="utf-8")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("risk_map.json must be a JSON object.")

    for bucket in ("critical", "moderate", "skip"):
        value = parsed.get(bucket, [])
        if not isinstance(value, list) or not all(
            isinstance(item, str) for item in value
        ):
            raise ValueError(
                f"risk_map.json field '{bucket}' must be a list of strings."
            )

    return parsed


def save_risk_map(risk_map_path: Path, risk_map: Mapping[str, object]) -> None:
    """Persist risk map JSON with deterministic formatting."""
    risk_map_path.parent.mkdir(parents=True, exist_ok=True)
    risk_map_path.write_text(json.dumps(dict(risk_map), indent=2), encoding="utf-8")
