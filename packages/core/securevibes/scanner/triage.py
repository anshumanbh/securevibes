"""Security triage pre-filter for PR review budget optimization."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from securevibes.diff.context import (
    normalize_repo_path,
    _load_threat_model,
)
from securevibes.diff.parser import DiffContext
from securevibes.scanner.artifacts import _derive_components_from_file_path
from securevibes.scanner.chain_analysis import (
    diff_file_path,
    diff_has_auth_privilege_signals,
    diff_has_command_builder_signals,
    diff_has_path_parser_signals,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

TriageClassification = Literal["security_relevant", "low_risk"]

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TriageOverrides:
    pr_review_attempts: int
    pr_timeout_seconds: int


@dataclass(frozen=True)
class SecuritySurfaceMap:
    vuln_paths: frozenset[str]
    affected_components: frozenset[str]


@dataclass(frozen=True)
class TriageResult:
    classification: TriageClassification
    reasons: tuple[str, ...]
    max_file_score: int
    detector_hits: tuple[str, ...]
    matched_vuln_paths: tuple[str, ...]
    matched_components: tuple[str, ...]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LOW_RISK_ATTEMPTS = 1
_LOW_RISK_TIMEOUT = 60
_SCORE_THRESHOLD = 72

# Doc/test path patterns for fail-closed exclusion
_DOC_PATH_PREFIXES = ("docs/", "doc/")
_TEST_PATH_MARKERS = ("/test/", "/tests/", "/__tests__/", ".test.", ".spec.", "_test.")


def _is_doc_or_test_path(path: str) -> bool:
    """Return True if path is obviously a doc or test file by convention."""
    lower = path.lower()
    if any(lower.startswith(prefix) for prefix in _DOC_PATH_PREFIXES):
        return True
    if any(marker in lower for marker in _TEST_PATH_MARKERS):
        return True
    # Avoid false positives like "contest_runner" matching a raw "test_" substring.
    if Path(lower).name.startswith("test_"):
        return True
    return False


# ---------------------------------------------------------------------------
# Surface map builder
# ---------------------------------------------------------------------------


def build_security_surface_map(securevibes_dir: Path) -> SecuritySurfaceMap:
    """Load baseline artifacts and build a deterministic security surface map."""
    vuln_paths: set[str] = set()
    affected_components: set[str] = set()

    # Load VULNERABILITIES.json
    vulns_path = securevibes_dir / "VULNERABILITIES.json"
    if vulns_path.exists():
        try:
            raw = vulns_path.read_text(encoding="utf-8", errors="ignore")
            if raw.strip():
                data = json.loads(raw)
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, dict):
                            fp = entry.get("file_path")
                            if isinstance(fp, str):
                                normalized = normalize_repo_path(fp).lower()
                                if normalized:
                                    vuln_paths.add(normalized)
        except (OSError, json.JSONDecodeError) as exc:
            logger.debug("Triage: could not load VULNERABILITIES.json: %s", exc)

    # Load THREAT_MODEL.json (reuse wrapper-compatible loader)
    threat_model_path = securevibes_dir / "THREAT_MODEL.json"
    if threat_model_path.exists():
        try:
            entries = _load_threat_model(threat_model_path)
            for entry in entries:
                components = entry.get("affected_components")
                if isinstance(components, list):
                    for comp in components:
                        if isinstance(comp, str):
                            normalized = comp.strip().lower()
                            if normalized:
                                affected_components.add(normalized)
                elif isinstance(components, str):
                    normalized = components.strip().lower()
                    if normalized:
                        affected_components.add(normalized)
        except OSError as exc:
            logger.debug("Triage: could not load THREAT_MODEL.json: %s", exc)

    return SecuritySurfaceMap(
        vuln_paths=frozenset(vuln_paths),
        affected_components=frozenset(affected_components),
    )


# ---------------------------------------------------------------------------
# Core triage logic
# ---------------------------------------------------------------------------


def triage_diff(
    diff_context: DiffContext,
    securevibes_dir: Path | None = None,
    *,
    surface_map: SecuritySurfaceMap | None = None,
) -> TriageResult:
    """Classify a diff as security_relevant or low_risk."""
    # Resolve surface map
    if surface_map is None:
        if securevibes_dir is not None:
            surface_map = build_security_surface_map(securevibes_dir)
        else:
            surface_map = SecuritySurfaceMap(
                vuln_paths=frozenset(),
                affected_components=frozenset(),
            )

    reasons: list[str] = []
    detector_hits: list[str] = []
    matched_vuln_paths: list[str] = []
    matched_components: list[str] = []
    max_file_score = 0

    # Import scoring function (lazy to avoid import cycle)
    from securevibes.scanner.scanner import (
        NON_CODE_SUFFIXES,
        score_diff_file_for_security_review,
    )

    # --- Step 1: Fail-closed file-shape checks ---
    for diff_file in diff_context.files:
        path = diff_file_path(diff_file)
        if not path:
            continue
        lower_path = path.lower()

        # 1a. No hunks (parser blind spot / binary metadata)
        if len(diff_file.hunks) == 0:
            reasons.append(f"fail_closed:no_hunks:{path}")
            continue

        # 1b. Extensionless file outside docs/tests
        suffix = Path(lower_path).suffix.lower()
        if suffix == "" and not _is_doc_or_test_path(lower_path):
            reasons.append(f"fail_closed:extensionless:{path}")
            continue

        # 1c. New code file (not in NON_CODE_SUFFIXES, not docs/test)
        if diff_file.is_new and suffix not in NON_CODE_SUFFIXES and not _is_doc_or_test_path(lower_path):
            reasons.append(f"fail_closed:new_code_file:{path}")

    # --- Step 2: Signal detectors ---
    if diff_has_command_builder_signals(diff_context):
        reasons.append("signal:command_builder")
        detector_hits.append("command_builder")
    if diff_has_path_parser_signals(diff_context):
        reasons.append("signal:path_parser")
        detector_hits.append("path_parser")
    if diff_has_auth_privilege_signals(diff_context):
        reasons.append("signal:auth_privilege")
        detector_hits.append("auth_privilege")

    # --- Step 3: File scoring ---
    for diff_file in diff_context.files:
        score = score_diff_file_for_security_review(diff_file)
        max_file_score = max(max_file_score, score)
        if score >= _SCORE_THRESHOLD:
            path = diff_file_path(diff_file)
            reasons.append(f"score_threshold:{path}:{score}")

    # --- Step 4: Baseline surface exact matches ---
    for diff_file in diff_context.files:
        path = diff_file_path(diff_file)
        if not path:
            continue
        normalized = normalize_repo_path(path).lower()

        # 4a. Exact vuln path match
        if normalized in surface_map.vuln_paths:
            reasons.append(f"baseline_vuln_path:{normalized}")
            matched_vuln_paths.append(normalized)

        # 4b. Exact component match via _derive_components_from_file_path
        derived_components = _derive_components_from_file_path(path)
        for comp in derived_components:
            comp_lower = comp.strip().lower()
            if comp_lower in surface_map.affected_components:
                reasons.append(f"baseline_component:{comp_lower}")
                matched_components.append(comp_lower)

    # --- Step 5: Determine classification ---
    # Any reason that is NOT "default:low_risk" means security_relevant
    security_reasons = [r for r in reasons if not r.startswith("default:")]
    if security_reasons:
        return TriageResult(
            classification="security_relevant",
            reasons=tuple(reasons),
            max_file_score=max_file_score,
            detector_hits=tuple(detector_hits),
            matched_vuln_paths=tuple(matched_vuln_paths),
            matched_components=tuple(matched_components),
        )

    # Default: low_risk
    reasons.append("default:low_risk")
    return TriageResult(
        classification="low_risk",
        reasons=tuple(reasons),
        max_file_score=max_file_score,
        detector_hits=tuple(detector_hits),
        matched_vuln_paths=tuple(matched_vuln_paths),
        matched_components=tuple(matched_components),
    )


# ---------------------------------------------------------------------------
# Override computation
# ---------------------------------------------------------------------------


def compute_triage_overrides(triage_result: TriageResult) -> TriageOverrides | None:
    """Return reduced budget overrides for low_risk, None for security_relevant."""
    if triage_result.classification == "low_risk":
        return TriageOverrides(
            pr_review_attempts=_LOW_RISK_ATTEMPTS,
            pr_timeout_seconds=_LOW_RISK_TIMEOUT,
        )
    return None
