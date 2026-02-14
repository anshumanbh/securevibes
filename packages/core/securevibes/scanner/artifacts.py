"""Helpers for updating base artifacts after PR review."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


@dataclass
class ArtifactUpdateResult:
    """Summary of artifact updates."""

    threats_added: int
    vulnerabilities_added: int
    new_components_detected: bool


def update_pr_review_artifacts(
    securevibes_dir: Path, pr_vulns: list[Mapping[str, object]]
) -> ArtifactUpdateResult:
    """Update THREAT_MODEL.json and VULNERABILITIES.json from PR findings."""
    threat_model_path = securevibes_dir / "THREAT_MODEL.json"
    vulnerabilities_path = securevibes_dir / "VULNERABILITIES.json"

    threats = _load_json_list(threat_model_path)
    vulnerabilities = _load_json_list(vulnerabilities_path)

    existing_threat_ids = {
        str(threat.get("id")) for threat in threats if isinstance(threat, dict) and threat.get("id")
    }
    existing_vuln_keys = {_vuln_key(vuln) for vuln in vulnerabilities if isinstance(vuln, dict)}

    threats_added = 0
    vulnerabilities_added = 0

    # Snapshot before mutation so _detect_new_components sees pre-existing threats only
    existing_threats_snapshot = list(threats)

    for vuln in pr_vulns:
        if not isinstance(vuln, dict):
            continue

        finding_type = str(vuln.get("finding_type", "")).lower()
        if finding_type == "new_threat":
            threat = _convert_vuln_to_threat(vuln)
            threat_id = str(threat.get("id", ""))
            if threat_id and threat_id not in existing_threat_ids:
                threats.append(threat)
                existing_threat_ids.add(threat_id)
                threats_added += 1
            continue

        # These finding types indicate vulnerabilities to track
        if finding_type in {"known_vuln", "regression", "threat_enabler", "mitigation_removal"}:
            key = _vuln_key(vuln)
            if key not in existing_vuln_keys:
                entry = dict(vuln)
                entry["source"] = "pr_review"
                vulnerabilities.append(entry)
                existing_vuln_keys.add(key)
                vulnerabilities_added += 1
            continue

        # Fallback: treat missing/unknown finding_type as new vulnerability
        # This handles cases where the model doesn't output finding_type
        if not finding_type or finding_type in {"unknown", ""}:
            key = _vuln_key(vuln)
            if key not in existing_vuln_keys:
                entry = dict(vuln)
                entry["source"] = "pr_review"
                vulnerabilities.append(entry)
                existing_vuln_keys.add(key)
                vulnerabilities_added += 1

    if threats_added:
        _write_json_list(threat_model_path, threats)
    if vulnerabilities_added:
        _write_json_list(vulnerabilities_path, vulnerabilities)

    new_components_detected = _detect_new_components(pr_vulns, existing_threats_snapshot)

    return ArtifactUpdateResult(
        threats_added=threats_added,
        vulnerabilities_added=vulnerabilities_added,
        new_components_detected=new_components_detected,
    )


def _load_json_list(path: Path) -> list[object]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def _write_json_list(path: Path, data: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _convert_vuln_to_threat(vuln: Mapping[str, object]) -> dict[str, object]:
    return {
        "id": str(vuln.get("threat_id", "")),
        "category": "PR-Review",
        "title": str(vuln.get("title", "")),
        "description": str(vuln.get("description", "")),
        "severity": str(vuln.get("severity", "")),
        "affected_components": _derive_components_from_file_path(str(vuln.get("file_path", ""))),
    }


def _derive_components_from_file_path(file_path: str) -> list[str]:
    if not file_path:
        return []
    parts = file_path.split("/")
    top_level = parts[0] if len(parts) > 1 else ""
    ext = Path(file_path).suffix.lstrip(".")
    if top_level and ext:
        return [f"{top_level}:{ext}"]
    if top_level:
        return [top_level]
    if ext:
        return [ext]
    return []


def _vuln_key(vuln: Mapping[str, object]) -> tuple[str, str, int, str]:
    file_path = str(vuln.get("file_path", ""))
    title = str(vuln.get("title", ""))
    severity = str(vuln.get("severity", ""))
    line_number = _coerce_int(vuln.get("line_number"))
    return (file_path, title, line_number, severity)


def _coerce_int(value: object) -> int:
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0


def _detect_new_components(pr_vulns: list[Mapping[str, object]], threats: list[object]) -> bool:
    existing_components: set[str] = set()
    for threat in threats:
        if not isinstance(threat, dict):
            continue
        components = threat.get("affected_components")
        if isinstance(components, list):
            for item in components:
                if isinstance(item, str) and item:
                    existing_components.add(item)

    pr_components: set[str] = set()
    for vuln in pr_vulns:
        if not isinstance(vuln, dict):
            continue
        for comp in _derive_components_from_file_path(str(vuln.get("file_path", ""))):
            if comp:
                pr_components.add(comp)

    if not pr_components:
        return False
    if not existing_components:
        return True
    return any(comp not in existing_components for comp in pr_components)
