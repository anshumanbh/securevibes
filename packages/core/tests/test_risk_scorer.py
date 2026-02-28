"""Tests for threat-aware incremental risk scoring."""

from __future__ import annotations

from securevibes.scanner.risk_scorer import (
    ChangedFile,
    build_risk_map_from_threat_model,
    classify_chunk,
)


def test_classify_chunk_matches_globs_and_unmapped_defaults_to_moderate() -> None:
    risk_map = {
        "critical": ["src/security/*"],
        "moderate": ["src/api/*"],
        "skip": ["docs/*"],
    }
    changed_files = [
        ChangedFile(path="src/security/auth.py", status="M"),
        ChangedFile(path="src/new/module.py", status="M"),
        ChangedFile(path="docs/readme.md", status="M"),
    ]

    result = classify_chunk(changed_files, risk_map)

    assert result.tier == "critical"
    assert "src/new/module.py" in result.unmapped_files
    assert any(
        file_risk.file_path == "docs/readme.md" and file_risk.tier == "skip"
        for file_risk in result.file_risks
    )


def test_dependency_change_promotes_skip_chunk_to_moderate() -> None:
    risk_map = {
        "critical": [],
        "moderate": [],
        "skip": ["docs/*", "package.json"],
    }
    changed_files = [
        ChangedFile(path="docs/notes.md", status="M"),
        ChangedFile(path="package.json", status="M"),
    ]

    result = classify_chunk(changed_files, risk_map)

    assert result.tier == "moderate"
    assert "dependency_change_promotion" in result.reasons
    assert result.dependency_only is False


def test_dependency_only_chunk_sets_dependency_only_flag() -> None:
    risk_map = {
        "critical": [],
        "moderate": [],
        "skip": ["package.json", "requirements.txt"],
    }
    changed_files = [
        ChangedFile(path="package.json", status="M"),
        ChangedFile(path="requirements.txt", status="M"),
    ]

    result = classify_chunk(changed_files, risk_map)

    assert result.tier == "moderate"
    assert result.dependency_only is True


def test_skip_safeguard_new_file_in_skip_path_promotes_to_moderate() -> None:
    risk_map = {"critical": [], "moderate": [], "skip": ["docs/*"]}
    changed_files = [ChangedFile(path="docs/new-guide.md", status="A")]

    result = classify_chunk(changed_files, risk_map)

    assert result.tier == "moderate"
    assert "skip_safeguard:new_file_in_skip_path" in result.reasons


def test_policy_file_change_forces_critical_tier() -> None:
    risk_map = {"critical": [], "moderate": [], "skip": ["docs/*"]}
    changed_files = [ChangedFile(path=".securevibes/THREAT_MODEL.json", status="M")]

    result = classify_chunk(changed_files, risk_map)

    assert result.tier == "critical"
    assert "policy_file_changed" in result.reasons


def test_build_risk_map_from_threat_model_maps_severity_to_tier() -> None:
    threats = [
        {"id": "T1", "severity": "high", "affected_components": ["src/auth/*"]},
        {"id": "T2", "severity": "medium", "affected_components": ["src/http/*"]},
        {"id": "T3", "severity": "low", "affected_components": ["src/docs/*"]},
    ]

    risk_map = build_risk_map_from_threat_model(
        threats,
        generated_at="2026-02-28T00:00:00Z",
    )

    assert "src/auth/*" in risk_map["critical"]
    assert "src/http/*" in risk_map["moderate"]
    assert "docs/*" in risk_map["skip"]
    assert risk_map["_meta"]["generated_from"] == "THREAT_MODEL.json"
