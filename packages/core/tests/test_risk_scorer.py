"""Tests for threat-aware incremental risk scoring."""

from __future__ import annotations

import json

import pytest

from securevibes.scanner.risk_scorer import (
    ChangedFile,
    build_risk_map_from_threat_model,
    classify_chunk,
    load_risk_map,
    load_threat_model_entries,
    resolve_component_globs,
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


def test_skip_safeguard_new_non_doc_file_in_skip_path_promotes_to_moderate() -> None:
    risk_map = {"critical": [], "moderate": [], "skip": ["scripts/*"]}
    changed_files = [ChangedFile(path="scripts/release.sh", status="A")]

    result = classify_chunk(changed_files, risk_map)

    assert result.tier == "moderate"
    assert "skip_safeguard:new_file_in_skip_path" in result.reasons


def test_new_markdown_file_in_skip_path_stays_skip() -> None:
    risk_map = {"critical": [], "moderate": [], "skip": ["docs/*"]}
    changed_files = [ChangedFile(path="docs/new-guide.md", status="A")]

    result = classify_chunk(changed_files, risk_map)

    assert result.tier == "skip"
    assert "skip_safeguard:new_file_in_skip_path" not in result.reasons


def test_policy_file_change_forces_critical_tier() -> None:
    risk_map = {"critical": [], "moderate": [], "skip": ["docs/*"]}
    changed_files = [ChangedFile(path=".securevibes/THREAT_MODEL.json", status="M")]

    result = classify_chunk(changed_files, risk_map)

    assert result.tier == "critical"
    assert "policy_file_changed" in result.reasons


def test_skip_safeguard_deleted_security_test_promotes_to_moderate() -> None:
    risk_map = {"critical": [], "moderate": [], "skip": ["*.spec.ts"]}
    changed_files = [ChangedFile(path="src/auth.spec.ts", status="D")]

    result = classify_chunk(changed_files, risk_map)

    assert result.tier == "moderate"
    assert "skip_safeguard:deleted_security_test" in result.reasons


def test_skip_safeguard_extensionless_file_promotes_to_moderate() -> None:
    risk_map = {"critical": [], "moderate": [], "skip": ["*"]}
    changed_files = [ChangedFile(path="Makefile", status="M")]

    result = classify_chunk(changed_files, risk_map)

    assert result.tier == "moderate"
    assert "skip_safeguard:extensionless_file" in result.reasons


def test_skip_safeguard_script_exec_signal_promotes_to_moderate() -> None:
    risk_map = {"critical": [], "moderate": [], "skip": ["scripts/*"]}
    changed_files = [
        ChangedFile(path="scripts/deploy.js", status="M", added_lines=("exec(cmd)",)),
    ]

    result = classify_chunk(changed_files, risk_map)

    assert result.tier == "moderate"
    assert "skip_safeguard:script_exec_eval_signal" in result.reasons


def test_mixed_tier_chunk_uses_highest_risk_file() -> None:
    risk_map = {
        "critical": ["src/security/*"],
        "moderate": [],
        "skip": ["docs/*"],
    }
    changed_files = [
        ChangedFile(path="docs/readme.md", status="M"),
        ChangedFile(path="src/security/auth.py", status="M"),
    ]

    result = classify_chunk(changed_files, risk_map)

    assert result.tier == "critical"


def test_unmapped_new_top_level_is_flagged_as_new_attack_surface() -> None:
    risk_map = {
        "critical": [],
        "moderate": ["src/app/*"],
        "skip": ["docs/*"],
    }
    changed_files = [ChangedFile(path="new-module/readme.md", status="A")]

    result = classify_chunk(changed_files, risk_map)

    assert result.tier == "moderate"
    assert result.new_attack_surface is True
    assert "unmapped_new_attack_surface" in result.reasons


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


def test_load_threat_model_entries_accepts_wrapped_and_list_formats(
    tmp_path,
) -> None:
    list_path = tmp_path / "THREAT_MODEL-list.json"
    wrapped_path = tmp_path / "THREAT_MODEL-wrapped.json"
    payload = [{"id": "T1", "severity": "high"}]
    list_path.write_text(json.dumps(payload), encoding="utf-8")
    wrapped_path.write_text(json.dumps({"threats": payload}), encoding="utf-8")

    assert load_threat_model_entries(list_path) == payload
    assert load_threat_model_entries(wrapped_path) == payload


def test_load_risk_map_requires_all_tier_buckets(tmp_path) -> None:
    risk_map_path = tmp_path / "risk_map.json"
    risk_map_path.write_text(json.dumps({"critical": [], "moderate": []}), encoding="utf-8")

    with pytest.raises(ValueError, match="missing required field"):
        load_risk_map(risk_map_path)


def test_resolve_component_globs_honors_max_depth(tmp_path) -> None:
    deep_dir = tmp_path / "a" / "b" / "c" / "d" / "e" / "f" / "g"
    deep_dir.mkdir(parents=True)
    deep_file = deep_dir / "gateway_handler.py"
    deep_file.write_text("pass", encoding="utf-8")

    shallow_globs = resolve_component_globs(tmp_path, "gateway", max_depth=4)
    deep_globs = resolve_component_globs(tmp_path, "gateway", max_depth=10)

    assert shallow_globs == []
    assert any(glob.startswith("a/b") for glob in deep_globs)
