"""Tests for THREAT_MODEL.json schema validation and auto-fix."""

import json

from securevibes.models.schemas import fix_threat_model_json, validate_threat_model_json


def _threat(tid: str) -> dict:
    return {
        "id": tid,
        "category": "Spoofing",
        "title": "Test threat",
        "description": "Test description",
        "severity": "high",
    }


def test_fix_threat_model_unwraps_threats_key():
    content = json.dumps({"threats": [_threat("THREAT-001")]})
    fixed, modified = fix_threat_model_json(content)

    assert modified is True
    assert json.loads(fixed) == [_threat("THREAT-001")]


def test_fix_threat_model_strips_code_fences():
    content = "```json\n" + json.dumps([_threat("THREAT-001")]) + "\n```"
    fixed, modified = fix_threat_model_json(content)

    assert modified is True
    assert json.loads(fixed) == [_threat("THREAT-001")]


def test_validate_threat_model_allows_non_agentic_without_asi():
    content = json.dumps([_threat("THREAT-001")])
    is_valid, error, warnings = validate_threat_model_json(content, require_asi=False)

    assert is_valid is True
    assert error is None
    assert isinstance(warnings, list)


def test_validate_threat_model_requires_asi_when_configured():
    content = json.dumps([_threat("THREAT-001")])
    is_valid, error, _warnings = validate_threat_model_json(content, require_asi=True)

    assert is_valid is False
    assert error is not None
    assert "ASI" in error


def test_validate_threat_model_warns_on_missing_critical_asi_categories():
    content = json.dumps([_threat("THREAT-ASI01-001")])
    is_valid, error, warnings = validate_threat_model_json(content, require_asi=True)

    assert is_valid is True
    assert error is None
    assert any("ASI03" in w for w in warnings)
