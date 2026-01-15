"""Tests for SubAgentManager"""

import json
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch

from securevibes.scanner.subagent_manager import (
    SubAgentManager,
    ScanMode,
    SUBAGENT_ARTIFACTS,
    SUBAGENT_ORDER,
)


@pytest.fixture
def temp_repo(tmp_path):
    """Create a temporary repository with .securevibes directory"""
    repo = tmp_path / "test_repo"
    repo.mkdir()
    securevibes = repo / ".securevibes"
    securevibes.mkdir()
    return repo


@pytest.fixture
def manager(temp_repo):
    """Create SubAgentManager instance"""
    return SubAgentManager(temp_repo, quiet=True)


def test_check_artifact_missing(manager, temp_repo):
    """Test artifact check when file doesn't exist"""
    status = manager.check_artifact("VULNERABILITIES.json")

    assert status.exists is False
    assert status.path is None
    assert status.valid is False


def test_check_artifact_valid_json(manager, temp_repo):
    """Test artifact check with valid JSON file"""
    vuln_file = temp_repo / ".securevibes" / "VULNERABILITIES.json"
    vulnerabilities = [
        {
            "id": "VULN-1",
            "severity": "high",
            "title": "SQL Injection",
            "description": "Test vulnerability",
            "file_path": "app.py",
            "line_number": 10,
        }
    ]
    vuln_file.write_text(json.dumps(vulnerabilities, indent=2))

    status = manager.check_artifact("VULNERABILITIES.json")

    assert status.exists is True
    assert status.valid is True
    assert status.issue_count == 1
    assert status.age_hours is not None
    assert status.age_hours < 1  # Just created
    assert status.size_bytes > 0


def test_check_artifact_invalid_json(manager, temp_repo):
    """Test artifact check with corrupted JSON"""
    vuln_file = temp_repo / ".securevibes" / "VULNERABILITIES.json"
    vuln_file.write_text("{ invalid json")

    status = manager.check_artifact("VULNERABILITIES.json")

    assert status.exists is True
    assert status.valid is False
    assert "Invalid JSON" in status.error


def test_check_artifact_empty_markdown(manager, temp_repo):
    """Test artifact check with empty markdown file"""
    security_file = temp_repo / ".securevibes" / "SECURITY.md"
    security_file.write_text("")

    status = manager.check_artifact("SECURITY.md")

    assert status.exists is True
    assert status.valid is False
    assert status.error == "Empty file"


def test_check_artifact_valid_markdown(manager, temp_repo):
    """Test artifact check with valid markdown"""
    security_file = temp_repo / ".securevibes" / "SECURITY.md"
    security_file.write_text("# Security Assessment\n\nThis is a test.")

    status = manager.check_artifact("SECURITY.md")

    assert status.exists is True
    assert status.valid is True
    assert status.error is None


def test_check_artifact_old_file(manager, temp_repo):
    """Test artifact age warning"""
    vuln_file = temp_repo / ".securevibes" / "VULNERABILITIES.json"
    vuln_file.write_text("[]")

    # Modify timestamp to be 48 hours ago
    old_time = (datetime.now() - timedelta(hours=48)).timestamp()
    vuln_file.touch()
    import os

    os.utime(vuln_file, (old_time, old_time))

    status = manager.check_artifact("VULNERABILITIES.json")

    assert status.exists is True
    assert status.age_hours >= 47  # Allow some tolerance


def test_get_subagent_dependencies_assessment(manager):
    """Test dependencies for assessment sub-agent"""
    deps = manager.get_subagent_dependencies("assessment")

    assert deps["creates"] == "SECURITY.md"
    assert deps["requires"] is None


def test_get_subagent_dependencies_code_review(manager):
    """Test dependencies for code-review sub-agent"""
    deps = manager.get_subagent_dependencies("code-review")

    assert deps["creates"] == "VULNERABILITIES.json"
    assert deps["requires"] == "THREAT_MODEL.json"


def test_get_subagent_dependencies_dast(manager):
    """Test dependencies for dast sub-agent"""
    deps = manager.get_subagent_dependencies("dast")

    assert deps["creates"] == "DAST_VALIDATION.json"
    assert deps["requires"] == "VULNERABILITIES.json"


def test_get_subagent_dependencies_invalid(manager):
    """Test error for unknown sub-agent"""
    with pytest.raises(ValueError, match="Unknown sub-agent"):
        manager.get_subagent_dependencies("invalid-agent")


def test_get_resume_subagents_from_assessment(manager):
    """Test resume list from assessment"""
    subagents = manager.get_resume_subagents("assessment")

    assert subagents == ["assessment", "threat-modeling", "code-review", "report-generator", "dast"]


def test_get_resume_subagents_from_code_review(manager):
    """Test resume list from code-review"""
    subagents = manager.get_resume_subagents("code-review")

    assert subagents == ["code-review", "report-generator", "dast"]


def test_get_resume_subagents_from_dast(manager):
    """Test resume list from dast"""
    subagents = manager.get_resume_subagents("dast")

    assert subagents == ["dast"]


def test_get_resume_subagents_invalid(manager):
    """Test error for unknown sub-agent"""
    with pytest.raises(ValueError, match="Unknown sub-agent"):
        manager.get_resume_subagents("invalid-agent")


def test_validate_prerequisites_assessment(manager):
    """Test prerequisite validation for assessment (no prerequisites)"""
    is_valid, error = manager.validate_prerequisites("assessment")

    assert is_valid is True
    assert error is None


def test_validate_prerequisites_missing(manager, temp_repo):
    """Test prerequisite validation when file missing"""
    is_valid, error = manager.validate_prerequisites("threat-modeling")

    assert is_valid is False
    assert "Missing prerequisite: SECURITY.md" in error


def test_validate_prerequisites_valid(manager, temp_repo):
    """Test prerequisite validation with valid file"""
    security_file = temp_repo / ".securevibes" / "SECURITY.md"
    security_file.write_text("# Security Assessment")

    is_valid, error = manager.validate_prerequisites("threat-modeling")

    assert is_valid is True
    assert error is None


def test_validate_prerequisites_invalid_json(manager, temp_repo):
    """Test prerequisite validation with corrupted file"""
    threat_file = temp_repo / ".securevibes" / "THREAT_MODEL.json"
    threat_file.write_text("{ invalid")

    is_valid, error = manager.validate_prerequisites("code-review")

    assert is_valid is False
    assert "Invalid prerequisite" in error


@patch("click.prompt")
def test_prompt_user_choice_use_existing(mock_prompt, manager, temp_repo):
    """Test user chooses to use existing artifact"""
    vuln_file = temp_repo / ".securevibes" / "VULNERABILITIES.json"
    vuln_file.write_text("[]")

    mock_prompt.return_value = 1

    status = manager.check_artifact("VULNERABILITIES.json")
    mode = manager.prompt_user_choice("dast", status, force=False)

    assert mode == ScanMode.USE_EXISTING


@patch("click.prompt")
def test_prompt_user_choice_full_rescan(mock_prompt, manager, temp_repo):
    """Test user chooses full rescan"""
    vuln_file = temp_repo / ".securevibes" / "VULNERABILITIES.json"
    vuln_file.write_text("[]")

    mock_prompt.return_value = 2

    status = manager.check_artifact("VULNERABILITIES.json")
    mode = manager.prompt_user_choice("dast", status, force=False)

    assert mode == ScanMode.FULL_RESCAN


@patch("click.prompt")
def test_prompt_user_choice_cancel(mock_prompt, manager, temp_repo):
    """Test user cancels"""
    vuln_file = temp_repo / ".securevibes" / "VULNERABILITIES.json"
    vuln_file.write_text("[]")

    mock_prompt.return_value = 3

    status = manager.check_artifact("VULNERABILITIES.json")
    mode = manager.prompt_user_choice("dast", status, force=False)

    assert mode == ScanMode.CANCEL


def test_prompt_user_choice_force(manager, temp_repo):
    """Test force mode skips prompts"""
    vuln_file = temp_repo / ".securevibes" / "VULNERABILITIES.json"
    vuln_file.write_text("[]")

    status = manager.check_artifact("VULNERABILITIES.json")
    mode = manager.prompt_user_choice("dast", status, force=True)

    assert mode == ScanMode.USE_EXISTING


def test_format_age_minutes(manager):
    """Test age formatting for minutes"""
    age_str = manager._format_age(0.5)
    assert age_str == "30m ago"


def test_format_age_hours(manager):
    """Test age formatting for hours"""
    age_str = manager._format_age(5.5)
    assert age_str == "5h ago"


def test_format_age_days(manager):
    """Test age formatting for days"""
    age_str = manager._format_age(50.0)
    assert age_str == "2d ago"


def test_format_size_bytes(manager):
    """Test size formatting for bytes"""
    size_str = manager._format_size(512)
    assert size_str == "512B"


def test_format_size_kilobytes(manager):
    """Test size formatting for kilobytes"""
    size_str = manager._format_size(5120)
    assert size_str == "5.0KB"


def test_format_size_megabytes(manager):
    """Test size formatting for megabytes"""
    size_str = manager._format_size(5242880)
    assert size_str == "5.0MB"


def test_subagent_artifacts_structure():
    """Test SUBAGENT_ARTIFACTS has correct structure"""
    required_keys = ["creates", "requires", "description"]

    for subagent, config in SUBAGENT_ARTIFACTS.items():
        assert all(key in config for key in required_keys), f"{subagent} missing required keys"


def test_subagent_order_completeness():
    """Test SUBAGENT_ORDER contains all sub-agents"""
    assert len(SUBAGENT_ORDER) == 5
    assert "assessment" in SUBAGENT_ORDER
    assert "threat-modeling" in SUBAGENT_ORDER
    assert "code-review" in SUBAGENT_ORDER
    assert "report-generator" in SUBAGENT_ORDER
    assert "dast" in SUBAGENT_ORDER


def test_scan_results_json_structure(manager, temp_repo):
    """Test scan_results.json structure detection"""
    results_file = temp_repo / ".securevibes" / "scan_results.json"
    results = {
        "repository_path": "/test",
        "issues": [{"id": "1", "severity": "high", "title": "Test"}],
    }
    results_file.write_text(json.dumps(results, indent=2))

    status = manager.check_artifact("scan_results.json")

    assert status.exists is True
    assert status.valid is True
    assert status.issue_count == 1
