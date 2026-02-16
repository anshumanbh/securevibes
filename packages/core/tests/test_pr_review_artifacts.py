"""Tests for PR review artifact updates."""

import json
from collections import UserDict
from pathlib import Path

import pytest

from securevibes.scanner import artifacts as artifacts_module
from securevibes.scanner.artifacts import ArtifactLoadError, update_pr_review_artifacts


def test_update_pr_review_artifacts_appends_entries(tmp_path: Path):
    securevibes_dir = tmp_path / ".securevibes"
    securevibes_dir.mkdir()

    threat_model_path = securevibes_dir / "THREAT_MODEL.json"
    vulnerabilities_path = securevibes_dir / "VULNERABILITIES.json"

    threat_model_path.write_text("[]", encoding="utf-8")
    vulnerabilities_path.write_text("[]", encoding="utf-8")

    pr_vulns = [
        {
            "threat_id": "NEW-001",
            "finding_type": "new_threat",
            "title": "New input vector",
            "description": "New attack surface",
            "severity": "high",
            "file_path": "ui/app.ts",
            "line_number": 10,
            "code_snippet": "dangerous()",
            "attack_scenario": "abuse",
            "evidence": "evidence",
            "cwe_id": "CWE-20",
            "recommendation": "validate",
        },
        {
            "threat_id": "THREAT-001",
            "finding_type": "known_vuln",
            "title": "Known threat enabled",
            "description": "Existing threat now exploitable",
            "severity": "medium",
            "file_path": "api/app.py",
            "line_number": 22,
            "code_snippet": "dangerous()",
            "attack_scenario": "abuse",
            "evidence": "evidence",
            "cwe_id": "CWE-79",
            "recommendation": "fix",
        },
    ]

    result = update_pr_review_artifacts(securevibes_dir, pr_vulns)

    assert result.threats_added == 1
    assert result.vulnerabilities_added == 1
    assert result.new_components_detected is True

    threats = json.loads(threat_model_path.read_text(encoding="utf-8"))
    vulns = json.loads(vulnerabilities_path.read_text(encoding="utf-8"))

    assert len(threats) == 1
    assert threats[0]["id"] == "NEW-001"
    assert len(vulns) == 1
    assert vulns[0]["threat_id"] == "THREAT-001"
    assert vulns[0]["source"] == "pr_review"


def test_update_pr_review_artifacts_dedupes_vulnerabilities(tmp_path: Path):
    securevibes_dir = tmp_path / ".securevibes"
    securevibes_dir.mkdir()

    vulnerabilities_path = securevibes_dir / "VULNERABILITIES.json"
    vulnerabilities_path.write_text(
        json.dumps(
            [
                {
                    "threat_id": "THREAT-001",
                    "title": "Known threat enabled",
                    "description": "Existing threat now exploitable",
                    "severity": "medium",
                    "file_path": "api/app.py",
                    "line_number": 22,
                    "code_snippet": "dangerous()",
                    "cwe_id": "CWE-79",
                    "recommendation": "fix",
                    "evidence": "evidence",
                }
            ],
            indent=2,
        ),
        encoding="utf-8",
    )

    pr_vulns = [
        {
            "threat_id": "THREAT-001",
            "finding_type": "known_vuln",
            "title": "Known threat enabled",
            "description": "Existing threat now exploitable",
            "severity": "medium",
            "file_path": "api/app.py",
            "line_number": 22,
            "code_snippet": "dangerous()",
            "attack_scenario": "abuse",
            "evidence": "evidence",
            "cwe_id": "CWE-79",
            "recommendation": "fix",
        }
    ]

    result = update_pr_review_artifacts(securevibes_dir, pr_vulns)

    assert result.vulnerabilities_added == 0
    vulns = json.loads(vulnerabilities_path.read_text(encoding="utf-8"))
    assert len(vulns) == 1


def test_update_pr_review_artifacts_adds_unknown_as_vulnerability(tmp_path: Path):
    """Unknown or missing finding_type should be added to VULNERABILITIES.json.

    This handles cases where the model doesn't output finding_type - we default
    to treating them as vulnerabilities rather than silently dropping them.
    """
    securevibes_dir = tmp_path / ".securevibes"
    securevibes_dir.mkdir()
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    (securevibes_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

    pr_vulns = [
        {
            "threat_id": "NEW-999",
            "finding_type": "unknown",
            "title": "Unknown",
            "description": "Unknown",
            "severity": "low",
            "file_path": "misc.txt",
            "line_number": 1,
            "code_snippet": "",
            "attack_scenario": "",
            "evidence": "",
            "cwe_id": "",
            "recommendation": "",
        }
    ]

    result = update_pr_review_artifacts(securevibes_dir, pr_vulns)

    assert result.threats_added == 0
    assert result.vulnerabilities_added == 1  # unknown is now added as vulnerability

    vulns = json.loads((securevibes_dir / "VULNERABILITIES.json").read_text(encoding="utf-8"))
    assert vulns[0]["source"] == "pr_review"


def test_update_pr_review_artifacts_adds_missing_finding_type(tmp_path: Path):
    """Vulnerabilities with no finding_type should be added to VULNERABILITIES.json."""
    securevibes_dir = tmp_path / ".securevibes"
    securevibes_dir.mkdir()
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    (securevibes_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

    pr_vulns = [
        {
            "threat_id": "PR-VULN-001",
            # No finding_type field at all
            "title": "Missing finding_type",
            "description": "Model did not output finding_type",
            "severity": "high",
            "file_path": "app.ts",
            "line_number": 50,
            "code_snippet": "vulnerable()",
            "attack_scenario": "attack",
            "evidence": "evidence",
            "cwe_id": "CWE-79",
            "recommendation": "fix",
        }
    ]

    result = update_pr_review_artifacts(securevibes_dir, pr_vulns)

    assert result.threats_added == 0
    assert result.vulnerabilities_added == 1

    vulns = json.loads((securevibes_dir / "VULNERABILITIES.json").read_text(encoding="utf-8"))
    assert vulns[0]["source"] == "pr_review"


def test_update_pr_review_artifacts_handles_threat_enabler(tmp_path: Path):
    """threat_enabler finding_type should be added to VULNERABILITIES.json."""
    securevibes_dir = tmp_path / ".securevibes"
    securevibes_dir.mkdir()
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    (securevibes_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

    pr_vulns = [
        {
            "threat_id": "THREAT-001-ENABLED",
            "finding_type": "threat_enabler",
            "title": "Existing threat now exploitable",
            "description": "Change enables exploitation of existing threat",
            "severity": "high",
            "file_path": "auth/login.ts",
            "line_number": 42,
            "code_snippet": "bypass()",
            "attack_scenario": "attacker exploits",
            "evidence": "evidence",
            "cwe_id": "CWE-287",
            "recommendation": "fix auth",
        }
    ]

    result = update_pr_review_artifacts(securevibes_dir, pr_vulns)

    assert result.threats_added == 0
    assert result.vulnerabilities_added == 1

    vulns = json.loads((securevibes_dir / "VULNERABILITIES.json").read_text(encoding="utf-8"))
    assert len(vulns) == 1
    assert vulns[0]["finding_type"] == "threat_enabler"
    assert vulns[0]["source"] == "pr_review"


def test_update_pr_review_artifacts_handles_mitigation_removal(tmp_path: Path):
    """mitigation_removal finding_type should be added to VULNERABILITIES.json."""
    securevibes_dir = tmp_path / ".securevibes"
    securevibes_dir.mkdir()
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    (securevibes_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

    pr_vulns = [
        {
            "threat_id": "MITIGATION-REMOVED-001",
            "finding_type": "mitigation_removal",
            "title": "Security control removed",
            "description": "Input validation was removed",
            "severity": "critical",
            "file_path": "api/input.ts",
            "line_number": 15,
            "code_snippet": "// removed validation",
            "attack_scenario": "attacker sends malicious input",
            "evidence": "validation code deleted",
            "cwe_id": "CWE-20",
            "recommendation": "restore validation",
        }
    ]

    result = update_pr_review_artifacts(securevibes_dir, pr_vulns)

    assert result.threats_added == 0
    assert result.vulnerabilities_added == 1

    vulns = json.loads((securevibes_dir / "VULNERABILITIES.json").read_text(encoding="utf-8"))
    assert len(vulns) == 1
    assert vulns[0]["finding_type"] == "mitigation_removal"
    assert vulns[0]["source"] == "pr_review"


def test_update_pr_review_artifacts_handles_regression(tmp_path: Path):
    """regression finding_type should be added to VULNERABILITIES.json."""
    securevibes_dir = tmp_path / ".securevibes"
    securevibes_dir.mkdir()
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    (securevibes_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

    pr_vulns = [
        {
            "threat_id": "REGRESSION-001",
            "finding_type": "regression",
            "title": "Previously fixed vulnerability reintroduced",
            "description": "XSS fix was reverted",
            "severity": "high",
            "file_path": "ui/render.ts",
            "line_number": 88,
            "code_snippet": "innerHTML = userInput",
            "attack_scenario": "XSS attack",
            "evidence": "fix commit was reverted",
            "cwe_id": "CWE-79",
            "recommendation": "re-apply fix",
        }
    ]

    result = update_pr_review_artifacts(securevibes_dir, pr_vulns)

    assert result.threats_added == 0
    assert result.vulnerabilities_added == 1

    vulns = json.loads((securevibes_dir / "VULNERABILITIES.json").read_text(encoding="utf-8"))
    assert len(vulns) == 1
    assert vulns[0]["finding_type"] == "regression"
    assert vulns[0]["source"] == "pr_review"


def test_update_pr_review_artifacts_accepts_mapping_inputs(tmp_path: Path):
    """Mapping-like inputs should be processed (not only plain dicts)."""
    securevibes_dir = tmp_path / ".securevibes"
    securevibes_dir.mkdir()
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    (securevibes_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

    pr_vulns = [
        UserDict(
            {
                "threat_id": "MAPPING-001",
                "finding_type": "known_vuln",
                "title": "Mapping-backed finding",
                "description": "Uses UserDict input",
                "severity": "medium",
                "file_path": "api/client.py",
                "line_number": 7,
                "code_snippet": "dangerous()",
            }
        )
    ]

    result = update_pr_review_artifacts(securevibes_dir, pr_vulns)

    assert result.vulnerabilities_added == 1
    vulns = json.loads((securevibes_dir / "VULNERABILITIES.json").read_text(encoding="utf-8"))
    assert len(vulns) == 1
    assert vulns[0]["threat_id"] == "MAPPING-001"


def test_update_pr_review_artifacts_ignores_non_mapping_findings(tmp_path: Path):
    securevibes_dir = tmp_path / ".securevibes"
    securevibes_dir.mkdir()
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    (securevibes_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

    pr_vulns = [
        "ignore-this",
        {
            "threat_id": "VALID-001",
            "finding_type": "known_vuln",
            "title": "Valid finding",
            "description": "Should be retained",
            "severity": "high",
            "file_path": "api/app.py",
            "line_number": 11,
            "code_snippet": "dangerous()",
        },
    ]

    result = update_pr_review_artifacts(securevibes_dir, pr_vulns)

    assert result.vulnerabilities_added == 1
    vulns = json.loads((securevibes_dir / "VULNERABILITIES.json").read_text(encoding="utf-8"))
    assert len(vulns) == 1
    assert vulns[0]["threat_id"] == "VALID-001"


def test_update_pr_review_artifacts_raises_on_malformed_threat_model(tmp_path: Path):
    securevibes_dir = tmp_path / ".securevibes"
    securevibes_dir.mkdir()

    threat_model_path = securevibes_dir / "THREAT_MODEL.json"
    vulnerabilities_path = securevibes_dir / "VULNERABILITIES.json"
    threat_model_path.write_text("{ not-json", encoding="utf-8")
    baseline_vulns = [{"threat_id": "BASE-001"}]
    vulnerabilities_path.write_text(json.dumps(baseline_vulns), encoding="utf-8")

    with pytest.raises(ArtifactLoadError, match=r"THREAT_MODEL\.json"):
        update_pr_review_artifacts(securevibes_dir, [])

    assert threat_model_path.read_text(encoding="utf-8") == "{ not-json"
    assert json.loads(vulnerabilities_path.read_text(encoding="utf-8")) == baseline_vulns


def test_update_pr_review_artifacts_raises_on_malformed_vulnerabilities(tmp_path: Path):
    securevibes_dir = tmp_path / ".securevibes"
    securevibes_dir.mkdir()

    threat_model_path = securevibes_dir / "THREAT_MODEL.json"
    vulnerabilities_path = securevibes_dir / "VULNERABILITIES.json"
    threat_model_path.write_text("[]", encoding="utf-8")
    vulnerabilities_path.write_text("{ broken", encoding="utf-8")

    with pytest.raises(ArtifactLoadError, match=r"VULNERABILITIES\.json"):
        update_pr_review_artifacts(securevibes_dir, [])

    assert json.loads(threat_model_path.read_text(encoding="utf-8")) == []
    assert vulnerabilities_path.read_text(encoding="utf-8") == "{ broken"


def test_update_pr_review_artifacts_raises_when_artifact_is_not_json_array(tmp_path: Path):
    securevibes_dir = tmp_path / ".securevibes"
    securevibes_dir.mkdir()
    (securevibes_dir / "THREAT_MODEL.json").write_text("{}", encoding="utf-8")
    (securevibes_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

    with pytest.raises(ArtifactLoadError, match="expected top-level JSON array"):
        update_pr_review_artifacts(securevibes_dir, [])


def test_update_pr_review_artifacts_raises_when_artifact_read_fails(tmp_path: Path, monkeypatch):
    securevibes_dir = tmp_path / ".securevibes"
    securevibes_dir.mkdir()
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    (securevibes_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

    def fail_read_text(self, encoding="utf-8"):  # noqa: ARG001
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "read_text", fail_read_text)

    with pytest.raises(ArtifactLoadError, match="unable to read artifact file"):
        update_pr_review_artifacts(securevibes_dir, [])


def test_write_json_list_cleans_temp_file_on_replace_failure(tmp_path: Path, monkeypatch):
    output_path = tmp_path / "THREAT_MODEL.json"

    def fail_replace(*_args, **_kwargs):
        raise OSError("replace failed")

    monkeypatch.setattr(artifacts_module.os, "replace", fail_replace)

    with pytest.raises(OSError, match="replace failed"):
        artifacts_module._write_json_list(output_path, [{"id": "X"}])

    assert not list(tmp_path.glob("*.tmp"))


def test_derive_components_from_file_path_covers_edge_cases():
    assert artifacts_module._derive_components_from_file_path("") == []
    assert artifacts_module._derive_components_from_file_path("docs/README") == ["docs"]
    assert artifacts_module._derive_components_from_file_path("main.py") == ["py"]
    assert artifacts_module._derive_components_from_file_path("README") == []


def test_coerce_int_returns_zero_for_non_numeric_values():
    assert artifacts_module._coerce_int(None) == 0
    assert artifacts_module._coerce_int("abc") == 0
    assert artifacts_module._coerce_int(object()) == 0


def test_detect_new_components_handles_non_mapping_and_empty_inputs():
    pr_vulns = ["bad", {"file_path": ""}]
    threats = ["bad", {"affected_components": [None, 1, "api:py"]}]

    assert artifacts_module._detect_new_components(pr_vulns, threats) is False


def test_detect_new_components_true_when_pr_introduces_new_component():
    pr_vulns = [{"file_path": "web/app.ts"}]
    threats = [{"affected_components": ["api:py"]}]

    assert artifacts_module._detect_new_components(pr_vulns, threats) is True


def test_detect_new_components_false_when_all_components_are_known():
    pr_vulns = [{"file_path": "api/handler.py"}]
    threats = [{"affected_components": ["api:py"]}]

    assert artifacts_module._detect_new_components(pr_vulns, threats) is False
