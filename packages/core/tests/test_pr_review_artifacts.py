"""Tests for PR review artifact updates."""

import json
from pathlib import Path

from securevibes.scanner.artifacts import update_pr_review_artifacts


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

    threats = json.loads(threat_model_path.read_text(encoding="utf-8"))
    vulns = json.loads(vulnerabilities_path.read_text(encoding="utf-8"))

    assert len(threats) == 1
    assert threats[0]["id"] == "NEW-001"
    assert len(vulns) == 1
    assert vulns[0]["threat_id"] == "THREAT-001"


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

    vulns = json.loads(
        (securevibes_dir / "VULNERABILITIES.json").read_text(encoding="utf-8")
    )
    assert len(vulns) == 1
    assert vulns[0]["finding_type"] == "threat_enabler"


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

    vulns = json.loads(
        (securevibes_dir / "VULNERABILITIES.json").read_text(encoding="utf-8")
    )
    assert len(vulns) == 1
    assert vulns[0]["finding_type"] == "mitigation_removal"


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

    vulns = json.loads(
        (securevibes_dir / "VULNERABILITIES.json").read_text(encoding="utf-8")
    )
    assert len(vulns) == 1
    assert vulns[0]["finding_type"] == "regression"
