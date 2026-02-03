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


def test_update_pr_review_artifacts_ignores_unknown(tmp_path: Path):
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
    assert result.vulnerabilities_added == 0
