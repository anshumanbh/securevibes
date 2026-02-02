"""Tests for PR review helpers."""

import json
from pathlib import Path

from click.testing import CliRunner

from securevibes.cli.main import cli
from securevibes.diff.context import extract_relevant_architecture, filter_relevant_threats
from securevibes.scanner.scanner import dedupe_pr_vulns


def test_extract_relevant_architecture_matches_sections(tmp_path: Path):
    """Relevant SECURITY.md sections should be extracted based on changed files."""
    security_md = tmp_path / "SECURITY.md"
    security_md.write_text(
        "# Overview\nGeneral info\n\n# Control UI\nThe UI lives under ui/\n\n# API\nOther notes\n",
        encoding="utf-8",
    )

    result = extract_relevant_architecture(security_md, ["ui/app-settings.ts"])

    assert "Control UI" in result


def test_filter_relevant_threats_matches_tokens(tmp_path: Path):
    """Threats mentioning changed components should be returned."""
    threat_model = tmp_path / "THREAT_MODEL.json"
    threats = [
        {
            "id": "THREAT-001",
            "title": "Token exposure in UI",
            "description": "UI sends tokens",
            "affected_components": ["ui"],
            "severity": "high",
        },
        {
            "id": "THREAT-002",
            "title": "Other threat",
            "description": "Database issue",
            "affected_components": ["db"],
            "severity": "medium",
        },
    ]
    threat_model.write_text(json.dumps(threats), encoding="utf-8")

    relevant = filter_relevant_threats(threat_model, ["ui/app-settings.ts"])

    assert len(relevant) == 1
    assert relevant[0]["id"] == "THREAT-001"


def test_dedupe_pr_vulns_filters_known():
    """Known issues should be filtered from PR findings."""
    pr_vulns = [
        {"file_path": "ui/app.ts", "threat_id": "THREAT-001", "title": "A"},
        {"file_path": "api/app.ts", "threat_id": "THREAT-002", "title": "B"},
    ]
    known_vulns = [
        {"file_path": "ui/app.ts", "threat_id": "THREAT-001", "title": "A"},
    ]

    filtered = dedupe_pr_vulns(pr_vulns, known_vulns)

    assert len(filtered) == 1
    assert filtered[0]["threat_id"] == "THREAT-002"


def test_pr_review_empty_diff_exits_cleanly(tmp_path: Path):
    """Empty diff should exit early without invoking the scanner."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    diff_file = tmp_path / "empty.patch"
    diff_file.write_text("", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["pr-review", str(repo), "--diff", str(diff_file)])

    assert result.exit_code == 0
    assert "No changes found" in result.output
