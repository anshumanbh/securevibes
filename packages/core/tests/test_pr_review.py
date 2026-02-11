"""Tests for PR review helpers."""

import json
from pathlib import Path

from click.testing import CliRunner

from securevibes.cli.main import cli
from securevibes.diff.context import extract_relevant_architecture, filter_relevant_threats
from securevibes.scanner.scanner import dedupe_pr_vulns, filter_baseline_vulns


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


def test_filter_baseline_vulns_excludes_pr_derived_with_threat_prefix():
    """A THREAT-001 entry with finding_type='known_vuln' is PR-derived, not baseline."""
    known_vulns = [
        {"file_path": "app.ts", "threat_id": "THREAT-001", "title": "SQLi"},  # baseline
        {"file_path": "app.ts", "threat_id": "THREAT-001", "title": "SQLi",
         "finding_type": "known_vuln"},  # PR-derived
    ]
    baseline = filter_baseline_vulns(known_vulns)
    assert len(baseline) == 1
    assert "finding_type" not in baseline[0]


def test_filter_baseline_vulns_excludes_pr_and_new_prefixes():
    """PR-/NEW- prefix entries filtered regardless of finding_type."""
    known_vulns = [
        {"file_path": "a.ts", "threat_id": "PR-abc123", "title": "A"},
        {"file_path": "b.ts", "threat_id": "NEW-001", "title": "B"},
        {"file_path": "c.ts", "threat_id": "THREAT-002", "title": "C"},
    ]
    baseline = filter_baseline_vulns(known_vulns)
    assert len(baseline) == 1
    assert baseline[0]["threat_id"] == "THREAT-002"


def test_filter_baseline_vulns_excludes_source_pr_review():
    """source='pr_review' entries should be filtered."""
    known_vulns = [
        {"file_path": "x.ts", "threat_id": "THREAT-005", "title": "X",
         "source": "pr_review"},
    ]
    baseline = filter_baseline_vulns(known_vulns)
    assert len(baseline) == 0


def test_dedupe_with_baseline_filter_preserves_pr_findings():
    """The real regression: THREAT-001 + finding_type in known should NOT suppress."""
    pr_vulns = [{"file_path": "app.ts", "threat_id": "THREAT-001", "title": "SQLi"}]
    known_vulns = [
        {"file_path": "app.ts", "threat_id": "THREAT-001", "title": "SQLi",
         "finding_type": "known_vuln"},
    ]
    baseline = filter_baseline_vulns(known_vulns)
    result = dedupe_pr_vulns(pr_vulns, baseline)
    assert len(result) == 1  # NOT deduped


def test_filter_baseline_vulns_normalizes_finding_type():
    """finding_type with mixed case or whitespace should still be recognized."""
    known_vulns = [
        {"file_path": "a.ts", "threat_id": "THREAT-010", "title": "A",
         "finding_type": " Known_Vuln "},
        {"file_path": "b.ts", "threat_id": "THREAT-011", "title": "B",
         "finding_type": "REGRESSION"},
    ]
    baseline = filter_baseline_vulns(known_vulns)
    assert len(baseline) == 0


def test_dedupe_with_baseline_filter_still_dedupes_real_baseline():
    """Baseline THREAT entries without finding_type should still dedupe correctly."""
    pr_vulns = [{"file_path": "app.ts", "threat_id": "THREAT-001", "title": "SQLi"}]
    known_vulns = [
        {"file_path": "app.ts", "threat_id": "THREAT-001", "title": "SQLi"},  # no finding_type
    ]
    baseline = filter_baseline_vulns(known_vulns)
    result = dedupe_pr_vulns(pr_vulns, baseline)
    assert len(result) == 0  # IS deduped — genuine baseline match


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


def test_pr_review_rejects_multiple_diff_sources(tmp_path: Path):
    """Multiple diff sources should be rejected."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    diff_file = tmp_path / "changes.patch"
    diff_file.write_text("diff --git a/a b/a\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "pr-review",
            str(repo),
            "--diff",
            str(diff_file),
            "--range",
            "abc123..def456",
        ],
    )

    assert result.exit_code == 1
    assert "Choose exactly one" in result.output


def test_pr_review_since_last_scan_requires_baseline(tmp_path: Path):
    """Missing scan_state.json should require a baseline scan."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["pr-review", str(repo), "--since-last-scan"])

    assert result.exit_code == 1
    assert "baseline scan" in result.output.lower()


def test_pr_review_since_invalid_date(tmp_path: Path):
    """Invalid --since date should be rejected."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["pr-review", str(repo), "--since", "2026-02-99"])

    assert result.exit_code == 1
    assert "YYYY-MM-DD" in result.output


def test_pr_review_since_no_commits(tmp_path: Path, monkeypatch):
    """No commits since date should exit cleanly."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    monkeypatch.setattr("securevibes.cli.main.get_commits_since", lambda *_args, **_kwargs: [])

    runner = CliRunner()
    result = runner.invoke(cli, ["pr-review", str(repo), "--since", "2026-02-01"])

    assert result.exit_code == 0
    assert "No commits since 2026-02-01" in result.output


def test_pr_review_last_no_commits(tmp_path: Path, monkeypatch):
    """--last with no commits should exit cleanly."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    monkeypatch.setattr(
        "securevibes.cli.main.get_last_n_commits",
        lambda *_args, **_kwargs: [],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["pr-review", str(repo), "--last", "5"])

    assert result.exit_code == 0
    assert "No commits found" in result.output
