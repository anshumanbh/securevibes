"""Tests for PR review helpers."""

import asyncio
import json
from io import StringIO
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner
from rich.console import Console

from securevibes.cli.main import cli
from securevibes.diff.context import (
    extract_relevant_architecture,
    filter_relevant_threats,
    filter_relevant_vulnerabilities,
    suggest_security_adjacent_files,
    summarize_threats_for_prompt,
    summarize_vulnerabilities_for_prompt,
)
from securevibes.diff.parser import DiffContext, DiffFile, DiffHunk, DiffLine
from securevibes.scanner.scanner import (
    Scanner,
    _build_focused_diff_context,
    dedupe_pr_vulns,
    filter_baseline_vulns,
)


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


def test_filter_relevant_threats_prioritizes_exact_file_overlap(tmp_path: Path):
    """Exact changed-file threat matches should outrank loose token matches."""
    threat_model = tmp_path / "THREAT_MODEL.json"
    threats = [
        {
            "id": "THREAT-LOOSE",
            "title": "Gateway auth issue",
            "description": "General auth weakness in gateway",
            "affected_components": ["gateway"],
        },
        {
            "id": "THREAT-EXACT",
            "title": "Config apply privilege issue",
            "description": "Direct overlap with changed file",
            "affected_files": [{"file_path": "src/gateway/server-methods/config.ts"}],
        },
    ]
    threat_model.write_text(json.dumps(threats), encoding="utf-8")

    relevant = filter_relevant_threats(
        threat_model,
        ["src/gateway/server-methods/config.ts"],
        max_items=2,
    )

    assert len(relevant) == 2
    assert relevant[0]["id"] == "THREAT-EXACT"


def test_filter_relevant_vulnerabilities_prefers_file_overlap():
    """Vulnerability relevance should prefer exact file overlap over loose text matches."""
    vulnerabilities = [
        {
            "threat_id": "THREAT-1",
            "title": "Gateway issue",
            "description": "General gateway auth concern",
            "file_path": "src/gateway/auth.ts",
        },
        {
            "threat_id": "THREAT-2",
            "title": "Config apply exploit chain",
            "description": "Direct overlap with changed method",
            "file_path": "src/gateway/server-methods/config.ts",
        },
    ]

    relevant = filter_relevant_vulnerabilities(
        vulnerabilities,
        ["src/gateway/server-methods/config.ts"],
        max_items=2,
    )

    assert len(relevant) == 2
    assert relevant[0]["threat_id"] == "THREAT-2"


def test_context_summaries_are_bounded():
    """Prompt summaries should include findings but respect char limits."""
    threats = [
        {
            "id": "THREAT-001",
            "title": "Very long threat title " * 20,
            "description": "Very long threat description " * 40,
            "severity": "high",
            "file_path": "src/gateway/auth.ts",
        }
    ]
    vulns = [
        {
            "threat_id": "THREAT-002",
            "title": "Very long vulnerability title " * 20,
            "description": "Very long vulnerability description " * 40,
            "severity": "critical",
            "file_path": "src/gateway/server.ts",
            "cwe_id": "CWE-306",
        }
    ]

    threat_summary = summarize_threats_for_prompt(threats, max_chars=180)
    vuln_summary = summarize_vulnerabilities_for_prompt(vulns, max_chars=180)

    assert len(threat_summary) <= 180
    assert len(vuln_summary) <= 180
    assert "THREAT-001" in threat_summary
    assert "THREAT-002" in vuln_summary


def test_suggest_security_adjacent_files_returns_ranked_neighbors(tmp_path: Path):
    """Security-adjacent hints should include nearby auth/policy files."""
    repo = tmp_path / "repo"
    (repo / "src/gateway/server-methods").mkdir(parents=True)
    (repo / "src/gateway/server-methods/config.ts").write_text("export const x = 1;\n", "utf-8")
    (repo / "src/gateway/auth.ts").write_text("export const y = 1;\n", "utf-8")
    (repo / "src/gateway/router.ts").write_text("export const z = 1;\n", "utf-8")
    (repo / "src/gateway/notes.txt").write_text("not code\n", "utf-8")

    hints = suggest_security_adjacent_files(
        repo, ["src/gateway/server-methods/config.ts"], max_items=5
    )

    assert "src/gateway/auth.ts" in hints
    assert "src/gateway/router.ts" in hints
    assert "src/gateway/server-methods/config.ts" not in hints


def test_build_focused_diff_context_prioritizes_source_over_docs():
    """Focused diff should prioritize code paths over docs noise."""
    docs_file = DiffFile(
        old_path="docs/readme.md",
        new_path="docs/readme.md",
        is_new=False,
        is_deleted=False,
        is_renamed=False,
        hunks=[
            DiffHunk(
                old_start=1,
                old_count=1,
                new_start=1,
                new_count=1,
                lines=[
                    DiffLine(type="add", content="doc update", old_line_num=None, new_line_num=1)
                ],
            )
        ],
    )
    code_file = DiffFile(
        old_path="src/gateway/server-methods/config.ts",
        new_path="src/gateway/server-methods/config.ts",
        is_new=False,
        is_deleted=False,
        is_renamed=False,
        hunks=[
            DiffHunk(
                old_start=10,
                old_count=1,
                new_start=10,
                new_count=1,
                lines=[
                    DiffLine(type="add", content="config.apply", old_line_num=None, new_line_num=10)
                ],
            )
        ],
    )
    context = DiffContext(
        files=[docs_file, code_file],
        added_lines=2,
        removed_lines=0,
        changed_files=["docs/readme.md", "src/gateway/server-methods/config.ts"],
    )

    focused = _build_focused_diff_context(context)

    assert focused.changed_files
    assert focused.changed_files[0] == "src/gateway/server-methods/config.ts"


def test_build_focused_diff_context_trims_oversized_hunks():
    """Focused diff should cap hunk size to keep prompts tractable."""
    many_lines = [
        DiffLine(type="add", content=f"line {idx}", old_line_num=None, new_line_num=idx)
        for idx in range(1, 280)
    ]
    noisy_file = DiffFile(
        old_path="src/gateway/server.ts",
        new_path="src/gateway/server.ts",
        is_new=False,
        is_deleted=False,
        is_renamed=False,
        hunks=[
            DiffHunk(
                old_start=1,
                old_count=200,
                new_start=1,
                new_count=200,
                lines=many_lines,
            )
        ],
    )
    context = DiffContext(
        files=[noisy_file],
        added_lines=len(many_lines),
        removed_lines=0,
        changed_files=["src/gateway/server.ts"],
    )

    focused = _build_focused_diff_context(context)

    assert len(focused.files) == 1
    assert len(focused.files[0].hunks) == 1
    assert len(focused.files[0].hunks[0].lines) == 200


def test_dedupe_pr_vulns_tags_known_matches():
    """Baseline overlaps should be retained and tagged as known_vuln."""
    pr_vulns = [
        {"file_path": "ui/app.ts", "threat_id": "THREAT-001", "title": "A"},
        {"file_path": "api/app.ts", "threat_id": "THREAT-002", "title": "B"},
    ]
    known_vulns = [
        {"file_path": "ui/app.ts", "threat_id": "THREAT-001", "title": "A"},
    ]

    filtered = dedupe_pr_vulns(pr_vulns, known_vulns)

    assert len(filtered) == 2
    assert filtered[0]["threat_id"] == "THREAT-001"
    assert filtered[0]["finding_type"] == "known_vuln"
    assert filtered[1]["threat_id"] == "THREAT-002"


def test_filter_baseline_vulns_excludes_pr_derived_with_threat_prefix():
    """A THREAT-001 entry with finding_type='known_vuln' is PR-derived, not baseline."""
    known_vulns = [
        {"file_path": "app.ts", "threat_id": "THREAT-001", "title": "SQLi"},  # baseline
        {
            "file_path": "app.ts",
            "threat_id": "THREAT-001",
            "title": "SQLi",
            "finding_type": "known_vuln",
        },  # PR-derived
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
        {"file_path": "x.ts", "threat_id": "THREAT-005", "title": "X", "source": "pr_review"},
    ]
    baseline = filter_baseline_vulns(known_vulns)
    assert len(baseline) == 0


def test_dedupe_with_baseline_filter_preserves_pr_findings():
    """The real regression: THREAT-001 + finding_type in known should NOT suppress."""
    pr_vulns = [{"file_path": "app.ts", "threat_id": "THREAT-001", "title": "SQLi"}]
    known_vulns = [
        {
            "file_path": "app.ts",
            "threat_id": "THREAT-001",
            "title": "SQLi",
            "finding_type": "known_vuln",
        },
    ]
    baseline = filter_baseline_vulns(known_vulns)
    result = dedupe_pr_vulns(pr_vulns, baseline)
    assert len(result) == 1  # NOT deduped


def test_filter_baseline_vulns_normalizes_finding_type():
    """finding_type with mixed case or whitespace should still be recognized."""
    known_vulns = [
        {
            "file_path": "a.ts",
            "threat_id": "THREAT-010",
            "title": "A",
            "finding_type": " Known_Vuln ",
        },
        {
            "file_path": "b.ts",
            "threat_id": "THREAT-011",
            "title": "B",
            "finding_type": "REGRESSION",
        },
    ]
    baseline = filter_baseline_vulns(known_vulns)
    assert len(baseline) == 0


def test_dedupe_with_baseline_filter_marks_real_baseline_as_known():
    """Baseline THREAT entries without finding_type should be tagged known_vuln."""
    pr_vulns = [{"file_path": "app.ts", "threat_id": "THREAT-001", "title": "SQLi"}]
    known_vulns = [
        {"file_path": "app.ts", "threat_id": "THREAT-001", "title": "SQLi"},  # no finding_type
    ]
    baseline = filter_baseline_vulns(known_vulns)
    result = dedupe_pr_vulns(pr_vulns, baseline)
    assert len(result) == 1
    assert result[0]["finding_type"] == "known_vuln"


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


def test_pr_review_clean_pr_artifacts_removes_transient_files(tmp_path: Path):
    """--clean-pr-artifacts should remove only transient PR outputs."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    (securevibes_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

    (securevibes_dir / "PR_VULNERABILITIES.json").write_text("[]", encoding="utf-8")
    (securevibes_dir / "DIFF_CONTEXT.json").write_text("{}", encoding="utf-8")
    (securevibes_dir / "pr_review_report.md").write_text("old report", encoding="utf-8")

    diff_file = tmp_path / "empty.patch"
    diff_file.write_text("", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "pr-review",
            str(repo),
            "--diff",
            str(diff_file),
            "--clean-pr-artifacts",
        ],
    )

    assert result.exit_code == 0
    assert not (securevibes_dir / "PR_VULNERABILITIES.json").exists()
    assert not (securevibes_dir / "DIFF_CONTEXT.json").exists()
    assert not (securevibes_dir / "pr_review_report.md").exists()
    assert (securevibes_dir / "SECURITY.md").exists()
    assert (securevibes_dir / "THREAT_MODEL.json").exists()
    assert (securevibes_dir / "VULNERABILITIES.json").exists()


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


def test_pr_review_last_zero_rejected(tmp_path: Path):
    """--last 0 should be rejected by CLI validation."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["pr-review", str(repo), "--last", "0"])

    assert result.exit_code != 0
    assert (
        "0" in result.output
        or "invalid" in result.output.lower()
        or "range" in result.output.lower()
    )


def test_pr_review_last_negative_rejected(tmp_path: Path):
    """--last -1 should be rejected by CLI validation."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["pr-review", str(repo), "--last", "-1"])

    assert result.exit_code != 0
    assert (
        "-1" in result.output
        or "invalid" in result.output.lower()
        or "range" in result.output.lower()
    )


@pytest.mark.asyncio
async def test_pr_review_handles_wrapper_format(tmp_path: Path):
    """Wrapper + schema variant should be normalized into proper issue locations/CWE."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    variant_vuln = {
        "id": "PR-VULN-001",
        "title": "SQL Injection",
        "description": "User input in query",
        "severity": "high",
        "location": "src/app.py:42-45",
        "cwe": "89",
        "recommendation": "Use parameterized queries",
    }
    # Write as wrapper dict with variant fields — scanner must unwrap + normalize it
    (securevibes_dir / "PR_VULNERABILITIES.json").write_text(
        json.dumps({"vulnerabilities": [variant_vuln]}),
        encoding="utf-8",
    )

    diff_context = DiffContext(files=[], added_lines=1, removed_lines=0, changed_files=["app.py"])

    scanner = Scanner(model="sonnet", debug=False)
    scanner.console = Console(file=StringIO())

    with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
        mock_instance.query = AsyncMock()

        async def async_gen():
            return
            yield  # pragma: no cover

        mock_instance.receive_messages = async_gen

        result = await scanner.pr_review(
            str(repo),
            diff_context,
            known_vulns_path=None,
            severity_threshold="low",
        )

    assert len(result.issues) > 0, "Wrapper format should produce non-empty issues after unwrap"
    assert result.issues[0].title == "SQL Injection"
    assert result.issues[0].file_path == "src/app.py"
    assert result.issues[0].line_number == 42
    assert result.issues[0].cwe_id == "CWE-89"


@pytest.mark.asyncio
async def test_pr_review_missing_artifact_returns_warning(tmp_path: Path):
    """Missing PR_VULNERABILITIES.json should return a warning instead of silent success."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    diff_context = DiffContext(files=[], added_lines=1, removed_lines=0, changed_files=["app.py"])

    scanner = Scanner(model="sonnet", debug=False)
    scanner.console = Console(file=StringIO())

    with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
        mock_instance.query = AsyncMock()

        async def async_gen():
            return
            yield  # pragma: no cover

        mock_instance.receive_messages = async_gen

        result = await scanner.pr_review(
            str(repo),
            diff_context,
            known_vulns_path=None,
            severity_threshold="low",
        )

    assert len(result.issues) == 0
    assert result.warnings
    assert any("did not produce a readable PR_VULNERABILITIES.json" in w for w in result.warnings)


@pytest.mark.asyncio
async def test_pr_review_retries_when_first_attempt_returns_empty(tmp_path: Path):
    """If first attempt returns empty findings, scanner should retry with follow-up pass."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    diff_context = DiffContext(files=[], added_lines=1, removed_lines=0, changed_files=["app.py"])

    scanner = Scanner(model="sonnet", debug=False)
    scanner.console = Console(file=StringIO())

    attempt_counter = {"count": 0}

    with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
        mock_instance.query = AsyncMock()

        async def query_side_effect(_prompt: str):
            attempt_counter["count"] += 1
            if attempt_counter["count"] == 1:
                (securevibes_dir / "PR_VULNERABILITIES.json").write_text("[]", encoding="utf-8")
            else:
                (securevibes_dir / "PR_VULNERABILITIES.json").write_text(
                    json.dumps(
                        [
                            {
                                "threat_id": "PR-001",
                                "finding_type": "new_threat",
                                "title": "Follow-up finding",
                                "description": "Second pass produced a finding.",
                                "severity": "high",
                                "file_path": "src/app.py",
                                "line_number": 1,
                                "code_snippet": "danger()",
                                "attack_scenario": "1) Input reaches sink.",
                                "evidence": "src/app.py:1",
                                "cwe_id": "CWE-94",
                                "recommendation": "Add validation.",
                            }
                        ]
                    ),
                    encoding="utf-8",
                )

        mock_instance.query.side_effect = query_side_effect

        async def async_gen():
            return
            yield  # pragma: no cover

        mock_instance.receive_messages = async_gen

        result = await scanner.pr_review(
            str(repo),
            diff_context,
            known_vulns_path=None,
            severity_threshold="low",
        )

    assert result.issues
    assert attempt_counter["count"] == 2
    assert any("retrying with chain-focused prompt" in warning for warning in result.warnings)


@pytest.mark.asyncio
async def test_pr_review_timeout_retries_and_succeeds(tmp_path: Path, monkeypatch):
    """A timeout on first pass should retry and accept a later successful pass."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    diff_context = DiffContext(files=[], added_lines=1, removed_lines=0, changed_files=["app.py"])

    monkeypatch.setenv("SECUREVIBES_PR_REVIEW_TIMEOUT_SECONDS", "1")
    monkeypatch.setenv("SECUREVIBES_PR_REVIEW_ATTEMPTS", "2")

    scanner = Scanner(model="sonnet", debug=False)
    scanner.console = Console(file=StringIO())

    stream_counter = {"count": 0}

    with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
        mock_instance.query = AsyncMock()

        async def query_side_effect(_prompt: str):
            if stream_counter["count"] >= 1:
                (securevibes_dir / "PR_VULNERABILITIES.json").write_text(
                    json.dumps(
                        [
                            {
                                "threat_id": "PR-002",
                                "finding_type": "new_threat",
                                "title": "Recovered finding",
                                "description": "Retry pass produced a finding.",
                                "severity": "high",
                                "file_path": "src/app.py",
                                "line_number": 2,
                                "code_snippet": "eval(x)",
                                "attack_scenario": "1) User input controls eval.",
                                "evidence": "src/app.py:2",
                                "cwe_id": "CWE-94",
                                "recommendation": "Avoid eval.",
                            }
                        ]
                    ),
                    encoding="utf-8",
                )

        mock_instance.query.side_effect = query_side_effect

        def receive_messages_side_effect():
            async def _stream():
                if stream_counter["count"] == 0:
                    stream_counter["count"] += 1
                    await asyncio.sleep(2)
                    return
                    yield  # pragma: no cover
                stream_counter["count"] += 1
                return
                yield  # pragma: no cover

            return _stream()

        mock_instance.receive_messages = receive_messages_side_effect

        result = await scanner.pr_review(
            str(repo),
            diff_context,
            known_vulns_path=None,
            severity_threshold="low",
        )

    assert result.issues
    assert any("timed out" in warning.lower() for warning in result.warnings)


@pytest.mark.asyncio
async def test_pr_review_uses_direct_tools_without_task(tmp_path: Path):
    """PR review should run with direct Read/Write/Grep tools and not require Task."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    diff_context = DiffContext(files=[], added_lines=1, removed_lines=0, changed_files=["app.py"])

    scanner = Scanner(model="sonnet", debug=False)
    scanner.console = Console(file=StringIO())

    with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
        mock_instance.query = AsyncMock()

        async def async_gen():
            return
            yield  # pragma: no cover

        mock_instance.receive_messages = async_gen

        await scanner.pr_review(
            str(repo),
            diff_context,
            known_vulns_path=None,
            severity_threshold="low",
        )

    # Verify direct tool execution surface for PR review
    options = mock_client.call_args[1]["options"]
    assert "Read" in options.allowed_tools
    assert "Write" in options.allowed_tools
    assert "Grep" in options.allowed_tools
    assert "Task" not in options.allowed_tools


@pytest.mark.asyncio
async def test_pr_review_has_subagent_hook(tmp_path: Path):
    """PR review must wire up SubagentStop hook for subagent lifecycle tracking."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    diff_context = DiffContext(files=[], added_lines=1, removed_lines=0, changed_files=["app.py"])

    scanner = Scanner(model="sonnet", debug=False)
    scanner.console = Console(file=StringIO())

    with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
        mock_instance.query = AsyncMock()

        async def async_gen():
            return
            yield  # pragma: no cover

        mock_instance.receive_messages = async_gen

        await scanner.pr_review(
            str(repo),
            diff_context,
            known_vulns_path=None,
            severity_threshold="low",
        )

    options = mock_client.call_args[1]["options"]
    assert "SubagentStop" in options.hooks, "SubagentStop hook must be configured"
    assert len(options.hooks["SubagentStop"]) > 0, "SubagentStop must have at least one hook"


def test_pr_code_review_prompt_requires_chain_analysis_text():
    """Prompt must explicitly require trust-boundary exploit chain reasoning."""
    prompt_path = (
        Path(__file__).resolve().parents[1]
        / "securevibes"
        / "prompts"
        / "agents"
        / "pr_code_review.txt"
    )
    prompt = prompt_path.read_text(encoding="utf-8")

    assert "existing auth/trust-boundary weaknesses" in prompt
    assert "do not auto-cap local access or localhost-only paths at MEDIUM" in prompt


def test_pr_code_review_prompt_disables_diff_context_file_reads():
    """PR review prompt must align with hooks and disallow DIFF_CONTEXT reads/greps."""
    prompt_path = (
        Path(__file__).resolve().parents[1]
        / "securevibes"
        / "prompts"
        / "agents"
        / "pr_code_review.txt"
    )
    prompt = prompt_path.read_text(encoding="utf-8")

    assert "Do not read or grep DIFF_CONTEXT.json" in prompt
