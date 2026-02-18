"""CLI-focused tests for PR review command selection and validation paths."""

from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from securevibes.cli.main import _clean_pr_artifacts, _parse_since_date_pacific, cli


@pytest.mark.parametrize(
    "args",
    [
        ["--base", "main"],
        ["--head", "feature-branch"],
    ],
)
def test_pr_review_requires_base_and_head_together(tmp_path: Path, args):
    """Specifying only one of --base/--head should fail."""
    repo = tmp_path / "repo"
    repo.mkdir()

    runner = CliRunner()
    result = runner.invoke(cli, ["pr-review", str(repo), *args])

    assert result.exit_code == 1
    assert "Must specify both --base and --head" in result.output


def test_pr_review_missing_required_artifacts(tmp_path: Path):
    """Missing SECURITY.md/THREAT_MODEL.json should fail early."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()
    (securevibes_dir / "SECURITY.md").write_text("# Security", encoding="utf-8")

    diff_file = tmp_path / "changes.patch"
    diff_file.write_text("diff --git a/a.py b/a.py\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["pr-review", str(repo), "--diff", str(diff_file)])

    assert result.exit_code == 1
    assert "Missing required artifacts" in result.output
    assert "THREAT_MODEL.json" in result.output


def test_parse_since_date_pacific_parses_midnight():
    """Date parser should return Pacific midnight ISO string."""
    parsed = _parse_since_date_pacific("2026-02-01")

    assert parsed == "2026-02-01T00:00:00-0800"


def test_parse_since_date_pacific_rejects_invalid_date():
    """Invalid date strings should raise click.BadParameter."""
    with pytest.raises(click.BadParameter, match="YYYY-MM-DD"):
        _parse_since_date_pacific("2026-02-99")


def test_clean_pr_artifacts_raises_on_unlink_error(tmp_path: Path, monkeypatch):
    """Cleanup helper should wrap unlink failures in RuntimeError."""
    securevibes_dir = tmp_path / ".securevibes"
    securevibes_dir.mkdir()
    artifact = securevibes_dir / "PR_VULNERABILITIES.json"
    artifact.write_text("[]", encoding="utf-8")

    def _raise_unlink(*_args, **_kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "unlink", _raise_unlink)

    with pytest.raises(RuntimeError, match="Failed to remove transient artifact"):
        _clean_pr_artifacts(securevibes_dir)


def test_clean_pr_artifacts_rejects_repo_symlink_escape(tmp_path: Path):
    """Cleanup should fail closed when `.securevibes` escapes repo via symlink."""
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    escaped_artifact = outside / "PR_VULNERABILITIES.json"
    escaped_artifact.write_text("[]", encoding="utf-8")

    securevibes_link = repo / ".securevibes"
    try:
        securevibes_link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not supported in this environment")

    with pytest.raises(RuntimeError, match="outside repository root"):
        _clean_pr_artifacts(securevibes_link, repo_root=repo)

    assert escaped_artifact.exists()


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


def test_pr_review_runtime_failure_exits_non_zero(tmp_path: Path, monkeypatch):
    """Scanner/runtime PR-review failures should never fail open with exit code 0."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()
    (securevibes_dir / "SECURITY.md").write_text("# Security", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    diff_file = tmp_path / "changes.patch"
    diff_file.write_text(
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1 +1 @@\n"
        "-print('old')\n"
        "+print('new')\n",
        encoding="utf-8",
    )

    def _raise_runtime(*_args, **_kwargs):
        raise RuntimeError("Refusing fail-open PR review result")

    monkeypatch.setattr("securevibes.cli.main._run_pr_review", _raise_runtime)

    runner = CliRunner()
    result = runner.invoke(cli, ["pr-review", str(repo), "--diff", str(diff_file)])

    assert result.exit_code == 1
    assert "Refusing fail-open PR review result" in result.output
