"""Tests for CLI commands"""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner

from securevibes.cli.main import _git_pull, _is_production_url, _repo_has_local_changes, cli
from securevibes.models.result import ScanResult


def _empty_scan_result(repo_path: Path) -> ScanResult:
    return ScanResult(
        repository_path=str(repo_path),
        issues=[],
        files_scanned=1,
        scan_time_seconds=1.0,
    )


@pytest.fixture
def runner():
    """Create a CLI test runner"""
    return CliRunner()


@pytest.fixture
def test_repo(tmp_path):
    """Create a minimal test repository"""
    (tmp_path / "app.py").write_text(
        """
def hello():
    print("Hello World")
"""
    )
    return tmp_path


class TestCLIBasics:
    """Test basic CLI functionality"""

    def test_cli_help(self, runner):
        """Test CLI help command"""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "SecureVibes" in result.output
        assert "scan" in result.output

    def test_cli_version(self, runner):
        """Test CLI version command"""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "securevibes" in result.output.lower()
        # Check for version format (X.Y.Z)
        import re

        assert re.search(r"\d+\.\d+\.\d+", result.output)

    def test_scan_help(self, runner):
        """Test scan command help"""
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "scan" in result.output.lower()
        assert "--no-save" not in result.output

    def test_catchup_help(self, runner):
        """Test catchup command help"""
        result = runner.invoke(cli, ["catchup", "--help"])
        assert result.exit_code == 0
        assert "catchup" in result.output.lower()


class TestCatchupCommand:
    """Tests for catchup command."""

    def test_catchup_branch_mismatch(self, runner, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        repo.mkdir()

        monkeypatch.setattr("securevibes.cli.main.get_repo_branch", lambda *_args, **_kwargs: "dev")

        result = runner.invoke(cli, ["catchup", str(repo), "--branch", "main"])

        assert result.exit_code == 1
        assert "checkout" in result.output.lower()

    def test_catchup_invokes_pr_review(self, runner, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        repo.mkdir()
        called = {}

        def fake_pr_review(**kwargs):
            called["since_last_scan"] = kwargs.get("since_last_scan")

        monkeypatch.setattr("securevibes.cli.main.pr_review", fake_pr_review)
        monkeypatch.setattr("securevibes.cli.main._git_pull", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(
            "securevibes.cli.main._repo_has_local_changes", lambda *_args, **_kwargs: False
        )
        monkeypatch.setattr(
            "securevibes.cli.main.get_repo_branch", lambda *_args, **_kwargs: "main"
        )

        result = runner.invoke(cli, ["catchup", str(repo), "--branch", "main"])

        assert result.exit_code == 0
        assert called["since_last_scan"] is True

    def test_catchup_fails_when_worktree_dirty(self, runner, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        repo.mkdir()

        monkeypatch.setattr("securevibes.cli.main._repo_has_local_changes", lambda *_a, **_k: True)
        monkeypatch.setattr(
            "securevibes.cli.main.get_repo_branch", lambda *_args, **_kwargs: "main"
        )

        def fail_pull(*_args, **_kwargs):
            pytest.fail("_git_pull should not be called when worktree is dirty")

        monkeypatch.setattr("securevibes.cli.main._git_pull", fail_pull)

        result = runner.invoke(cli, ["catchup", str(repo), "--branch", "main"])

        assert result.exit_code == 1
        assert "working tree is not clean" in result.output.lower()


class TestProductionUrlDetection:
    """Tests for production URL safety gate detection."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost:3000",
            "https://127.0.0.1:8443",
            "https://qa.internal.local",
            "http://service.test",
        ],
    )
    def test_is_production_url_detects_safe_urls(self, url):
        assert _is_production_url(url) is False

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com",
            "https://api.company.io",
            "https://www.company.org",
            "https://my-production-host",
            "https://prod.internal",
            "https://contest.com",
            "https://prod-dev.company.com",
        ],
    )
    def test_is_production_url_detects_production_urls(self, url):
        assert _is_production_url(url) is True

    def test_is_production_url_detects_private_network_as_production(self):
        assert _is_production_url("http://192.168.1.100:8080") is True


class TestGitHelpers:
    """Tests for git command helper wrappers."""

    def test_git_pull_raises_runtime_error_on_failure(self, monkeypatch):
        observed = {}

        class DummyResult:
            returncode = 1
            stderr = "fatal: no such remote"

        def fake_run(cmd, **_kwargs):
            observed["cmd"] = cmd
            return DummyResult()

        monkeypatch.setattr("securevibes.cli.main.subprocess.run", fake_run)

        with pytest.raises(RuntimeError, match="no such remote"):
            _git_pull(Path("."), "main")
        assert observed["cmd"] == ["git", "pull", "origin", "--", "main"]

    def test_git_pull_rejects_option_style_branch_name(self):
        with pytest.raises(ValueError, match="option-style refs are not allowed"):
            _git_pull(Path("."), "--upload-pack=malicious")

    def test_repo_has_local_changes_returns_true_for_dirty_worktree(self, monkeypatch):
        class DummyResult:
            returncode = 0
            stdout = " M app.py\n"

        monkeypatch.setattr("securevibes.cli.main.subprocess.run", lambda *_a, **_k: DummyResult())

        assert _repo_has_local_changes(Path(".")) is True

    def test_repo_has_local_changes_returns_true_when_git_status_fails(self, monkeypatch):
        class DummyResult:
            returncode = 1
            stdout = ""

        monkeypatch.setattr("securevibes.cli.main.subprocess.run", lambda *_a, **_k: DummyResult())

        assert _repo_has_local_changes(Path(".")) is True

    def test_repo_has_local_changes_returns_false_for_clean_worktree(self, monkeypatch):
        class DummyResult:
            returncode = 0
            stdout = "   \n"

        monkeypatch.setattr("securevibes.cli.main.subprocess.run", lambda *_a, **_k: DummyResult())

        assert _repo_has_local_changes(Path(".")) is False


class TestScanCommand:
    """Test scan command"""

    def test_scan_nonexistent_path(self, runner):
        """Test scan with non-existent path"""
        result = runner.invoke(cli, ["scan", "/nonexistent/path"])
        assert result.exit_code != 0
        assert "Error" in result.output or "does not exist" in result.output.lower()

    def test_scan_with_path(self, runner, test_repo):
        """Test scan with valid path and mocked scanner."""
        with patch("securevibes.cli.main._run_scan", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = _empty_scan_result(test_repo)
            result = runner.invoke(cli, ["scan", str(test_repo), "--format", "table"])

        assert result.exit_code == 0
        assert "Scan Results" in result.output

    def test_scan_with_options(self, runner, test_repo):
        """Test scan with options and mocked scanner."""
        with patch("securevibes.cli.main._run_scan", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = _empty_scan_result(test_repo)
            result = runner.invoke(
                cli,
                [
                    "scan",
                    str(test_repo),
                    "--model",
                    "claude-3-5-haiku-20241022",
                    "--format",
                    "json",
                ],
            )

        assert result.exit_code == 0
        assert '"issues": []' in result.output

    def test_scan_markdown_format_default(self, runner, test_repo):
        """Test default markdown output path."""
        with patch("securevibes.cli.main._run_scan", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = _empty_scan_result(test_repo)
            result = runner.invoke(cli, ["scan", str(test_repo)])

        report_path = test_repo / ".securevibes" / "scan_report.md"
        assert result.exit_code == 0
        assert report_path.exists()
        assert "Markdown report" in result.output

    def test_scan_markdown_output_relative_path(self, runner, test_repo):
        """Test markdown output with relative filename saves to .securevibes/"""
        with patch("securevibes.cli.main._run_scan", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = _empty_scan_result(test_repo)
            result = runner.invoke(
                cli,
                ["scan", str(test_repo), "--format", "markdown", "--output", "custom_report.md"],
            )

        report_path = test_repo / ".securevibes" / "custom_report.md"
        assert result.exit_code == 0
        assert report_path.exists()
        assert "custom_report.md" in result.output

    def test_scan_markdown_output_absolute_path(self, runner, test_repo, tmp_path):
        """Test markdown output with absolute path preserves the path"""
        output_file = tmp_path / "absolute_report.md"
        with patch("securevibes.cli.main._run_scan", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = _empty_scan_result(test_repo)
            result = runner.invoke(
                cli, ["scan", str(test_repo), "--format", "markdown", "--output", str(output_file)]
            )

        assert result.exit_code == 0
        assert output_file.exists()
        assert output_file.name in result.output

    def test_scan_markdown_output_rejects_relative_path_escape(self, runner, test_repo, tmp_path):
        """Relative markdown output should not allow escaping repository boundaries."""
        escaped_name = "escaped_scan_report.md"
        escaped_path = (test_repo / ".securevibes" / ".." / ".." / escaped_name).resolve()
        if escaped_path.exists():
            escaped_path.unlink()

        with patch("securevibes.cli.main._run_scan", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = _empty_scan_result(test_repo)
            result = runner.invoke(
                cli,
                [
                    "scan",
                    str(test_repo),
                    "--format",
                    "markdown",
                    "--output",
                    f"../../{escaped_name}",
                ],
            )

        assert result.exit_code == 1
        assert "outside repository root" in result.output
        assert not escaped_path.exists()

    def test_scan_rejects_securevibes_symlink_escape(self, runner, tmp_path):
        """Scan should fail closed when `.securevibes` symlink resolves outside repo."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()

        try:
            (repo / ".securevibes").symlink_to(outside_dir, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks are not supported in this environment")

        with patch("securevibes.cli.main._run_scan", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = _empty_scan_result(repo)
            result = runner.invoke(cli, ["scan", str(repo), "--format", "table"])

        assert result.exit_code == 1
        assert "outside repository root" in result.output
        mock_run.assert_not_called()

    def test_scan_table_format_still_works(self, runner, test_repo):
        """Test backward compatibility - table format still works"""
        with patch("securevibes.cli.main._run_scan", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = _empty_scan_result(test_repo)
            result = runner.invoke(cli, ["scan", str(test_repo), "--format", "table"])

        assert result.exit_code == 0
        assert "Scan Results" in result.output


class TestReportCommand:
    """Test report command"""

    def test_report_nonexistent_file(self, runner):
        """Test report with non-existent file"""
        result = runner.invoke(cli, ["report", "/nonexistent/report.json"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "Error" in result.output

    def test_report_with_sample_data(self, runner, tmp_path):
        """Test report with valid sample data"""
        import json

        # Create sample scan results
        scan_data = {
            "repository_path": str(tmp_path),
            "files_scanned": 10,
            "scan_time_seconds": 5.2,
            "issues": [
                {
                    "id": "test-1",
                    "severity": "high",
                    "title": "Test Issue",
                    "description": "Test description",
                    "file_path": "test.py",
                    "line_number": 42,
                    "code_snippet": "code here",
                    "recommendation": "Fix this",
                    "cwe_id": "CWE-89",
                }
            ],
        }

        report_file = tmp_path / "scan_results.json"
        report_file.write_text(json.dumps(scan_data))

        result = runner.invoke(cli, ["report", str(report_file)])
        assert result.exit_code == 0
        assert "Scan Results" in result.output
        assert "Test Issue" in result.output


class TestCLIOutputFormats:
    """Test CLI output formatting"""

    def test_json_output_format(self, runner, test_repo):
        """Test JSON output format"""
        with patch("securevibes.cli.main._run_scan", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = _empty_scan_result(test_repo)
            result = runner.invoke(cli, ["scan", str(test_repo), "--format", "json"])

        assert result.exit_code == 0
        assert '"repository_path"' in result.output

    def test_table_output_format(self, runner, test_repo):
        """Test table output format."""
        with patch("securevibes.cli.main._run_scan", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = _empty_scan_result(test_repo)
            result = runner.invoke(cli, ["scan", str(test_repo), "--format", "table"])

        assert result.exit_code == 0
        assert "Scan Results" in result.output


class TestCLIErrorMessages:
    """Test CLI error messages are helpful"""

    # Removed test_missing_api_key_message - API key validation is now delegated to claude CLI
    # Authentication is handled through environment inheritance (ANTHROPIC_API_KEY, session tokens, etc.)
