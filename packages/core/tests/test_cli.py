"""Tests for CLI commands"""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from securevibes.cli.main import (
    _git_pull,
    _is_production_url,
    _repo_has_local_changes,
    cli,
)
from securevibes.models.issue import SecurityIssue, Severity
from securevibes.models.result import ScanResult
from securevibes.scanner.incremental_planning import (
    CommitSynopsis,
    IncrementalPlan,
    ReviewCluster,
)
from securevibes.scanner.incremental_execution import (
    ClusterExecutionResult,
    IncrementalExecutionResult,
)


def _empty_scan_result(repo_path: Path) -> ScanResult:
    return ScanResult(
        repository_path=str(repo_path),
        issues=[],
        files_scanned=1,
        scan_time_seconds=1.0,
    )


def _scan_result_with_issue(
    repo_path: Path,
    *,
    severity: Severity = Severity.HIGH,
    issue_id: str = "ISSUE-1",
) -> ScanResult:
    return ScanResult(
        repository_path=str(repo_path),
        issues=[
            SecurityIssue(
                id=issue_id,
                severity=severity,
                title="Injected issue",
                description="Test issue for CLI JSON output.",
                file_path="src/app.py",
                line_number=7,
                code_snippet="danger()",
                cwe_id="CWE-94",
            )
        ],
        files_scanned=1,
        scan_time_seconds=1.0,
    )


def _incremental_plan() -> IncrementalPlan:
    return IncrementalPlan(
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
        synopses=(
            CommitSynopsis(
                sha="commit-1",
                subject="Modify auth flow",
                file_paths=("src/auth.py",),
                derived_components=("src:py",),
                matched_baseline_vuln_paths=("src/auth.py",),
                matched_baseline_components=("src:py",),
                coarse_intent="existing_surface_delta",
                route="targeted_pr_review",
                risk_tier="critical",
                reasons=("critical_pattern_match",),
                dependency_files=(),
                new_attack_surface=False,
                insertions=8,
                deletions=2,
            ),
        ),
        clusters=(
            ReviewCluster(
                cluster_id="cluster-001",
                route="targeted_pr_review",
                commit_shas=("commit-1",),
                file_paths=("src/auth.py",),
                baseline_vuln_paths=("src/auth.py",),
                baseline_components=("src:py",),
                coarse_intents=("existing_surface_delta",),
                reasons=("critical_pattern_match",),
            ),
        ),
    )


def _incremental_execution_result() -> IncrementalExecutionResult:
    return IncrementalExecutionResult(
        cluster_results=(
            ClusterExecutionResult(
                cluster_id="cluster-001",
                route="targeted_pr_review",
                status="executed",
                findings_count=1,
                high_count=1,
            ),
            ClusterExecutionResult(
                cluster_id="cluster-002",
                route="supply_chain_review",
                status="skipped",
                skip_reason="route_not_implemented",
            ),
        ),
    )


@pytest.fixture
def runner():
    """Create a CLI test runner"""
    return CliRunner()


@pytest.fixture
def test_repo(tmp_path):
    """Create a minimal test repository"""
    (tmp_path / "app.py").write_text("""
def hello():
    print("Hello World")
""")
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

    def test_catchup_prefers_last_incremental_anchor(self, runner, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        repo.mkdir()
        securevibes_dir = repo / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "scan_state.json").write_text(
            json.dumps(
                {
                    "last_full_scan": {
                        "commit": "base123",
                        "branch": "main",
                        "timestamp": "2026-03-21T00:00:00Z",
                    },
                    "last_incremental_run": {
                        "commit": "incr456",
                        "base_commit": "base123",
                        "branch": "main",
                        "timestamp": "2026-03-21T01:00:00Z",
                    },
                }
            ),
            encoding="utf-8",
        )
        observed = {}

        async def fake_execute_incremental_plan(*_args, **_kwargs):
            return _incremental_execution_result()

        def fake_plan_incremental_range(
            repo_path: Path,
            securevibes_path: Path,
            *,
            base_ref: str,
            head_ref: str,
            generated_at: str | None = None,
        ) -> IncrementalPlan:
            observed["plan"] = (repo_path, securevibes_path, base_ref, head_ref, generated_at)
            return _incremental_plan()

        monkeypatch.setattr(
            "securevibes.cli.main.plan_incremental_range", fake_plan_incremental_range
        )
        monkeypatch.setattr(
            "securevibes.cli.main.get_diff_from_git_range",
            lambda *_args, **_kwargs: "diff --git a/src/auth.py b/src/auth.py\n",
        )
        monkeypatch.setattr(
            "securevibes.cli.main.parse_unified_diff",
            lambda diff: SimpleNamespace(raw=diff, changed_files=["src/auth.py"]),
        )
        monkeypatch.setattr(
            "securevibes.cli.main.execute_incremental_plan",
            fake_execute_incremental_plan,
        )
        monkeypatch.setattr("securevibes.cli.main._git_pull", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(
            "securevibes.cli.main._repo_has_local_changes",
            lambda *_args, **_kwargs: False,
        )
        monkeypatch.setattr(
            "securevibes.cli.main.get_repo_branch", lambda *_args, **_kwargs: "main"
        )
        monkeypatch.setattr(
            "securevibes.cli.main.get_repo_head_commit", lambda *_args, **_kwargs: "head789"
        )
        monkeypatch.setattr(
            "securevibes.cli.main.resolve_repo_commit",
            lambda _repo, ref: {"incr456": "incr456", "HEAD": "head789"}[ref],
        )

        result = runner.invoke(cli, ["catchup", str(repo), "--branch", "main"])

        assert result.exit_code == 1
        assert observed["plan"] == (
            repo.resolve(),
            repo.resolve() / ".securevibes",
            "incr456",
            "HEAD",
            None,
        )

    def test_catchup_falls_back_to_last_full_scan_anchor(self, runner, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        repo.mkdir()
        securevibes_dir = repo / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "scan_state.json").write_text(
            json.dumps(
                {
                    "last_full_scan": {
                        "commit": "base123",
                        "branch": "main",
                        "timestamp": "2026-03-21T00:00:00Z",
                    }
                }
            ),
            encoding="utf-8",
        )
        observed = {}

        async def fake_execute_incremental_plan(*_args, **_kwargs):
            return _incremental_execution_result()

        def fake_plan_incremental_range(
            repo_path: Path,
            securevibes_path: Path,
            *,
            base_ref: str,
            head_ref: str,
            generated_at: str | None = None,
        ) -> IncrementalPlan:
            observed["plan"] = (repo_path, securevibes_path, base_ref, head_ref, generated_at)
            return _incremental_plan()

        monkeypatch.setattr(
            "securevibes.cli.main.plan_incremental_range", fake_plan_incremental_range
        )
        monkeypatch.setattr(
            "securevibes.cli.main.get_diff_from_git_range",
            lambda *_args, **_kwargs: "diff --git a/src/auth.py b/src/auth.py\n",
        )
        monkeypatch.setattr(
            "securevibes.cli.main.parse_unified_diff",
            lambda diff: SimpleNamespace(raw=diff, changed_files=["src/auth.py"]),
        )
        monkeypatch.setattr(
            "securevibes.cli.main.execute_incremental_plan",
            fake_execute_incremental_plan,
        )
        monkeypatch.setattr("securevibes.cli.main._git_pull", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(
            "securevibes.cli.main._repo_has_local_changes",
            lambda *_args, **_kwargs: False,
        )
        monkeypatch.setattr(
            "securevibes.cli.main.get_repo_branch", lambda *_args, **_kwargs: "main"
        )
        monkeypatch.setattr(
            "securevibes.cli.main.get_repo_head_commit", lambda *_args, **_kwargs: "head789"
        )
        monkeypatch.setattr(
            "securevibes.cli.main.resolve_repo_commit",
            lambda _repo, ref: {"base123": "base123", "HEAD": "head789"}[ref],
        )

        result = runner.invoke(cli, ["catchup", str(repo), "--branch", "main"])

        assert result.exit_code == 1
        assert observed["plan"] == (
            repo.resolve(),
            repo.resolve() / ".securevibes",
            "base123",
            "HEAD",
            None,
        )

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


class TestIncrementalCommand:
    """Tests for incremental planning command."""

    def test_incremental_help(self, runner):
        result = runner.invoke(cli, ["incremental", "--help"])

        assert result.exit_code == 0
        assert "--base" in result.output
        assert "--head" in result.output

    def test_incremental_invokes_planner_and_prints_summary(
        self,
        runner,
        tmp_path,
        monkeypatch,
    ):
        repo = tmp_path / "repo"
        repo.mkdir()
        observed = {}

        def fake_plan_incremental_range(
            repo_path: Path,
            securevibes_dir: Path,
            *,
            base_ref: str,
            head_ref: str,
            generated_at: str | None = None,
        ) -> IncrementalPlan:
            observed["args"] = (repo_path, securevibes_dir, base_ref, head_ref, generated_at)
            return _incremental_plan()

        monkeypatch.setattr(
            "securevibes.cli.main.plan_incremental_range",
            fake_plan_incremental_range,
        )

        result = runner.invoke(
            cli,
            ["incremental", str(repo), "--base", "base123", "--head", "head456"],
        )

        assert result.exit_code == 0
        assert observed["args"] == (
            repo.resolve(),
            repo.resolve() / ".securevibes",
            "base123",
            "head456",
            None,
        )
        assert "planned 1 commit" in result.output.lower()
        assert "1 review cluster" in result.output.lower()

    def test_incremental_quiet_suppresses_summary(self, runner, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        repo.mkdir()

        monkeypatch.setattr(
            "securevibes.cli.main.plan_incremental_range",
            lambda *_args, **_kwargs: _incremental_plan(),
        )

        result = runner.invoke(
            cli,
            ["incremental", str(repo), "--base", "base123", "--head", "head456", "--quiet"],
        )

        assert result.exit_code == 0
        assert result.output == ""

    def test_incremental_reports_planner_errors(self, runner, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        repo.mkdir()

        def fail(*_args, **_kwargs):
            raise FileNotFoundError("Missing required baseline artifact: risk_map.json")

        monkeypatch.setattr("securevibes.cli.main.plan_incremental_range", fail)

        result = runner.invoke(
            cli,
            ["incremental", str(repo), "--base", "base123", "--head", "head456"],
        )

        assert result.exit_code == 1
        assert "risk_map.json" in result.output


class TestIncrementalRunCommand:
    """Tests for incremental execution command."""

    def test_incremental_run_help(self, runner):
        result = runner.invoke(cli, ["incremental-run", "--help"])

        assert result.exit_code == 0
        assert "--base" in result.output
        assert "--head" in result.output
        assert "--model" in result.output

    def test_incremental_run_invokes_planner_and_executor(
        self,
        runner,
        tmp_path,
        monkeypatch,
    ):
        repo = tmp_path / "repo"
        repo.mkdir()
        observed = {}

        async def fake_execute_incremental_plan(
            repo_path: Path,
            securevibes_dir: Path,
            plan: IncrementalPlan,
            diff_context,
            *,
            model: str,
            quiet: bool,
            debug: bool,
            known_vulns_path: Path | None = None,
            severity_threshold: str = "medium",
            update_artifacts: bool = False,
            scanner_factory=None,
        ) -> IncrementalExecutionResult:
            observed["execute"] = (
                repo_path,
                securevibes_dir,
                plan.base_ref,
                diff_context,
                model,
                quiet,
                debug,
                known_vulns_path,
                severity_threshold,
                update_artifacts,
            )
            return _incremental_execution_result()

        monkeypatch.setattr(
            "securevibes.cli.main.plan_incremental_range",
            lambda repo_path, securevibes_dir, *, base_ref, head_ref: _incremental_plan(),
        )
        monkeypatch.setattr(
            "securevibes.cli.main.get_diff_from_git_range",
            lambda repo_path, base, head: "diff --git a/a.py b/a.py\n",
        )
        monkeypatch.setattr(
            "securevibes.cli.main.parse_unified_diff",
            lambda diff: SimpleNamespace(raw=diff, changed_files=["a.py"]),
        )
        monkeypatch.setattr(
            "securevibes.cli.main.execute_incremental_plan",
            fake_execute_incremental_plan,
        )

        result = runner.invoke(
            cli,
            [
                "incremental-run",
                str(repo),
                "--base",
                "base123",
                "--head",
                "head456",
                "--model",
                "sonnet",
                "--update-artifacts",
            ],
        )

        assert result.exit_code == 1
        assert observed["execute"] == (
            repo.resolve(),
            repo.resolve() / ".securevibes",
            "base123",
            SimpleNamespace(raw="diff --git a/a.py b/a.py\n", changed_files=["a.py"]),
            "sonnet",
            False,
            False,
            None,
            "medium",
            True,
        )
        assert "executed 1 cluster" in result.output.lower()
        assert "skipped 1 cluster" in result.output.lower()

    def test_incremental_run_quiet_suppresses_summary(self, runner, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        repo.mkdir()

        async def fake_execute_incremental_plan(*_args, **_kwargs):
            return _incremental_execution_result()

        monkeypatch.setattr(
            "securevibes.cli.main.plan_incremental_range",
            lambda repo_path, securevibes_dir, *, base_ref, head_ref: _incremental_plan(),
        )
        monkeypatch.setattr(
            "securevibes.cli.main.get_diff_from_git_range",
            lambda repo_path, base, head: "diff --git a/a.py b/a.py\n",
        )
        monkeypatch.setattr(
            "securevibes.cli.main.parse_unified_diff",
            lambda diff: SimpleNamespace(raw=diff, changed_files=["a.py"]),
        )
        monkeypatch.setattr(
            "securevibes.cli.main.execute_incremental_plan",
            fake_execute_incremental_plan,
        )

        result = runner.invoke(
            cli,
            ["incremental-run", str(repo), "--base", "base123", "--head", "head456", "--quiet"],
        )

        assert result.exit_code == 1
        assert result.output == ""

    def test_incremental_run_persists_last_incremental_anchor(self, runner, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        repo.mkdir()

        async def fake_execute_incremental_plan(*_args, **_kwargs):
            return IncrementalExecutionResult(
                cluster_results=(
                    ClusterExecutionResult(
                        cluster_id="cluster-001",
                        route="targeted_pr_review",
                        status="executed",
                    ),
                )
            )

        monkeypatch.setattr(
            "securevibes.cli.main.plan_incremental_range",
            lambda repo_path, securevibes_dir, *, base_ref, head_ref: _incremental_plan(),
        )
        monkeypatch.setattr(
            "securevibes.cli.main.get_diff_from_git_range",
            lambda repo_path, base, head: "diff --git a/a.py b/a.py\n",
        )
        monkeypatch.setattr(
            "securevibes.cli.main.parse_unified_diff",
            lambda diff: SimpleNamespace(raw=diff, changed_files=["a.py"]),
        )
        monkeypatch.setattr(
            "securevibes.cli.main.execute_incremental_plan",
            fake_execute_incremental_plan,
        )
        monkeypatch.setattr(
            "securevibes.cli.main.resolve_repo_commit",
            lambda _repo, ref: {"base123": "abc123", "head456": "def456"}[ref],
        )
        monkeypatch.setattr(
            "securevibes.cli.main.get_repo_branch", lambda *_args, **_kwargs: "main"
        )

        result = runner.invoke(
            cli,
            ["incremental-run", str(repo), "--base", "base123", "--head", "head456"],
        )

        assert result.exit_code == 0
        state_payload = json.loads((repo / ".securevibes" / "scan_state.json").read_text())
        assert state_payload["last_incremental_run"] == {
            "commit": "def456",
            "base_commit": "abc123",
            "branch": "main",
            "timestamp": state_payload["last_incremental_run"]["timestamp"],
        }


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

    def test_json_quiet_output_is_parseable_json(self, runner, test_repo):
        """Quiet JSON scan output should remain parseable on stdout."""
        scanner = MagicMock()
        scanner.configure_agentic_detection = MagicMock()
        scanner.configure_dast = MagicMock()
        scanner.scan = AsyncMock(return_value=_empty_scan_result(test_repo))

        with patch("securevibes.cli.main.Scanner", return_value=scanner) as mock_scanner:
            result = runner.invoke(cli, ["scan", str(test_repo), "--format", "json", "--quiet"])

        assert result.exit_code == 0
        mock_scanner.assert_called_once_with(model="sonnet", debug=False, quiet=True)
        payload = json.loads(result.stdout)
        assert payload["repository_path"] == str(test_repo)
        assert payload["issues"] == []

    def test_json_quiet_runtime_failure_writes_error_to_stderr(self, runner, test_repo):
        """Quiet JSON scan failures should not pollute stdout."""
        with patch(
            "securevibes.cli.main._run_scan",
            new_callable=AsyncMock,
            side_effect=RuntimeError("boom"),
        ):
            result = runner.invoke(cli, ["scan", str(test_repo), "--format", "json", "--quiet"])

        assert result.exit_code == 1
        assert result.stdout == ""
        assert "boom" in result.stderr

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
                [
                    "scan",
                    str(test_repo),
                    "--format",
                    "markdown",
                    "--output",
                    "custom_report.md",
                ],
            )

        report_path = test_repo / ".securevibes" / "custom_report.md"
        assert result.exit_code == 0
        assert report_path.exists()
        assert "custom_report.md" in result.output

    def test_scan_markdown_output_absolute_path(self, runner, test_repo):
        """Absolute markdown output path is allowed when it stays within repo root."""
        output_file = (test_repo / "absolute_report.md").resolve()
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
                    str(output_file),
                ],
            )

        assert result.exit_code == 0
        assert output_file.exists()
        assert output_file.name in result.output

    def test_scan_markdown_output_rejects_absolute_path_outside_repo(
        self, runner, test_repo, tmp_path
    ):
        """Absolute markdown output path must not escape repository boundaries."""
        output_file = (test_repo.parent / "outside_report.md").resolve()
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
                    str(output_file),
                ],
            )

        assert result.exit_code == 1
        assert "outside repository root" in result.output
        assert not output_file.exists()

    def test_scan_json_output_absolute_path_inside_repo(self, runner, test_repo):
        """Absolute JSON output path is allowed when it stays within repo root."""
        output_file = (test_repo / "scan_results.json").resolve()
        with patch("securevibes.cli.main._run_scan", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = _empty_scan_result(test_repo)
            result = runner.invoke(
                cli,
                [
                    "scan",
                    str(test_repo),
                    "--format",
                    "json",
                    "--output",
                    str(output_file),
                ],
            )

        assert result.exit_code == 0
        assert output_file.exists()
        assert "Results saved to" in result.output

    def test_scan_json_output_rejects_absolute_path_outside_repo(self, runner, test_repo, tmp_path):
        """Absolute JSON output path must not escape repository boundaries."""
        output_file = (test_repo.parent / "outside_results.json").resolve()
        with patch("securevibes.cli.main._run_scan", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = _empty_scan_result(test_repo)
            result = runner.invoke(
                cli,
                [
                    "scan",
                    str(test_repo),
                    "--format",
                    "json",
                    "--output",
                    str(output_file),
                ],
            )

        assert result.exit_code == 1
        assert "outside repository root" in result.output
        assert not output_file.exists()

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


class TestPRReviewOutput:
    """Test PR review JSON output behavior."""

    @staticmethod
    def _prepare_pr_review_repo(tmp_path: Path) -> tuple[Path, Path]:
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
            "-safe()\n"
            "+danger()\n",
            encoding="utf-8",
        )
        return repo, diff_file

    def test_pr_review_json_quiet_output_is_parseable_json(self, runner, tmp_path):
        """Quiet JSON PR review output should remain parseable on stdout."""
        repo, diff_file = self._prepare_pr_review_repo(tmp_path)
        scanner = MagicMock()
        scanner.pr_review = AsyncMock(return_value=_empty_scan_result(repo))

        with patch("securevibes.cli.main.Scanner", return_value=scanner) as mock_scanner:
            result = runner.invoke(
                cli,
                [
                    "pr-review",
                    str(repo),
                    "--diff",
                    str(diff_file),
                    "--format",
                    "json",
                    "--quiet",
                ],
            )

        assert result.exit_code == 0
        mock_scanner.assert_called_once_with(model="sonnet", debug=False, quiet=True)
        payload = json.loads(result.stdout)
        assert payload["repository_path"] == str(repo)
        assert payload["issues"] == []

    def test_pr_review_nonzero_exit_with_parseable_json(self, runner, tmp_path):
        """PR review should keep stdout parseable even when findings drive a non-zero exit."""
        repo, diff_file = self._prepare_pr_review_repo(tmp_path)
        scanner = MagicMock()
        scanner.pr_review = AsyncMock(return_value=_scan_result_with_issue(repo))

        with patch("securevibes.cli.main.Scanner", return_value=scanner):
            result = runner.invoke(
                cli,
                [
                    "pr-review",
                    str(repo),
                    "--diff",
                    str(diff_file),
                    "--format",
                    "json",
                    "--quiet",
                ],
            )

        assert result.exit_code == 1
        payload = json.loads(result.stdout)
        assert payload["summary"]["high"] == 1
        assert payload["issues"][0]["id"] == "ISSUE-1"

    def test_pr_review_runtime_failure_writes_error_to_stderr(self, runner, tmp_path):
        """Quiet JSON PR review failures should not pollute stdout."""
        repo, diff_file = self._prepare_pr_review_repo(tmp_path)

        with patch(
            "securevibes.cli.main._run_pr_review",
            new_callable=AsyncMock,
            side_effect=RuntimeError("boom"),
        ):
            result = runner.invoke(
                cli,
                [
                    "pr-review",
                    str(repo),
                    "--diff",
                    str(diff_file),
                    "--format",
                    "json",
                    "--quiet",
                ],
            )

        assert result.exit_code == 1
        assert result.stdout == ""
        assert "boom" in result.stderr


class TestCLIErrorMessages:
    """Test CLI error messages are helpful"""

    # Removed test_missing_api_key_message - API key validation is now delegated to claude CLI
    # Authentication is handled through environment inheritance (ANTHROPIC_API_KEY, session tokens, etc.)
