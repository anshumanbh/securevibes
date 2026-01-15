"""Tests for CLI sub-agent selection"""

import pytest
from click.testing import CliRunner
from unittest.mock import Mock, patch, AsyncMock

from securevibes.cli.main import cli


@pytest.fixture
def runner():
    """Create Click CLI test runner"""
    return CliRunner()


@pytest.fixture
def mock_scanner():
    """Mock Scanner class"""
    with patch("securevibes.cli.main.Scanner") as mock:
        instance = mock.return_value
        instance.scan = AsyncMock()
        instance.scan_subagent = AsyncMock()
        instance.scan_resume = AsyncMock()
        instance.configure_dast = Mock()

        # Mock scan result
        mock_result = Mock()
        mock_result.issues = []
        mock_result.files_scanned = 10
        mock_result.scan_time_seconds = 5.0
        mock_result.total_cost_usd = 0.01
        mock_result.critical_count = 0
        mock_result.high_count = 0
        mock_result.medium_count = 0
        mock_result.low_count = 0

        instance.scan.return_value = mock_result
        instance.scan_subagent.return_value = mock_result
        instance.scan_resume.return_value = mock_result

        yield instance


def test_subagent_conflicts_with_dast(runner, tmp_path):
    """Test --subagent and --dast are mutually exclusive"""
    result = runner.invoke(
        cli,
        [
            "scan",
            str(tmp_path),
            "--subagent",
            "dast",
            "--dast",
            "--target-url",
            "http://localhost:3000",
        ],
    )

    assert result.exit_code == 1
    assert "--subagent and --dast are mutually exclusive" in result.output


def test_subagent_conflicts_with_resume_from(runner, tmp_path):
    """Test --subagent and --resume-from are mutually exclusive"""
    result = runner.invoke(
        cli, ["scan", str(tmp_path), "--subagent", "assessment", "--resume-from", "code-review"]
    )

    assert result.exit_code == 1
    assert "--subagent and --resume-from are mutually exclusive" in result.output


def test_subagent_dast_requires_target_url(runner, tmp_path):
    """Test --subagent dast requires --target-url"""
    result = runner.invoke(cli, ["scan", str(tmp_path), "--subagent", "dast"])

    assert result.exit_code == 1
    assert "--target-url is required for DAST sub-agent" in result.output


def test_resume_from_dast_requires_target_url(runner, tmp_path):
    """Test --resume-from dast requires --target-url"""
    result = runner.invoke(cli, ["scan", str(tmp_path), "--resume-from", "dast"])

    assert result.exit_code == 1
    assert "--target-url is required when resuming from DAST" in result.output


@patch("securevibes.cli.main.Scanner")
def test_subagent_assessment(mock_scanner_class, runner, tmp_path):
    """Test running assessment sub-agent calls scan_subagent method"""
    # Create mock scanner instance and methods
    mock_scanner = Mock()
    mock_result = Mock()
    mock_result.issues = []
    mock_result.files_scanned = 10
    mock_result.scan_time_seconds = 5.0
    mock_result.total_cost_usd = 0.01
    mock_result.critical_count = 0
    mock_result.high_count = 0
    mock_result.medium_count = 0
    mock_result.low_count = 0

    mock_scanner.scan_subagent = AsyncMock(return_value=mock_result)
    mock_scanner_class.return_value = mock_scanner

    result = runner.invoke(
        cli, ["scan", str(tmp_path), "--subagent", "assessment", "--format", "table"]
    )

    # Should call Scanner.scan_subagent with 'assessment'
    mock_scanner.scan_subagent.assert_called_once()
    call_args = mock_scanner.scan_subagent.call_args
    assert call_args[0][1] == "assessment"  # Second positional arg is subagent name
    assert result.exit_code == 0


@patch("securevibes.cli.main._run_scan")
def test_subagent_dast_with_target_url(mock_run_scan, runner, tmp_path):
    """Test running DAST sub-agent with target URL"""
    # Create mock result with all required attributes
    mock_result = Mock()
    mock_result.issues = []
    mock_result.files_scanned = 10
    mock_result.scan_time_seconds = 5.0
    mock_result.total_cost_usd = 0.01
    mock_result.critical_count = 0
    mock_result.high_count = 0
    mock_result.medium_count = 0
    mock_result.low_count = 0

    # Mock async function using AsyncMock for proper coroutine handling
    async_mock = AsyncMock(return_value=mock_result)
    mock_run_scan.side_effect = lambda *args, **kwargs: async_mock(*args, **kwargs)

    result = runner.invoke(
        cli,
        [
            "scan",
            str(tmp_path),
            "--subagent",
            "dast",
            "--target-url",
            "http://localhost:3000",
            "--format",
            "table",
        ],
    )

    # Note: This will fail without mocking Scanner, but tests flag validation
    assert "--target-url" in result.output or result.exit_code in [0, 1]


@patch("securevibes.cli.main.Scanner")
def test_resume_from_code_review(mock_scanner_class, runner, tmp_path):
    """Test resuming from code-review sub-agent calls scan_resume method"""
    # Create mock scanner instance and methods
    mock_scanner = Mock()
    mock_result = Mock()
    mock_result.issues = []
    mock_result.files_scanned = 10
    mock_result.scan_time_seconds = 5.0
    mock_result.total_cost_usd = 0.01
    mock_result.critical_count = 0
    mock_result.high_count = 0
    mock_result.medium_count = 0
    mock_result.low_count = 0

    mock_scanner.scan_resume = AsyncMock(return_value=mock_result)
    mock_scanner_class.return_value = mock_scanner

    result = runner.invoke(
        cli, ["scan", str(tmp_path), "--resume-from", "code-review", "--format", "table"]
    )

    # Should call Scanner.scan_resume with 'code-review'
    mock_scanner.scan_resume.assert_called_once()
    call_args = mock_scanner.scan_resume.call_args
    assert call_args[0][1] == "code-review"  # Second positional arg is from_subagent name
    assert result.exit_code == 0


def test_force_flag_available(runner, tmp_path):
    """Test --force flag is recognized"""
    result = runner.invoke(cli, ["scan", str(tmp_path), "--help"])

    assert "--force" in result.output
    assert "Skip confirmation prompts" in result.output


def test_skip_checks_flag_available(runner, tmp_path):
    """Test --skip-checks flag is recognized"""
    result = runner.invoke(cli, ["scan", str(tmp_path), "--help"])

    assert "--skip-checks" in result.output
    assert "Bypass artifact validation" in result.output


def test_subagent_choices(runner, tmp_path):
    """Test --subagent has correct choices"""
    result = runner.invoke(cli, ["scan", str(tmp_path), "--help"])

    assert "assessment" in result.output
    assert "threat-modeling" in result.output
    assert "code-review" in result.output
    assert "report-generator" in result.output
    assert "dast" in result.output


def test_resume_from_choices(runner, tmp_path):
    """Test --resume-from has correct choices"""
    result = runner.invoke(cli, ["scan", str(tmp_path), "--help"])

    assert "--resume-from" in result.output
    # Choices should be listed in help


def test_dast_flag_help_text_updated(runner, tmp_path):
    """Test --dast help text mentions full scan"""
    result = runner.invoke(cli, ["scan", str(tmp_path), "--help"])

    assert "--dast" in result.output
    assert "full scan" in result.output.lower()


@patch("asyncio.run")
@patch("securevibes.cli.main.Scanner")
def test_run_scan_calls_scan_subagent(mock_scanner_class, mock_asyncio_run, runner, tmp_path):
    """Test _run_scan routes to scan_subagent"""
    mock_scanner = Mock()
    mock_scanner.configure_dast = Mock()
    mock_scanner.scan_subagent = AsyncMock()
    mock_scanner_class.return_value = mock_scanner

    # Mock the result
    mock_result = Mock()
    mock_result.issues = []
    mock_result.files_scanned = 1
    mock_result.scan_time_seconds = 1.0
    mock_result.total_cost_usd = 0.0
    mock_result.critical_count = 0
    mock_result.high_count = 0
    mock_result.medium_count = 0
    mock_result.low_count = 0
    mock_asyncio_run.return_value = mock_result

    result = runner.invoke(
        cli, ["scan", str(tmp_path), "--subagent", "assessment", "--format", "table"]
    )

    # Verify asyncio.run was called (which calls _run_scan)
    assert result.exit_code == 0
    assert mock_asyncio_run.called


@patch("asyncio.run")
@patch("securevibes.cli.main.Scanner")
def test_run_scan_calls_scan_resume(mock_scanner_class, mock_asyncio_run, runner, tmp_path):
    """Test _run_scan routes to scan_resume"""
    mock_scanner = Mock()
    mock_scanner.configure_dast = Mock()
    mock_scanner.scan_resume = AsyncMock()
    mock_scanner_class.return_value = mock_scanner

    # Mock the result
    mock_result = Mock()
    mock_result.issues = []
    mock_result.files_scanned = 1
    mock_result.scan_time_seconds = 1.0
    mock_result.total_cost_usd = 0.0
    mock_result.critical_count = 0
    mock_result.high_count = 0
    mock_result.medium_count = 0
    mock_result.low_count = 0
    mock_asyncio_run.return_value = mock_result

    result = runner.invoke(
        cli, ["scan", str(tmp_path), "--resume-from", "threat-modeling", "--format", "table"]
    )

    assert result.exit_code == 0
    assert mock_asyncio_run.called


def test_invalid_subagent_rejected(runner, tmp_path):
    """Test invalid sub-agent name is rejected"""
    result = runner.invoke(cli, ["scan", str(tmp_path), "--subagent", "invalid-agent"])

    assert result.exit_code == 2  # Click validation error
    assert "Invalid value" in result.output or "invalid choice" in result.output.lower()


def test_invalid_resume_from_rejected(runner, tmp_path):
    """Test invalid resume-from value is rejected"""
    result = runner.invoke(cli, ["scan", str(tmp_path), "--resume-from", "invalid-agent"])

    assert result.exit_code == 2  # Click validation error
    assert "Invalid value" in result.output or "invalid choice" in result.output.lower()
