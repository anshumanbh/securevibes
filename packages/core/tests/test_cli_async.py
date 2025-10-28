
import pytest
from click.testing import CliRunner
from securevibes.cli.main import cli

def test_scan_with_mutually_exclusive_flags():
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '.', '--subagent', 'assessment', '--resume-from', 'code-review'])
    assert result.exit_code == 1
    assert "mutually exclusive" in result.output

def test_scan_with_mutually_exclusive_flags_2():
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '.', '--subagent', 'assessment', '--dast'])
    assert result.exit_code == 1
    assert "mutually exclusive" in result.output

def test_scan_dast_requires_target_url():
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '.', '--dast'])
    assert result.exit_code == 1
    assert "--target-url is required" in result.output

def test_scan_dast_subagent_requires_target_url():
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '.', '--subagent', 'dast'])
    assert result.exit_code == 1
    assert "--target-url is required" in result.output

def test_scan_resume_from_dast_requires_target_url():
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '.', '--resume-from', 'dast'])
    assert result.exit_code == 1
    assert "--target-url is required" in result.output

def test_scan_dast_production_url_fails_without_allow():
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '.', '--dast', '--target-url', 'https://example.com'])
    assert result.exit_code == 1
    assert "PRODUCTION URL DETECTED" in result.output

def test_scan_dast_production_url_succeeds_with_allow(mocker):
    from securevibes.models.result import ScanResult
    async def _run_scan(*args, **kwargs):
        return ScanResult(repository_path='.', issues=[], files_scanned=0, scan_time_seconds=0)
    mocker.patch('securevibes.cli.main._run_scan', side_effect=_run_scan)
    mocker.patch('securevibes.cli.main._check_target_reachability', return_value=True)
    runner = CliRunner()
    try:
        cli.main(['scan', '.', '--dast', '--target-url', 'https://example.com', '--allow-production', '--force'], standalone_mode=False)
    except SystemExit as e:
        assert e.code == 0

def test_scan_json_output_to_file(mocker, tmp_path):
    from securevibes.models.result import ScanResult
    async def _run_scan(*args, **kwargs):
        return ScanResult(repository_path='.', issues=[], files_scanned=0, scan_time_seconds=0)
    mocker.patch('securevibes.cli.main._run_scan', side_effect=_run_scan)
    runner = CliRunner()
    output_path = tmp_path / "results.json"
    try:
        cli.main(['scan', '.', '--format', 'json', '--output', str(output_path)], standalone_mode=False)
    except SystemExit as e:
        assert e.code == 0
    assert output_path.exists()

def test_scan_markdown_output_to_file(mocker, tmp_path):
    from securevibes.models.result import ScanResult
    async def _run_scan(*args, **kwargs):
        return ScanResult(repository_path='.', issues=[], files_scanned=0, scan_time_seconds=0)
    mocker.patch('securevibes.cli.main._run_scan', side_effect=_run_scan)
    mocker.patch('securevibes.reporters.markdown_reporter.MarkdownReporter.save')
    runner = CliRunner()
    output_path = tmp_path / "report.md"
    try:
        cli.main(['scan', '.', '--format', 'markdown', '--output', str(output_path)], standalone_mode=False)
    except SystemExit as e:
        assert e.code == 0

def test_report_valid_file(mocker, tmp_path):
    mock_data = {
        "repository_path": "/path/to/repo",
        "files_scanned": 10,
        "scan_time_seconds": 120,
        "issues": []
    }
    mocker.patch('securevibes.reporters.json_reporter.JSONReporter.load', return_value=mock_data)
    runner = CliRunner()
    report_path = tmp_path / "report.json"
    report_path.touch()
    result = runner.invoke(cli, ['report', str(report_path)])
    assert result.exit_code == 0
    assert "Loading report" in result.output
    assert "Scan Results" in result.output

def test_report_missing_file():
    runner = CliRunner()
    result = runner.invoke(cli, ['report', 'nonexistent.json'])
    assert result.exit_code == 2
    assert "does not exist" in result.output

def test_report_invalid_json(tmp_path):
    runner = CliRunner()
    report_path = tmp_path / "invalid.json"
    report_path.write_text("{")
    result = runner.invoke(cli, ['report', str(report_path)])
    assert result.exit_code == 1
    assert "Error loading report" in result.output

def test_report_missing_fields(mocker, tmp_path):
    mock_data = {"issues": []}
    mocker.patch('securevibes.reporters.json_reporter.JSONReporter.load', return_value=mock_data)
    runner = CliRunner()
    report_path = tmp_path / "report.json"
    report_path.touch()
    result = runner.invoke(cli, ['report', str(report_path)])
    assert result.exit_code == 1
    assert "Invalid report format" in result.output
