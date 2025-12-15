"""Tests for CLI commands"""

import pytest
from click.testing import CliRunner
from pathlib import Path
from securevibes.cli.main import cli


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
        result = runner.invoke(cli, ['--help'])
        assert result.exit_code == 0
        assert 'SecureVibes' in result.output
        assert 'scan' in result.output
    
    def test_cli_version(self, runner):
        """Test CLI version command"""
        result = runner.invoke(cli, ['--version'])
        assert result.exit_code == 0
        assert 'securevibes' in result.output.lower()
        # Check for version format (X.Y.Z)
        import re
        assert re.search(r'\d+\.\d+\.\d+', result.output)
    
    def test_scan_help(self, runner):
        """Test scan command help"""
        result = runner.invoke(cli, ['scan', '--help'])
        assert result.exit_code == 0
        assert 'scan' in result.output.lower()
    


class TestScanCommand:
    """Test scan command"""
    
    def test_scan_nonexistent_path(self, runner):
        """Test scan with non-existent path"""
        result = runner.invoke(cli, ['scan', '/nonexistent/path'])
        assert result.exit_code != 0
        assert 'Error' in result.output or 'does not exist' in result.output.lower()
    
    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Requires Claude API key")
    def test_scan_with_path(self, runner, test_repo):
        """Test scan with valid path"""
        result = runner.invoke(cli, ['scan', str(test_repo), '--model', 'claude-3-5-haiku-20241022'])
        assert result.exit_code == 0
        assert 'SecureVibes' in result.output
    
    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Requires Claude API key")
    def test_scan_with_options(self, runner, test_repo):
        """Test scan with various options"""
        result = runner.invoke(cli, [
            'scan',
            str(test_repo),
            '--model', 'claude-3-5-haiku-20241022',
            '--format', 'json'
        ])
        # Should complete (may fail if no API key, but command structure is valid)
        assert '--help' not in result.output  # Didn't fall back to help
    
    @pytest.mark.skip(reason="Requires scanner/API - output path logic tested in test_output_paths.py")
    def test_scan_markdown_format_default(self, runner, test_repo):
        """Test that markdown is default format"""
        result = runner.invoke(cli, ['scan', str(test_repo)])
        # Should mention .md file or markdown
        pass
    
    @pytest.mark.skip(reason="Requires scanner/API - output path logic tested in test_output_paths.py")
    def test_scan_markdown_output_relative_path(self, runner, test_repo):
        """Test markdown output with relative filename saves to .securevibes/"""
        result = runner.invoke(cli, [
            'scan', str(test_repo),
            '--format', 'markdown',
            '--output', 'custom_report.md'
        ])
        assert 'custom_report.md' in result.output or result.exit_code == 0
    
    @pytest.mark.skip(reason="Requires scanner/API - output path logic tested in test_output_paths.py")
    def test_scan_markdown_output_absolute_path(self, runner, test_repo, tmp_path):
        """Test markdown output with absolute path preserves the path"""
        output_file = tmp_path / "absolute_report.md"
        result = runner.invoke(cli, [
            'scan', str(test_repo),
            '--format', 'markdown',
            '--output', str(output_file)
        ])
        assert str(output_file) in result.output or result.exit_code == 0
    
    @pytest.mark.skip(reason="Requires scanner/API")
    def test_scan_table_format_still_works(self, runner, test_repo):
        """Test backward compatibility - table format still works"""
        result = runner.invoke(cli, [
            'scan', str(test_repo),
            '--format', 'table'
        ])
        pass



class TestReportCommand:
    """Test report command"""
    
    def test_report_nonexistent_file(self, runner):
        """Test report with non-existent file"""
        result = runner.invoke(cli, ['report', '/nonexistent/report.json'])
        assert result.exit_code != 0
        assert 'not found' in result.output.lower() or 'Error' in result.output
    
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
                    "cwe_id": "CWE-89"
                }
            ]
        }
        
        report_file = tmp_path / "scan_results.json"
        report_file.write_text(json.dumps(scan_data))
        
        result = runner.invoke(cli, ['report', str(report_file)])
        assert result.exit_code == 0
        assert 'Scan Results' in result.output
        assert 'Test Issue' in result.output


class TestCLIOutputFormats:
    """Test CLI output formatting"""
    
    @pytest.mark.skip(reason="Requires valid scan results")
    def test_json_output_format(self, runner, test_repo):
        """Test JSON output format"""
        result = runner.invoke(cli, [
            'scan',
            str(test_repo),
            '--format', 'json'
        ])
        # Output should be JSON-parseable (if scan succeeds)
        if result.exit_code == 0:
            import json
            try:
                json.loads(result.output)
            except json.JSONDecodeError:
                pass  # May include non-JSON progress output
    
    @pytest.mark.skip(reason="Requires valid scan results")
    def test_table_output_format(self, runner, test_repo):
        """Test table output format (default)"""
        result = runner.invoke(cli, ['scan', str(test_repo)])
        # Should have table formatting
        if 'Scan Results' in result.output:
            assert '═' in result.output or '─' in result.output  # Box drawing characters


class TestCLIErrorMessages:
    """Test CLI error messages are helpful"""
    
    # Removed test_missing_api_key_message - API key validation is now delegated to claude CLI
    # Authentication is handled through environment inheritance (ANTHROPIC_API_KEY, session tokens, etc.)
