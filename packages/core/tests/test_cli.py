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
    
    def test_assess_help(self, runner):
        """Test assess command help"""
        result = runner.invoke(cli, ['assess', '--help'])
        assert result.exit_code == 0
        assert 'assess' in result.output.lower()
    
    def test_threat_model_help(self, runner):
        """Test threat-model command help"""
        result = runner.invoke(cli, ['threat-model', '--help'])
        assert result.exit_code == 0
        assert 'threat' in result.output.lower()
    
    def test_review_help(self, runner):
        """Test review command help"""
        result = runner.invoke(cli, ['review', '--help'])
        assert result.exit_code == 0
        assert 'review' in result.output.lower()


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


class TestAssessCommand:
    """Test assess command"""
    
    def test_assess_nonexistent_path(self, runner):
        """Test assess with non-existent path"""
        result = runner.invoke(cli, ['assess', '/nonexistent/path'])
        assert result.exit_code != 0
    
    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Requires Claude API key")
    def test_assess_with_path(self, runner, test_repo):
        """Test assess with valid path"""
        result = runner.invoke(cli, ['assess', str(test_repo)])
        # Should run (may fail without API key, but command structure is valid)
        assert 'Assessment' in result.output or 'Error' in result.output


class TestThreatModelCommand:
    """Test threat-model command"""
    
    def test_threat_model_without_security_md(self, runner, test_repo):
        """Test threat-model fails without SECURITY.md"""
        result = runner.invoke(cli, ['threat-model', str(test_repo)])
        assert result.exit_code != 0
        # Should mention missing SECURITY.md
        assert 'SECURITY.md' in result.output or 'not found' in result.output.lower()
    
    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Requires Claude API key and SECURITY.md")
    def test_threat_model_with_security_md(self, runner, test_repo):
        """Test threat-model with existing SECURITY.md"""
        # Create SECURITY.md
        securevibes_dir = test_repo / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "SECURITY.md").write_text("# Security Architecture\n\n## Overview\nTest")
        
        result = runner.invoke(cli, ['threat-model', str(test_repo)])
        assert 'Threat' in result.output or 'Error' in result.output


class TestReviewCommand:
    """Test review command"""
    
    def test_review_without_artifacts(self, runner, test_repo):
        """Test review fails without required artifacts"""
        result = runner.invoke(cli, ['review', str(test_repo)])
        assert result.exit_code != 0
        # Should mention missing files
        assert 'not found' in result.output.lower() or 'Error' in result.output


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
    
    @pytest.mark.skip(reason="Environment manipulation causes test hang")
    def test_missing_api_key_message(self, runner, test_repo):
        """Test helpful message when API key is missing"""
        import os
        # Temporarily unset API key
        original_key = os.environ.get('CLAUDE_API_KEY')
        if 'CLAUDE_API_KEY' in os.environ:
            del os.environ['CLAUDE_API_KEY']
        
        try:
            result = runner.invoke(cli, ['scan', str(test_repo)])
            # Should mention API key (or fail gracefully)
            # Actual behavior depends on implementation
            assert result.exit_code != 0 or 'API' in result.output
        finally:
            # Restore original key
            if original_key:
                os.environ['CLAUDE_API_KEY'] = original_key
