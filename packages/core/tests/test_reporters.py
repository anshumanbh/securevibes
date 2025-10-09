"""Tests for reporters"""

import pytest
import json
from pathlib import Path
from securevibes.reporters.json_reporter import JSONReporter
from securevibes.models.issue import SecurityIssue, Severity
from securevibes.models.result import ScanResult


@pytest.fixture
def sample_result():
    """Create a sample scan result"""
    issues = [
        SecurityIssue(
            id="test-1",
            severity=Severity.CRITICAL,
            title="SQL Injection",
            description="SQL injection vulnerability",
            file_path="app.py",
            line_number=42,
            code_snippet="query = f'SELECT * FROM users WHERE id={user_id}'",
            recommendation="Use parameterized queries",
            cwe_id="CWE-89"
        ),
        SecurityIssue(
            id="test-2",
            severity=Severity.HIGH,
            title="Command Injection",
            description="Command injection via os.system",
            file_path="admin.py",
            line_number=15,
            code_snippet="os.system(f'cat {filename}')",
            recommendation="Use subprocess with arguments list",
            cwe_id="CWE-78"
        ),
    ]
    
    return ScanResult(
        repository_path="/tmp/test-repo",
        issues=issues,
        files_scanned=10,
        scan_time_seconds=5.5
    )


class TestJSONReporter:
    """Test JSON reporter functionality"""
    
    def test_save_creates_file(self, tmp_path, sample_result):
        """Test that save creates a file"""
        output_file = tmp_path / "results.json"
        
        JSONReporter.save(sample_result, output_file)
        
        assert output_file.exists()
        assert output_file.stat().st_size > 0
    
    def test_save_creates_directory(self, tmp_path, sample_result):
        """Test that save creates parent directory if needed"""
        output_file = tmp_path / "nested" / "dir" / "results.json"
        
        JSONReporter.save(sample_result, output_file)
        
        assert output_file.exists()
        assert output_file.parent.exists()
    
    def test_saved_content_is_valid_json(self, tmp_path, sample_result):
        """Test that saved content is valid JSON"""
        output_file = tmp_path / "results.json"
        
        JSONReporter.save(sample_result, output_file)
        
        # Should be valid JSON
        with open(output_file) as f:
            data = json.load(f)
        
        assert isinstance(data, dict)
    
    def test_saved_content_has_expected_structure(self, tmp_path, sample_result):
        """Test that saved JSON has expected structure"""
        output_file = tmp_path / "results.json"
        
        JSONReporter.save(sample_result, output_file)
        
        with open(output_file) as f:
            data = json.load(f)
        
        # Check top-level keys
        assert 'repository_path' in data
        assert 'issues' in data
        assert 'files_scanned' in data
        assert 'scan_time_seconds' in data
        assert 'summary' in data
        
        # Check issues structure
        assert isinstance(data['issues'], list)
        assert len(data['issues']) == 2
        
        # Check first issue structure
        issue = data['issues'][0]
        assert 'id' in issue
        assert 'severity' in issue
        assert 'title' in issue
        assert 'description' in issue
        assert 'file_path' in issue
        assert 'line_number' in issue
        
        # Check summary
        assert data['summary']['total'] == 2
        assert data['summary']['critical'] == 1
        assert data['summary']['high'] == 1
    
    def test_load_reads_file(self, tmp_path, sample_result):
        """Test that load reads a file correctly"""
        output_file = tmp_path / "results.json"
        
        # Save first
        JSONReporter.save(sample_result, output_file)
        
        # Load back
        loaded_data = JSONReporter.load(output_file)
        
        assert loaded_data is not None
        assert isinstance(loaded_data, dict)
        assert loaded_data['repository_path'] == "/tmp/test-repo"
        assert len(loaded_data['issues']) == 2
    
    def test_load_nonexistent_file_raises_error(self, tmp_path):
        """Test that load raises error for non-existent file"""
        output_file = tmp_path / "nonexistent.json"
        
        with pytest.raises(FileNotFoundError):
            JSONReporter.load(output_file)
    
    def test_load_invalid_json_raises_error(self, tmp_path):
        """Test that load raises error for invalid JSON"""
        output_file = tmp_path / "invalid.json"
        output_file.write_text("not valid json {")
        
        with pytest.raises(json.JSONDecodeError):
            JSONReporter.load(output_file)
    
    def test_roundtrip_preserves_data(self, tmp_path, sample_result):
        """Test that save -> load preserves all data"""
        output_file = tmp_path / "results.json"
        
        # Save
        JSONReporter.save(sample_result, output_file)
        
        # Load
        loaded_data = JSONReporter.load(output_file)
        
        # Verify data preserved
        assert loaded_data['repository_path'] == sample_result.repository_path
        assert loaded_data['files_scanned'] == sample_result.files_scanned
        assert loaded_data['scan_time_seconds'] == sample_result.scan_time_seconds
        assert len(loaded_data['issues']) == len(sample_result.issues)
        
        # Check first issue
        loaded_issue = loaded_data['issues'][0]
        original_issue = sample_result.issues[0]
        assert loaded_issue['id'] == original_issue.id
        assert loaded_issue['title'] == original_issue.title
        assert loaded_issue['severity'] == original_issue.severity.value
        assert loaded_issue['cwe_id'] == original_issue.cwe_id
    
    def test_empty_issues_list(self, tmp_path):
        """Test saving result with no issues"""
        result = ScanResult(
            repository_path="/tmp/clean-repo",
            issues=[],
            files_scanned=5,
            scan_time_seconds=2.0
        )
        
        output_file = tmp_path / "empty.json"
        JSONReporter.save(result, output_file)
        
        loaded_data = JSONReporter.load(output_file)
        assert loaded_data['issues'] == []
        assert loaded_data['summary']['total'] == 0
    
    def test_handles_special_characters(self, tmp_path):
        """Test handling of special characters in strings"""
        issue = SecurityIssue(
            id="test-1",
            severity=Severity.MEDIUM,
            title='Issue with "quotes" and \\backslashes',
            description="Description with\nnewlines\tand\ttabs",
            file_path="path/with/unicode/→/file.py",
            line_number=1,
            code_snippet='code = "value with \'mixed\' quotes"'
        )
        
        result = ScanResult(
            repository_path="/tmp/test",
            issues=[issue],
            files_scanned=1
        )
        
        output_file = tmp_path / "special.json"
        JSONReporter.save(result, output_file)
        
        # Should load without errors
        loaded_data = JSONReporter.load(output_file)
        assert loaded_data['issues'][0]['title'] == issue.title
        assert loaded_data['issues'][0]['description'] == issue.description
    
    def test_pretty_printed_json(self, tmp_path, sample_result):
        """Test that JSON is pretty-printed (indented)"""
        output_file = tmp_path / "pretty.json"
        JSONReporter.save(sample_result, output_file)
        
        content = output_file.read_text()
        
        # Check for indentation
        assert '\n' in content  # Has newlines
        assert '  ' in content or '\t' in content  # Has indentation
