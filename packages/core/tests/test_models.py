"""Tests for data models"""

from securevibes.models.issue import SecurityIssue, Severity
from securevibes.models.result import ScanResult


def test_security_issue_creation():
    """Test creating a SecurityIssue"""
    issue = SecurityIssue(
        id="test-1",
        severity=Severity.HIGH,
        title="SQL Injection",
        description="Potential SQL injection vulnerability",
        file_path="src/db.py",
        line_number=42,
        code_snippet="query = f'SELECT * FROM users WHERE id={user_id}'",
        recommendation="Use parameterized queries"
    )
    
    assert issue.id == "test-1"
    assert issue.severity == Severity.HIGH
    assert issue.title == "SQL Injection"
    assert issue.line_number == 42


def test_security_issue_to_dict():
    """Test converting SecurityIssue to dict"""
    issue = SecurityIssue(
        id="test-1",
        severity=Severity.CRITICAL,
        title="Test Issue",
        description="Test description",
        file_path="test.py",
        line_number=10,
        code_snippet="code here"
    )
    
    data = issue.to_dict()
    
    assert data["id"] == "test-1"
    assert data["severity"] == "critical"
    assert data["title"] == "Test Issue"


def test_scan_result_creation():
    """Test creating a ScanResult"""
    result = ScanResult(
        repository_path="/tmp/test-repo",
        issues=[],
        files_scanned=10,
        scan_time_seconds=5.2
    )
    
    assert result.repository_path == "/tmp/test-repo"
    assert len(result.issues) == 0
    assert result.files_scanned == 10
    assert result.scan_time_seconds == 5.2


def test_scan_result_counts():
    """Test issue count properties"""
    issues = [
        SecurityIssue("1", Severity.CRITICAL, "C1", "d", "f.py", 1, "code"),
        SecurityIssue("2", Severity.HIGH, "H1", "d", "f.py", 2, "code"),
        SecurityIssue("3", Severity.HIGH, "H2", "d", "f.py", 3, "code"),
        SecurityIssue("4", Severity.MEDIUM, "M1", "d", "f.py", 4, "code"),
    ]
    
    result = ScanResult(
        repository_path="/tmp/test",
        issues=issues,
        files_scanned=5
    )
    
    assert result.critical_count == 1
    assert result.high_count == 2
    assert result.medium_count == 1
    assert result.low_count == 0


def test_scan_result_to_dict():
    """Test converting ScanResult to dict"""
    issue = SecurityIssue("1", Severity.HIGH, "Test", "desc", "file.py", 1, "code")
    result = ScanResult(
        repository_path="/tmp/test",
        issues=[issue],
        files_scanned=10,
        scan_time_seconds=3.5
    )
    
    data = result.to_dict()
    
    assert data["repository_path"] == "/tmp/test"
    assert len(data["issues"]) == 1
    assert data["files_scanned"] == 10
    assert data["summary"]["total"] == 1
    assert data["summary"]["high"] == 1


def test_scan_result_to_markdown():
    """Test ScanResult.to_markdown() method"""
    result = ScanResult(
        repository_path="/test/repo",
        issues=[],
        files_scanned=10,
        scan_time_seconds=5.5
    )
    
    markdown_str = result.to_markdown()
    
    assert isinstance(markdown_str, str)
    assert len(markdown_str) > 0
    assert "# Security Scan Report" in markdown_str
    assert "/test/repo" in markdown_str
