"""Tests for markdown reporter"""

import pytest
from pathlib import Path
from securevibes.reporters.markdown_reporter import MarkdownReporter
from securevibes.models.issue import SecurityIssue, Severity
from securevibes.models.result import ScanResult


@pytest.fixture
def sample_result():
    """Create a sample scan result with multiple issues"""
    issues = [
        SecurityIssue(
            id="test-1",
            severity=Severity.CRITICAL,
            title="SQL Injection in Login",
            description="User input is directly concatenated into SQL queries without parameterization.",
            file_path="app/views.py",
            line_number=42,
            code_snippet="query = 'SELECT * FROM users WHERE username=' + username",
            recommendation="Use parameterized queries or an ORM",
            cwe_id="CWE-89"
        ),
        SecurityIssue(
            id="test-2",
            severity=Severity.HIGH,
            title="Command Injection via os.system",
            description="User-controlled input is passed to os.system without validation.",
            file_path="admin/tools.py",
            line_number=15,
            code_snippet="os.system(f'cat {filename}')",
            recommendation="Use subprocess with argument list instead of shell=True",
            cwe_id="CWE-78"
        ),
        SecurityIssue(
            id="test-3",
            severity=Severity.MEDIUM,
            title="Weak Cryptographic Hash (MD5)",
            description="MD5 is used for password hashing which is cryptographically broken.",
            file_path="auth/utils.py",
            line_number=25,
            code_snippet="hash = md5(password).hexdigest()",
            recommendation="Use bcrypt, Argon2, or scrypt for password hashing",
            cwe_id="CWE-327"
        ),
    ]
    
    return ScanResult(
        repository_path="/tmp/test-repo",
        issues=issues,
        files_scanned=125,
        scan_time_seconds=45.6,
        total_cost_usd=1.25
    )


@pytest.fixture
def empty_result():
    """Create a result with no issues"""
    return ScanResult(
        repository_path="/tmp/clean-repo",
        issues=[],
        files_scanned=50,
        scan_time_seconds=12.3
    )


class TestMarkdownReporterBasics:
    """Test basic markdown reporter functionality"""
    
    def test_save_creates_file(self, tmp_path, sample_result):
        """Test that save creates a markdown file"""
        output_file = tmp_path / "report.md"
        
        MarkdownReporter.save(sample_result, output_file)
        
        assert output_file.exists()
        assert output_file.stat().st_size > 0
    
    def test_save_creates_directory(self, tmp_path, sample_result):
        """Test that save creates parent directory if needed"""
        output_file = tmp_path / "nested" / "dir" / "report.md"
        
        MarkdownReporter.save(sample_result, output_file)
        
        assert output_file.exists()
        assert output_file.parent.exists()
    
    def test_generate_returns_string(self, sample_result):
        """Test that generate returns a string"""
        markdown = MarkdownReporter.generate(sample_result)
        
        assert isinstance(markdown, str)
        assert len(markdown) > 0


class TestMarkdownStructure:
    """Test markdown document structure"""
    
    def test_markdown_has_title(self, sample_result):
        """Test markdown starts with proper title"""
        markdown = MarkdownReporter.generate(sample_result)
        
        assert markdown.startswith("# Security Scan Report")
    
    def test_markdown_has_metadata(self, sample_result):
        """Test markdown includes scan metadata"""
        markdown = MarkdownReporter.generate(sample_result)
        
        assert "**Repository:**" in markdown
        assert "/tmp/test-repo" in markdown
        assert "**Scan Date:**" in markdown
        assert "**Files Scanned:**" in markdown
        assert "125" in markdown
        assert "**Scan Duration:**" in markdown
    
    def test_markdown_has_executive_summary(self, sample_result):
        """Test markdown includes executive summary section"""
        markdown = MarkdownReporter.generate(sample_result)
        
        assert "## Executive Summary" in markdown
        assert "3 security vulnerabilities found" in markdown
    
    def test_markdown_has_severity_table(self, sample_result):
        """Test markdown includes severity distribution table"""
        markdown = MarkdownReporter.generate(sample_result)
        
        assert "## Severity Distribution" in markdown
        assert "| Severity | Count | Percentage |" in markdown
        assert "Critical" in markdown
        assert "High" in markdown
        assert "Medium" in markdown
    
    def test_markdown_has_vulnerability_overview(self, sample_result):
        """Test markdown includes vulnerability overview table"""
        markdown = MarkdownReporter.generate(sample_result)
        
        assert "## Vulnerability Overview" in markdown
        assert "| # | Severity | Title | Location |" in markdown
    
    def test_markdown_has_detailed_findings(self, sample_result):
        """Test markdown includes detailed findings sections"""
        markdown = MarkdownReporter.generate(sample_result)
        
        assert "## Detailed Findings" in markdown
        assert "### 1. SQL Injection in Login" in markdown
        assert "### 2. Command Injection via os.system" in markdown
        assert "### 3. Weak Cryptographic Hash (MD5)" in markdown


class TestMarkdownContent:
    """Test markdown content details"""
    
    def test_severity_icons_present(self, sample_result):
        """Test severity icons are included"""
        markdown = MarkdownReporter.generate(sample_result)
        
        assert "🔴" in markdown  # Critical
        assert "🟠" in markdown  # High
        assert "🟡" in markdown  # Medium
    
    def test_code_snippets_are_fenced(self, sample_result):
        """Test code snippets use proper markdown fencing"""
        markdown = MarkdownReporter.generate(sample_result)
        
        # Should have code blocks
        assert "```" in markdown
        assert "query = 'SELECT * FROM users WHERE username=' + username" in markdown
    
    def test_cwe_ids_included(self, sample_result):
        """Test CWE IDs are included"""
        markdown = MarkdownReporter.generate(sample_result)
        
        assert "CWE-89" in markdown
        assert "CWE-78" in markdown
        assert "CWE-327" in markdown
    
    def test_recommendations_included(self, sample_result):
        """Test recommendations are included"""
        markdown = MarkdownReporter.generate(sample_result)
        
        assert "**Recommendation:**" in markdown
        assert "Use parameterized queries or an ORM" in markdown
        assert "Use subprocess with argument list" in markdown
    
    def test_file_paths_in_code_format(self, sample_result):
        """Test file paths are formatted as code"""
        markdown = MarkdownReporter.generate(sample_result)
        
        assert "`app/views.py:42`" in markdown
        assert "`admin/tools.py:15`" in markdown


class TestMarkdownEmptyResult:
    """Test markdown for scans with no issues"""
    
    def test_markdown_with_no_issues(self, empty_result):
        """Test markdown handles empty results gracefully"""
        markdown = MarkdownReporter.generate(empty_result)
        
        assert "# Security Scan Report" in markdown
        assert "## Executive Summary" in markdown
        assert "No security vulnerabilities found" in markdown or "✅" in markdown
    
    def test_no_vulnerability_tables_when_empty(self, empty_result):
        """Test vulnerability tables are omitted when no issues"""
        markdown = MarkdownReporter.generate(empty_result)
        
        # These sections should not appear
        assert "## Severity Distribution" not in markdown
        assert "## Vulnerability Overview" not in markdown
        assert "## Detailed Findings" not in markdown


class TestMarkdownSpecialCharacters:
    """Test handling of special characters"""
    
    def test_handles_markdown_special_chars(self):
        """Test markdown special characters are escaped properly"""
        issue = SecurityIssue(
            id="test-1",
            severity=Severity.MEDIUM,
            title="Issue with | pipes and * asterisks",
            description="Description with **bold** and _italic_ markers",
            file_path="path/to/file.py",
            line_number=1,
            code_snippet="code = 'value with | pipe'",
            recommendation="Fix the | pipe issue"
        )
        
        result = ScanResult(
            repository_path="/tmp/test",
            issues=[issue],
            files_scanned=1
        )
        
        markdown = MarkdownReporter.generate(result)
        
        # Pipes in table cells should be escaped
        assert "\\|" in markdown
    
    def test_handles_unicode_characters(self):
        """Test unicode characters are preserved"""
        issue = SecurityIssue(
            id="test-1",
            severity=Severity.LOW,
            title="Issue with unicode → characters",
            description="Description with émojis and spéciål characters",
            file_path="path/tö/fïle.py",
            line_number=1,
            code_snippet="code with → unicode"
        )
        
        result = ScanResult(
            repository_path="/tmp/test",
            issues=[issue],
            files_scanned=1
        )
        
        markdown = MarkdownReporter.generate(result)
        
        assert "→" in markdown
        assert "émojis" in markdown or "emojis" in markdown
    
    def test_handles_newlines_in_description(self):
        """Test newlines in descriptions are preserved"""
        issue = SecurityIssue(
            id="test-1",
            severity=Severity.MEDIUM,
            title="Multi-line Issue",
            description="Line 1\nLine 2\nLine 3",
            file_path="file.py",
            line_number=1,
            code_snippet="multi_line_code()"
        )
        
        result = ScanResult(
            repository_path="/tmp/test",
            issues=[issue],
            files_scanned=1
        )
        
        markdown = MarkdownReporter.generate(result)
        
        assert "Line 1" in markdown
        assert "Line 2" in markdown
        assert "Line 3" in markdown


class TestMarkdownLanguageDetection:
    """Test code block language detection"""
    
    def test_python_file_gets_python_syntax(self):
        """Test Python files use python syntax highlighting"""
        issue = SecurityIssue(
            id="test-1",
            severity=Severity.HIGH,
            title="Python Issue",
            description="Test",
            file_path="app/views.py",
            line_number=1,
            code_snippet="def vulnerable(): pass"
        )
        
        result = ScanResult(
            repository_path="/tmp/test",
            issues=[issue],
            files_scanned=1
        )
        
        markdown = MarkdownReporter.generate(result)
        
        assert "```python" in markdown
    
    def test_javascript_file_gets_js_syntax(self):
        """Test JavaScript files use javascript syntax"""
        issue = SecurityIssue(
            id="test-1",
            severity=Severity.HIGH,
            title="JS Issue",
            description="Test",
            file_path="app/routes.js",
            line_number=1,
            code_snippet="function vulnerable() {}"
        )
        
        result = ScanResult(
            repository_path="/tmp/test",
            issues=[issue],
            files_scanned=1
        )
        
        markdown = MarkdownReporter.generate(result)
        
        assert "```javascript" in markdown
    
    def test_typescript_file_gets_ts_syntax(self):
        """Test TypeScript files use typescript syntax"""
        issue = SecurityIssue(
            id="test-1",
            severity=Severity.HIGH,
            title="TS Issue",
            description="Test",
            file_path="server/routes.ts",
            line_number=1,
            code_snippet="const vuln: string = input"
        )
        
        result = ScanResult(
            repository_path="/tmp/test",
            issues=[issue],
            files_scanned=1
        )
        
        markdown = MarkdownReporter.generate(result)
        
        assert "```typescript" in markdown


class TestMarkdownRoundTrip:
    """Test markdown save and load"""
    
    def test_roundtrip_preserves_content(self, tmp_path, sample_result):
        """Test save -> load preserves content"""
        output_file = tmp_path / "report.md"
        
        # Save
        MarkdownReporter.save(sample_result, output_file)
        
        # Load
        loaded_content = output_file.read_text()
        
        # Verify key content preserved
        assert "# Security Scan Report" in loaded_content
        assert "SQL Injection" in loaded_content
        assert "Command Injection" in loaded_content
        assert "CWE-89" in loaded_content
    
    def test_file_is_readable_markdown(self, tmp_path, sample_result):
        """Test output is valid markdown"""
        output_file = tmp_path / "report.md"
        
        MarkdownReporter.save(sample_result, output_file)
        content = output_file.read_text()
        
        # Basic markdown structure checks
        assert content.startswith("# ")  # Starts with heading
        assert "\n## " in content  # Has subheadings
        assert "\n---\n" in content  # Has horizontal rules
        assert "| " in content  # Has tables


class TestMarkdownFormatting:
    """Test markdown formatting details"""
    
    def test_section_separators(self, sample_result):
        """Test sections are separated by horizontal rules"""
        markdown = MarkdownReporter.generate(sample_result)
        
        # Should have multiple horizontal rules
        assert markdown.count("---") >= 3
    
    def test_proper_heading_hierarchy(self, sample_result):
        """Test proper heading hierarchy (h1, h2, h3)"""
        markdown = MarkdownReporter.generate(sample_result)
        
        lines = markdown.split('\n')
        has_h1 = any(line.startswith("# ") for line in lines)
        has_h2 = any(line.startswith("## ") for line in lines)
        has_h3 = any(line.startswith("### ") for line in lines)
        
        assert has_h1  # Top level title
        assert has_h2  # Sections
        assert has_h3  # Individual findings
    
    def test_footer_present(self, sample_result):
        """Test footer is included"""
        markdown = MarkdownReporter.generate(sample_result)
        
        assert "Generated by SecureVibes" in markdown
        assert "Report generated at:" in markdown


class TestMarkdownScanTime:
    """Test scan time formatting"""
    
    def test_short_scan_time(self):
        """Test scan times under 1 minute"""
        result = ScanResult(
            repository_path="/tmp/test",
            issues=[],
            files_scanned=10,
            scan_time_seconds=45.6
        )
        
        markdown = MarkdownReporter.generate(result)
        
        assert "45.60s" in markdown
    
    def test_long_scan_time(self):
        """Test scan times over 1 minute"""
        result = ScanResult(
            repository_path="/tmp/test",
            issues=[],
            files_scanned=1000,
            scan_time_seconds=125.7  # 2m 5.7s
        )
        
        markdown = MarkdownReporter.generate(result)
        
        assert "125.70s" in markdown
        assert "2m" in markdown
