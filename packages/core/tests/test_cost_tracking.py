"""Tests for cost tracking functionality"""

import pytest
from securevibes.models.result import ScanResult
from securevibes.models.issue import SecurityIssue, Severity


class TestCostFieldInModel:
    """Test that total_cost_usd field exists and works in ScanResult"""
    
    def test_scan_result_has_cost_field(self):
        """Test that ScanResult has total_cost_usd field"""
        result = ScanResult(
            repository_path="/test/repo",
            total_cost_usd=1.2345
        )
        
        assert hasattr(result, "total_cost_usd")
        assert result.total_cost_usd == 1.2345
    
    def test_cost_field_defaults_to_zero(self):
        """Test that cost field defaults to 0.0"""
        result = ScanResult(repository_path="/test/repo")
        
        assert result.total_cost_usd == 0.0
    
    def test_cost_field_accepts_float(self):
        """Test that cost field accepts float values"""
        result = ScanResult(
            repository_path="/test/repo",
            total_cost_usd=0.0042
        )
        
        assert isinstance(result.total_cost_usd, float)
        assert result.total_cost_usd == 0.0042
    
    def test_cost_field_precision(self):
        """Test that cost field maintains precision"""
        cost = 1.23456789
        result = ScanResult(
            repository_path="/test/repo",
            total_cost_usd=cost
        )
        
        assert result.total_cost_usd == cost


class TestCostInSerialization:
    """Test that cost is included in JSON serialization"""
    
    def test_cost_in_to_dict(self):
        """Test that total_cost_usd is included in to_dict()"""
        result = ScanResult(
            repository_path="/test/repo",
            total_cost_usd=2.5
        )
        
        result_dict = result.to_dict()
        
        assert "total_cost_usd" in result_dict
        assert result_dict["total_cost_usd"] == 2.5
    
    def test_cost_in_json_serialization(self):
        """Test that cost appears in JSON string"""
        result = ScanResult(
            repository_path="/test/repo",
            total_cost_usd=1.5
        )
        
        json_str = result.to_json()
        
        assert "total_cost_usd" in json_str
        assert "1.5" in json_str
    
    def test_cost_with_full_scan_result(self):
        """Test cost serialization with complete scan result"""
        issues = [
            SecurityIssue(
                id="ISSUE-001",
                title="SQL Injection",
                description="SQL injection in login",
                severity=Severity.CRITICAL,
                file_path="app/views.py",
                line_number=42,
                code_snippet="query = 'SELECT * FROM users WHERE id=' + user_id"
            )
        ]
        
        result = ScanResult(
            repository_path="/test/repo",
            issues=issues,
            files_scanned=100,
            scan_time_seconds=45.2,
            total_cost_usd=0.85
        )
        
        result_dict = result.to_dict()
        
        # Verify all fields present
        assert result_dict["repository_path"] == "/test/repo"
        assert result_dict["files_scanned"] == 100
        assert result_dict["scan_time_seconds"] == 45.2
        assert result_dict["total_cost_usd"] == 0.85
        assert len(result_dict["issues"]) == 1


class TestCostTracking:
    """Test cost tracking scenarios"""
    
    def test_zero_cost_for_no_api_calls(self):
        """Test that cost is 0 when no API calls are made"""
        result = ScanResult(repository_path="/test/repo")
        
        assert result.total_cost_usd == 0.0
    
    def test_cost_accumulation(self):
        """Test that cost accumulates from multiple phases"""
        # Simulate costs from different phases
        assessment_cost = 0.12
        threat_modeling_cost = 0.25
        code_review_cost = 0.48
        report_generation_cost = 0.05
        
        total_cost = (
            assessment_cost + 
            threat_modeling_cost + 
            code_review_cost + 
            report_generation_cost
        )
        
        result = ScanResult(
            repository_path="/test/repo",
            total_cost_usd=total_cost
        )
        
        assert result.total_cost_usd == 0.90
        assert result.total_cost_usd == pytest.approx(0.90, abs=0.01)
    
    def test_realistic_cost_range(self):
        """Test realistic cost ranges for scans"""
        # Small project
        small_cost = 0.15
        small_result = ScanResult(repository_path="/small", total_cost_usd=small_cost)
        assert 0.10 <= small_result.total_cost_usd <= 0.50
        
        # Medium project (like PyGoat)
        medium_cost = 1.25
        medium_result = ScanResult(repository_path="/medium", total_cost_usd=medium_cost)
        assert 0.50 <= medium_result.total_cost_usd <= 3.00
        
        # Large project
        large_cost = 5.50
        large_result = ScanResult(repository_path="/large", total_cost_usd=large_cost)
        assert 3.00 <= large_result.total_cost_usd <= 10.00
    
    def test_cost_formatting(self):
        """Test cost formatting for display"""
        result = ScanResult(
            repository_path="/test/repo",
            total_cost_usd=1.2345
        )
        
        # Format to 4 decimal places (like $0.0042)
        formatted = f"${result.total_cost_usd:.4f}"
        assert formatted == "$1.2345"
        
        # Format to 2 decimal places (like $1.23)
        formatted_short = f"${result.total_cost_usd:.2f}"
        assert formatted_short == "$1.23"


class TestCostInScanMetadata:
    """Test cost tracking in scan metadata"""
    
    def test_cost_with_scan_metadata(self):
        """Test cost alongside other scan metadata"""
        result = ScanResult(
            repository_path="/test/repo",
            files_scanned=1692,
            scan_time_seconds=512.82,
            total_cost_usd=1.45
        )
        
        # Verify all metadata present
        assert result.files_scanned == 1692
        assert result.scan_time_seconds == 512.82
        assert result.total_cost_usd == 1.45
    
    def test_cost_per_file_metric(self):
        """Test calculating cost per file scanned"""
        result = ScanResult(
            repository_path="/test/repo",
            files_scanned=100,
            total_cost_usd=2.00
        )
        
        cost_per_file = result.total_cost_usd / result.files_scanned if result.files_scanned > 0 else 0
        
        assert cost_per_file == 0.02
        assert cost_per_file == pytest.approx(0.02, abs=0.001)
    
    def test_cost_per_vulnerability_metric(self):
        """Test calculating cost per vulnerability found"""
        issues = [
            SecurityIssue(
                id=f"ISSUE-{i:03d}",
                title=f"Issue {i}",
                description=f"Description {i}",
                severity=Severity.HIGH,
                file_path=f"file{i}.py",
                line_number=i * 10,
                code_snippet=f"code snippet {i}"
            )
            for i in range(1, 11)  # 10 issues
        ]
        
        result = ScanResult(
            repository_path="/test/repo",
            issues=issues,
            total_cost_usd=1.50
        )
        
        cost_per_vuln = result.total_cost_usd / len(result.issues) if result.issues else 0
        
        assert cost_per_vuln == 0.15
        assert cost_per_vuln == pytest.approx(0.15, abs=0.01)


class TestCostDisplayRequirements:
    """Test requirements for displaying cost in CLI"""
    
    def test_cost_available_for_display(self):
        """Test that cost is accessible for CLI display"""
        result = ScanResult(
            repository_path="/test/repo",
            total_cost_usd=1.234
        )
        
        # CLI should be able to access this
        display_cost = result.total_cost_usd
        
        assert display_cost is not None
        assert isinstance(display_cost, float)
        assert display_cost > 0
    
    def test_cost_format_for_cli_display(self):
        """Test cost formatting for CLI display"""
        result = ScanResult(
            repository_path="/test/repo",
            total_cost_usd=1.2345
        )
        
        # Format as CLI would display it
        cli_display = f"💰 Total cost: ${result.total_cost_usd:.4f}"
        
        assert cli_display == "💰 Total cost: $1.2345"
    
    def test_pygoat_scan_cost(self):
        """Test cost for PyGoat scan (real scenario)"""
        # PyGoat scan took 512 seconds, scanned 1692 files, found 28 vulnerabilities
        result = ScanResult(
            repository_path="/repos/pygoat",
            files_scanned=1692,
            scan_time_seconds=512.82,
            total_cost_usd=1.85  # Estimated realistic cost
        )
        
        # Verify cost is reasonable
        assert result.total_cost_usd > 0
        assert result.total_cost_usd < 5.0  # Should be under $5 for this size
        
        # Format for display
        display = f"💰 Total cost: ${result.total_cost_usd:.4f}"
        assert "1.85" in display
