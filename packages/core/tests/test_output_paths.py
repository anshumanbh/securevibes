"""Tests for output path handling logic"""

import pytest
from pathlib import Path


class TestMarkdownOutputPaths:
    """Test markdown report output path logic"""
    
    def test_default_output_path(self):
        """Test default output goes to .securevibes/scan_report.md"""
        path = Path(".")
        output = None
        
        # Logic from CLI
        if output:
            output_path = Path(output)
            if not output_path.is_absolute():
                result = path / '.securevibes' / output
            else:
                result = output_path
        else:
            result = path / '.securevibes' / 'scan_report.md'
        
        assert str(result) == ".securevibes/scan_report.md"
    
    def test_relative_filename_to_securevibes(self):
        """Test relative filename saves to .securevibes/"""
        path = Path(".")
        output = "custom_report.md"
        
        output_path = Path(output)
        if not output_path.is_absolute():
            result = path / '.securevibes' / output
        else:
            result = output_path
        
        assert str(result) == ".securevibes/custom_report.md"
    
    def test_relative_path_with_directory(self):
        """Test relative path with subdirectory"""
        path = Path(".")
        output = "reports/security_scan.md"
        
        output_path = Path(output)
        if not output_path.is_absolute():
            result = path / '.securevibes' / output
        else:
            result = output_path
        
        assert str(result) == ".securevibes/reports/security_scan.md"
    
    def test_absolute_path_preserved(self):
        """Test absolute path is preserved as-is"""
        path = Path(".")
        output = "/tmp/report.md"
        
        output_path = Path(output)
        if not output_path.is_absolute():
            result = path / '.securevibes' / output
        else:
            result = output_path
        
        assert str(result) == "/tmp/report.md"
    
    def test_different_scan_directory(self):
        """Test with different scan directory path"""
        path = Path("/path/to/project")
        output = "my_report.md"
        
        output_path = Path(output)
        if not output_path.is_absolute():
            result = path / '.securevibes' / output
        else:
            result = output_path
        
        assert str(result) == "/path/to/project/.securevibes/my_report.md"
    
    def test_nested_relative_path(self):
        """Test deeply nested relative path"""
        path = Path(".")
        output = "reports/2024/january/scan.md"
        
        output_path = Path(output)
        if not output_path.is_absolute():
            result = path / '.securevibes' / output
        else:
            result = output_path
        
        assert str(result) == ".securevibes/reports/2024/january/scan.md"
    
    def test_windows_style_absolute_path(self):
        """Test Windows-style absolute path detection"""
        path = Path(".")
        
        # Unix absolute path
        output_unix = "/tmp/report.md"
        output_path = Path(output_unix)
        assert output_path.is_absolute()
        
        # Note: Windows paths like C:\... would also be detected as absolute
        # by Path.is_absolute() on the respective platform


class TestOutputPathEdgeCases:
    """Test edge cases in output path handling"""
    
    def test_empty_string_output(self):
        """Test empty string is treated as relative"""
        path = Path(".")
        output = ""
        
        output_path = Path(output)
        # Empty path is relative
        assert not output_path.is_absolute()
        
        if not output_path.is_absolute():
            result = path / '.securevibes' / output
        else:
            result = output_path
        
        # Results in .securevibes/ directory
        assert ".securevibes" in str(result)
    
    def test_dot_relative_path(self):
        """Test paths starting with ./"""
        path = Path(".")
        output = "./custom.md"
        
        output_path = Path(output)
        if not output_path.is_absolute():
            result = path / '.securevibes' / output
        else:
            result = output_path
        
        # Should still be relative and go to .securevibes
        assert ".securevibes" in str(result)
    
    def test_parent_directory_reference(self):
        """Test paths with ../"""
        path = Path(".")
        output = "../reports/scan.md"
        
        output_path = Path(output)
        if not output_path.is_absolute():
            result = path / '.securevibes' / output
        else:
            result = output_path
        
        # Should be prefixed with .securevibes
        assert ".securevibes" in str(result)
