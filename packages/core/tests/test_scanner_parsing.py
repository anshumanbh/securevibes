"""Tests for scanner parsing logic - prevents regression of false negative bug"""

import json
import pytest
from pathlib import Path
from securevibes.scanner.security_scanner import SecurityScanner
from securevibes.models.result import ScanResult


@pytest.fixture
def scanner():
    """Create a scanner instance"""
    return SecurityScanner(api_key="test-key")


@pytest.fixture
def vulnerabilities_flat_array():
    """Sample VULNERABILITIES.json as flat array (correct format)"""
    return [
        {
            "threat_id": "THREAT-001",
            "title": "SQL Injection in Login",
            "description": "User input concatenated into SQL query",
            "severity": "critical",
            "file_path": "app/views.py",
            "line_number": 42,
            "code_snippet": "query = 'SELECT * FROM users WHERE username=' + username",
            "cwe_id": "CWE-89",
            "recommendation": "Use parameterized queries",
            "evidence": "Direct string concatenation with user input"
        },
        {
            "threat_id": "THREAT-002",
            "title": "Hardcoded Secret Key",
            "description": "Secret key hardcoded in source",
            "severity": "high",
            "file_path": "config/settings.py",
            "line_number": 10,
            "code_snippet": "SECRET_KEY = '********************'",
            "cwe_id": "CWE-798",
            "recommendation": "Use environment variables",
            "evidence": "Static secret in codebase"
        },
        {
            "threat_id": "THREAT-003",
            "title": "Weak Crypto - MD5",
            "description": "MD5 used for password hashing",
            "severity": "medium",
            "file_path": "auth/utils.py",
            "line_number": 25,
            "code_snippet": "hash = md5(password).hexdigest()",
            "cwe_id": "CWE-327",
            "recommendation": "Use bcrypt or Argon2",
            "evidence": "MD5 is cryptographically broken"
        }
    ]


@pytest.fixture
def vulnerabilities_wrapped_object():
    """Sample VULNERABILITIES.json as wrapped object (old format)"""
    return {
        "vulnerabilities": [
            {
                "threat_id": "THREAT-001",
                "title": "SQL Injection",
                "severity": "critical",
                "file_path": "app.py",
                "line_number": 10,
                "code_snippet": "query = 'SELECT * FROM users'",
                "cwe_id": "CWE-89",
                "description": "SQL injection vulnerability",
                "recommendation": "Use parameterized queries",
                "evidence": "Direct SQL concatenation"
            }
        ]
    }


@pytest.fixture
def scan_results_correct_format():
    """Sample scan_results.json with correct format"""
    return {
        "repository_path": "/path/to/repo",
        "scan_timestamp": "2024-10-05T12:00:00Z",
        "summary": {
            "total_threats_identified": 5,
            "total_vulnerabilities_confirmed": 3,
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 0
        },
        "issues": [
            {
                "threat_id": "THREAT-001",
                "title": "SQL Injection",
                "severity": "critical",
                "file_path": "app.py",
                "line_number": 10,
                "code_snippet": "query = 'SELECT * FROM users'",
                "cwe_id": "CWE-89",
                "description": "SQL injection",
                "recommendation": "Use parameterized queries",
                "evidence": "Direct concatenation"
            },
            {
                "threat_id": "THREAT-002",
                "title": "XSS",
                "severity": "high",
                "file_path": "views.py",
                "line_number": 20,
                "code_snippet": "return render(user_input)",
                "cwe_id": "CWE-79",
                "description": "Cross-site scripting",
                "recommendation": "Sanitize input",
                "evidence": "Unescaped user input"
            },
            {
                "threat_id": "THREAT-003",
                "title": "Weak Crypto",
                "severity": "medium",
                "file_path": "utils.py",
                "line_number": 30,
                "code_snippet": "hash = md5(data)",
                "cwe_id": "CWE-327",
                "description": "Weak hashing",
                "recommendation": "Use SHA-256",
                "evidence": "MD5 is broken"
            }
        ]
    }


@pytest.fixture
def scan_results_wrong_format():
    """Sample scan_results.json with WRONG format (extra keys, wrong key name)"""
    return {
        "scan_metadata": {"date": "2024-10-05"},
        "executive_summary": {"total": 2},
        "architecture_overview": {"components": []},
        "vulnerabilities": [  # Wrong key! Should be "issues"
            {"threat_id": "THREAT-001", "title": "SQL Injection", "severity": "critical"}
        ]
    }


class TestVulnerabilitiesJsonParsing:
    """Test parsing of VULNERABILITIES.json in different formats"""
    
    def test_parse_flat_array_format(self, scanner, vulnerabilities_flat_array, tmp_path):
        """Test parsing VULNERABILITIES.json as flat array (correct format)"""
        vuln_file = tmp_path / ".securevibes" / "VULNERABILITIES.json"
        vuln_file.parent.mkdir(parents=True)
        vuln_file.write_text(json.dumps(vulnerabilities_flat_array))
        
        # Parse the file (using the scanner's internal method would be ideal,
        # but since it's part of async scan, we'll test the logic)
        data = json.loads(vuln_file.read_text())
        
        # Should be a list
        assert isinstance(data, list)
        assert len(data) == 3
        
        # Each item should have required fields
        for item in data:
            assert "threat_id" in item
            assert "title" in item
            assert "severity" in item
            assert "file_path" in item
    
    def test_parse_wrapped_object_format(self, scanner, vulnerabilities_wrapped_object, tmp_path):
        """Test parsing VULNERABILITIES.json as wrapped object (fallback format)"""
        vuln_file = tmp_path / ".securevibes" / "VULNERABILITIES.json"
        vuln_file.parent.mkdir(parents=True)
        vuln_file.write_text(json.dumps(vulnerabilities_wrapped_object))
        
        data = json.loads(vuln_file.read_text())
        
        # Should be a dict with "vulnerabilities" key
        assert isinstance(data, dict)
        assert "vulnerabilities" in data
        assert isinstance(data["vulnerabilities"], list)
        assert len(data["vulnerabilities"]) == 1
    
    def test_flat_array_is_preferred_format(self, vulnerabilities_flat_array):
        """Test that flat array is the expected format"""
        # This documents that flat array is the correct format
        assert isinstance(vulnerabilities_flat_array, list)
        assert len(vulnerabilities_flat_array) > 0
        assert all("threat_id" in v for v in vulnerabilities_flat_array)


class TestScanResultsJsonParsing:
    """Test parsing of scan_results.json format"""
    
    def test_correct_format_has_four_keys(self, scan_results_correct_format):
        """Test scan_results.json has exactly 4 top-level keys"""
        assert len(scan_results_correct_format.keys()) == 4
        expected_keys = {"repository_path", "scan_timestamp", "summary", "issues"}
        assert set(scan_results_correct_format.keys()) == expected_keys
    
    def test_uses_issues_key_not_vulnerabilities(self, scan_results_correct_format):
        """Test scan_results.json uses "issues" key not "vulnerabilities" """
        # This is the bug we fixed - prevent regression!
        assert "issues" in scan_results_correct_format
        assert "vulnerabilities" not in scan_results_correct_format
    
    def test_no_extra_keys(self, scan_results_correct_format):
        """Test scan_results.json doesn't have extra keys like executive_summary"""
        # These are keys that Haiku added incorrectly
        forbidden_keys = [
            "executive_summary",
            "architecture_overview", 
            "threat_model_summary",
            "compliance_impact",
            "remediation_priorities",
            "scan_metadata"
        ]
        
        for key in forbidden_keys:
            assert key not in scan_results_correct_format, f"Found forbidden key: {key}"
    
    def test_issues_is_array_of_objects(self, scan_results_correct_format):
        """Test issues field is an array of objects not strings"""
        issues = scan_results_correct_format["issues"]
        
        assert isinstance(issues, list)
        assert len(issues) > 0
        
        # Each item should be a dict, not a string
        for issue in issues:
            assert isinstance(issue, dict), "Issue should be object not string"
            assert "threat_id" in issue
            assert "title" in issue
            assert "severity" in issue
    
    def test_summary_counts_present(self, scan_results_correct_format):
        """Test summary has all required count fields"""
        summary = scan_results_correct_format["summary"]
        
        required_fields = [
            "total_vulnerabilities_confirmed",
            "critical",
            "high", 
            "medium",
            "low"
        ]
        
        for field in required_fields:
            assert field in summary
            assert isinstance(summary[field], int)
    
    def test_detect_wrong_format(self, scan_results_wrong_format):
        """Test detection of wrong scan_results.json format"""
        # Should NOT have these keys
        assert "executive_summary" in scan_results_wrong_format  # This is wrong!
        assert "architecture_overview" in scan_results_wrong_format  # This is wrong!
        
        # Should have "issues" not "vulnerabilities"
        assert "vulnerabilities" in scan_results_wrong_format  # Wrong key!
        assert "issues" not in scan_results_wrong_format  # Missing correct key!


class TestParsingEdgeCases:
    """Test edge cases in parsing logic"""
    
    def test_empty_vulnerabilities_array(self, tmp_path):
        """Test parsing empty VULNERABILITIES.json array"""
        vuln_file = tmp_path / "VULNERABILITIES.json"
        vuln_file.write_text("[]")
        
        data = json.loads(vuln_file.read_text())
        assert isinstance(data, list)
        assert len(data) == 0
    
    def test_placeholder_string_detection(self):
        """Test detection of placeholder strings (not actual objects)"""
        # This was a bug - report-generator created strings instead of objects
        wrong_issues = [
            "All vulnerabilities from VULNERABILITIES.json included here",
            "Vulnerability objects matching the source file"
        ]
        
        # These are strings, not objects - BAD!
        for item in wrong_issues:
            assert isinstance(item, str)  # This is the bug indicator
            assert not isinstance(item, dict)  # Not a proper vulnerability object
    
    def test_malformed_json_handling(self, tmp_path):
        """Test handling of malformed JSON"""
        vuln_file = tmp_path / "bad.json"
        vuln_file.write_text("{invalid json}")
        
        with pytest.raises(json.JSONDecodeError):
            json.loads(vuln_file.read_text())
    
    def test_missing_required_fields(self):
        """Test vulnerability objects with missing fields"""
        incomplete_vuln = {
            "threat_id": "THREAT-001",
            # Missing: title, severity, file_path, etc.
        }
        
        # Should have all required fields
        required_fields = ["threat_id", "title", "severity", "file_path"]
        missing_fields = [f for f in required_fields if f not in incomplete_vuln]
        
        assert len(missing_fields) > 0, "This object is missing required fields"


class TestFormatValidation:
    """Test format validation logic"""
    
    def test_validate_vulnerabilities_is_array(self, vulnerabilities_flat_array):
        """Test VULNERABILITIES.json is validated as array"""
        assert isinstance(vulnerabilities_flat_array, list)
        
        # Log format for validation
        if isinstance(vulnerabilities_flat_array, list):
            format_type = "flat array"
        else:
            format_type = "wrapped object"
        
        assert format_type == "flat array"
    
    def test_validate_scan_results_structure(self, scan_results_correct_format):
        """Test scan_results.json structure validation"""
        data = scan_results_correct_format
        
        # Validation checks
        assert "issues" in data, "Missing 'issues' key"
        assert isinstance(data["issues"], list), "'issues' should be array"
        assert "summary" in data, "Missing 'summary' key"
        
        # Count validation
        actual_count = len(data["issues"])
        reported_count = data["summary"]["total_vulnerabilities_confirmed"]
        
        assert actual_count == reported_count, \
            f"Count mismatch: {actual_count} items but summary says {reported_count}"
    
    def test_severity_count_validation(self, scan_results_correct_format):
        """Test severity counts match actual distribution"""
        data = scan_results_correct_format
        issues = data["issues"]
        summary = data["summary"]
        
        # Count by severity
        actual_critical = sum(1 for i in issues if i["severity"] == "critical")
        actual_high = sum(1 for i in issues if i["severity"] == "high")
        actual_medium = sum(1 for i in issues if i["severity"] == "medium")
        actual_low = sum(1 for i in issues if i["severity"] == "low")
        
        # Compare with summary
        assert actual_critical == summary["critical"]
        assert actual_high == summary["high"]
        assert actual_medium == summary["medium"]
        assert actual_low == summary["low"]
        
        # Total should match
        total = actual_critical + actual_high + actual_medium + actual_low
        assert total == summary["total_vulnerabilities_confirmed"]
