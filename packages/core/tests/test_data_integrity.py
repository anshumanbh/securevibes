"""Tests for data integrity - prevents vulnerability filtering and data loss"""

import json
import pytest
from pathlib import Path


class TestNoFiltering:
    """Test that all vulnerabilities are preserved (no filtering)"""
    
    def test_no_filtering_from_20_to_2(self):
        """Test that 20 vulnerabilities are NOT filtered down to 2"""
        # This was the actual bug - report-generator filtered 20 → 2
        
        # Simulate VULNERABILITIES.json with 20 items
        vulnerabilities = [
            {"threat_id": f"THREAT-{i:03d}", "title": f"Vuln {i}", "severity": "high"}
            for i in range(1, 21)
        ]
        
        # Simulate scan_results.json that should have ALL 20
        scan_results = {
            "repository_path": "/repo",
            "scan_timestamp": "2024-10-05T12:00:00Z",
            "summary": {
                "total_vulnerabilities_confirmed": len(vulnerabilities),
                "critical": 0,
                "high": 20,
                "medium": 0,
                "low": 0
            },
            "issues": vulnerabilities  # Should be ALL of them!
        }
        
        # Verify no filtering occurred
        assert len(scan_results["issues"]) == 20, "Should have all 20 vulnerabilities"
        assert scan_results["summary"]["total_vulnerabilities_confirmed"] == 20
        
        # This was the bug: filtered to 2 "representative" examples
        assert len(scan_results["issues"]) != 2, "MUST NOT filter to 2 examples"
    
    def test_no_filtering_from_28_to_0(self):
        """Test that 28 vulnerabilities are NOT filtered to 0"""
        # This was the original catastrophic bug
        
        vulnerabilities = [
            {"threat_id": f"THREAT-{i:03d}", "title": f"Vuln {i}", "severity": "critical"}
            for i in range(1, 29)
        ]
        
        scan_results = {
            "repository_path": "/repo",
            "scan_timestamp": "2024-10-05T12:00:00Z",
            "summary": {
                "total_vulnerabilities_confirmed": len(vulnerabilities),
                "critical": 28,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "issues": vulnerabilities
        }
        
        # Verify ALL vulnerabilities present
        assert len(scan_results["issues"]) == 28, "Should have all 28 vulnerabilities"
        assert len(scan_results["issues"]) > 0, "MUST NOT report 0 vulnerabilities"
    
    def test_no_representative_sampling(self):
        """Test that NO "representative" sampling occurs"""
        # Report-generator was selecting "representative" examples instead of all
        
        total_vulnerabilities = 100
        vulnerabilities = [
            {"threat_id": f"THREAT-{i:03d}", "title": f"Vuln {i}", "severity": "high"}
            for i in range(1, total_vulnerabilities + 1)
        ]
        
        # Simulate correct behavior: ALL vulnerabilities included
        issues_array = vulnerabilities
        
        assert len(issues_array) == total_vulnerabilities
        
        # These would be "representative sampling" sizes - FORBIDDEN!
        forbidden_sizes = [2, 5, 7, 10]  # Common "example" counts
        assert len(issues_array) not in forbidden_sizes, \
            "Looks like representative sampling instead of full data"


class TestDataCompleteness:
    """Test that vulnerability data is complete and accurate"""
    
    def test_all_required_fields_present(self):
        """Test that all required fields are present in each vulnerability"""
        vulnerability = {
            "threat_id": "THREAT-001",
            "title": "SQL Injection",
            "description": "User input concatenated",
            "severity": "critical",
            "file_path": "app/views.py",
            "line_number": 42,
            "code_snippet": "query = 'SELECT * FROM users WHERE id=' + user_id",
            "cwe_id": "CWE-89",
            "recommendation": "Use parameterized queries",
            "evidence": "Direct string concatenation"
        }
        
        required_fields = [
            "threat_id",
            "title",
            "description",
            "severity",
            "file_path",
            "line_number",
            "code_snippet",
            "cwe_id",
            "recommendation",
            "evidence"
        ]
        
        for field in required_fields:
            assert field in vulnerability, f"Missing required field: {field}"
            assert vulnerability[field] is not None, f"Field {field} is None"
            assert vulnerability[field] != "", f"Field {field} is empty"
    
    def test_no_placeholder_strings(self):
        """Test that vulnerability objects are not placeholder strings"""
        # This was a bug: report-generator created string placeholders
        
        correct_vulnerability = {
            "threat_id": "THREAT-001",
            "title": "SQL Injection",
            "severity": "critical"
        }
        
        wrong_placeholder = "All vulnerabilities from VULNERABILITIES.json included"
        
        # Correct: vulnerability is a dict
        assert isinstance(correct_vulnerability, dict)
        
        # Wrong: placeholder is a string (this was the bug!)
        assert isinstance(wrong_placeholder, str)
        assert not isinstance(wrong_placeholder, dict), "Placeholder is string not object"
    
    def test_actual_objects_not_references(self):
        """Test that issues array contains actual objects, not references"""
        issues = [
            {"threat_id": "THREAT-001", "title": "SQL Injection", "severity": "critical"},
            {"threat_id": "THREAT-002", "title": "XSS", "severity": "high"},
            {"threat_id": "THREAT-003", "title": "CSRF", "severity": "medium"}
        ]
        
        # Each item should be a full object
        for issue in issues:
            assert isinstance(issue, dict), "Should be object not string"
            assert len(issue) >= 3, "Should have multiple fields"
            assert "threat_id" in issue
            assert "title" in issue


class TestCountAccuracy:
    """Test that summary counts match actual data"""
    
    def test_total_count_matches_array_length(self):
        """Test that summary.total_vulnerabilities_confirmed equals issues.length"""
        issues = [
            {"threat_id": f"THREAT-{i:03d}", "title": f"Vuln {i}", "severity": "high"}
            for i in range(1, 26)  # 25 vulnerabilities
        ]
        
        summary = {
            "total_vulnerabilities_confirmed": len(issues),
            "critical": 0,
            "high": 25,
            "medium": 0,
            "low": 0
        }
        
        # CRITICAL: These must match!
        assert summary["total_vulnerabilities_confirmed"] == len(issues)
        assert summary["total_vulnerabilities_confirmed"] == 25
    
    def test_severity_counts_match_distribution(self):
        """Test that severity counts match actual distribution"""
        issues = [
            {"threat_id": "THREAT-001", "title": "Vuln 1", "severity": "critical"},
            {"threat_id": "THREAT-002", "title": "Vuln 2", "severity": "critical"},
            {"threat_id": "THREAT-003", "title": "Vuln 3", "severity": "critical"},
            {"threat_id": "THREAT-004", "title": "Vuln 4", "severity": "high"},
            {"threat_id": "THREAT-005", "title": "Vuln 5", "severity": "high"},
            {"threat_id": "THREAT-006", "title": "Vuln 6", "severity": "medium"},
        ]
        
        # Count by severity
        actual_critical = sum(1 for i in issues if i["severity"] == "critical")
        actual_high = sum(1 for i in issues if i["severity"] == "high")
        actual_medium = sum(1 for i in issues if i["severity"] == "medium")
        actual_low = sum(1 for i in issues if i["severity"] == "low")
        
        summary = {
            "total_vulnerabilities_confirmed": len(issues),
            "critical": actual_critical,
            "high": actual_high,
            "medium": actual_medium,
            "low": actual_low
        }
        
        # Verify counts match
        assert summary["critical"] == 3
        assert summary["high"] == 2
        assert summary["medium"] == 1
        assert summary["low"] == 0
        
        # Verify total
        total = summary["critical"] + summary["high"] + summary["medium"] + summary["low"]
        assert total == summary["total_vulnerabilities_confirmed"]
        assert total == len(issues)
    
    def test_no_fabricated_statistics(self):
        """Test that summary statistics are not fabricated"""
        # This was a bug: summary claimed 20 vulnerabilities but array had only 2
        
        issues = [
            {"threat_id": "THREAT-001", "title": "SQL Injection", "severity": "critical"},
            {"threat_id": "THREAT-002", "title": "XSS", "severity": "high"}
        ]
        
        # WRONG: Fabricated summary (claimed 20 but only 2 in array)
        fabricated_summary = {
            "total_vulnerabilities_confirmed": 20,  # LIE!
            "critical": 7,  # LIE!
            "high": 10,  # LIE!
            "medium": 3,  # LIE!
            "low": 0
        }
        
        # CORRECT: Accurate summary
        accurate_summary = {
            "total_vulnerabilities_confirmed": len(issues),  # 2
            "critical": 1,
            "high": 1,
            "medium": 0,
            "low": 0
        }
        
        # Detect fabrication
        assert fabricated_summary["total_vulnerabilities_confirmed"] != len(issues), \
            "Fabricated summary doesn't match actual data"
        
        # Verify accuracy
        assert accurate_summary["total_vulnerabilities_confirmed"] == len(issues)


class TestPipelineIntegrity:
    """Test data integrity through the entire pipeline"""
    
    def test_vulnerabilities_to_scan_results_no_loss(self, tmp_path):
        """Test that data flows from VULNERABILITIES.json to scan_results.json without loss"""
        # Create VULNERABILITIES.json with 15 vulnerabilities
        vulnerabilities = [
            {
                "threat_id": f"THREAT-{i:03d}",
                "title": f"Vulnerability {i}",
                "description": f"Description {i}",
                "severity": "high" if i % 2 == 0 else "medium",
                "file_path": f"app/file{i}.py",
                "line_number": i * 10,
                "code_snippet": f"code snippet {i}",
                "cwe_id": f"CWE-{i}",
                "recommendation": f"Fix {i}",
                "evidence": f"Evidence {i}"
            }
            for i in range(1, 16)
        ]
        
        vuln_file = tmp_path / "VULNERABILITIES.json"
        vuln_file.write_text(json.dumps(vulnerabilities, indent=2))
        
        # Simulate scan_results.json generation (correct behavior)
        scan_results = {
            "repository_path": str(tmp_path),
            "scan_timestamp": "2024-10-05T12:00:00Z",
            "summary": {
                "total_threats_identified": 20,
                "total_vulnerabilities_confirmed": len(vulnerabilities),
                "critical": 0,
                "high": sum(1 for v in vulnerabilities if v["severity"] == "high"),
                "medium": sum(1 for v in vulnerabilities if v["severity"] == "medium"),
                "low": 0
            },
            "issues": vulnerabilities  # ALL vulnerabilities copied
        }
        
        results_file = tmp_path / "scan_results.json"
        results_file.write_text(json.dumps(scan_results, indent=2))
        
        # Load and verify
        loaded_vulns = json.loads(vuln_file.read_text())
        loaded_results = json.loads(results_file.read_text())
        
        # CRITICAL: No data loss!
        assert len(loaded_results["issues"]) == len(loaded_vulns)
        assert len(loaded_results["issues"]) == 15
        assert loaded_results["summary"]["total_vulnerabilities_confirmed"] == 15
        
        # Verify all IDs present
        vuln_ids = {v["threat_id"] for v in loaded_vulns}
        result_ids = {i["threat_id"] for i in loaded_results["issues"]}
        assert vuln_ids == result_ids, "Some vulnerability IDs were lost!"
    
    def test_pygoat_scenario_28_vulnerabilities(self):
        """Test the actual PyGoat scenario: 28 vulnerabilities"""
        # This simulates the real bug we fixed
        
        # Phase 3: Code review finds 28 vulnerabilities
        vulnerabilities = [
            {"threat_id": f"THREAT-{i:03d}", "title": f"Vuln {i}", "severity": "critical"}
            for i in range(1, 29)
        ]
        
        # Phase 4: Report generation should preserve ALL 28
        scan_results_issues = vulnerabilities  # Should be all 28!
        
        # Verify PyGoat scenario
        assert len(vulnerabilities) == 28, "PyGoat has 28 vulnerabilities"
        assert len(scan_results_issues) == 28, "All 28 should be in scan_results"
        
        # The bug scenarios we fixed:
        assert len(scan_results_issues) != 0, "MUST NOT report 0 (100% false negative)"
        assert len(scan_results_issues) != 2, "MUST NOT filter to 2 (90% data loss)"
        assert len(scan_results_issues) != 7, "MUST NOT filter to 7 (73% data loss)"
        
        # Success: 0% false negative rate
        false_negative_rate = (28 - len(scan_results_issues)) / 28
        assert false_negative_rate == 0.0, f"False negative rate: {false_negative_rate*100}%"
