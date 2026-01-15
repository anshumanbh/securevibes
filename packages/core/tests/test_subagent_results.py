"""Tests for single subagent result loading"""

import json
import pytest
from datetime import datetime
from io import StringIO

from rich.console import Console

from securevibes.scanner.scanner import Scanner
from securevibes.models.result import ScanResult


class TestSubagentResultLoading:
    """Test result loading for single subagent runs"""

    @pytest.fixture
    def scanner(self):
        """Create a scanner instance with mocked console"""
        scanner = Scanner(model="sonnet", debug=False)
        scanner.console = Console(file=StringIO())
        scanner.total_cost = 0.5
        return scanner

    @pytest.fixture
    def securevibes_dir(self, tmp_path):
        """Create .securevibes directory"""
        dir_path = tmp_path / ".securevibes"
        dir_path.mkdir()
        return dir_path

    def test_assessment_returns_partial_result(self, scanner, securevibes_dir, tmp_path):
        """Assessment subagent returns result with 0 issues"""
        # Create SECURITY.md only
        security_md = securevibes_dir / "SECURITY.md"
        security_md.write_text("# Security Assessment\n\nTest content")

        # Call _load_subagent_results
        result = scanner._load_subagent_results(
            securevibes_dir=securevibes_dir,
            repo=tmp_path,
            files_scanned=10,
            scan_start_time=datetime.now().timestamp() - 5,
            subagent="assessment",
        )

        # Assert result structure
        assert isinstance(result, ScanResult)
        assert result.issues == []
        assert result.files_scanned == 10
        assert result.total_cost_usd == 0.5
        assert str(tmp_path) in result.repository_path

    def test_assessment_shows_next_step_message(self, scanner, securevibes_dir, tmp_path):
        """Assessment shows message about running threat-modeling next"""
        security_md = securevibes_dir / "SECURITY.md"
        security_md.write_text("# Security Assessment")

        scanner._load_subagent_results(
            securevibes_dir=securevibes_dir,
            repo=tmp_path,
            files_scanned=10,
            scan_start_time=datetime.now().timestamp(),
            subagent="assessment",
        )

        output = scanner.console.file.getvalue()
        assert "Assessment complete" in output
        assert "threat-modeling" in output

    def test_threat_modeling_returns_threat_count(self, scanner, securevibes_dir, tmp_path):
        """Threat modeling returns threat count in output"""
        # Create THREAT_MODEL.json with wrapped format (as agent produces)
        threat_model = securevibes_dir / "THREAT_MODEL.json"
        threat_data = {
            "metadata": {"timestamp": "2026-01-08T10:00:00Z"},
            "threats": [
                {"id": "THREAT-001", "title": "Test threat 1"},
                {"id": "THREAT-002", "title": "Test threat 2"},
                {"id": "THREAT-003", "title": "Test threat 3"},
            ],
        }
        threat_model.write_text(json.dumps(threat_data))

        result = scanner._load_subagent_results(
            securevibes_dir=securevibes_dir,
            repo=tmp_path,
            files_scanned=15,
            scan_start_time=datetime.now().timestamp() - 10,
            subagent="threat-modeling",
        )

        # Check output mentions threat count
        output = scanner.console.file.getvalue()
        assert "Threat modeling complete" in output
        assert "3 threats" in output
        assert "code-review" in output

        # Result should still have no issues (threats != vulnerabilities)
        assert result.issues == []

    def test_threat_modeling_handles_flat_array_format(self, scanner, securevibes_dir, tmp_path):
        """Threat modeling also handles flat array format"""
        # Create THREAT_MODEL.json with flat array format
        threat_model = securevibes_dir / "THREAT_MODEL.json"
        threats = [
            {"id": "THREAT-001", "title": "Test threat 1"},
            {"id": "THREAT-002", "title": "Test threat 2"},
        ]
        threat_model.write_text(json.dumps(threats))

        scanner._load_subagent_results(
            securevibes_dir=securevibes_dir,
            repo=tmp_path,
            files_scanned=10,
            scan_start_time=datetime.now().timestamp(),
            subagent="threat-modeling",
        )

        output = scanner.console.file.getvalue()
        assert "2 threats" in output

    def test_code_review_loads_vulnerabilities(self, scanner, securevibes_dir, tmp_path):
        """Code review delegates to _load_scan_results for full loading"""
        # Create VULNERABILITIES.json
        vulns = [
            {
                "threat_id": "VULN-001",
                "title": "SQL Injection",
                "description": "Test vulnerability",
                "severity": "high",
                "cwe_id": "CWE-89",
                "file_path": "test.py",
                "line_number": 10,
                "code_snippet": "query = f'SELECT * FROM {user_input}'",
                "recommendation": "Use parameterized queries",
            }
        ]
        vuln_file = securevibes_dir / "VULNERABILITIES.json"
        vuln_file.write_text(json.dumps(vulns))

        result = scanner._load_subagent_results(
            securevibes_dir=securevibes_dir,
            repo=tmp_path,
            files_scanned=20,
            scan_start_time=datetime.now().timestamp() - 15,
            subagent="code-review",
        )

        # Should have loaded the vulnerability
        assert len(result.issues) == 1
        assert result.issues[0].title == "SQL Injection"

    def test_dast_returns_validation_count(self, scanner, securevibes_dir, tmp_path):
        """DAST subagent shows validation count"""
        # Create DAST_VALIDATION.json
        validations = [
            {"vulnerability_id": "VULN-001", "validation_status": "VALIDATED"},
            {"vulnerability_id": "VULN-002", "validation_status": "FALSE_POSITIVE"},
        ]
        dast_file = securevibes_dir / "DAST_VALIDATION.json"
        dast_file.write_text(json.dumps(validations))

        result = scanner._load_subagent_results(
            securevibes_dir=securevibes_dir,
            repo=tmp_path,
            files_scanned=25,
            scan_start_time=datetime.now().timestamp() - 20,
            subagent="dast",
        )

        output = scanner.console.file.getvalue()
        assert "DAST validation complete" in output
        assert "2 validations" in output

        # DAST returns partial result
        assert result.issues == []

    def test_missing_artifact_raises_clear_error(self, scanner, securevibes_dir, tmp_path):
        """Missing expected artifact gives helpful error"""
        # Don't create any artifact

        with pytest.raises(RuntimeError) as exc_info:
            scanner._load_subagent_results(
                securevibes_dir=securevibes_dir,
                repo=tmp_path,
                files_scanned=10,
                scan_start_time=datetime.now().timestamp(),
                subagent="assessment",
            )

        error_msg = str(exc_info.value)
        assert "assessment" in error_msg
        assert "SECURITY.md" in error_msg
        assert "failed to create" in error_msg

    def test_unknown_subagent_raises_error(self, scanner, securevibes_dir, tmp_path):
        """Unknown subagent name raises RuntimeError"""
        with pytest.raises(RuntimeError) as exc_info:
            scanner._load_subagent_results(
                securevibes_dir=securevibes_dir,
                repo=tmp_path,
                files_scanned=10,
                scan_start_time=datetime.now().timestamp(),
                subagent="invalid-subagent",
            )

        assert "Unknown subagent" in str(exc_info.value)

    def test_assessment_only_no_error_on_missing_scan_results(
        self, scanner, securevibes_dir, tmp_path
    ):
        """Running only assessment doesn't error on missing scan_results.json

        This is the main bug fix test - previously this would fail because
        _load_scan_results expected scan_results.json to exist.
        """
        # Create only SECURITY.md (assessment artifact)
        security_md = securevibes_dir / "SECURITY.md"
        security_md.write_text("# Security Assessment\n\nArchitecture docs here")

        # These files should NOT exist
        assert not (securevibes_dir / "scan_results.json").exists()
        assert not (securevibes_dir / "VULNERABILITIES.json").exists()

        # This should NOT raise an error
        result = scanner._load_subagent_results(
            securevibes_dir=securevibes_dir,
            repo=tmp_path,
            files_scanned=10,
            scan_start_time=datetime.now().timestamp(),
            subagent="assessment",
        )

        # Should return valid partial result
        assert isinstance(result, ScanResult)
        assert result.issues == []

    def test_threat_model_with_malformed_json(self, scanner, securevibes_dir, tmp_path):
        """Threat modeling handles malformed JSON gracefully"""
        threat_model = securevibes_dir / "THREAT_MODEL.json"
        threat_model.write_text("not valid json {")

        # Should not raise - just show 0 threats
        result = scanner._load_subagent_results(
            securevibes_dir=securevibes_dir,
            repo=tmp_path,
            files_scanned=10,
            scan_start_time=datetime.now().timestamp(),
            subagent="threat-modeling",
        )

        output = scanner.console.file.getvalue()
        assert "0 threats" in output
        assert result.issues == []


class TestReportGeneratorSubagent:
    """Test report-generator subagent result loading"""

    @pytest.fixture
    def scanner(self):
        scanner = Scanner(model="sonnet", debug=False)
        scanner.console = Console(file=StringIO())
        scanner.total_cost = 1.0
        return scanner

    @pytest.fixture
    def securevibes_dir(self, tmp_path):
        dir_path = tmp_path / ".securevibes"
        dir_path.mkdir()
        return dir_path

    def test_report_generator_loads_scan_results(self, scanner, securevibes_dir, tmp_path):
        """Report generator loads from scan_results.json"""
        # Create scan_results.json (report-generator output)
        scan_results = {
            "repository_path": str(tmp_path),
            "scan_timestamp": datetime.now().isoformat(),
            "files_scanned": 50,
            "scan_time_seconds": 30.5,
            "total_cost_usd": 1.5,
            "summary": {
                "total_vulnerabilities_confirmed": 1,
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
            },
            "issues": [
                {
                    "threat_id": "VULN-001",
                    "title": "XSS Vulnerability",
                    "description": "Cross-site scripting",
                    "severity": "high",
                    "cwe_id": "CWE-79",
                    "file_path": "app.js",
                    "line_number": 25,
                    "code_snippet": "innerHTML = userInput",
                    "recommendation": "Sanitize input",
                }
            ],
        }
        results_file = securevibes_dir / "scan_results.json"
        results_file.write_text(json.dumps(scan_results))

        result = scanner._load_subagent_results(
            securevibes_dir=securevibes_dir,
            repo=tmp_path,
            files_scanned=50,
            scan_start_time=datetime.now().timestamp() - 30,
            subagent="report-generator",
        )

        assert len(result.issues) == 1
        assert result.issues[0].title == "XSS Vulnerability"
