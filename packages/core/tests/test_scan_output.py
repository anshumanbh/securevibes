"""Tests for scan_output Pydantic models"""

import pytest
from securevibes.models.scan_output import ScanOutput, Vulnerability, AffectedFile
from securevibes.models.issue import Severity


class TestSeverityHandling:
    """Test Severity enum case-insensitive matching"""

    def test_severity_lowercase(self):
        """Test lowercase severity values"""
        vuln = Vulnerability(
            threat_id="T-001",
            title="Test",
            description="Test desc",
            severity="critical"
        )
        assert vuln.severity == Severity.CRITICAL

    def test_severity_uppercase(self):
        """Test uppercase severity values"""
        vuln = Vulnerability(
            threat_id="T-001",
            title="Test",
            description="Test desc",
            severity="HIGH"
        )
        assert vuln.severity == Severity.HIGH

    def test_severity_mixed_case(self):
        """Test mixed case severity values"""
        vuln = Vulnerability(
            threat_id="T-001",
            title="Test",
            description="Test desc",
            severity="Medium"
        )
        assert vuln.severity == Severity.MEDIUM

    def test_severity_informational_alias(self):
        """Test 'informational' maps to INFO"""
        vuln = Vulnerability(
            threat_id="T-001",
            title="Test",
            description="Test desc",
            severity="informational"
        )
        assert vuln.severity == Severity.INFO


class TestAffectedFile:
    """Test AffectedFile model and validators"""

    def test_basic_creation(self):
        """Test basic AffectedFile creation"""
        af = AffectedFile(file_path="src/app.py", line_number=42)
        assert af.file_path == "src/app.py"
        assert af.line_number == 42

    def test_path_alias(self):
        """Test 'path' field aliased to 'file_path'"""
        af = AffectedFile(**{"path": "src/app.py"})
        assert af.file_path == "src/app.py"

    def test_line_numbers_alias(self):
        """Test 'line_numbers' aliased to 'line_number'"""
        af = AffectedFile(**{"file_path": "app.py", "line_numbers": [10, 20]})
        assert af.line_number == [10, 20]

    def test_with_code_snippet(self):
        """Test AffectedFile with code snippet"""
        af = AffectedFile(
            file_path="src/db.py",
            line_number=15,
            code_snippet="query = f'SELECT * FROM {table}'"
        )
        assert af.code_snippet == "query = f'SELECT * FROM {table}'"


class TestVulnerability:
    """Test Vulnerability model and validators"""

    def test_basic_creation(self):
        """Test basic Vulnerability creation"""
        vuln = Vulnerability(
            threat_id="THREAT-001",
            title="SQL Injection",
            description="User input not sanitized",
            severity="high",
            file_path="src/db.py",
            line_number=42,
            cwe_id="CWE-89",
            recommendation="Use parameterized queries"
        )
        assert vuln.threat_id == "THREAT-001"
        assert vuln.severity == Severity.HIGH
        assert vuln.cwe_id == "CWE-89"

    def test_id_alias_to_threat_id(self):
        """Test 'id' field maps to 'threat_id'"""
        vuln = Vulnerability(**{
            "id": "V-001",
            "title": "Test",
            "description": "Test desc",
            "severity": "low"
        })
        assert vuln.threat_id == "V-001"

    def test_missing_id_gets_default(self):
        """Test missing id gets UNKNOWN-ID default"""
        vuln = Vulnerability(**{
            "title": "Test",
            "description": "Test desc",
            "severity": "low"
        })
        assert vuln.threat_id == "UNKNOWN-ID"

    def test_line_number_list_takes_first(self):
        """Test line_number list extracts first element"""
        vuln = Vulnerability(
            threat_id="T-001",
            title="Test",
            description="Test",
            severity="medium",
            line_number=[10, 15, 20]
        )
        assert vuln.line_number == 10

    def test_vulnerable_code_extraction(self):
        """Test extraction from vulnerable_code object"""
        vuln = Vulnerability(**{
            "threat_id": "T-001",
            "title": "Test",
            "description": "Test desc",
            "severity": "high",
            "vulnerable_code": {
                "file": "src/auth.py",
                "line_numbers": [42, 43],
                "code_snippet": "password = request.form['pass']"
            }
        })
        assert vuln.file_path == "src/auth.py"
        assert vuln.line_number == 42
        assert vuln.code_snippet == "password = request.form['pass']"

    def test_affected_files_string_list_conversion(self):
        """Test affected_files list of strings converts to AffectedFile objects"""
        vuln = Vulnerability(**{
            "threat_id": "T-001",
            "title": "Test",
            "description": "Test desc",
            "severity": "medium",
            "affected_files": ["src/a.py", "src/b.py", "src/c.py"]
        })
        assert len(vuln.affected_files) == 3
        assert vuln.affected_files[0].file_path == "src/a.py"
        assert vuln.affected_files[1].file_path == "src/b.py"

    def test_affected_files_object_list(self):
        """Test affected_files list of objects"""
        vuln = Vulnerability(**{
            "threat_id": "T-001",
            "title": "Test",
            "description": "Test desc",
            "severity": "low",
            "affected_files": [
                {"file_path": "src/a.py", "line_number": 10},
                {"path": "src/b.py", "line_numbers": [20, 21]}
            ]
        })
        assert len(vuln.affected_files) == 2
        assert vuln.affected_files[0].line_number == 10
        assert vuln.affected_files[1].file_path == "src/b.py"

    def test_remediation_to_recommendation_string(self):
        """Test 'remediation' string maps to 'recommendation'"""
        vuln = Vulnerability(**{
            "threat_id": "T-001",
            "title": "Test",
            "description": "Test desc",
            "severity": "high",
            "remediation": "Fix the code by doing X"
        })
        assert vuln.recommendation == "Fix the code by doing X"

    def test_remediation_to_recommendation_dict(self):
        """Test 'remediation' dict extracts 'recommendation' field"""
        vuln = Vulnerability(**{
            "threat_id": "T-001",
            "title": "Test",
            "description": "Test desc",
            "severity": "high",
            "remediation": {
                "recommendation": "Use secure method",
                "priority": "high"
            }
        })
        assert vuln.recommendation == "Use secure method"

    def test_proof_of_concept_to_evidence(self):
        """Test 'proof_of_concept' maps to 'evidence'"""
        vuln = Vulnerability(**{
            "threat_id": "T-001",
            "title": "Test",
            "description": "Test desc",
            "severity": "critical",
            "proof_of_concept": "curl -X POST http://..."
        })
        assert vuln.evidence == "curl -X POST http://..."

    def test_evidence_dict(self):
        """Test evidence can be a dict"""
        vuln = Vulnerability(
            threat_id="T-001",
            title="Test",
            description="Test desc",
            severity="high",
            evidence={"request": "GET /admin", "response": "200 OK"}
        )
        assert isinstance(vuln.evidence, dict)
        assert vuln.evidence["request"] == "GET /admin"


class TestScanOutput:
    """Test ScanOutput model and validate_input"""

    def test_validate_input_flat_list(self):
        """Test parsing flat list of vulnerabilities"""
        data = [
            {
                "threat_id": "T-001",
                "title": "Issue 1",
                "description": "Desc 1",
                "severity": "high"
            },
            {
                "threat_id": "T-002",
                "title": "Issue 2",
                "description": "Desc 2",
                "severity": "low"
            }
        ]
        result = ScanOutput.validate_input(data)
        assert len(result.vulnerabilities) == 2
        assert result.vulnerabilities[0].threat_id == "T-001"
        assert result.vulnerabilities[1].severity == Severity.LOW

    def test_validate_input_wrapped_vulnerabilities(self):
        """Test parsing dict wrapped in 'vulnerabilities' key"""
        data = {
            "vulnerabilities": [
                {
                    "threat_id": "T-001",
                    "title": "Test",
                    "description": "Test desc",
                    "severity": "critical"
                }
            ]
        }
        result = ScanOutput.validate_input(data)
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].severity == Severity.CRITICAL

    def test_validate_input_wrapped_issues(self):
        """Test parsing dict wrapped in 'issues' key"""
        data = {
            "issues": [
                {
                    "threat_id": "T-001",
                    "title": "Test",
                    "description": "Test desc",
                    "severity": "medium"
                }
            ]
        }
        result = ScanOutput.validate_input(data)
        assert len(result.vulnerabilities) == 1

    def test_validate_input_empty_list(self):
        """Test parsing empty list"""
        result = ScanOutput.validate_input([])
        assert len(result.vulnerabilities) == 0

    def test_validate_input_invalid_format(self):
        """Test invalid input format raises error"""
        with pytest.raises(ValueError, match="Invalid input format"):
            ScanOutput.validate_input("invalid string")

    def test_validate_input_invalid_type(self):
        """Test invalid type raises error"""
        with pytest.raises(ValueError, match="Invalid input format"):
            ScanOutput.validate_input(12345)


class TestRealWorldFormats:
    """Test parsing real-world JSON formats from agent output"""

    def test_code_review_agent_format(self):
        """Test format typically output by code review agent"""
        data = [
            {
                "threat_id": "THREAT-AUTH-001",
                "title": "Hardcoded Credentials",
                "description": "Password stored in source code",
                "severity": "critical",
                "file_path": "src/config.py",
                "line_number": 15,
                "code_snippet": "PASSWORD = 'admin123'",
                "cwe_id": "CWE-798",
                "recommendation": "Use environment variables",
                "evidence": "Direct password assignment found"
            }
        ]
        result = ScanOutput.validate_input(data)
        vuln = result.vulnerabilities[0]
        assert vuln.threat_id == "THREAT-AUTH-001"
        assert vuln.severity == Severity.CRITICAL
        assert vuln.file_path == "src/config.py"
        assert vuln.cwe_id == "CWE-798"

    def test_legacy_scan_results_format(self):
        """Test legacy scan_results.json format with nested vulnerable_code"""
        data = {
            "vulnerabilities": [
                {
                    "id": "SQL-001",
                    "title": "SQL Injection",
                    "description": "User input in query",
                    "severity": "HIGH",
                    "vulnerable_code": {
                        "file": "src/db.py",
                        "line_no": 42,
                        "code": "query = f'SELECT * FROM users WHERE id={id}'"
                    },
                    "remediation": {
                        "recommendation": "Use parameterized queries",
                        "references": ["https://owasp.org/sql-injection"]
                    },
                    "proof_of_concept": "id=1 OR 1=1"
                }
            ]
        }
        result = ScanOutput.validate_input(data)
        vuln = result.vulnerabilities[0]
        assert vuln.threat_id == "SQL-001"
        assert vuln.file_path == "src/db.py"
        assert vuln.line_number == 42
        assert vuln.recommendation == "Use parameterized queries"
        assert vuln.evidence == "id=1 OR 1=1"

    def test_dast_agent_format(self):
        """Test format from DAST agent with affected_files"""
        data = [
            {
                "threat_id": "DAST-XSS-001",
                "title": "Reflected XSS",
                "description": "Script injection in search parameter",
                "severity": "high",
                "affected_files": [
                    {"file_path": "src/views/search.py", "line_number": 25},
                    {"path": "templates/results.html", "line_numbers": [10, 12]}
                ],
                "evidence": {
                    "url": "/search?q=<script>alert(1)</script>",
                    "response": "200 OK with script reflected"
                }
            }
        ]
        result = ScanOutput.validate_input(data)
        vuln = result.vulnerabilities[0]
        assert len(vuln.affected_files) == 2
        assert vuln.affected_files[0].file_path == "src/views/search.py"
        assert vuln.affected_files[1].file_path == "templates/results.html"
        assert isinstance(vuln.evidence, dict)


class TestScanOutputSchemaHelpers:
    """Test ScanOutput JSON schema helper methods for structured outputs"""

    def test_get_json_schema_returns_array_type(self):
        """Test get_json_schema returns array schema"""
        schema = ScanOutput.get_json_schema()
        
        assert isinstance(schema, dict)
        assert schema["type"] == "array"

    def test_get_json_schema_has_items(self):
        """Test schema has items definition for vulnerabilities"""
        schema = ScanOutput.get_json_schema()
        
        assert "items" in schema
        assert schema["items"]["type"] == "object"

    def test_get_json_schema_required_fields(self):
        """Test schema items have required fields"""
        schema = ScanOutput.get_json_schema()
        items = schema["items"]
        
        assert "required" in items
        required = items["required"]
        assert "threat_id" in required
        assert "title" in required
        assert "description" in required
        assert "severity" in required

    def test_get_json_schema_severity_enum(self):
        """Test severity property has enum constraint"""
        schema = ScanOutput.get_json_schema()
        props = schema["items"]["properties"]
        
        assert "severity" in props
        assert "enum" in props["severity"]
        assert set(props["severity"]["enum"]) == {"critical", "high", "medium", "low", "info"}

    def test_get_output_format_returns_correct_structure(self):
        """Test get_output_format returns SDK-compatible config"""
        config = ScanOutput.get_output_format()
        
        assert isinstance(config, dict)
        assert "type" in config
        assert "schema" in config

    def test_get_output_format_type_is_json_schema(self):
        """Test output_format type is 'json_schema'"""
        config = ScanOutput.get_output_format()
        
        assert config["type"] == "json_schema"

    def test_get_output_format_schema_matches_get_json_schema(self):
        """Test output_format schema matches get_json_schema"""
        config = ScanOutput.get_output_format()
        schema = ScanOutput.get_json_schema()
        
        assert config["schema"] == schema

    def test_schema_compatible_with_sdk_structured_outputs(self):
        """Test schema structure is compatible with Claude SDK output_format"""
        config = ScanOutput.get_output_format()
        
        # Claude SDK expects: {"type": "json_schema", "schema": {...}}
        assert config["type"] == "json_schema"
        assert isinstance(config["schema"], dict)
        assert config["schema"]["type"] == "array"
