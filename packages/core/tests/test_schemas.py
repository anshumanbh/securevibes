"""Tests for JSON schema validation and auto-fix functionality."""

import json
import pytest

from securevibes.models.schemas import (
    fix_vulnerabilities_json,
    validate_vulnerabilities_json,
    get_output_format_config,
    VULNERABILITY_SCHEMA,
    VULNERABILITIES_ARRAY_SCHEMA,
)


class TestFixVulnerabilitiesJson:
    """Tests for fix_vulnerabilities_json() auto-fix function."""

    def _make_valid_vuln(self, threat_id="THREAT-001", title="SQL Injection"):
        """Helper to create a valid vulnerability dict."""
        return {
            "threat_id": threat_id,
            "title": title,
            "description": "Test vulnerability",
            "severity": "high"
        }

    def test_flat_array_unchanged(self):
        """Flat array should pass through without modification."""
        vuln = self._make_valid_vuln()
        content = json.dumps([vuln])
        
        fixed, modified = fix_vulnerabilities_json(content)
        
        assert modified is False
        assert json.loads(fixed) == [vuln]

    def test_wrapped_vulnerabilities_unwrapped(self):
        """Wrapped {'vulnerabilities': [...]} should be unwrapped."""
        vuln = self._make_valid_vuln()
        content = json.dumps({"vulnerabilities": [vuln]})
        
        fixed, modified = fix_vulnerabilities_json(content)
        
        assert modified is True
        assert fixed.startswith("[")
        assert json.loads(fixed) == [vuln]

    def test_wrapped_issues_unwrapped(self):
        """Wrapped {'issues': [...]} should be unwrapped."""
        vuln = self._make_valid_vuln()
        content = json.dumps({"issues": [vuln]})
        
        fixed, modified = fix_vulnerabilities_json(content)
        
        assert modified is True
        assert json.loads(fixed) == [vuln]

    def test_wrapped_results_unwrapped(self):
        """Wrapped {'results': [...]} should be unwrapped."""
        vuln = self._make_valid_vuln()
        content = json.dumps({"results": [vuln]})
        
        fixed, modified = fix_vulnerabilities_json(content)
        
        assert modified is True
        assert json.loads(fixed) == [vuln]

    def test_wrapped_findings_unwrapped(self):
        """Wrapped {'findings': [...]} should be unwrapped."""
        vuln = self._make_valid_vuln()
        content = json.dumps({"findings": [vuln]})
        
        fixed, modified = fix_vulnerabilities_json(content)
        
        assert modified is True
        assert json.loads(fixed) == [vuln]

    def test_wrapped_data_unwrapped(self):
        """Wrapped {'data': [...]} should be unwrapped."""
        vuln = self._make_valid_vuln()
        content = json.dumps({"data": [vuln]})
        
        fixed, modified = fix_vulnerabilities_json(content)
        
        assert modified is True
        assert json.loads(fixed) == [vuln]

    def test_empty_string_returns_empty_array(self):
        """Empty string should return empty array."""
        fixed, modified = fix_vulnerabilities_json("")
        
        assert modified is True
        assert fixed == "[]"

    def test_whitespace_only_returns_empty_array(self):
        """Whitespace-only string should return empty array."""
        fixed, modified = fix_vulnerabilities_json("   \n\t  ")
        
        assert modified is True
        assert fixed == "[]"

    def test_empty_array_unchanged(self):
        """Empty array should pass through unchanged."""
        fixed, modified = fix_vulnerabilities_json("[]")
        
        assert modified is False
        assert fixed == "[]"

    def test_single_vuln_object_wrapped_in_array(self):
        """Single vulnerability object should be wrapped in array."""
        vuln = self._make_valid_vuln()
        content = json.dumps(vuln)
        
        fixed, modified = fix_vulnerabilities_json(content)
        
        assert modified is True
        assert json.loads(fixed) == [vuln]

    def test_invalid_json_returns_unchanged(self):
        """Invalid JSON should be returned as-is."""
        content = "not valid json {"
        
        fixed, modified = fix_vulnerabilities_json(content)
        
        assert modified is False
        assert fixed == content

    def test_nested_wrapper_with_summary(self):
        """Nested wrapper with summary should extract array."""
        vuln = self._make_valid_vuln()
        content = json.dumps({
            "summary": {"total": 1},
            "vulnerabilities": [vuln]
        })
        
        fixed, modified = fix_vulnerabilities_json(content)
        
        assert modified is True
        assert json.loads(fixed) == [vuln]

    def test_multiple_vulnerabilities(self):
        """Multiple vulnerabilities should be preserved."""
        vulns = [
            self._make_valid_vuln("THREAT-001", "SQL Injection"),
            self._make_valid_vuln("THREAT-002", "XSS"),
            self._make_valid_vuln("THREAT-003", "CSRF")
        ]
        content = json.dumps({"vulnerabilities": vulns})
        
        fixed, modified = fix_vulnerabilities_json(content)
        
        assert modified is True
        parsed = json.loads(fixed)
        assert len(parsed) == 3
        assert parsed[0]["threat_id"] == "THREAT-001"
        assert parsed[2]["threat_id"] == "THREAT-003"


class TestValidateVulnerabilitiesJson:
    """Tests for validate_vulnerabilities_json() validation function."""

    def _make_valid_vuln(self):
        """Helper to create a valid vulnerability dict."""
        return {
            "threat_id": "THREAT-001",
            "title": "SQL Injection",
            "description": "Test vulnerability",
            "severity": "high"
        }

    def test_valid_flat_array(self):
        """Valid flat array should pass validation."""
        content = json.dumps([self._make_valid_vuln()])
        
        is_valid, error = validate_vulnerabilities_json(content)
        
        assert is_valid is True
        assert error is None

    def test_valid_empty_array(self):
        """Empty array should pass validation."""
        is_valid, error = validate_vulnerabilities_json("[]")
        
        assert is_valid is True
        assert error is None

    def test_missing_threat_id(self):
        """Missing threat_id should fail validation."""
        vuln = self._make_valid_vuln()
        del vuln["threat_id"]
        content = json.dumps([vuln])
        
        is_valid, error = validate_vulnerabilities_json(content)
        
        assert is_valid is False
        assert "threat_id" in error

    def test_missing_title(self):
        """Missing title should fail validation."""
        vuln = self._make_valid_vuln()
        del vuln["title"]
        content = json.dumps([vuln])
        
        is_valid, error = validate_vulnerabilities_json(content)
        
        assert is_valid is False
        assert "title" in error

    def test_missing_description(self):
        """Missing description should fail validation."""
        vuln = self._make_valid_vuln()
        del vuln["description"]
        content = json.dumps([vuln])
        
        is_valid, error = validate_vulnerabilities_json(content)
        
        assert is_valid is False
        assert "description" in error

    def test_missing_severity(self):
        """Missing severity should fail validation."""
        vuln = self._make_valid_vuln()
        del vuln["severity"]
        content = json.dumps([vuln])
        
        is_valid, error = validate_vulnerabilities_json(content)
        
        assert is_valid is False
        assert "severity" in error

    def test_invalid_severity_value(self):
        """Invalid severity value should fail validation."""
        vuln = self._make_valid_vuln()
        vuln["severity"] = "INVALID"
        content = json.dumps([vuln])
        
        is_valid, error = validate_vulnerabilities_json(content)
        
        assert is_valid is False
        assert "severity" in error.lower()

    def test_valid_severity_values(self):
        """All valid severity values should pass."""
        for severity in ["critical", "high", "medium", "low", "info"]:
            vuln = self._make_valid_vuln()
            vuln["severity"] = severity
            content = json.dumps([vuln])
            
            is_valid, error = validate_vulnerabilities_json(content)
            
            assert is_valid is True, f"Severity '{severity}' should be valid"

    def test_wrapped_object_fails(self):
        """Wrapped object should fail (must start with '[')."""
        vuln = self._make_valid_vuln()
        content = json.dumps({"vulnerabilities": [vuln]})
        
        is_valid, error = validate_vulnerabilities_json(content)
        
        assert is_valid is False
        assert "[" in error

    def test_empty_string_fails(self):
        """Empty string should fail validation."""
        is_valid, error = validate_vulnerabilities_json("")
        
        assert is_valid is False

    def test_invalid_json_fails(self):
        """Invalid JSON should fail validation."""
        is_valid, error = validate_vulnerabilities_json("not json")
        
        assert is_valid is False
        # Fails first check (must start with '[') before JSON parsing
        assert error is not None

    def test_invalid_json_array_fails(self):
        """Invalid JSON that starts with '[' should fail with JSON error."""
        is_valid, error = validate_vulnerabilities_json("[invalid json")
        
        assert is_valid is False
        assert "Invalid JSON" in error

    def test_non_object_item_fails(self):
        """Non-object items in array should fail."""
        content = json.dumps(["string", 123])
        
        is_valid, error = validate_vulnerabilities_json(content)
        
        assert is_valid is False
        assert "not an object" in error


class TestGetOutputFormatConfig:
    """Tests for get_output_format_config() SDK helper."""

    def test_returns_correct_structure(self):
        """Should return dict with type and schema keys."""
        config = get_output_format_config()
        
        assert isinstance(config, dict)
        assert "type" in config
        assert "schema" in config

    def test_type_is_json_schema(self):
        """Type should be 'json_schema'."""
        config = get_output_format_config()
        
        assert config["type"] == "json_schema"

    def test_schema_is_array_schema(self):
        """Schema should be the vulnerabilities array schema."""
        config = get_output_format_config()
        
        assert config["schema"] == VULNERABILITIES_ARRAY_SCHEMA
        assert config["schema"]["type"] == "array"


class TestSchemaStructure:
    """Tests for schema constant definitions."""

    def test_vulnerability_schema_has_required_fields(self):
        """Vulnerability schema should have correct required fields."""
        required = VULNERABILITY_SCHEMA["required"]
        
        assert "threat_id" in required
        assert "title" in required
        assert "description" in required
        assert "severity" in required

    def test_vulnerability_schema_severity_enum(self):
        """Severity should have correct enum values."""
        severity_prop = VULNERABILITY_SCHEMA["properties"]["severity"]
        
        assert "enum" in severity_prop
        assert set(severity_prop["enum"]) == {"critical", "high", "medium", "low", "info"}

    def test_array_schema_wraps_vulnerability(self):
        """Array schema should use vulnerability schema as items."""
        assert VULNERABILITIES_ARRAY_SCHEMA["type"] == "array"
        assert VULNERABILITIES_ARRAY_SCHEMA["items"] == VULNERABILITY_SCHEMA
