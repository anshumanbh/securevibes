"""Tests for JSON schema validation and auto-fix functionality."""

import json

import pytest

from securevibes.models.schemas import (
    derive_pr_finding_id,
    extract_cwe_id,
    fix_pr_vulnerabilities_json,
    fix_vulnerabilities_json,
    normalize_pr_vulnerability,
    validate_vulnerabilities_json,
    validate_pr_vulnerabilities_json,
    get_output_format_config,
    VULNERABILITY_SCHEMA,
    VULNERABILITIES_ARRAY_SCHEMA,
)


@pytest.fixture
def valid_pr_vuln():
    """Fixture providing a valid PR vulnerability dict for testing."""
    return {
        "threat_id": "THREAT-001",
        "finding_type": "new_threat",
        "title": "Gateway URL injection",
        "description": "Test description",
        "severity": "high",
        "file_path": "ui/app.ts",
        "line_number": 10,
        "code_snippet": "const gatewayUrl = params.get('gatewayUrl')",
        "attack_scenario": "Attacker controls gatewayUrl",
        "evidence": "Token sent to attacker",
        "cwe_id": "CWE-918",
        "recommendation": "Validate URL input",
    }


class TestFixVulnerabilitiesJson:
    """Tests for fix_vulnerabilities_json() auto-fix function."""

    def _make_valid_vuln(self, threat_id="THREAT-001", title="SQL Injection"):
        """Helper to create a valid vulnerability dict."""
        return {
            "threat_id": threat_id,
            "title": title,
            "description": "Test vulnerability",
            "severity": "high",
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
        content = json.dumps({"summary": {"total": 1}, "vulnerabilities": [vuln]})

        fixed, modified = fix_vulnerabilities_json(content)

        assert modified is True
        assert json.loads(fixed) == [vuln]

    def test_multiple_vulnerabilities(self):
        """Multiple vulnerabilities should be preserved."""
        vulns = [
            self._make_valid_vuln("THREAT-001", "SQL Injection"),
            self._make_valid_vuln("THREAT-002", "XSS"),
            self._make_valid_vuln("THREAT-003", "CSRF"),
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
            "severity": "high",
            "file_path": "app.py",
            "line_number": 42,
            "code_snippet": "cursor.execute(query)",
            "cwe_id": "CWE-89",
            "recommendation": "Use parameterized queries",
            "evidence": "User input concatenated into SQL query",
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

    def test_missing_file_path(self):
        """Missing file_path should fail validation."""
        vuln = self._make_valid_vuln()
        del vuln["file_path"]
        content = json.dumps([vuln])

        is_valid, error = validate_vulnerabilities_json(content)

        assert is_valid is False
        assert "file_path" in error

    def test_missing_line_number(self):
        """Missing line_number should fail validation."""
        vuln = self._make_valid_vuln()
        del vuln["line_number"]
        content = json.dumps([vuln])

        is_valid, error = validate_vulnerabilities_json(content)

        assert is_valid is False
        assert "line_number" in error

    def test_missing_code_snippet(self):
        """Missing code_snippet should fail validation."""
        vuln = self._make_valid_vuln()
        del vuln["code_snippet"]
        content = json.dumps([vuln])

        is_valid, error = validate_vulnerabilities_json(content)

        assert is_valid is False
        assert "code_snippet" in error

    def test_missing_cwe_id(self):
        """Missing cwe_id should fail validation."""
        vuln = self._make_valid_vuln()
        del vuln["cwe_id"]
        content = json.dumps([vuln])

        is_valid, error = validate_vulnerabilities_json(content)

        assert is_valid is False
        assert "cwe_id" in error

    def test_missing_recommendation(self):
        """Missing recommendation should fail validation."""
        vuln = self._make_valid_vuln()
        del vuln["recommendation"]
        content = json.dumps([vuln])

        is_valid, error = validate_vulnerabilities_json(content)

        assert is_valid is False
        assert "recommendation" in error

    def test_missing_evidence(self):
        """Missing evidence should fail validation."""
        vuln = self._make_valid_vuln()
        del vuln["evidence"]
        content = json.dumps([vuln])

        is_valid, error = validate_vulnerabilities_json(content)

        assert is_valid is False
        assert "evidence" in error

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
        assert "file_path" in required
        assert "line_number" in required
        assert "code_snippet" in required
        assert "cwe_id" in required
        assert "recommendation" in required
        assert "evidence" in required

    def test_vulnerability_schema_severity_enum(self):
        """Severity should have correct enum values."""
        severity_prop = VULNERABILITY_SCHEMA["properties"]["severity"]

        assert "enum" in severity_prop
        assert set(severity_prop["enum"]) == {"critical", "high", "medium", "low", "info"}

    def test_array_schema_wraps_vulnerability(self):
        """Array schema should use vulnerability schema as items."""
        assert VULNERABILITIES_ARRAY_SCHEMA["type"] == "array"
        assert VULNERABILITIES_ARRAY_SCHEMA["items"] == VULNERABILITY_SCHEMA


class TestFixPrVulnerabilitiesJson:
    """Tests for fix_pr_vulnerabilities_json() auto-fix function."""

    def test_wrapped_pr_vulns_unwrapped(self, valid_pr_vuln):
        content = json.dumps({"vulnerabilities": [valid_pr_vuln]})

        fixed, modified = fix_pr_vulnerabilities_json(content)

        assert modified is True
        assert json.loads(fixed) == [valid_pr_vuln]

    def test_flat_pr_array_unchanged(self, valid_pr_vuln):
        content = json.dumps([valid_pr_vuln])

        fixed, modified = fix_pr_vulnerabilities_json(content)

        assert modified is False
        assert json.loads(fixed) == [valid_pr_vuln]


class TestValidatePrVulnerabilitiesJson:
    """Tests for validate_pr_vulnerabilities_json() validation function."""

    def test_valid_pr_vuln(self, valid_pr_vuln):
        content = json.dumps([valid_pr_vuln])

        is_valid, error = validate_pr_vulnerabilities_json(content)

        assert is_valid is True
        assert error is None

    def test_unknown_finding_type_allowed(self, valid_pr_vuln):
        """Unknown finding_type should be allowed for normalized output."""
        valid_pr_vuln["finding_type"] = "unknown"
        content = json.dumps([valid_pr_vuln])

        is_valid, error = validate_pr_vulnerabilities_json(content)

        assert is_valid is True
        assert error is None

    def test_missing_required_field(self, valid_pr_vuln):
        del valid_pr_vuln["attack_scenario"]
        content = json.dumps([valid_pr_vuln])

        is_valid, error = validate_pr_vulnerabilities_json(content)

        assert is_valid is False
        assert "attack_scenario" in error

    def test_empty_file_path_fails_validation(self, valid_pr_vuln):
        """Empty file_path should fail validation."""
        valid_pr_vuln["file_path"] = ""
        content = json.dumps([valid_pr_vuln])

        is_valid, error = validate_pr_vulnerabilities_json(content)

        assert is_valid is False
        assert "empty required evidence fields" in error
        assert "file_path" in error

    def test_empty_code_snippet_fails_validation(self, valid_pr_vuln):
        """Empty code_snippet should fail validation."""
        valid_pr_vuln["code_snippet"] = ""
        content = json.dumps([valid_pr_vuln])

        is_valid, error = validate_pr_vulnerabilities_json(content)

        assert is_valid is False
        assert "empty required evidence fields" in error
        assert "code_snippet" in error

    def test_empty_evidence_fails_validation(self, valid_pr_vuln):
        """Empty evidence should fail validation."""
        valid_pr_vuln["evidence"] = ""
        content = json.dumps([valid_pr_vuln])

        is_valid, error = validate_pr_vulnerabilities_json(content)

        assert is_valid is False
        assert "empty required evidence fields" in error
        assert "evidence" in error

    def test_empty_cwe_id_fails_validation(self, valid_pr_vuln):
        """Empty cwe_id should fail validation."""
        valid_pr_vuln["cwe_id"] = ""
        content = json.dumps([valid_pr_vuln])

        is_valid, error = validate_pr_vulnerabilities_json(content)

        assert is_valid is False
        assert "empty required evidence fields" in error
        assert "cwe_id" in error

    def test_zero_line_number_fails_validation(self, valid_pr_vuln):
        """line_number must be a positive integer."""
        valid_pr_vuln["line_number"] = 0
        content = json.dumps([valid_pr_vuln])

        is_valid, error = validate_pr_vulnerabilities_json(content)

        assert is_valid is False
        assert "invalid line_number" in error
        assert "must be >= 1" in error

    def test_whitespace_only_evidence_fails_validation(self, valid_pr_vuln):
        """Whitespace-only evidence should fail validation."""
        valid_pr_vuln["evidence"] = "   \n\t  "
        content = json.dumps([valid_pr_vuln])

        is_valid, error = validate_pr_vulnerabilities_json(content)

        assert is_valid is False
        assert "empty required evidence fields" in error
        assert "evidence" in error

    def test_valid_pr_vuln_still_passes(self, valid_pr_vuln):
        """A fully populated valid PR vulnerability should still pass."""
        content = json.dumps([valid_pr_vuln])

        is_valid, error = validate_pr_vulnerabilities_json(content)

        assert is_valid is True
        assert error is None


class TestNormalizePrVulnerability:
    """Tests for normalize_pr_vulnerability() helper."""

    def test_normalizes_common_field_variations(self):
        vuln = {
            "id": "NEW-001",
            "title": "Gateway URL injection",
            "description": "Test description",
            "severity": "high",
            "file_path": "ui/app.ts",
            "line_numbers": [10, 11],
            "code_snippet": "const gatewayUrl = params.get('gatewayUrl')",
            "attack_scenario": "Attacker controls gatewayUrl",
            "evidence": "Token sent to attacker",
            "vulnerability_types": ["CWE-918: SSRF"],
            "recommendation": "Validate URL input",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["threat_id"] == "NEW-001"
        assert normalized["finding_type"] == "unknown"
        assert normalized["line_number"] == 10
        assert normalized["cwe_id"] == "CWE-918"
        assert isinstance(normalized["evidence"], str)
        assert "line_numbers" in normalized["evidence"]

    def test_derive_pr_finding_id_is_stable(self):
        vuln = {
            "title": "Issue",
            "file_path": "src/app.py",
            "line_number": 42,
        }

        first = derive_pr_finding_id(vuln)
        second = derive_pr_finding_id(vuln)

        assert first == second
        assert first.startswith("PR-")

    def test_extract_cwe_id_supports_string_and_dict_entries(self):
        vuln = {
            "vulnerability_types": [
                {"id": "CWE-79"},
                {"name": "CWE-89: SQL Injection"},
                "CWE-20: Improper Input Validation",
            ]
        }

        assert extract_cwe_id(vuln) == "CWE-79"

    def test_maps_location_file_to_file_path(self):
        """location.file → file_path, location.line → line_number."""
        vuln = {
            "title": "Broken access control",
            "description": "Missing auth check",
            "severity": "high",
            "location": {"file": "src/app.ts", "line": 42},
            "code_snippet": "if (user) {",
            "attack_scenario": "Bypass auth",
            "evidence": "No middleware",
            "cwe_id": "CWE-862",
            "recommendation": "Add auth middleware",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["file_path"] == "src/app.ts"
        assert normalized["line_number"] == 42

    def test_maps_cwe_to_cwe_id(self):
        """cwe field → cwe_id when cwe_id is absent."""
        vuln = {
            "title": "SSRF",
            "description": "Server-side request forgery",
            "severity": "high",
            "file_path": "api/fetch.ts",
            "line_number": 10,
            "code_snippet": "fetch(url)",
            "attack_scenario": "Attacker controls URL",
            "evidence": "Unvalidated URL",
            "cwe": "CWE-862",
            "recommendation": "Validate URLs",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["cwe_id"] == "CWE-862"

    def test_maps_bare_cwe_number_to_cwe_id(self):
        """Bare numeric cwe '862' → 'CWE-862'."""
        vuln = {
            "title": "Missing auth",
            "description": "No authorization check",
            "severity": "high",
            "file_path": "api/route.ts",
            "line_number": 5,
            "code_snippet": "app.get('/admin')",
            "attack_scenario": "Direct access",
            "evidence": "No auth middleware",
            "cwe": "862",
            "recommendation": "Add auth",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["cwe_id"] == "CWE-862"

    def test_location_does_not_override_explicit_file_path(self):
        """Explicit file_path should not be overwritten by location.file."""
        vuln = {
            "title": "XSS",
            "description": "Cross-site scripting",
            "severity": "medium",
            "file_path": "explicit/path.ts",
            "line_number": 7,
            "location": {"file": "other/path.ts", "line": 99},
            "code_snippet": "innerHTML = data",
            "attack_scenario": "Script injection",
            "evidence": "Unescaped output",
            "cwe_id": "CWE-79",
            "recommendation": "Escape output",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["file_path"] == "explicit/path.ts"
        assert normalized["line_number"] == 7

    def test_location_line_non_numeric_is_ignored(self):
        """Non-numeric location.line should be silently ignored."""
        vuln = {
            "title": "Issue",
            "description": "Test",
            "severity": "low",
            "location": {"file": "x.ts", "line": "abc"},
            "code_snippet": "code",
            "attack_scenario": "scenario",
            "evidence": "evidence",
            "cwe_id": "CWE-1",
            "recommendation": "fix",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["file_path"] == "x.ts"
        assert normalized["line_number"] == 0

    def test_maps_location_string_path_and_range_to_file_path_and_line_number(self):
        """location='path:start-end' should map file_path and first line."""
        vuln = {
            "title": "Issue",
            "description": "Test",
            "severity": "high",
            "location": "src/gateway/server-methods/config.ts:111-208",
            "code_snippet": "code",
            "attack_scenario": "scenario",
            "evidence": "evidence",
            "cwe_id": "CWE-269",
            "recommendation": "fix",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["file_path"] == "src/gateway/server-methods/config.ts"
        assert normalized["line_number"] == 111

    def test_maps_location_string_path_and_single_line(self):
        """location='path:line' should map file_path and line."""
        vuln = {
            "title": "Issue",
            "description": "Test",
            "severity": "high",
            "location": "src/infra/update-runner.ts:145",
            "code_snippet": "code",
            "attack_scenario": "scenario",
            "evidence": "evidence",
            "cwe_id": "CWE-78",
            "recommendation": "fix",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["file_path"] == "src/infra/update-runner.ts"
        assert normalized["line_number"] == 145

    def test_maps_location_string_with_multiple_segments_uses_first(self):
        """location with commas should use first segment for path/line extraction."""
        vuln = {
            "title": "Issue",
            "description": "Test",
            "severity": "medium",
            "location": "src/a.ts:16-119, src/b.ts",
            "code_snippet": "code",
            "attack_scenario": "scenario",
            "evidence": "evidence",
            "cwe_id": "CWE-200",
            "recommendation": "fix",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["file_path"] == "src/a.ts"
        assert normalized["line_number"] == 16

    def test_maps_location_string_path_only_to_file_path(self):
        """location='path' should set file_path but keep unresolved line_number."""
        vuln = {
            "title": "Issue",
            "description": "Test",
            "severity": "low",
            "location": "src/only-path.ts",
            "code_snippet": "code",
            "attack_scenario": "scenario",
            "evidence": "evidence",
            "cwe_id": "CWE-770",
            "recommendation": "fix",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["file_path"] == "src/only-path.ts"
        assert normalized["line_number"] == 0

    def test_maps_file_alias_to_file_path(self):
        """Top-level file alias should map to file_path when absent."""
        vuln = {
            "title": "Issue",
            "description": "Test",
            "severity": "high",
            "file": "src/alias.ts",
            "code_snippet": "code",
            "attack_scenario": "scenario",
            "evidence": "evidence",
            "cwe_id": "CWE-79",
            "recommendation": "fix",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["file_path"] == "src/alias.ts"

    def test_maps_line_alias_numeric_string_to_line_number(self):
        """Top-level line alias as numeric string should map to line_number."""
        vuln = {
            "title": "Issue",
            "description": "Test",
            "severity": "high",
            "line": "42",
            "code_snippet": "code",
            "attack_scenario": "scenario",
            "evidence": "evidence",
            "cwe_id": "CWE-79",
            "recommendation": "fix",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["line_number"] == 42

    def test_maps_line_alias_range_to_start_line(self):
        """Top-level line alias as range should map to first line."""
        vuln = {
            "title": "Issue",
            "description": "Test",
            "severity": "high",
            "line": "42-80",
            "code_snippet": "code",
            "attack_scenario": "scenario",
            "evidence": "evidence",
            "cwe_id": "CWE-79",
            "recommendation": "fix",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["line_number"] == 42

    def test_file_alias_does_not_override_explicit_file_path(self):
        """file alias should not override explicit file_path."""
        vuln = {
            "title": "Issue",
            "description": "Test",
            "severity": "high",
            "file_path": "src/explicit.ts",
            "file": "src/alias.ts",
            "line_number": 7,
            "code_snippet": "code",
            "attack_scenario": "scenario",
            "evidence": "evidence",
            "cwe_id": "CWE-79",
            "recommendation": "fix",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["file_path"] == "src/explicit.ts"
        assert normalized["line_number"] == 7

    def test_line_alias_non_numeric_ignored_when_no_other_line(self):
        """Non-numeric top-level line alias should be ignored."""
        vuln = {
            "title": "Issue",
            "description": "Test",
            "severity": "high",
            "line": "abc",
            "code_snippet": "code",
            "attack_scenario": "scenario",
            "evidence": "evidence",
            "cwe_id": "CWE-79",
            "recommendation": "fix",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["line_number"] == 0

    def test_line_alias_used_when_location_missing(self):
        """line alias should populate line_number when location is missing."""
        vuln = {
            "title": "Issue",
            "description": "Test",
            "severity": "high",
            "file": "src/alias.ts",
            "line": "145-217",
            "code_snippet": "code",
            "attack_scenario": "scenario",
            "evidence": "evidence",
            "cwe_id": "CWE-78",
            "recommendation": "fix",
        }

        normalized = normalize_pr_vulnerability(vuln)

        assert normalized["file_path"] == "src/alias.ts"
        assert normalized["line_number"] == 145
