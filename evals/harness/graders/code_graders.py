"""Code-based graders for deterministic evaluation.

These graders are fast, cheap, and reproducible. They check
concrete properties of the scan output.

Reference: https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents
"""

import json
import re
from pathlib import Path
from typing import Optional

import jsonschema

from harness.graders.base import Grader, GradeResult


class ArtifactExistsGrader(Grader):
    """Check that expected output files exist."""
    
    @property
    def grader_type(self) -> str:
        return "artifact_exists"
    
    async def grade(
        self,
        task: dict,
        scan_dir: Path,
        config: dict,
        schemas_dir: Optional[Path] = None,
    ) -> GradeResult:
        """Check that all specified files exist.
        
        Config:
            files: List of file paths relative to scan_dir parent
        """
        files = config.get("files", [])
        repo_dir = scan_dir.parent
        
        missing = []
        for file_path in files:
            full_path = repo_dir / file_path
            if not full_path.exists():
                missing.append(file_path)
        
        passed = len(missing) == 0
        
        return GradeResult(
            grader_type=self.grader_type,
            passed=passed,
            details={
                "expected": files,
                "missing": missing,
            },
            error=f"Missing files: {missing}" if missing else None,
        )


class JsonSchemaGrader(Grader):
    """Validate JSON output against a schema."""
    
    @property
    def grader_type(self) -> str:
        return "json_schema"
    
    async def grade(
        self,
        task: dict,
        scan_dir: Path,
        config: dict,
        schemas_dir: Optional[Path] = None,
    ) -> GradeResult:
        """Validate JSON file against schema.
        
        Config:
            file: Path to JSON file (relative to scan_dir parent)
            schema: Path to schema file (relative to schemas_dir)
        """
        file_path = config.get("file")
        schema_path = config.get("schema")
        
        if not file_path or not schema_path:
            return GradeResult(
                grader_type=self.grader_type,
                passed=False,
                error="Missing 'file' or 'schema' in config",
            )
        
        repo_dir = scan_dir.parent
        full_file_path = repo_dir / file_path
        
        if not full_file_path.exists():
            return GradeResult(
                grader_type=self.grader_type,
                passed=False,
                error=f"File not found: {file_path}",
            )
        
        # Load JSON
        try:
            with open(full_file_path) as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            return GradeResult(
                grader_type=self.grader_type,
                passed=False,
                error=f"Invalid JSON: {e}",
            )
        
        # Load schema
        if schemas_dir:
            full_schema_path = schemas_dir / schema_path
        else:
            full_schema_path = Path(schema_path)
        
        if not full_schema_path.exists():
            return GradeResult(
                grader_type=self.grader_type,
                passed=False,
                error=f"Schema not found: {schema_path}",
            )
        
        try:
            with open(full_schema_path) as f:
                schema = json.load(f)
        except json.JSONDecodeError as e:
            return GradeResult(
                grader_type=self.grader_type,
                passed=False,
                error=f"Invalid schema JSON: {e}",
            )
        
        # Validate
        try:
            jsonschema.validate(data, schema)
            return GradeResult(
                grader_type=self.grader_type,
                passed=True,
                details={"file": file_path, "schema": schema_path},
            )
        except jsonschema.ValidationError as e:
            return GradeResult(
                grader_type=self.grader_type,
                passed=False,
                details={"validation_path": list(e.absolute_path)},
                error=f"Schema validation failed: {e.message}",
            )


class VulnerabilityMatchGrader(Grader):
    """Check that expected vulnerabilities are found."""
    
    @property
    def grader_type(self) -> str:
        return "vulnerability_match"
    
    async def grade(
        self,
        task: dict,
        scan_dir: Path,
        config: dict,
        schemas_dir: Optional[Path] = None,
    ) -> GradeResult:
        """Match vulnerabilities against expected criteria.
        
        Config:
            require_all: If true, all expected vulns must be found
            
        Task expected_outcome.vulnerabilities:
            - threat_id_pattern: Regex for threat ID
            - title_contains: List of strings that must appear in title
            - severity: List of acceptable severities
            - cwe_id: Expected CWE ID
            - file_path_contains: String that must appear in file path
            - has_code_snippet: Boolean
            - has_recommendation: Boolean
        """
        expected_vulns = task.get("expected_outcome", {}).get("vulnerabilities", [])
        require_all = config.get("require_all", True)
        
        # Load scan results
        results_file = scan_dir / "scan_results.json"
        if not results_file.exists():
            return GradeResult(
                grader_type=self.grader_type,
                passed=False,
                error="scan_results.json not found",
            )
        
        try:
            with open(results_file) as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            return GradeResult(
                grader_type=self.grader_type,
                passed=False,
                error=f"Invalid JSON: {e}",
            )
        
        found_vulns = data.get("vulnerabilities", data.get("issues", []))
        
        # Match each expected vulnerability
        matched = []
        unmatched = []
        
        for expected in expected_vulns:
            found = False
            
            for vuln in found_vulns:
                if self._matches(vuln, expected):
                    found = True
                    matched.append({
                        "expected": expected,
                        "actual": vuln.get("threat_id") or vuln.get("id"),
                    })
                    break
            
            if not found:
                unmatched.append(expected)
        
        if require_all:
            passed = len(unmatched) == 0
        else:
            passed = len(matched) > 0
        
        return GradeResult(
            grader_type=self.grader_type,
            passed=passed,
            score=len(matched) / len(expected_vulns) if expected_vulns else 1.0,
            details={
                "matched": matched,
                "unmatched": unmatched,
                "total_found": len(found_vulns),
            },
            error=f"Unmatched vulnerabilities: {unmatched}" if unmatched else None,
        )
    
    def _matches(self, vuln: dict, expected: dict) -> bool:
        """Check if a vulnerability matches expected criteria."""
        # Check threat_id pattern
        if "threat_id_pattern" in expected:
            threat_id = vuln.get("threat_id") or vuln.get("id", "")
            if not re.match(expected["threat_id_pattern"], threat_id):
                return False
        
        # Check title contains
        if "title_contains" in expected:
            title = vuln.get("title", "").lower()
            for term in expected["title_contains"]:
                if term.lower() not in title:
                    return False
        
        # Check severity
        if "severity" in expected:
            severity = vuln.get("severity", "").upper()
            if severity not in [s.upper() for s in expected["severity"]]:
                return False
        
        # Check CWE
        if "cwe_id" in expected:
            if vuln.get("cwe_id") != expected["cwe_id"]:
                return False
        
        # Check file path
        if "file_path_contains" in expected:
            file_path = vuln.get("file_path", "")
            if expected["file_path_contains"] not in file_path:
                return False
        
        # Check code snippet
        if expected.get("has_code_snippet"):
            if not vuln.get("code_snippet"):
                return False
        
        # Check recommendation
        if expected.get("has_recommendation"):
            if not vuln.get("recommendation"):
                return False
        
        return True


class NoFalsePositiveGrader(Grader):
    """Check that specific false positives are NOT reported."""
    
    @property
    def grader_type(self) -> str:
        return "no_false_positive"
    
    async def grade(
        self,
        task: dict,
        scan_dir: Path,
        config: dict,
        schemas_dir: Optional[Path] = None,
    ) -> GradeResult:
        """Verify that certain vulnerabilities are NOT reported.
        
        Config:
            cwe_ids: List of CWE IDs that should NOT appear
            files: List of file paths where vulns should NOT be found
        """
        cwe_ids = config.get("cwe_ids", [])
        files = config.get("files", [])
        
        # Load scan results
        results_file = scan_dir / "scan_results.json"
        if not results_file.exists():
            # No results = no false positives
            return GradeResult(
                grader_type=self.grader_type,
                passed=True,
                details={"reason": "No scan results found"},
            )
        
        try:
            with open(results_file) as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            return GradeResult(
                grader_type=self.grader_type,
                passed=False,
                error=f"Invalid JSON: {e}",
            )
        
        found_vulns = data.get("vulnerabilities", data.get("issues", []))
        
        # Check for false positives
        false_positives = []
        
        for vuln in found_vulns:
            vuln_cwe = vuln.get("cwe_id", "")
            vuln_file = vuln.get("file_path", "")
            
            # Check if this matches our false positive criteria
            cwe_match = vuln_cwe in cwe_ids if cwe_ids else True
            file_match = any(f in vuln_file for f in files) if files else True
            
            if cwe_match and file_match:
                false_positives.append({
                    "cwe_id": vuln_cwe,
                    "file_path": vuln_file,
                    "title": vuln.get("title"),
                })
        
        passed = len(false_positives) == 0
        
        return GradeResult(
            grader_type=self.grader_type,
            passed=passed,
            details={
                "false_positives": false_positives,
                "checked_cwes": cwe_ids,
                "checked_files": files,
            },
            error=f"False positives found: {false_positives}" if false_positives else None,
        )


class ToolCallsGrader(Grader):
    """Analyze tool calls in the scan transcript."""
    
    @property
    def grader_type(self) -> str:
        return "tool_calls"
    
    async def grade(
        self,
        task: dict,
        scan_dir: Path,
        config: dict,
        schemas_dir: Optional[Path] = None,
    ) -> GradeResult:
        """Check that required tools were called.
        
        Config:
            required:
              - tool: "Read"
                min_calls: 5
              - tool: "Grep"
                min_calls: 1
        
        Note: This requires transcript logging to be enabled.
        Currently returns a pass with a note about implementation.
        """
        # TODO: Implement transcript analysis once transcript
        # logging is added to the Scanner
        
        return GradeResult(
            grader_type=self.grader_type,
            passed=True,
            details={"note": "Transcript analysis not yet implemented"},
        )
