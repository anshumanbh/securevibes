"""Pydantic models for parsing and validating scan output JSON."""

from typing import List, Optional, Union, Dict, Any
from pydantic import BaseModel, Field, field_validator, model_validator

from securevibes.models.issue import Severity
from securevibes.models.schemas import VULNERABILITIES_ARRAY_SCHEMA, get_output_format_config

class AffectedFile(BaseModel):
    file_path: str = Field(..., description="Path to the affected file")
    line_number: Optional[Union[int, List[int], str]] = Field(None, description="Line number(s) where the issue occurs")
    code_snippet: Optional[str] = Field(None, description="Relevant code snippet")

    @model_validator(mode='before')
    @classmethod
    def alias_path(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Handle 'path' vs 'file_path'
            if 'path' in data and 'file_path' not in data:
                data['file_path'] = data['path']
            # Handle 'line_numbers' vs 'line_number'
            if 'line_numbers' in data and 'line_number' not in data:
                data['line_number'] = data['line_numbers']
        return data

class Vulnerability(BaseModel):
    threat_id: str = Field(..., description="ID of the threat from the threat model")
    title: str = Field(..., description="Title of the vulnerability")
    description: str = Field(..., description="Detailed description of the vulnerability")
    severity: Severity = Field(..., description="Severity level of the vulnerability")
    cwe_id: Optional[str] = Field(None, description="CWE Identifier (e.g., CWE-89)")
    recommendation: Optional[str] = Field(None, description="Remediation steps")
    
    # Direct location fields (primary location)
    file_path: Optional[str] = Field(None, description="Primary file path")
    line_number: Optional[Union[int, List[int], str]] = Field(None, description="Primary line number(s)")
    code_snippet: Optional[str] = Field(None, description="Primary code snippet")
    
    # Complex location fields
    affected_files: Optional[List[AffectedFile]] = Field(None, description="List of all affected files/locations")
    
    # Evidence / PoC
    evidence: Optional[Union[str, Dict[str, Any]]] = Field(None, description="Proof of concept or evidence")

    @field_validator('line_number')
    @classmethod
    def validate_line_number(cls, v):
        if isinstance(v, list) and len(v) > 0:
            return v[0] # Take first line if list
        return v

    @model_validator(mode='before')
    @classmethod
    def normalize_input(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # 1. Normalize ID
            if 'threat_id' not in data:
                data['threat_id'] = data.get('id', 'UNKNOWN-ID')
            
            # 2. Extract primary location from vulnerable_code (scan_results2.json)
            if 'vulnerable_code' in data and isinstance(data['vulnerable_code'], dict):
                vc = data['vulnerable_code']
                if 'file_path' not in data:
                    data['file_path'] = vc.get('file')
                if 'line_number' not in data:
                    data['line_number'] = vc.get('line_numbers') or vc.get('line_no')
                if 'code_snippet' not in data:
                    data['code_snippet'] = vc.get('code_snippet') or vc.get('code')

            # 3. Handle affected_files being list of strings
            if 'affected_files' in data and isinstance(data['affected_files'], list):
                if data['affected_files'] and isinstance(data['affected_files'][0], str):
                    # Convert list of strings to list of AffectedFile objects
                    data['affected_files'] = [{'file_path': p} for p in data['affected_files']]

            # 4. Map 'remediation' to 'recommendation' if missing
            if 'recommendation' not in data and 'remediation' in data:
                val = data['remediation']
                if isinstance(val, dict): # scan_results2.json has object
                    data['recommendation'] = val.get('recommendation')
                elif isinstance(val, str):
                    data['recommendation'] = val

            # 5. Map DAST/Legacy 'proof_of_concept' to 'evidence'
            if 'evidence' not in data and 'proof_of_concept' in data:
                data['evidence'] = data['proof_of_concept']

        return data

class ScanOutput(BaseModel):
    vulnerabilities: List[Vulnerability] = Field(default_factory=list, description="List of identified vulnerabilities")

    # Helper validator to handle flat list input (common in current output) by wrapping it
    @classmethod
    def validate_input(cls, data: Any) -> 'ScanOutput':
        if isinstance(data, list):
            return cls(vulnerabilities=[Vulnerability(**item) for item in data])
        elif isinstance(data, dict):
            # Check if it's wrapped in 'vulnerabilities' or 'issues'
            if 'vulnerabilities' in data:
                return cls(vulnerabilities=[Vulnerability(**item) for item in data['vulnerabilities']])
            elif 'issues' in data:
                return cls(vulnerabilities=[Vulnerability(**item) for item in data['issues']])
            return cls(**data)
        raise ValueError("Invalid input format for ScanOutput")

    @classmethod
    def get_json_schema(cls) -> Dict[str, Any]:
        """
        Get the JSON schema for vulnerabilities output.
        
        This schema is used for:
        1. Claude SDK structured outputs (output_format option)
        2. Validation hooks to enforce schema compliance
        3. Documentation of expected output format
        
        Returns:
            JSON Schema dict for flat vulnerabilities array
        """
        return VULNERABILITIES_ARRAY_SCHEMA

    @classmethod
    def get_output_format(cls) -> Dict[str, Any]:
        """
        Get the output_format configuration for Claude SDK structured outputs.
        
        Use this with ClaudeAgentOptions for guaranteed schema compliance:
        
            from securevibes.models.scan_output import ScanOutput
            
            options = ClaudeAgentOptions(
                output_format=ScanOutput.get_output_format()
            )
        
        Returns:
            Dict compatible with SDK output_format parameter
        """
        return get_output_format_config()
