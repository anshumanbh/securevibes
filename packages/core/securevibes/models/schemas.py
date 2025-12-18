"""JSON Schema definitions for structured output validation.

These schemas are used to:
1. Validate JSON output from agents before file writes
2. Auto-fix common schema violations (e.g., unwrap wrapper objects)
3. Provide schema definitions for Claude SDK's output_format option

The schemas are derived from the Pydantic models in scan_output.py.
"""

import json
from typing import Any, Dict, Optional, Tuple

# JSON Schema for a single vulnerability
VULNERABILITY_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "threat_id": {
            "type": "string",
            "description": "Reference to threat from THREAT_MODEL.json"
        },
        "title": {
            "type": "string",
            "description": "Clear vulnerability title"
        },
        "description": {
            "type": "string",
            "description": "What makes this exploitable"
        },
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "info"],
            "description": "Severity level"
        },
        "cwe_id": {
            "type": ["string", "null"],
            "description": "CWE identifier (e.g., CWE-89)"
        },
        "recommendation": {
            "type": ["string", "null"],
            "description": "How to fix it"
        },
        "file_path": {
            "type": ["string", "null"],
            "description": "Exact file path"
        },
        "line_number": {
            "oneOf": [
                {"type": "integer"},
                {"type": "array", "items": {"type": "integer"}},
                {"type": "null"}
            ],
            "description": "Specific line number(s)"
        },
        "code_snippet": {
            "type": ["string", "null"],
            "description": "The actual vulnerable code"
        },
        "affected_files": {
            "type": ["array", "null"],
            "items": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "line_number": {
                        "oneOf": [
                            {"type": "integer"},
                            {"type": "array", "items": {"type": "integer"}},
                            {"type": "null"}
                        ]
                    },
                    "code_snippet": {"type": ["string", "null"]}
                },
                "required": ["file_path"]
            },
            "description": "List of all affected files/locations"
        },
        "evidence": {
            "oneOf": [
                {"type": "string"},
                {"type": "object"},
                {"type": "null"}
            ],
            "description": "Proof this is exploitable"
        }
    },
    "required": ["threat_id", "title", "description", "severity"],
    "additionalProperties": False
}

# JSON Schema for the vulnerabilities array (flat array format)
VULNERABILITIES_ARRAY_SCHEMA: Dict[str, Any] = {
    "type": "array",
    "items": VULNERABILITY_SCHEMA,
    "description": "Flat array of vulnerability objects - no wrapper"
}

# Common wrapper keys that agents mistakenly use
WRAPPER_KEYS = ["vulnerabilities", "issues", "results", "findings", "data"]


def fix_vulnerabilities_json(content: str) -> Tuple[str, bool]:
    """
    Fix common JSON format issues in vulnerability output.
    
    Handles:
    1. Wrapped arrays: {"vulnerabilities": [...]} -> [...]
    2. Nested wrappers: {"summary": {...}, "vulnerabilities": [...]} -> [...]
    3. Already correct flat arrays: [...] -> [...] (no change)
    
    Args:
        content: Raw JSON string from agent output
        
    Returns:
        Tuple of (fixed_content, was_modified)
    """
    if not content or not content.strip():
        return "[]", True
    
    content = content.strip()
    
    # Already a flat array - no fix needed
    if content.startswith("["):
        return content, False
    
    # Try to parse and unwrap
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        # Can't parse, return as-is
        return content, False
    
    # If it's already a list, serialize it back
    if isinstance(data, list):
        return json.dumps(data, indent=2), False
    
    # If it's a dict, try to find the array inside
    if isinstance(data, dict):
        # Try common wrapper keys
        for key in WRAPPER_KEYS:
            if key in data and isinstance(data[key], list):
                return json.dumps(data[key], indent=2), True
        
        # Try to find any array value
        for key, value in data.items():
            if isinstance(value, list):
                return json.dumps(value, indent=2), True
        
        # No array found - might be a single vulnerability
        # Check if it looks like a vulnerability object
        if "threat_id" in data or "title" in data:
            return json.dumps([data], indent=2), True
    
    # Couldn't fix, return as-is
    return content, False


def validate_vulnerabilities_json(content: str) -> Tuple[bool, Optional[str]]:
    """
    Validate that JSON content matches the vulnerabilities array schema.
    
    Args:
        content: JSON string to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not content or not content.strip():
        return False, "Empty content"
    
    content = content.strip()
    
    # Must start with [ for flat array
    if not content.startswith("["):
        return False, "Output must be a flat JSON array starting with '['"
    
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {e}"
    
    if not isinstance(data, list):
        return False, "Output must be a JSON array"
    
    # Validate each vulnerability
    required_fields = {"threat_id", "title", "description", "severity"}
    valid_severities = {"critical", "high", "medium", "low", "info"}
    
    for i, vuln in enumerate(data):
        if not isinstance(vuln, dict):
            return False, f"Item {i} is not an object"
        
        # Check required fields
        missing = required_fields - set(vuln.keys())
        if missing:
            return False, f"Item {i} missing required fields: {missing}"
        
        # Validate severity
        severity = vuln.get("severity", "").lower()
        if severity not in valid_severities:
            return False, f"Item {i} has invalid severity: {vuln.get('severity')}"
    
    return True, None


def get_output_format_config() -> Dict[str, Any]:
    """
    Get the output_format configuration for Claude SDK structured outputs.
    
    Use this with ClaudeAgentOptions:
        options = ClaudeAgentOptions(
            output_format=get_output_format_config()
        )
    
    Returns:
        Dict compatible with SDK output_format parameter
    """
    return {
        "type": "json_schema",
        "schema": VULNERABILITIES_ARRAY_SCHEMA
    }
