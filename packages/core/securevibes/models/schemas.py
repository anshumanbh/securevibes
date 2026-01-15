"""JSON Schema definitions for structured output validation.

These schemas are used to:
1. Validate JSON output from agents before file writes
2. Auto-fix common schema violations (e.g., unwrap wrapper objects)
3. Provide schema definitions for Claude SDK's output_format option

The schemas are derived from the Pydantic models in scan_output.py.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

# JSON Schema for a single vulnerability
VULNERABILITY_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "threat_id": {
            "type": "string",
            "description": "Reference to threat from THREAT_MODEL.json",
        },
        "title": {"type": "string", "description": "Clear vulnerability title"},
        "description": {"type": "string", "description": "What makes this exploitable"},
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "info"],
            "description": "Severity level",
        },
        "cwe_id": {"type": ["string", "null"], "description": "CWE identifier (e.g., CWE-89)"},
        "recommendation": {"type": ["string", "null"], "description": "How to fix it"},
        "file_path": {"type": ["string", "null"], "description": "Exact file path"},
        "line_number": {
            "oneOf": [
                {"type": "integer"},
                {"type": "array", "items": {"type": "integer"}},
                {"type": "null"},
            ],
            "description": "Specific line number(s)",
        },
        "code_snippet": {"type": ["string", "null"], "description": "The actual vulnerable code"},
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
                            {"type": "null"},
                        ]
                    },
                    "code_snippet": {"type": ["string", "null"]},
                },
                "required": ["file_path"],
            },
            "description": "List of all affected files/locations",
        },
        "evidence": {
            "oneOf": [{"type": "string"}, {"type": "object"}, {"type": "null"}],
            "description": "Proof this is exploitable",
        },
    },
    "required": ["threat_id", "title", "description", "severity"],
    "additionalProperties": False,
}

# JSON Schema for the vulnerabilities array (flat array format)
VULNERABILITIES_ARRAY_SCHEMA: Dict[str, Any] = {
    "type": "array",
    "items": VULNERABILITY_SCHEMA,
    "description": "Flat array of vulnerability objects - no wrapper",
}

# Common wrapper keys that agents mistakenly use
WRAPPER_KEYS = ["vulnerabilities", "issues", "results", "findings", "data"]


THREAT_MODEL_WRAPPER_KEYS = ["threats", "threat_model", *WRAPPER_KEYS]


ASI_THREAT_ID_RE = re.compile(r"^THREAT-ASI(?P<category>\d{2})-\d{3,}$", re.IGNORECASE)


def _strip_code_fences(content: str) -> str:
    content = content.strip()
    if not content.startswith("```"):
        return content

    lines = content.splitlines()
    if not lines:
        return ""

    # Drop opening fence (``` or ```json)
    lines = lines[1:]
    # Drop closing fence if present
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def extract_asi_category(threat_id: str) -> Optional[str]:
    """Extract ASI category (e.g., "ASI01") from a threat id."""

    match = ASI_THREAT_ID_RE.match((threat_id or "").strip())
    if not match:
        return None
    return f"ASI{match.group('category')}"


def fix_threat_model_json(content: str) -> Tuple[str, bool]:
    """Fix common JSON format issues in threat model output.

    Handles:
      1. Wrapped arrays: {"threats": [...]} -> [...]
      2. Code fences: ```json ... ``` -> ...

    Args:
        content: Raw JSON string from agent output.

    Returns:
        Tuple of (fixed_content, was_modified)
    """

    if not content or not content.strip():
        return "[]", True

    original = content
    content = _strip_code_fences(content)

    # Already a flat array
    if content.lstrip().startswith("["):
        return content.strip(), content.strip() != original.strip()

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return content, content != original

    if isinstance(data, list):
        return json.dumps(data, indent=2), True

    if isinstance(data, dict):
        for key in THREAT_MODEL_WRAPPER_KEYS:
            if key in data and isinstance(data[key], list):
                return json.dumps(data[key], indent=2), True

        for value in data.values():
            if isinstance(value, list):
                return json.dumps(value, indent=2), True

        # Single threat object -> wrap
        if "id" in data or "title" in data:
            return json.dumps([data], indent=2), True

    return content, content != original


def validate_threat_model_json(
    content: str,
    *,
    require_asi: bool = False,
    critical_asi_categories: Optional[set[str]] = None,
) -> Tuple[bool, Optional[str], List[str]]:
    """Validate that THREAT_MODEL.json is parseable and meets minimum requirements.

    Args:
        content: JSON string to validate.
        require_asi: If True, fail validation when there are zero ASI threats.
        critical_asi_categories: Optional set of critical ASI categories to warn on if missing.

    Returns:
        Tuple of (is_valid, error_message, warnings)
    """

    warnings: List[str] = []
    if not content or not content.strip():
        return False, "Empty content", warnings

    normalized = _strip_code_fences(content)
    try:
        data: Any = json.loads(normalized)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {e}", warnings

    # Accept wrapper objects (we'll validate the contained list)
    if isinstance(data, dict):
        unwrapped = None
        for key in THREAT_MODEL_WRAPPER_KEYS:
            if key in data and isinstance(data[key], list):
                unwrapped = data[key]
                break
        if unwrapped is None:
            return False, "Output must be a JSON array of threats", warnings
        data = unwrapped

    if not isinstance(data, list):
        return False, "Output must be a JSON array of threats", warnings

    if len(data) < 10:
        warnings.append(f"Only {len(data)} threats found (expected ~10-30)")

    required_fields = {"id", "category", "title", "description", "severity"}
    valid_severities = {"critical", "high", "medium", "low"}

    asi_categories: set[str] = set()
    asi_count = 0

    for i, threat in enumerate(data):
        if not isinstance(threat, dict):
            return False, f"Threat {i} is not an object", warnings

        missing = required_fields - set(threat.keys())
        if missing:
            return False, f"Threat {i} missing required fields: {missing}", warnings

        severity = str(threat.get("severity", "")).lower()
        if severity not in valid_severities:
            return False, f"Threat {i} has invalid severity: {threat.get('severity')}", warnings

        tid = str(threat.get("id", ""))
        category = extract_asi_category(tid)
        if category:
            asi_count += 1
            asi_categories.add(category)

    if require_asi and asi_count == 0:
        return False, "Agentic application requires ASI threats (none found)", warnings

    if require_asi:
        critical = critical_asi_categories or {"ASI01", "ASI03"}
        missing_critical = sorted(critical - asi_categories)
        if missing_critical:
            warnings.append(f"Missing critical ASI categories: {', '.join(missing_critical)}")

    return True, None, warnings


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
    return {"type": "json_schema", "schema": VULNERABILITIES_ARRAY_SCHEMA}
