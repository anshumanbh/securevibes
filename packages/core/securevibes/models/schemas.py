"""JSON Schema definitions for structured output validation.

These schemas are used to:
1. Validate JSON output from agents before file writes
2. Auto-fix common schema violations (e.g., unwrap wrapper objects)
3. Provide schema definitions for Claude SDK's output_format option

The schemas are derived from the Pydantic models in scan_output.py.
"""

import hashlib
import json
import logging
import re
from typing import Any, Dict, List, Mapping, Optional, Tuple

logger = logging.getLogger(__name__)

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
        "source": {
            "type": ["string", "null"],
            "description": "Origin of the entry (e.g. 'pr_review'). Internal metadata.",
        },
    },
    "required": [
        "threat_id",
        "title",
        "description",
        "severity",
        "file_path",
        "line_number",
        "code_snippet",
        "cwe_id",
        "recommendation",
        "evidence",
    ],
    "additionalProperties": False,
}

# JSON Schema for the vulnerabilities array (flat array format)
VULNERABILITIES_ARRAY_SCHEMA: Dict[str, Any] = {
    "type": "array",
    "items": VULNERABILITY_SCHEMA,
    "description": "Flat array of vulnerability objects - no wrapper",
}

# JSON Schema for PR review vulnerabilities
PR_VULNERABILITY_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "threat_id": {"type": "string"},
        "finding_type": {
            "type": "string",
            "enum": [
                "new_threat",
                "threat_enabler",
                "mitigation_removal",
                "known_vuln",
                "regression",
                "unknown",
            ],
        },
        "title": {"type": "string"},
        "description": {"type": "string"},
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low"],
        },
        "file_path": {"type": "string"},
        "line_number": {"type": "integer"},
        "code_snippet": {"type": "string"},
        "attack_scenario": {"type": "string"},
        "evidence": {"type": "string"},
        "cwe_id": {"type": "string"},
        "recommendation": {"type": "string"},
        "source": {
            "type": ["string", "null"],
            "description": "Origin of the entry (e.g. 'pr_review'). Internal metadata.",
        },
    },
    "required": [
        "threat_id",
        "finding_type",
        "title",
        "description",
        "severity",
        "file_path",
        "line_number",
        "code_snippet",
        "attack_scenario",
        "evidence",
        "cwe_id",
        "recommendation",
    ],
    "additionalProperties": False,
}

PR_VULNERABILITIES_ARRAY_SCHEMA: Dict[str, Any] = {
    "type": "array",
    "items": PR_VULNERABILITY_SCHEMA,
    "description": "Flat array of PR vulnerability objects - no wrapper",
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
        # Fail closed: empty agent output must not be normalized to "no threats found".
        return content, False

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


def _unwrap_json_array(content: str) -> Tuple[str, Any, bool]:
    """Shared unwrapping logic for vulnerability JSON output.

    Handles empty/whitespace input, code fences, flat arrays, wrapper dicts,
    and single-object wrapping.

    Args:
        content: Raw JSON string from agent output.

    Returns:
        Tuple of (stripped_content, parsed_data_or_None, was_modified).
        When parsed_data is None the caller should return stripped_content as-is.
    """
    if not content or not content.strip():
        return "[]", None, True

    original = content.strip()
    content = _strip_code_fences(content).strip()
    stripped_code_fences = content != original

    # Already a flat array - no fix needed
    if content.startswith("["):
        return content, None, stripped_code_fences

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return content, None, stripped_code_fences

    if isinstance(data, list):
        return json.dumps(data, indent=2), None, True

    if isinstance(data, dict):
        for key in WRAPPER_KEYS:
            if key in data and isinstance(data[key], list):
                return "", data[key], True

        for value in data.values():
            if isinstance(value, list):
                return "", value, True

        if "threat_id" in data or "title" in data:
            return "", [data], True

    return content, None, stripped_code_fences


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
    stripped, unwrapped, was_modified = _unwrap_json_array(content)
    if unwrapped is None:
        return stripped, was_modified
    return json.dumps(unwrapped, indent=2), True


def fix_pr_vulnerabilities_json(content: str) -> Tuple[str, bool]:
    """
    Fix common JSON format issues in PR vulnerability output.

    Handles:
    1. Wrapped arrays: {"vulnerabilities": [...]} -> [...]
    2. Nested wrappers: {"summary": {...}, "findings": [...]} -> [...]
    3. Already correct flat arrays: [...] -> [...] (no change)

    Args:
        content: Raw JSON string from agent output

    Returns:
        Tuple of (fixed_content, was_modified)
    """
    stripped, unwrapped, was_modified = _unwrap_json_array(content)

    if unwrapped is not None:
        normalized, normalized_modified = _normalize_pr_vulnerability_list(unwrapped)
        return json.dumps(normalized, indent=2), was_modified or normalized_modified

    # For flat arrays / already-parsed content, try to normalize in place.
    if not was_modified and stripped.lstrip().startswith("["):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return stripped, False
        if isinstance(data, list):
            normalized, normalized_modified = _normalize_pr_vulnerability_list(data)
            if normalized_modified:
                return json.dumps(normalized, indent=2), True

    return stripped, was_modified


def _normalize_pr_vulnerability_list(
    vulnerabilities: list[object],
) -> tuple[list[object], bool]:
    """Normalize PR vulnerability list items and report if any changes occurred."""
    normalized: list[object] = []
    modified = False
    for item in vulnerabilities:
        if isinstance(item, dict):
            normalized_item = normalize_pr_vulnerability(item)
            if normalized_item != item:
                modified = True
            normalized.append(normalized_item)
        else:
            normalized.append(item)
    return normalized, modified


def derive_pr_finding_id(vuln: Mapping[str, object]) -> str:
    """Derive a stable ID for a PR finding when threat_id is missing.

    Args:
        vuln: Raw vulnerability mapping.

    Returns:
        Stable PR finding identifier.
    """
    file_path = str(vuln.get("file_path", ""))
    title = str(vuln.get("title", ""))
    line_number = _extract_primary_line_number(vuln)
    raw_key = f"{file_path}|{title}|{line_number}"
    digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    return f"PR-{digest[:12]}"


def infer_finding_type(vuln: Mapping[str, object]) -> Optional[str]:
    """Infer finding_type from common alternative fields.

    Args:
        vuln: Raw vulnerability mapping.

    Returns:
        Inferred finding type or None.
    """
    candidate = vuln.get("category") or vuln.get("type") or vuln.get("finding_type")
    if not candidate:
        return None

    normalized = str(candidate).strip().lower().replace("-", "_").replace(" ", "_")
    mapping = {
        "new": "new_threat",
        "new_threat": "new_threat",
        "threat_enabler": "threat_enabler",
        "enabler": "threat_enabler",
        "mitigation_removal": "mitigation_removal",
        "mitigation": "mitigation_removal",
        "removal": "mitigation_removal",
        "known_vuln": "known_vuln",
        "known": "known_vuln",
        "regression": "regression",
        "unknown": "unknown",
    }

    return mapping.get(normalized)


def extract_cwe_id(vuln: Mapping[str, object]) -> Optional[str]:
    """Extract CWE ID from vulnerability_types if present.

    Args:
        vuln: Raw vulnerability mapping.

    Returns:
        CWE identifier (e.g., CWE-79) or None.
    """
    types_value = vuln.get("vulnerability_types")
    if not isinstance(types_value, list):
        return None

    for entry in types_value:
        if isinstance(entry, str):
            match = re.search(r"CWE-\d+", entry)
            if match:
                return match.group(0)
        elif isinstance(entry, dict):
            for key in ("id", "cwe_id", "cwe", "name", "title"):
                value = entry.get(key)
                if isinstance(value, str):
                    match = re.search(r"CWE-\d+", value)
                    if match:
                        return match.group(0)
    return None


def normalize_pr_vulnerability(vuln: Mapping[str, object]) -> Dict[str, object]:
    """Transform common PR schema variations into the expected format.

    Args:
        vuln: Raw vulnerability mapping from the agent.

    Returns:
        Normalized vulnerability dict.
    """
    normalized: Dict[str, object] = {}
    warnings: list[str] = []

    threat_id = vuln.get("threat_id") or vuln.get("id") or vuln.get("finding_id")
    if not threat_id:
        threat_id = derive_pr_finding_id(vuln)
        warnings.append("threat_id")
    normalized["threat_id"] = threat_id

    finding_type = vuln.get("finding_type")
    if not finding_type:
        finding_type = infer_finding_type(vuln) or "unknown"
        warnings.append("finding_type")
    normalized["finding_type"] = finding_type

    line_number = _extract_primary_line_number(vuln)
    if "line_number" not in vuln and "line_numbers" in vuln:
        warnings.append("line_number")
    normalized["line_number"] = line_number

    cwe_id = extract_cwe_id(vuln) or vuln.get("cwe_id", "")
    if "cwe_id" not in vuln and "vulnerability_types" in vuln:
        warnings.append("cwe_id")
    normalized["cwe_id"] = cwe_id

    for field in [
        "title",
        "description",
        "severity",
        "file_path",
        "code_snippet",
        "attack_scenario",
        "evidence",
    ]:
        normalized[field] = vuln.get(field, "")

    # Map location.file → file_path, location.line → line_number (if not already set)
    location = vuln.get("location")
    if isinstance(location, dict):
        if not str(normalized.get("file_path", "")).strip() and location.get("file"):
            normalized["file_path"] = str(location["file"])
            warnings.append("file_path")
        loc_line = location.get("line")
        if loc_line is not None and (
            not isinstance(normalized.get("line_number"), int) or normalized["line_number"] < 1
        ):
            try:
                parsed_line = int(loc_line)
                normalized["line_number"] = parsed_line
                warnings.append("line_number")
            except (TypeError, ValueError):
                pass  # leave line_number from _extract_primary_line_number

    # Map location string forms like:
    # - src/app.ts:42
    # - src/app.ts:111-208
    # - src/a.ts:16-119, src/b.ts
    if isinstance(location, str):
        parsed_path, parsed_line = _parse_location_string(location)
        if parsed_path and not str(normalized.get("file_path", "")).strip():
            normalized["file_path"] = parsed_path
            warnings.append("file_path")
        if parsed_line is not None and (
            not isinstance(normalized.get("line_number"), int) or normalized["line_number"] < 1
        ):
            normalized["line_number"] = parsed_line
            warnings.append("line_number")

    # Map top-level aliases file → file_path, line → line_number.
    file_alias = vuln.get("file")
    if file_alias and not str(normalized.get("file_path", "")).strip():
        normalized["file_path"] = str(file_alias).strip()
        warnings.append("file_path")

    line_alias = vuln.get("line")
    if line_alias is not None and (
        not isinstance(normalized.get("line_number"), int) or normalized["line_number"] < 1
    ):
        parsed_line_alias = _parse_line_value(line_alias)
        if parsed_line_alias is not None:
            normalized["line_number"] = parsed_line_alias
            warnings.append("line_number")

    # Map bare cwe → cwe_id (if extract_cwe_id and field copy didn't produce one)
    if not str(normalized.get("cwe_id", "")).strip() and vuln.get("cwe"):
        raw_cwe = str(vuln["cwe"]).strip()
        # Normalize bare numbers: "862" → "CWE-862"
        if re.fullmatch(r"\d+", raw_cwe):
            raw_cwe = f"CWE-{raw_cwe}"
        normalized["cwe_id"] = raw_cwe
        warnings.append("cwe_id")

    evidence_fields = ("file_path", "code_snippet", "evidence", "cwe_id")
    empty_evidence_fields = [
        field for field in evidence_fields if not str(normalized.get(field, "")).strip()
    ]
    if empty_evidence_fields:
        logger.warning(
            "Normalized PR vulnerability has empty evidence fields: %s",
            ", ".join(sorted(empty_evidence_fields)),
        )

    normalized_line_number = normalized.get("line_number")
    if not isinstance(normalized_line_number, int) or normalized_line_number < 1:
        logger.warning(
            "Normalized PR vulnerability has invalid line_number: %s",
            normalized_line_number,
        )

    normalized["recommendation"] = vuln.get("recommendation") or vuln.get("mitigation", "")

    evidence_text = _coerce_evidence_to_string(normalized.get("evidence"))
    line_numbers = _extract_line_numbers(vuln)
    if line_numbers:
        evidence_text = _append_line_numbers_to_evidence(evidence_text, line_numbers)
        warnings.append("evidence")
    normalized["evidence"] = evidence_text

    if warnings:
        logger.warning("Normalized PR vulnerability fields: %s", ", ".join(sorted(set(warnings))))

    return normalized


def _extract_primary_line_number(vuln: Mapping[str, object]) -> int:
    line_value = vuln.get("line_number")
    if line_value is not None:
        try:
            return int(line_value)
        except (TypeError, ValueError):
            return 0

    line_numbers = _extract_line_numbers(vuln)
    if line_numbers:
        return line_numbers[0]
    return 0


def _extract_line_numbers(vuln: Mapping[str, object]) -> list[int]:
    value = vuln.get("line_numbers")
    if not isinstance(value, list):
        return []
    line_numbers: list[int] = []
    for entry in value:
        try:
            line_numbers.append(int(entry))
        except (TypeError, ValueError):
            continue
    return line_numbers


def _parse_location_string(location: str) -> tuple[Optional[str], Optional[int]]:
    """Parse common location string variants into (file_path, line_number)."""
    raw = (location or "").strip()
    if not raw:
        return None, None

    first_segment = raw.split(",", 1)[0].strip()
    if not first_segment:
        return None, None

    # path:42 or path:111-208
    match = re.match(r"^(?P<path>.+?):(?P<line>\d+)(?:-\d+)?$", first_segment)
    if match:
        path = match.group("path").strip()
        line = int(match.group("line"))
        return (path or None), (line if line >= 1 else None)

    # path without line
    return first_segment, None


def _parse_line_value(value: object) -> Optional[int]:
    """Parse line value variants into a positive line number."""
    if isinstance(value, int):
        return value if value >= 1 else None

    raw = str(value).strip()
    if not raw:
        return None

    if raw.isdigit():
        parsed = int(raw)
        return parsed if parsed >= 1 else None

    # Range or mixed form like "42-80" or "42-80,90-100" -> first start line.
    match = re.search(r"\b(\d+)(?:-\d+)?\b", raw)
    if not match:
        return None

    parsed = int(match.group(1))
    return parsed if parsed >= 1 else None


def _coerce_evidence_to_string(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=True)
    except (TypeError, ValueError):
        return str(value)


def _append_line_numbers_to_evidence(evidence: str, line_numbers: list[int]) -> str:
    if not line_numbers:
        return evidence
    suffix = f"line_numbers: {line_numbers}"
    if evidence:
        if suffix in evidence:
            return evidence
        return f"{evidence}\n{suffix}"
    return suffix


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
    required_fields = set(VULNERABILITY_SCHEMA["required"])
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


def validate_pr_vulnerabilities_json(content: str) -> Tuple[bool, Optional[str]]:
    """
    Validate that JSON content matches the PR vulnerabilities array schema.

    Args:
        content: JSON string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not content or not content.strip():
        return False, "Empty content"

    content = content.strip()

    if not content.startswith("["):
        return False, "Output must be a flat JSON array starting with '['"

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {e}"

    if not isinstance(data, list):
        return False, "Output must be a JSON array"

    required_fields = set(PR_VULNERABILITY_SCHEMA["required"])
    valid_severities = {"critical", "high", "medium", "low"}
    valid_finding_types = {
        "new_threat",
        "threat_enabler",
        "mitigation_removal",
        "known_vuln",
        "regression",
        "unknown",
    }

    for i, vuln in enumerate(data):
        if not isinstance(vuln, dict):
            return False, f"Item {i} is not an object"

        missing = required_fields - set(vuln.keys())
        if missing:
            return False, f"Item {i} missing required fields: {missing}"

        severity = str(vuln.get("severity", "")).lower()
        if severity not in valid_severities:
            return False, f"Item {i} has invalid severity: {vuln.get('severity')}"

        finding_type = str(vuln.get("finding_type", "")).lower()
        if finding_type not in valid_finding_types:
            return False, f"Item {i} has invalid finding_type: {vuln.get('finding_type')}"

        evidence_fields = {"file_path", "code_snippet", "evidence", "cwe_id"}
        empty_fields = [field for field in evidence_fields if not str(vuln.get(field, "")).strip()]
        if empty_fields:
            return (
                False,
                f"Item {i} has empty required evidence fields: {', '.join(sorted(empty_fields))}",
            )

        line_number = vuln.get("line_number", 0)
        if not isinstance(line_number, int) or line_number < 1:
            return False, f"Item {i} has invalid line_number: {line_number} (must be >= 1)"

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
