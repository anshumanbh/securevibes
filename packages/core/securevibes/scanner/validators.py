"""Validation utilities for scan output files"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def validate_threat_model(file_path: Path) -> Tuple[bool, Optional[str], Optional[List[Dict]]]:
    """
    Validate THREAT_MODEL.json format
    
    Returns:
        (is_valid, error_message, threats_data)
    """
    if not file_path.exists():
        return False, "File does not exist", None
    
    try:
        with open(file_path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {e}", None
    
    if not isinstance(data, list):
        return False, "Expected JSON array at root level", None
    
    required_fields = {"id", "category", "title", "description", "severity"}
    
    for i, threat in enumerate(data):
        if not isinstance(threat, dict):
            return False, f"Threat {i} is not a JSON object", None
        
        missing_fields = required_fields - set(threat.keys())
        if missing_fields:
            return False, f"Threat {i} missing required fields: {missing_fields}", None
        
        # Validate STRIDE category
        valid_categories = {
            "Spoofing", "Tampering", "Repudiation", 
            "Information Disclosure", "Denial of Service", "Elevation of Privilege"
        }
        if threat.get("category") not in valid_categories:
            return False, f"Threat {i} has invalid category: {threat.get('category')}", None
        
        # Validate severity
        valid_severities = {"critical", "high", "medium", "low"}
        if threat.get("severity") not in valid_severities:
            return False, f"Threat {i} has invalid severity: {threat.get('severity')}", None
    
    return True, None, data


def validate_vulnerabilities(file_path: Path) -> Tuple[bool, Optional[str], Optional[List[Dict]]]:
    """
    Validate VULNERABILITIES.json format
    
    Returns:
        (is_valid, error_message, vulnerabilities_data)
    """
    if not file_path.exists():
        return False, "File does not exist", None
    
    try:
        with open(file_path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {e}", None
    
    if not isinstance(data, list):
        return False, "Expected JSON array at root level", None
    
    required_fields = {"title", "description", "severity", "file_path"}
    
    for i, vuln in enumerate(data):
        if not isinstance(vuln, dict):
            return False, f"Vulnerability {i} is not a JSON object", None
        
        missing_fields = required_fields - set(vuln.keys())
        if missing_fields:
            return False, f"Vulnerability {i} missing required fields: {missing_fields}", None
        
        # Check for either 'id' or 'threat_id'
        if 'id' not in vuln and 'threat_id' not in vuln:
            return False, f"Vulnerability {i} missing 'id' or 'threat_id' field", None
        
        # Validate severity
        valid_severities = {"critical", "high", "medium", "low"}
        if vuln.get("severity") not in valid_severities:
            return False, f"Vulnerability {i} has invalid severity: {vuln.get('severity')}", None
    
    return True, None, data


def validate_scan_results(file_path: Path) -> Tuple[bool, Optional[str], Optional[Dict]]:
    """
    Validate scan_results.json format
    
    Returns:
        (is_valid, error_message, results_data)
    """
    if not file_path.exists():
        return False, "File does not exist", None
    
    try:
        with open(file_path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {e}", None
    
    if not isinstance(data, dict):
        return False, "Expected JSON object at root level", None
    
    required_fields = {"repository_path", "summary", "issues"}
    missing_fields = required_fields - set(data.keys())
    if missing_fields:
        return False, f"Missing required fields: {missing_fields}", None
    
    # Validate summary
    if not isinstance(data.get("summary"), dict):
        return False, "'summary' must be an object", None
    
    # Validate issues
    if not isinstance(data.get("issues"), list):
        return False, "'issues' must be an array", None
    
    return True, None, data


def validate_security_md(file_path: Path) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validate SECURITY.md format
    
    Returns:
        (is_valid, error_message, content)
    """
    if not file_path.exists():
        return False, "File does not exist", None
    
    try:
        content = file_path.read_text()
    except Exception as e:
        return False, f"Error reading file: {e}", None
    
    if not content.strip():
        return False, "File is empty", None
    
    # Basic validation: should have markdown structure
    if not content.startswith("#"):
        return False, "Should start with markdown header", None
    
    # Check for key sections
    required_sections = ["overview", "technology", "component"]
    content_lower = content.lower()
    
    missing_sections = [s for s in required_sections if s not in content_lower]
    if missing_sections:
        return False, f"Missing recommended sections: {missing_sections}", content
    
    return True, None, content
