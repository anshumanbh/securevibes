#!/usr/bin/env python3
"""
Reference example: IDOR validation pattern

This file is provided as a reference implementation to illustrate
how an IDOR test might be structured (requests, classification,
and redaction). It is NOT intended to run verbatim across apps.
Adapt to the specific application's auth, endpoints, and payloads.
"""
import argparse
import json
import hashlib
import requests
from typing import Dict, Any, Optional

# 8KB response body limit (reasonable for MVP)
MAX_RESPONSE_SIZE = 8 * 1024

def redact_sensitive_fields(data: Any) -> Any:
    """Redact sensitive fields from response data"""
    sensitive_keys = [
        'ssn', 'social_security_number', 'password', 'passwd',
        'credit_card', 'card_number', 'cvv', 'api_key', 'secret',
        'private_key', 'token', 'access_token', 'refresh_token'
    ]
    
    if isinstance(data, dict):
        redacted = {}
        for key, value in data.items():
            if any(s in key.lower() for s in sensitive_keys):
                redacted[key] = "[REDACTED]"
            elif isinstance(value, (dict, list)):
                redacted[key] = redact_sensitive_fields(value)
            else:
                redacted[key] = value
        return redacted
    elif isinstance(data, list):
        return [redact_sensitive_fields(item) for item in data]
    return data

def truncate_and_hash(response_text: str) -> tuple:
    """Truncate response to MAX_RESPONSE_SIZE and compute hash"""
    full_hash = hashlib.sha256(response_text.encode()).hexdigest()
    truncated = response_text[:MAX_RESPONSE_SIZE]
    
    metadata = {
        "truncated": len(response_text) > MAX_RESPONSE_SIZE,
        "original_size_bytes": len(response_text)
    }
    
    if len(response_text) > MAX_RESPONSE_SIZE:
        truncated += f"\n... [truncated {len(response_text) - MAX_RESPONSE_SIZE} bytes]"
    
    return truncated, f"sha256:{full_hash}", metadata

def test_idor(
    endpoint: str,
    method: str,
    user1_token: str,
    user1_id: str,
    user2_id: str,
    timeout: int = 30
) -> Dict[str, Any]:
    """
    Execute IDOR test
    
    Returns:
        {
            "status": "VALIDATED|FALSE_POSITIVE|UNVALIDATED",
            "baseline": {...},
            "test": {...},
            "evidence": "..."
        }
    """
    headers = {"Authorization": f"Bearer {user1_token}"}
    
    # Baseline: authorized access
    baseline_url = endpoint.replace("{id}", user1_id)
    try:
        baseline_response = requests.request(
            method, baseline_url, headers=headers, timeout=timeout
        )
        
        # Parse response
        baseline_text = baseline_response.text
        baseline_snippet, baseline_hash, baseline_meta = truncate_and_hash(baseline_text)
        
        # Try to parse as JSON for better redaction
        try:
            baseline_json = baseline_response.json()
            baseline_redacted = redact_sensitive_fields(baseline_json)
            baseline_snippet = json.dumps(baseline_redacted)[:200]
        except:
            # Not JSON, redact what we can
            baseline_snippet = baseline_snippet[:200]
        
        baseline = {
            "url": baseline_url,
            "method": method,
            "status": baseline_response.status_code,
            "response_snippet": baseline_snippet,
            "response_hash": baseline_hash,
            **baseline_meta
        }
    except requests.RequestException as e:
        return {
            "status": "UNVALIDATED",
            "reason": f"Baseline request failed: {str(e)}",
            "evidence": None
        }
    
    # Test: unauthorized access
    test_url = endpoint.replace("{id}", user2_id)
    try:
        test_response = requests.request(
            method, test_url, headers=headers, timeout=timeout
        )
        
        # Parse response
        test_text = test_response.text
        test_snippet, test_hash, test_meta = truncate_and_hash(test_text)
        
        # Try to parse as JSON for better redaction
        try:
            test_json = test_response.json()
            test_redacted = redact_sensitive_fields(test_json)
            test_snippet = json.dumps(test_redacted)[:200]
        except:
            # Not JSON, redact what we can
            test_snippet = test_snippet[:200]
        
        test = {
            "url": test_url,
            "method": method,
            "status": test_response.status_code,
            "response_snippet": test_snippet,
            "response_hash": test_hash,
            **test_meta
        }
        
        # Classification
        if test_response.status_code == 200:
            status = "VALIDATED"
            evidence = f"User1 successfully accessed User2's resource at {test_url}"
        elif test_response.status_code in [401, 403]:
            status = "FALSE_POSITIVE"
            evidence = f"Access properly denied with {test_response.status_code}"
        else:
            status = "UNVALIDATED"
            evidence = f"Unexpected status {test_response.status_code}"
        
        return {
            "status": status,
            "baseline": baseline,
            "test": test,
            "evidence": evidence
        }
        
    except requests.RequestException as e:
        return {
            "status": "UNVALIDATED",
            "reason": f"Test request failed: {str(e)}",
            "baseline": baseline,
            "test": None,
            "evidence": None
        }

def main():
    parser = argparse.ArgumentParser(description="IDOR Validation Script")
    parser.add_argument("--endpoint", required=True, help="API endpoint with {id} placeholder")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("--user1-token", required=True, help="User1 auth token")
    parser.add_argument("--user1-id", required=True, help="User1 object ID")
    parser.add_argument("--user2-id", required=True, help="User2 object ID")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout (seconds)")
    parser.add_argument("--output", required=True, help="Output JSON file")
    
    args = parser.parse_args()
    
    result = test_idor(
        endpoint=args.endpoint,
        method=args.method,
        user1_token=args.user1_token,
        user1_id=args.user1_id,
        user2_id=args.user2_id,
        timeout=args.timeout
    )
    
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"IDOR test complete: {result['status']}")
    print(f"Evidence saved to {args.output}")
    
    return 0 if result['status'] != 'UNVALIDATED' else 1

if __name__ == "__main__":
    exit(main())
