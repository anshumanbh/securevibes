#!/usr/bin/env python3
"""
Reference example: Non-SQL injection validation pattern.

These helpers illustrate payloads, detection, and classification for command
injection, reflected XSS, and SSTI. Adapt to the target application's
endpoints, parameters, and context before use.
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

MAX_RESPONSE_SIZE = 8 * 1024

CMD_ERROR_PATTERNS = [
    r"sh: .+: not found",
    r"command not found",
    r"is not recognized as an internal or external command",
    r"/bin/sh:",
    r"syntax error near unexpected token",
]


def redact_sensitive_fields(data: Any) -> Any:
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
    if isinstance(data, list):
        return [redact_sensitive_fields(item) for item in data]
    return data


def truncate_and_hash(response_text: str) -> tuple:
    full_hash = hashlib.sha256(response_text.encode()).hexdigest()
    truncated = response_text[:MAX_RESPONSE_SIZE]
    metadata = {
        "truncated": len(response_text) > MAX_RESPONSE_SIZE,
        "original_size_bytes": len(response_text),
    }
    return truncated, f"sha256:{full_hash}", metadata


def has_cmd_errors(content: str) -> bool:
    for pattern in CMD_ERROR_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False


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
    payloads = [
        f"{original_value}; sleep 5",
        f"{original_value}| sleep 5",
        f"{original_value}& sleep 5",
        f"{original_value}`sleep 5`",
        f"{original_value}$(sleep 5)",
    ]

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

    for payload in payloads:
        try:
            test_start = time.time()
            test_url = f"{url}?{param}={quote(payload)}"
            test_resp = requests.get(test_url, headers=headers, timeout=timeout + 10)
            test_time = time.time() - test_start
        except requests.Timeout:
            test_time = timeout + 10
            test_resp = None
        except requests.RequestException:
            continue

        delay = test_time - baseline_time
        output_indicator = has_cmd_errors(test_resp.text) if test_resp else False

        if delay >= delay_threshold or output_indicator:
            test_snippet, test_hash, test_meta = truncate_and_hash(test_resp.text if test_resp else "")
            return {
                "status": "VALIDATED",
                "injection_type": "os_command_injection",
                "cwe": "CWE-78",
                "baseline": baseline,
                "test": {
                    "url": test_url,
                    "method": "GET",
                    "status": test_resp.status_code if test_resp else None,
                    "response_time_seconds": round(test_time, 3),
                    "response_snippet": test_snippet[:500],
                    "response_hash": test_hash,
                    **test_meta,
                },
                "evidence": "Command injection indicators (delay or command output)",
                "payload_used": payload,
            }

    return {
        "status": "FALSE_POSITIVE",
        "injection_type": "os_command_injection",
        "baseline": baseline,
        "evidence": "No significant time delay or command output detected",
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
        default="cmdi,xss,ssti",
        help="Comma-separated injection types",
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
