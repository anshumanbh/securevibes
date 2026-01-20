#!/usr/bin/env python3
"""
SQL injection validation helper (reference only).

Implements time-based, boolean-based, error-based, UNION, and stacked query checks.
Adapt endpoints/methods/payloads to the target application before use.
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

from sql_payloads import (
    get_boolean_payloads,
    get_error_payloads,
    get_stacked_payloads,
    get_time_payloads,
    get_union_payloads,
)

MAX_RESPONSE_SIZE = 8 * 1024

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


def truncate_and_hash(response_text: str) -> tuple:
    full_hash = hashlib.sha256(response_text.encode()).hexdigest()
    truncated = response_text[:MAX_RESPONSE_SIZE]
    metadata = {
        "truncated": len(response_text) > MAX_RESPONSE_SIZE,
        "original_size_bytes": len(response_text),
    }
    return truncated, f"sha256:{full_hash}", metadata


def has_sql_errors(content: str) -> bool:
    content_lower = content.lower()
    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, content_lower, re.IGNORECASE):
            return True
    return False


def baseline_request(
    url: str, param: str, value: str, headers: Optional[Dict], timeout: int
) -> Dict[str, Any]:
    baseline_url = f"{url}?{param}={quote(value)}"
    start = time.time()
    resp = requests.get(baseline_url, headers=headers, timeout=timeout)
    duration = time.time() - start
    snippet, resp_hash, meta = truncate_and_hash(resp.text)
    return {
        "url": baseline_url,
        "method": "GET",
        "status": resp.status_code,
        "response_time_seconds": round(duration, 3),
        "response_snippet": snippet[:500],
        "response_hash": resp_hash,
        **meta,
    }


def test_time_based(
    url: str, param: str, value: str, headers: Optional[Dict], timeout: int, db: str
) -> Dict[str, Any]:
    baseline = baseline_request(url, param, value, headers, timeout)
    payloads = get_time_payloads(db)

    for entry in payloads:
        payload = value + entry["payload"]
        test_url = f"{url}?{param}={quote(payload)}"
        try:
            start = time.time()
            resp = requests.get(test_url, headers=headers, timeout=timeout + 10)
            duration = time.time() - start
        except requests.Timeout:
            duration = timeout + 10
            resp = None
        except requests.RequestException as exc:
            return {"status": "UNVALIDATED", "reason": f"Request failed: {exc}"}

        delay = duration - baseline["response_time_seconds"]
        if delay >= entry.get("delay", 5) - 0.5:
            snippet, resp_hash, meta = truncate_and_hash(resp.text if resp else "")
            return {
                "status": "VALIDATED",
                "injection_type": "sql_injection_time_based",
                "cwe": "CWE-89",
                "baseline": baseline,
                "test": {
                    "url": test_url,
                    "status": resp.status_code if resp else None,
                    "response_time_seconds": round(duration, 3),
                    "response_snippet": snippet[:500],
                    "response_hash": resp_hash,
                    **meta,
                },
                "evidence": f"Time-based SQLi: {delay:.2f}s delay",
                "payload_used": payload,
            }

    return {
        "status": "FALSE_POSITIVE",
        "injection_type": "sql_injection_time_based",
        "baseline": baseline,
        "evidence": "No significant delay detected",
    }


def test_error_based(
    url: str, param: str, value: str, headers: Optional[Dict], timeout: int, db: str
) -> Dict[str, Any]:
    baseline = baseline_request(url, param, value, headers, timeout)
    for entry in get_error_payloads(db):
        payload = value + entry["payload"]
        test_url = f"{url}?{param}={quote(payload)}"
        try:
            resp = requests.get(test_url, headers=headers, timeout=timeout)
        except requests.RequestException:
            continue

        if has_sql_errors(resp.text):
            snippet, resp_hash, meta = truncate_and_hash(resp.text)
            return {
                "status": "VALIDATED",
                "injection_type": "sql_injection_error_based",
                "cwe": "CWE-89",
                "baseline": baseline,
                "test": {
                    "url": test_url,
                    "status": resp.status_code,
                    "response_snippet": snippet[:500],
                    "response_hash": resp_hash,
                    **meta,
                },
                "evidence": "Error-based SQLi: SQL parser error returned",
                "payload_used": payload,
            }

    return {
        "status": "FALSE_POSITIVE",
        "injection_type": "sql_injection_error_based",
        "baseline": baseline,
        "evidence": "No SQL error indicators detected",
    }


def test_boolean_based(
    url: str, param: str, value: str, headers: Optional[Dict], timeout: int
) -> Dict[str, Any]:
    baseline = baseline_request(url, param, value, headers, timeout)
    payload_pairs = get_boolean_payloads()

    for pair in payload_pairs:
        true_payload = value + pair["true_payload"]
        false_payload = value + pair["false_payload"]

        try:
            true_url = f"{url}?{param}={quote(true_payload)}"
            false_url = f"{url}?{param}={quote(false_payload)}"
            true_resp = requests.get(true_url, headers=headers, timeout=timeout)
            false_resp = requests.get(false_url, headers=headers, timeout=timeout)
        except requests.RequestException:
            continue

        len_true = len(true_resp.text)
        len_false = len(false_resp.text)
        len_diff = abs(len_true - len_false)

        if len_diff >= 50 or true_resp.status_code != false_resp.status_code:
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
                        "content_length": len_true,
                        "response_hash": true_hash,
                        **true_meta,
                    },
                    "false_condition": {
                        "url": false_url,
                        "status": false_resp.status_code,
                        "content_length": len_false,
                        "response_hash": false_hash,
                        **false_meta,
                    },
                },
                "evidence": f"Boolean-based SQLi: length delta {len_diff} bytes",
                "payload_used": pair,
            }

    return {
        "status": "FALSE_POSITIVE",
        "injection_type": "sql_injection_boolean_based",
        "baseline": baseline,
        "evidence": "No significant difference between true/false conditions",
    }


def test_union_based(
    url: str, param: str, value: str, headers: Optional[Dict], timeout: int
) -> Dict[str, Any]:
    baseline = baseline_request(url, param, value, headers, timeout)
    for entry in get_union_payloads():
        payload = value + entry["payload"]
        test_url = f"{url}?{param}={quote(payload)}"
        try:
            resp = requests.get(test_url, headers=headers, timeout=timeout)
        except requests.RequestException:
            continue

        # Heuristic: status code differs or body grows (UNION success)
        len_delta = len(resp.text) - len(baseline.get("response_snippet", ""))
        if resp.status_code == 200 and abs(len_delta) > 50:
            snippet, resp_hash, meta = truncate_and_hash(resp.text)
            return {
                "status": "VALIDATED",
                "injection_type": "sql_injection_union",
                "cwe": "CWE-89",
                "baseline": baseline,
                "test": {
                    "url": test_url,
                    "status": resp.status_code,
                    "response_snippet": snippet[:500],
                    "response_hash": resp_hash,
                    **meta,
                },
                "evidence": "UNION-based SQLi indicators (body size change)",
                "payload_used": payload,
            }

    return {
        "status": "FALSE_POSITIVE",
        "injection_type": "sql_injection_union",
        "baseline": baseline,
        "evidence": "No UNION indicators detected",
    }


def test_stacked(
    url: str, param: str, value: str, headers: Optional[Dict], timeout: int, db: str
) -> Dict[str, Any]:
    baseline = baseline_request(url, param, value, headers, timeout)
    for entry in get_stacked_payloads(db):
        payload = entry["payload"]
        test_url = f"{url}?{param}={quote(payload)}"
        try:
            start = time.time()
            resp = requests.get(test_url, headers=headers, timeout=timeout + 10)
            duration = time.time() - start
        except requests.Timeout:
            duration = timeout + 10
            resp = None
        except requests.RequestException:
            continue

        delay = duration - baseline["response_time_seconds"]
        if delay >= entry.get("delay", 5) - 0.5:
            snippet, resp_hash, meta = truncate_and_hash(resp.text if resp else "")
            return {
                "status": "VALIDATED",
                "injection_type": "sql_injection_stacked",
                "cwe": "CWE-89",
                "baseline": baseline,
                "test": {
                    "url": test_url,
                    "status": resp.status_code if resp else None,
                    "response_time_seconds": round(duration, 3),
                    "response_snippet": snippet[:500],
                    "response_hash": resp_hash,
                    **meta,
                },
                "evidence": "Stacked query delay detected",
                "payload_used": payload,
            }

    return {
        "status": "FALSE_POSITIVE",
        "injection_type": "sql_injection_stacked",
        "baseline": baseline,
        "evidence": "No stacked query indicators detected",
    }


def run_tests(
    url: str,
    param: str,
    value: str,
    injection_types: List[str],
    headers: Optional[Dict],
    timeout: int,
    db: str,
) -> Dict[str, Any]:
    tests = {
        "time": lambda: test_time_based(url, param, value, headers, timeout, db),
        "error": lambda: test_error_based(url, param, value, headers, timeout, db),
        "boolean": lambda: test_boolean_based(url, param, value, headers, timeout),
        "union": lambda: test_union_based(url, param, value, headers, timeout),
        "stacked": lambda: test_stacked(url, param, value, headers, timeout, db),
    }
    results = {}
    for name in injection_types:
        if name in tests:
            results[name] = tests[name]()
    return results


def parse_headers(header_args: Optional[List[str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if not header_args:
        return headers
    for h in header_args:
        if ":" not in h:
            continue
        key, value = h.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def main() -> int:
    parser = argparse.ArgumentParser(description="SQLi validation helper")
    parser.add_argument("--url", required=True, help="Target URL (without params)")
    parser.add_argument("--param", required=True, help="Parameter to test")
    parser.add_argument("--value", default="1", help="Baseline parameter value")
    parser.add_argument(
        "--types",
        default="time,error,boolean,union",
        help="Comma-separated injection types (time,error,boolean,union,stacked)",
    )
    parser.add_argument(
        "--db",
        default="generic",
        help="Database type (mysql, postgres, mssql, oracle, sqlite, generic)",
    )
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout seconds")
    parser.add_argument("--output", required=True, help="Output JSON file")
    parser.add_argument("--header", action="append", help="Headers (key:value)")

    args = parser.parse_args()
    headers = parse_headers(args.header)
    types = [t.strip() for t in args.types.split(",") if t.strip()]

    results = run_tests(
        url=args.url,
        param=args.param,
        value=args.value,
        injection_types=types,
        headers=headers if headers else None,
        timeout=args.timeout,
        db=args.db,
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
        print("No SQLi confirmed")

    print(f"Results saved to {output_path}")
    return 0 if not validated else 1


if __name__ == "__main__":
    raise SystemExit(main())
