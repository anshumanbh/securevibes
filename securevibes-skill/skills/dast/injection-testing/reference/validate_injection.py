"""
Miscellaneous injection validation script.

This module covers injection types NOT handled by dedicated skills:
- SQL Injection -> sql-injection-testing
- NoSQL Injection -> nosql-injection-testing
- XSS -> xss-testing
- XXE -> xxe-testing
- Command Injection -> command-injection-testing

CWE Coverage: CWE-1336, CWE-90, CWE-643, CWE-652, CWE-93, CWE-113,
              CWE-917, CWE-1333, CWE-1236, CWE-94, CWE-95
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin

# Type hints for requests (not imported to avoid dependency)


@dataclass
class InjectionTestResult:
    """Result of an injection test."""

    status: str  # VALIDATED, FALSE_POSITIVE, PARTIAL, UNVALIDATED
    injection_type: str
    cwe: str
    payload_used: str
    evidence: str
    test_details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "injection_type": self.injection_type,
            "cwe": self.cwe,
            "payload_used": self.payload_used,
            "evidence": self.evidence,
            "test": self.test_details,
        }


class InjectionValidator:
    """Validates miscellaneous injection vulnerabilities."""

    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        verify_ssl: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> tuple[int, str, dict, float]:
        """Make HTTP request. Implement with actual HTTP client."""
        raise NotImplementedError("Implement with HTTP client library")

    def _hash_response(self, content: str) -> str:
        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()[:16]}"

    def _truncate_snippet(self, content: str, max_len: int = 500) -> str:
        return content[:max_len] + "..." if len(content) > max_len else content

    def validate_ssti(
        self,
        endpoint: str,
        param: str,
        method: str = "GET",
    ) -> InjectionTestResult:
        """
        Validate Server-Side Template Injection.
        CWE-1336.
        """
        url = urljoin(self.base_url, endpoint)

        # Detection payloads by engine
        payloads = [
            ("{{7*7}}", "49", "jinja2/twig"),
            ("${7*7}", "49", "freemarker/thymeleaf"),
            ("#{7*7}", "49", "jsp_el"),
            ("<%= 7*7 %>", "49", "erb"),
            ("{7*7}", "49", "smarty"),
            ("{{7*'7'}}", "7777777", "jinja2"),
        ]

        for payload, expected, engine in payloads:
            try:
                if method.upper() == "GET":
                    params = {param: payload}
                    status_code, response_body, _, _ = self._make_request(
                        "GET", endpoint, params=params
                    )
                else:
                    data = {param: payload}
                    status_code, response_body, _, _ = self._make_request(
                        "POST", endpoint, data=data
                    )
            except Exception:
                continue

            if expected in response_body and payload not in response_body:
                return InjectionTestResult(
                    status="VALIDATED",
                    injection_type=f"ssti_{engine.split('/')[0]}",
                    cwe="CWE-1336",
                    payload_used=payload,
                    evidence=f"SSTI ({engine}): {payload} evaluated to {expected}",
                    test_details={
                        "url": url,
                        "param": param,
                        "engine": engine,
                        "response_snippet": self._truncate_snippet(response_body),
                    },
                )

        return InjectionTestResult(
            status="FALSE_POSITIVE",
            injection_type="ssti",
            cwe="CWE-1336",
            payload_used="multiple",
            evidence="No SSTI indicators - payloads rendered as literal text",
            test_details={"url": url, "param": param},
        )

    def validate_ldap(
        self,
        endpoint: str,
        param: str,
        method: str = "GET",
    ) -> InjectionTestResult:
        """
        Validate LDAP Injection.
        CWE-90.
        """
        url = urljoin(self.base_url, endpoint)

        # Get baseline with normal value
        try:
            if method.upper() == "GET":
                _, baseline_body, _, _ = self._make_request("GET", endpoint, params={param: "test"})
            else:
                _, baseline_body, _, _ = self._make_request("POST", endpoint, data={param: "test"})
            baseline_len = len(baseline_body)
        except Exception as e:
            return InjectionTestResult(
                status="UNVALIDATED",
                injection_type="ldap_injection",
                cwe="CWE-90",
                payload_used="",
                evidence=f"Baseline request failed: {str(e)}",
                test_details={"url": url, "error": str(e)},
            )

        # Test with wildcard
        try:
            if method.upper() == "GET":
                _, test_body, _, _ = self._make_request("GET", endpoint, params={param: "*"})
            else:
                _, test_body, _, _ = self._make_request("POST", endpoint, data={param: "*"})
            test_len = len(test_body)
        except Exception:
            return InjectionTestResult(
                status="UNVALIDATED",
                injection_type="ldap_injection",
                cwe="CWE-90",
                payload_used="*",
                evidence="Test request failed",
                test_details={"url": url},
            )

        # Check for significant content increase (wildcard returned more data)
        if test_len > baseline_len * 3:
            return InjectionTestResult(
                status="VALIDATED",
                injection_type="ldap_injection",
                cwe="CWE-90",
                payload_used="*",
                evidence=f"LDAP injection: wildcard returned {test_len} bytes vs {baseline_len}",
                test_details={
                    "url": url,
                    "param": param,
                    "baseline_length": baseline_len,
                    "test_length": test_len,
                },
            )

        return InjectionTestResult(
            status="FALSE_POSITIVE",
            injection_type="ldap_injection",
            cwe="CWE-90",
            payload_used="*",
            evidence="No LDAP injection indicators - wildcard treated as literal",
            test_details={"url": url, "param": param},
        )

    def validate_crlf(
        self,
        endpoint: str,
        param: str,
        method: str = "GET",
    ) -> InjectionTestResult:
        """
        Validate CRLF / HTTP Header Injection.
        CWE-93, CWE-113.
        """
        url = urljoin(self.base_url, endpoint)

        payloads = [
            ("%0d%0aX-Injected:true", "X-Injected"),
            ("%0aX-Injected:true", "X-Injected"),
            ("\r\nX-Injected:true", "X-Injected"),
        ]

        for payload, expected_header in payloads:
            try:
                if method.upper() == "GET":
                    _, _, response_headers, _ = self._make_request(
                        "GET", endpoint, params={param: payload}
                    )
                else:
                    _, _, response_headers, _ = self._make_request(
                        "POST", endpoint, data={param: payload}
                    )
            except Exception:
                continue

            # Check if our header was injected
            if expected_header.lower() in [h.lower() for h in response_headers.keys()]:
                return InjectionTestResult(
                    status="VALIDATED",
                    injection_type="crlf_header_injection",
                    cwe="CWE-113",
                    payload_used=payload,
                    evidence=f"CRLF injection: {expected_header} header injected",
                    test_details={
                        "url": url,
                        "param": param,
                        "injected_header": expected_header,
                        "response_headers": dict(response_headers),
                    },
                )

        return InjectionTestResult(
            status="FALSE_POSITIVE",
            injection_type="crlf_header_injection",
            cwe="CWE-113",
            payload_used="multiple",
            evidence="No CRLF injection - headers not injectable",
            test_details={"url": url, "param": param},
        )

    def validate_el(
        self,
        endpoint: str,
        param: str,
        method: str = "GET",
    ) -> InjectionTestResult:
        """
        Validate Expression Language Injection.
        CWE-917.
        """
        url = urljoin(self.base_url, endpoint)

        payloads = [
            ("${7*7}", "49", "spring/generic"),
            ("#{7*7}", "49", "jsp_el"),
            ("%{7*7}", "49", "ognl"),
        ]

        for payload, expected, framework in payloads:
            try:
                if method.upper() == "GET":
                    _, response_body, _, _ = self._make_request(
                        "GET", endpoint, params={param: payload}
                    )
                else:
                    _, response_body, _, _ = self._make_request(
                        "POST", endpoint, data={param: payload}
                    )
            except Exception:
                continue

            if expected in response_body and payload not in response_body:
                return InjectionTestResult(
                    status="VALIDATED",
                    injection_type=f"el_injection_{framework.split('/')[0]}",
                    cwe="CWE-917",
                    payload_used=payload,
                    evidence=f"EL injection ({framework}): {payload} evaluated to {expected}",
                    test_details={
                        "url": url,
                        "param": param,
                        "framework": framework,
                        "response_snippet": self._truncate_snippet(response_body),
                    },
                )

        return InjectionTestResult(
            status="FALSE_POSITIVE",
            injection_type="el_injection",
            cwe="CWE-917",
            payload_used="multiple",
            evidence="No EL injection indicators",
            test_details={"url": url, "param": param},
        )

    def validate_redos(
        self,
        endpoint: str,
        pattern_param: str,
        input_param: str,
        method: str = "GET",
    ) -> InjectionTestResult:
        """
        Validate ReDoS (Regex Denial of Service).
        CWE-1333.
        """
        url = urljoin(self.base_url, endpoint)

        # Get baseline
        try:
            start = time.time()
            if method.upper() == "GET":
                self._make_request(
                    "GET", endpoint, params={pattern_param: "test", input_param: "test"}
                )
            baseline_time = time.time() - start
        except Exception as e:
            return InjectionTestResult(
                status="UNVALIDATED",
                injection_type="redos",
                cwe="CWE-1333",
                payload_used="",
                evidence=f"Baseline failed: {str(e)}",
                test_details={"url": url},
            )

        # Evil pattern
        evil_pattern = "(a+)+$"
        evil_input = "a" * 25 + "!"

        try:
            start = time.time()
            if method.upper() == "GET":
                self._make_request(
                    "GET",
                    endpoint,
                    params={pattern_param: evil_pattern, input_param: evil_input},
                )
            test_time = time.time() - start
        except Exception:
            test_time = self.timeout  # Timeout indicates possible ReDoS

        delay = test_time - baseline_time
        if delay >= 3.0:  # 3+ second delay
            return InjectionTestResult(
                status="VALIDATED",
                injection_type="redos",
                cwe="CWE-1333",
                payload_used=evil_pattern,
                evidence=f"ReDoS: {delay:.1f}s delay with catastrophic backtracking pattern",
                test_details={
                    "url": url,
                    "pattern": evil_pattern,
                    "input_length": len(evil_input),
                    "baseline_time_ms": int(baseline_time * 1000),
                    "test_time_ms": int(test_time * 1000),
                },
            )

        return InjectionTestResult(
            status="FALSE_POSITIVE",
            injection_type="redos",
            cwe="CWE-1333",
            payload_used=evil_pattern,
            evidence="No ReDoS - regex engine handles pattern efficiently",
            test_details={"url": url},
        )

    def validate_xpath(
        self,
        endpoint: str,
        param: str,
        method: str = "GET",
    ) -> InjectionTestResult:
        """
        Validate XPath Injection.
        CWE-643.
        """
        url = urljoin(self.base_url, endpoint)

        # Get baseline
        try:
            if method.upper() == "GET":
                _, baseline_body, _, _ = self._make_request("GET", endpoint, params={param: "test"})
            baseline_len = len(baseline_body)
        except Exception as e:
            return InjectionTestResult(
                status="UNVALIDATED",
                injection_type="xpath_injection",
                cwe="CWE-643",
                payload_used="",
                evidence=f"Baseline failed: {str(e)}",
                test_details={"url": url},
            )

        # Boolean bypass
        payload = "' or '1'='1"
        try:
            if method.upper() == "GET":
                _, test_body, _, _ = self._make_request("GET", endpoint, params={param: payload})
            test_len = len(test_body)
        except Exception:
            return InjectionTestResult(
                status="UNVALIDATED",
                injection_type="xpath_injection",
                cwe="CWE-643",
                payload_used=payload,
                evidence="Test request failed",
                test_details={"url": url},
            )

        if test_len > baseline_len * 2:
            return InjectionTestResult(
                status="VALIDATED",
                injection_type="xpath_injection",
                cwe="CWE-643",
                payload_used=payload,
                evidence=f"XPath injection: boolean bypass returned {test_len} vs {baseline_len} bytes",
                test_details={
                    "url": url,
                    "param": param,
                    "baseline_length": baseline_len,
                    "test_length": test_len,
                },
            )

        return InjectionTestResult(
            status="FALSE_POSITIVE",
            injection_type="xpath_injection",
            cwe="CWE-643",
            payload_used=payload,
            evidence="No XPath injection indicators",
            test_details={"url": url, "param": param},
        )

    def validate_xquery(
        self,
        endpoint: str,
        param: str,
        method: str = "GET",
    ) -> InjectionTestResult:
        """
        Validate XQuery Injection.
        CWE-652.
        """
        url = urljoin(self.base_url, endpoint)

        # Get baseline
        try:
            if method.upper() == "GET":
                _, baseline_body, _, _ = self._make_request("GET", endpoint, params={param: "test"})
            else:
                _, baseline_body, _, _ = self._make_request("POST", endpoint, data={param: "test"})
            baseline_len = len(baseline_body)
        except Exception as e:
            return InjectionTestResult(
                status="UNVALIDATED",
                injection_type="xquery_injection",
                cwe="CWE-652",
                payload_used="",
                evidence=f"Baseline failed: {str(e)}",
                test_details={"url": url},
            )

        payloads = ["' or '1'='1", "') or ('1'='1"]

        for payload in payloads:
            try:
                if method.upper() == "GET":
                    _, test_body, _, _ = self._make_request(
                        "GET", endpoint, params={param: payload}
                    )
                else:
                    _, test_body, _, _ = self._make_request("POST", endpoint, data={param: payload})
                test_len = len(test_body)
            except Exception:
                continue

            if test_len > baseline_len * 2:
                return InjectionTestResult(
                    status="VALIDATED",
                    injection_type="xquery_injection",
                    cwe="CWE-652",
                    payload_used=payload,
                    evidence=f"XQuery injection: boolean bypass returned {test_len} vs {baseline_len} bytes",
                    test_details={
                        "url": url,
                        "param": param,
                        "baseline_length": baseline_len,
                        "test_length": test_len,
                    },
                )

        return InjectionTestResult(
            status="FALSE_POSITIVE",
            injection_type="xquery_injection",
            cwe="CWE-652",
            payload_used="multiple",
            evidence="No XQuery injection indicators",
            test_details={"url": url, "param": param},
        )

    def validate_js_eval(
        self,
        endpoint: str,
        param: str,
        method: str = "GET",
    ) -> InjectionTestResult:
        """
        Validate JSON/JavaScript eval injection.

        CWE-95 (Eval Injection) and CWE-94 (Code Injection).
        """
        url = urljoin(self.base_url, endpoint)

        payloads = [
            ("7*7", "49"),
            ("Math.imul(7,7)", "49"),
            ("['a','b'].length", "2"),
        ]

        for payload, expected in payloads:
            try:
                if method.upper() == "GET":
                    _, response_body, _, _ = self._make_request(
                        "GET", endpoint, params={param: payload}
                    )
                else:
                    _, response_body, _, _ = self._make_request(
                        "POST", endpoint, data={param: payload}
                    )
            except Exception:
                continue

            if expected in response_body and payload not in response_body:
                return InjectionTestResult(
                    status="VALIDATED",
                    injection_type="js_eval_injection",
                    cwe="CWE-95",
                    payload_used=payload,
                    evidence=f"JavaScript eval injection: {payload} evaluated to {expected}",
                    test_details={
                        "url": url,
                        "param": param,
                        "response_snippet": self._truncate_snippet(response_body),
                    },
                )

        return InjectionTestResult(
            status="FALSE_POSITIVE",
            injection_type="js_eval_injection",
            cwe="CWE-95",
            payload_used="multiple",
            evidence="No JavaScript eval injection indicators",
            test_details={"url": url, "param": param},
        )


def validate_from_vulnerabilities(vulns_file: str, base_url: str) -> list[dict[str, Any]]:
    """Validate injection findings from VULNERABILITIES.json."""
    with open(vulns_file) as f:
        vulns = json.load(f)

    validator = InjectionValidator(base_url)
    results = []

    # Map CWEs to validation methods
    cwe_validators = {
        "CWE-1336": validator.validate_ssti,
        "CWE-90": validator.validate_ldap,
        "CWE-643": validator.validate_xpath,
        "CWE-652": validator.validate_xquery,
        "CWE-93": validator.validate_crlf,
        "CWE-113": validator.validate_crlf,
        "CWE-917": validator.validate_el,
        "CWE-94": validator.validate_js_eval,
        "CWE-95": validator.validate_js_eval,
        "CWE-1333": validator.validate_redos,
    }

    for vuln in vulns:
        cwe = vuln.get("cwe")
        if cwe in cwe_validators:
            endpoint = vuln.get("endpoint", "/")
            param = vuln.get("param", "input")
            result = cwe_validators[cwe](endpoint, param)
            results.append(result.to_dict())

    return results


if __name__ == "__main__":
    print("Injection Validator - Example Usage")
    print("=" * 50)
    print(
        """
from validate_injection import InjectionValidator

validator = InjectionValidator("http://target.com")

# Test SSTI
result = validator.validate_ssti("/greet", "name")
print(result.to_dict())

# Test LDAP injection
result = validator.validate_ldap("/search", "user")
print(result.to_dict())

# Test CRLF injection
result = validator.validate_crlf("/redirect", "url")
print(result.to_dict())

# Test EL injection
result = validator.validate_el("/page", "input")
print(result.to_dict())

# Test XPath injection
result = validator.validate_xpath("/user", "name")
print(result.to_dict())

# Test ReDoS
result = validator.validate_redos("/search", "pattern", "text")
print(result.to_dict())
    """
    )
