"""
XSS validation script for Cross-Site Scripting testing.

Validates XSS vulnerabilities by:
1. Sending payloads to target endpoints
2. Checking for unencoded reflection in responses
3. Detecting injection context (HTML body, attribute, JavaScript, etc.)
4. Classifying results (VALIDATED, FALSE_POSITIVE, PARTIAL, UNVALIDATED)

CWE Coverage: CWE-79, CWE-80, CWE-81, CWE-83, CWE-84, CWE-85, CWE-86, CWE-87
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote, urljoin

# Type hints for requests (not imported to avoid dependency)
# In actual use, import requests


@dataclass
class XSSTestResult:
    """Result of an XSS test."""

    status: str  # VALIDATED, FALSE_POSITIVE, PARTIAL, UNVALIDATED
    injection_type: str
    cwe: str
    context: str
    payload_used: str
    evidence: str
    test_details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "injection_type": self.injection_type,
            "cwe": self.cwe,
            "context": self.context,
            "payload_used": self.payload_used,
            "evidence": self.evidence,
            "test": self.test_details,
        }


class XSSValidator:
    """Validates XSS vulnerabilities across different contexts."""

    # Patterns indicating successful XSS reflection
    XSS_INDICATORS = [
        r"<script[^>]*>",  # Script tags
        r"onerror\s*=",  # Event handlers
        r"onload\s*=",
        r"onclick\s*=",
        r"onmouseover\s*=",
        r"onfocus\s*=",
        r"onmouseenter\s*=",
        r"ontoggle\s*=",
        r"javascript:",  # URI schemes
        r"data:text/html",
        r"<svg[^>]*onload",  # SVG with handlers
        r"<img[^>]*onerror",  # IMG with handlers
    ]

    # Patterns indicating encoding (mitigation)
    ENCODED_PATTERNS = [
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", '"'),
        ("&#39;", "'"),
        ("&#x27;", "'"),
        ("&amp;", "&"),
        ("&#60;", "<"),
        ("&#62;", ">"),
    ]

    def __init__(self, base_url: str, timeout: int = 10, verify_ssl: bool = True):
        """
        Initialize XSS validator.

        Args:
            base_url: Base URL of target application
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = None  # Set up requests session when needed

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> tuple[int, str, dict]:
        """
        Make HTTP request and return status, body, headers.
        Placeholder - implement with actual HTTP client.
        """
        # In actual implementation, use requests library
        # import requests
        # response = requests.request(method, url, ...)
        raise NotImplementedError("Implement with HTTP client library")

    def _hash_response(self, content: str) -> str:
        """Generate SHA256 hash of response content."""
        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()[:16]}"

    def _truncate_snippet(self, content: str, payload: str, max_len: int = 500) -> str:
        """Extract relevant snippet around payload reflection."""
        idx = content.find(payload)
        if idx == -1:
            # Try case-insensitive or partial match
            idx = content.lower().find(payload.lower()[:20])
        if idx == -1:
            return content[:max_len] + "..." if len(content) > max_len else content

        start = max(0, idx - 100)
        end = min(len(content), idx + len(payload) + 100)
        snippet = content[start:end]
        if start > 0:
            snippet = "..." + snippet
        if end < len(content):
            snippet = snippet + "..."
        return snippet

    def _detect_context(self, response: str, payload: str) -> str:
        """Detect the injection context based on response analysis."""
        idx = response.find(payload)
        if idx == -1:
            return "unknown"

        # Look at surrounding context
        before = response[max(0, idx - 100) : idx]
        after = response[idx + len(payload) : idx + len(payload) + 100]

        # Check for JavaScript context
        if re.search(r"<script[^>]*>", before, re.IGNORECASE):
            if "</script>" in after or not re.search(r"</script>", before, re.IGNORECASE):
                return "javascript"

        # Check for attribute context
        attr_pattern = r'(?:value|href|src|data-\w+|title|alt)\s*=\s*["\'][^"\']*$'
        if re.search(attr_pattern, before, re.IGNORECASE):
            return "html_attribute"

        # Check for URI context
        if re.search(r'(?:href|src|action)\s*=\s*["\']?$', before, re.IGNORECASE):
            return "uri"

        # Check for style context
        if re.search(r"<style[^>]*>", before, re.IGNORECASE) or re.search(
            r"style\s*=", before, re.IGNORECASE
        ):
            return "css"

        # Default to HTML body
        return "html_body"

    def _is_payload_encoded(self, response: str, payload: str) -> bool:
        """Check if payload appears to be HTML-encoded."""
        # Check if raw payload exists
        if payload in response:
            # Check if it's actually inside a comment or CDATA
            idx = response.find(payload)
            before = response[max(0, idx - 50) : idx]
            if "<!--" in before and "-->" not in before:
                return True  # In comment
            if "<![CDATA[" in before:
                return True  # In CDATA
            return False  # Unencoded

        # Check for common encodings
        for encoded, original in self.ENCODED_PATTERNS:
            if original in payload:
                encoded_payload = payload.replace(original, encoded)
                if encoded_payload in response:
                    return True

        return True  # Not found, assume blocked/encoded

    def _check_xss_indicators(self, response: str) -> list[str]:
        """Find XSS indicators in response."""
        found = []
        for pattern in self.XSS_INDICATORS:
            if re.search(pattern, response, re.IGNORECASE):
                found.append(pattern)
        return found

    def validate_reflected_xss(
        self,
        endpoint: str,
        param: str,
        payload: str,
        method: str = "GET",
    ) -> XSSTestResult:
        """
        Validate reflected XSS vulnerability.

        Args:
            endpoint: Target endpoint path
            param: Parameter name to inject
            payload: XSS payload to test
            method: HTTP method (GET or POST)

        Returns:
            XSSTestResult with validation status
        """
        url = urljoin(self.base_url, endpoint)

        try:
            if method.upper() == "GET":
                params = {param: payload}
                status_code, response_body, _ = self._make_request("GET", endpoint, params=params)
            else:
                data = {param: payload}
                status_code, response_body, _ = self._make_request("POST", endpoint, data=data)
        except Exception as e:
            return XSSTestResult(
                status="UNVALIDATED",
                injection_type="xss_reflected",
                cwe="CWE-79",
                context="unknown",
                payload_used=payload,
                evidence=f"Request failed: {str(e)}",
                test_details={"url": url, "error": str(e)},
            )

        # Check for WAF/blocking
        if status_code in (403, 406, 429):
            return XSSTestResult(
                status="UNVALIDATED",
                injection_type="xss_reflected",
                cwe="CWE-79",
                context="unknown",
                payload_used=payload,
                evidence=f"Blocked by WAF/security (HTTP {status_code})",
                test_details={"url": url, "status": status_code},
            )

        # Check if payload is reflected unencoded
        if not self._is_payload_encoded(response_body, payload):
            context = self._detect_context(response_body, payload)
            indicators = self._check_xss_indicators(response_body)

            return XSSTestResult(
                status="VALIDATED",
                injection_type="xss_reflected",
                cwe="CWE-79",
                context=context,
                payload_used=payload,
                evidence=f"Reflected XSS: payload unencoded in {context}",
                test_details={
                    "url": f"{url}?{param}={quote(payload)}",
                    "method": method,
                    "status": status_code,
                    "response_snippet": self._truncate_snippet(response_body, payload),
                    "response_hash": self._hash_response(response_body),
                    "indicators": indicators,
                },
            )
        else:
            return XSSTestResult(
                status="FALSE_POSITIVE",
                injection_type="xss_reflected",
                cwe="CWE-79",
                context="n/a",
                payload_used=payload,
                evidence="XSS mitigated: payload encoded or blocked",
                test_details={
                    "url": url,
                    "status": status_code,
                    "response_snippet": self._truncate_snippet(response_body, payload[:20]),
                },
            )

    def validate_stored_xss(
        self,
        submit_endpoint: str,
        submit_param: str,
        retrieve_endpoint: str,
        payload: str,
        submit_method: str = "POST",
    ) -> XSSTestResult:
        """
        Validate stored XSS vulnerability.

        Args:
            submit_endpoint: Endpoint to submit payload
            submit_param: Parameter name for payload
            retrieve_endpoint: Endpoint to retrieve stored content
            payload: XSS payload to test
            submit_method: HTTP method for submission

        Returns:
            XSSTestResult with validation status
        """
        submit_url = urljoin(self.base_url, submit_endpoint)
        retrieve_url = urljoin(self.base_url, retrieve_endpoint)

        try:
            # Submit payload
            data = {submit_param: payload}
            submit_status, _, _ = self._make_request(submit_method, submit_endpoint, data=data)

            # Retrieve and check
            _, retrieve_body, _ = self._make_request("GET", retrieve_endpoint)

        except Exception as e:
            return XSSTestResult(
                status="UNVALIDATED",
                injection_type="xss_stored",
                cwe="CWE-79",
                context="unknown",
                payload_used=payload,
                evidence=f"Request failed: {str(e)}",
                test_details={"error": str(e)},
            )

        if not self._is_payload_encoded(retrieve_body, payload):
            context = self._detect_context(retrieve_body, payload)

            return XSSTestResult(
                status="VALIDATED",
                injection_type="xss_stored",
                cwe="CWE-79",
                context=context,
                payload_used=payload,
                evidence=f"Stored XSS: payload persists unencoded in {context}",
                test_details={
                    "submit_url": submit_url,
                    "retrieve_url": retrieve_url,
                    "response_snippet": self._truncate_snippet(retrieve_body, payload),
                    "response_hash": self._hash_response(retrieve_body),
                },
            )
        else:
            return XSSTestResult(
                status="FALSE_POSITIVE",
                injection_type="xss_stored",
                cwe="CWE-79",
                context="n/a",
                payload_used=payload,
                evidence="Stored XSS mitigated: payload encoded or not stored",
                test_details={
                    "submit_url": submit_url,
                    "retrieve_url": retrieve_url,
                },
            )

    def validate_attribute_xss(
        self,
        endpoint: str,
        param: str,
        quote_char: str = '"',
    ) -> XSSTestResult:
        """
        Validate attribute-context XSS (CWE-83).

        Args:
            endpoint: Target endpoint
            param: Parameter reflected in attribute
            quote_char: Quote character used in attribute

        Returns:
            XSSTestResult with validation status
        """
        if quote_char == '"':
            payload = '" onfocus="alert(1)" autofocus="'
        else:
            payload = "' onfocus='alert(1)' autofocus='"

        result = self.validate_reflected_xss(endpoint, param, payload)

        if result.status == "VALIDATED":
            result.injection_type = "xss_attribute_breakout"
            result.cwe = "CWE-83"
            result.evidence = f"Attribute XSS: broke out of {quote_char}-quoted attribute"

        return result

    def validate_uri_xss(
        self,
        endpoint: str,
        param: str,
    ) -> XSSTestResult:
        """
        Validate URI scheme XSS (CWE-84).

        Args:
            endpoint: Target endpoint
            param: Parameter reflected in href/src

        Returns:
            XSSTestResult with validation status
        """
        payload = "javascript:alert(1)"
        result = self.validate_reflected_xss(endpoint, param, payload)

        if result.status == "VALIDATED":
            result.injection_type = "xss_uri_javascript"
            result.cwe = "CWE-84"
            result.evidence = "URI scheme XSS: javascript: protocol accepted"

        return result


def validate_from_vulnerabilities(vulns_file: str, base_url: str) -> list[dict[str, Any]]:
    """
    Validate XSS findings from VULNERABILITIES.json.

    Args:
        vulns_file: Path to VULNERABILITIES.json
        base_url: Base URL of target

    Returns:
        List of validation results
    """
    with open(vulns_file) as f:
        vulns = json.load(f)

    validator = XSSValidator(base_url)
    results = []

    for vuln in vulns:
        if vuln.get("cwe") not in [
            "CWE-79",
            "CWE-80",
            "CWE-81",
            "CWE-83",
            "CWE-84",
            "CWE-85",
            "CWE-86",
            "CWE-87",
        ]:
            continue

        endpoint = vuln.get("endpoint", "/")
        param = vuln.get("param", "q")
        payload = vuln.get("payload", "<script>alert(1)</script>")

        # Determine test type based on CWE
        cwe = vuln.get("cwe", "CWE-79")
        if cwe == "CWE-83":
            result = validator.validate_attribute_xss(endpoint, param)
        elif cwe == "CWE-84":
            result = validator.validate_uri_xss(endpoint, param)
        else:
            result = validator.validate_reflected_xss(endpoint, param, payload)

        results.append(result.to_dict())

    return results


if __name__ == "__main__":
    print("XSS Validator - Example Usage")
    print("=" * 40)
    print(
        """
from validate_xss import XSSValidator

validator = XSSValidator("http://target.com")

# Test reflected XSS
result = validator.validate_reflected_xss(
    endpoint="/search",
    param="q",
    payload="<script>alert(1)</script>"
)
print(result.to_dict())

# Test attribute XSS
result = validator.validate_attribute_xss(
    endpoint="/profile",
    param="name",
    quote_char='"'
)
print(result.to_dict())

# Test URI scheme XSS
result = validator.validate_uri_xss(
    endpoint="/redirect",
    param="url"
)
print(result.to_dict())
    """
    )
