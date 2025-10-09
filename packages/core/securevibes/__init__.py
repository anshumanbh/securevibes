"""
SecureVibes - AI-Native Platform to Secure Vibecoded Applications
"""

from securevibes.scanner.security_scanner import SecurityScanner
from securevibes.models.issue import SecurityIssue, Severity
from securevibes.models.result import ScanResult

__version__ = "0.1.0"  # Fresh start as SecureVibes

__all__ = [
    "SecurityScanner",
    "SecurityIssue",
    "Severity",
    "ScanResult",
]
