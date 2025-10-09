"""Data models for SecureVibes"""

from securevibes.models.issue import SecurityIssue, Severity
from securevibes.models.result import ScanResult

__all__ = ["SecurityIssue", "Severity", "ScanResult"]
