"""
SecureVibes - AI-Native Platform to Secure Vibecoded Applications
"""

from securevibes.scanner.scanner import Scanner
from securevibes.models.issue import SecurityIssue, Severity
from securevibes.models.result import ScanResult
from securevibes.reporters.markdown_reporter import MarkdownReporter
from securevibes.reporters.json_reporter import JSONReporter

__version__ = "0.1.0"  # Fresh start as SecureVibes

__all__ = [
    "Scanner",
    "SecurityIssue",
    "Severity",
    "ScanResult",
    "MarkdownReporter",
    "JSONReporter",
]
