"""
SecureVibes - AI-Native Platform to Secure Vibecoded Applications
"""

from securevibes.scanner.scanner import Scanner
from securevibes.models.issue import SecurityIssue, Severity
from securevibes.models.result import ScanResult
from securevibes.reporters.markdown_reporter import MarkdownReporter
from securevibes.reporters.json_reporter import JSONReporter

# Version is read dynamically from package metadata (pyproject.toml)
# This ensures single source of truth - only update version in pyproject.toml
try:
    from importlib.metadata import version

    __version__ = version("securevibes")
except Exception:
    # Fallback for development/editable installs
    __version__ = "0.3.1-dev"

__all__ = [
    "Scanner",
    "SecurityIssue",
    "Severity",
    "ScanResult",
    "MarkdownReporter",
    "JSONReporter",
]
