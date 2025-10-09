"""Security issue data model"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Issue severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityIssue:
    """Represents a security vulnerability found in code"""
    
    id: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
        }
