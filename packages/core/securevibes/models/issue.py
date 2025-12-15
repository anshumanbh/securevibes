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

    @classmethod
    def _missing_(cls, value):
        """Handle case-insensitive matching and aliases"""
        if isinstance(value, str):
            value = value.lower()
            if value == "informational":
                return cls.INFO
            for member in cls:
                if member.value == value:
                    return member
        return None


class ValidationStatus(str, Enum):
    """DAST validation status"""
    VALIDATED = "VALIDATED"  # Successfully exploited
    FALSE_POSITIVE = "FALSE_POSITIVE"  # Disproven by testing
    UNVALIDATED = "UNVALIDATED"  # Couldn't test (timeout, unreachable)
    PARTIAL = "PARTIAL"  # Exploitable but different impact


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
    
    # DAST validation fields
    validation_status: Optional[ValidationStatus] = None
    dast_evidence: Optional[dict] = None
    exploitability_score: Optional[float] = None
    validated_at: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        base_dict = {
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
        
        # Include DAST fields if present
        if self.validation_status:
            base_dict.update({
                "validation_status": self.validation_status.value,
                "dast_evidence": self.dast_evidence,
                "exploitability_score": self.exploitability_score,
                "validated_at": self.validated_at
            })
        
        return base_dict
    
    @property
    def is_validated(self) -> bool:
        """Check if issue was validated by DAST"""
        return self.validation_status == ValidationStatus.VALIDATED
    
    @property
    def is_false_positive(self) -> bool:
        """Check if issue was disproven by DAST"""
        return self.validation_status == ValidationStatus.FALSE_POSITIVE
