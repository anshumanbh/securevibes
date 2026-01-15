"""Scan result data model"""

import json
from dataclasses import dataclass, field
from typing import List
from securevibes.models.issue import SecurityIssue


@dataclass
class ScanResult:
    """Results from a security scan"""

    repository_path: str
    issues: List[SecurityIssue] = field(default_factory=list)
    files_scanned: int = 0
    scan_time_seconds: float = 0.0
    total_cost_usd: float = 0.0

    # DAST metrics
    dast_enabled: bool = False
    dast_validation_rate: float = 0.0
    dast_false_positive_rate: float = 0.0
    dast_scan_time_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity.value == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity.value == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity.value == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity.value == "low")

    @property
    def validated_issues(self) -> List[SecurityIssue]:
        """Return only DAST-validated issues"""
        return [i for i in self.issues if i.is_validated]

    @property
    def false_positives(self) -> List[SecurityIssue]:
        """Return issues disproven by DAST"""
        return [i for i in self.issues if i.is_false_positive]

    @property
    def unvalidated_issues(self) -> List[SecurityIssue]:
        """Return issues that couldn't be tested"""
        from securevibes.models.issue import ValidationStatus

        return [i for i in self.issues if i.validation_status == ValidationStatus.UNVALIDATED]

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        result = {
            "repository_path": self.repository_path,
            "issues": [issue.to_dict() for issue in self.issues],
            "files_scanned": self.files_scanned,
            "scan_time_seconds": self.scan_time_seconds,
            "total_cost_usd": self.total_cost_usd,
            "summary": {
                "total": len(self.issues),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
        }

        # Add DAST metrics if enabled
        if self.dast_enabled:
            result["dast_metrics"] = {
                "enabled": True,
                "validation_rate": self.dast_validation_rate,
                "false_positive_rate": self.dast_false_positive_rate,
                "scan_time_seconds": self.dast_scan_time_seconds,
                "validated_count": len(self.validated_issues),
                "false_positive_count": len(self.false_positives),
                "unvalidated_count": len(self.unvalidated_issues),
            }

        return result

    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)

    def to_markdown(self) -> str:
        """Convert to Markdown string"""
        from securevibes.reporters.markdown_reporter import MarkdownReporter

        return MarkdownReporter.generate(self)
