"""Base grader interface.

All graders inherit from this base class and implement the grade() method.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class GradeResult:
    """Result from a grader evaluation.
    
    Attributes:
        grader_type: Name of the grader that produced this result
        passed: Whether the grading check passed
        score: Optional numeric score (0.0 to 1.0 or 1-5 for rubrics)
        details: Additional details about the grading
        error: Error message if grading failed
    """
    
    grader_type: str
    passed: bool
    score: Optional[float] = None
    details: dict = field(default_factory=dict)
    error: Optional[str] = None


class Grader(ABC):
    """Abstract base class for all graders.
    
    Graders evaluate some aspect of SecureVibes output and return
    a GradeResult indicating whether the check passed.
    
    Types of graders (from Anthropic guide):
    - Code-based: Fast, cheap, deterministic (schema validation, artifact checks)
    - Model-based: Flexible, captures nuance (LLM-as-judge with rubrics)
    - Human: Gold standard for calibration
    """
    
    @property
    @abstractmethod
    def grader_type(self) -> str:
        """Return the grader type name."""
        pass
    
    @abstractmethod
    async def grade(
        self,
        task: dict,
        scan_dir: Path,
        config: dict,
        schemas_dir: Optional[Path] = None,
    ) -> GradeResult:
        """Evaluate the scan output.
        
        Args:
            task: The task definition dict
            scan_dir: Path to .securevibes/ output directory
            config: Grader-specific configuration from task.yaml
            schemas_dir: Path to schemas/ directory for validation
            
        Returns:
            GradeResult with pass/fail status and details
        """
        pass
