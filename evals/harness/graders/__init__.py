"""Graders for SecureVibes evaluations.

Provides code-based, model-based, and human graders for evaluating
SecureVibes agent outputs.

Reference: https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents
"""

from harness.graders.base import Grader, GradeResult
from harness.graders.code_graders import (
    ArtifactExistsGrader,
    JsonSchemaGrader,
    VulnerabilityMatchGrader,
    NoFalsePositiveGrader,
    ToolCallsGrader,
)
from harness.graders.model_graders import LLMRubricGrader

# Registry of available graders
GRADERS = {
    "artifact_exists": ArtifactExistsGrader,
    "json_schema": JsonSchemaGrader,
    "vulnerability_match": VulnerabilityMatchGrader,
    "no_false_positive": NoFalsePositiveGrader,
    "tool_calls": ToolCallsGrader,
    "llm_rubric": LLMRubricGrader,
}


def get_grader(grader_type: str) -> Grader | None:
    """Get a grader instance by type name."""
    grader_class = GRADERS.get(grader_type)
    if grader_class:
        return grader_class()
    return None


__all__ = [
    "Grader",
    "GradeResult",
    "get_grader",
    "ArtifactExistsGrader",
    "JsonSchemaGrader",
    "VulnerabilityMatchGrader",
    "NoFalsePositiveGrader",
    "ToolCallsGrader",
    "LLMRubricGrader",
]
