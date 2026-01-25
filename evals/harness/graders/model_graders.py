"""Model-based graders using LLM-as-judge.

These graders use Claude to evaluate outputs against rubrics,
capturing nuance that deterministic graders miss.

Reference: https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents
"""

import json
from pathlib import Path
from typing import Optional

from harness.graders.base import Grader, GradeResult


class LLMRubricGrader(Grader):
    """Use an LLM to grade outputs against a rubric.
    
    From Anthropic guide:
    - Rubric-based scoring
    - Natural language assertions
    - Requires calibration with human graders
    """
    
    @property
    def grader_type(self) -> str:
        return "llm_rubric"
    
    async def grade(
        self,
        task: dict,
        scan_dir: Path,
        config: dict,
        schemas_dir: Optional[Path] = None,
    ) -> GradeResult:
        """Grade output using LLM-as-judge.
        
        Config:
            rubric: Inline rubric text
            rubric_file: Path to rubric file (relative to rubrics/)
            min_score: Minimum passing score (default: 3)
            assertions: List of specific checks
        """
        rubric = config.get("rubric")
        rubric_file = config.get("rubric_file")
        min_score = config.get("min_score", 3)
        assertions = config.get("assertions", [])
        
        # Load rubric
        if rubric_file and schemas_dir:
            rubrics_dir = schemas_dir.parent / "rubrics"
            rubric_path = rubrics_dir / rubric_file
            if rubric_path.exists():
                rubric = rubric_path.read_text()
        
        if not rubric:
            return GradeResult(
                grader_type=self.grader_type,
                passed=False,
                error="No rubric provided",
            )
        
        # Load scan results
        results_file = scan_dir / "scan_results.json"
        if not results_file.exists():
            return GradeResult(
                grader_type=self.grader_type,
                passed=False,
                error="scan_results.json not found",
            )
        
        try:
            with open(results_file) as f:
                scan_data = json.load(f)
        except json.JSONDecodeError as e:
            return GradeResult(
                grader_type=self.grader_type,
                passed=False,
                error=f"Invalid JSON: {e}",
            )
        
        # Call LLM for grading
        try:
            score, evaluation = await self._llm_grade(
                rubric=rubric,
                scan_data=scan_data,
                assertions=assertions,
            )
            
            passed = score >= min_score
            
            return GradeResult(
                grader_type=self.grader_type,
                passed=passed,
                score=score,
                details={
                    "evaluation": evaluation,
                    "min_score": min_score,
                    "assertions_checked": assertions,
                },
            )
            
        except Exception as e:
            return GradeResult(
                grader_type=self.grader_type,
                passed=False,
                error=f"LLM grading failed: {e}",
            )
    
    async def _llm_grade(
        self,
        rubric: str,
        scan_data: dict,
        assertions: list[str],
    ) -> tuple[float, str]:
        """Call LLM to grade the scan output.
        
        Returns:
            Tuple of (score, evaluation_text)
        """
        import anthropic
        
        # Format the grading prompt
        prompt = f"""You are an expert security evaluator. Grade the following security scan output against the rubric.

<rubric>
{rubric}
</rubric>

<scan_output>
{json.dumps(scan_data, indent=2)[:10000]}
</scan_output>

{self._format_assertions(assertions)}

Provide your evaluation in the following format:

SCORE: [1-5]
EVALUATION: [Your detailed evaluation explaining the score]
ASSERTION_RESULTS: [For each assertion, state PASS or FAIL with reason]
"""
        
        client = anthropic.Anthropic()
        
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}],
        )
        
        response_text = response.content[0].text
        
        # Parse score from response
        score = 3.0  # Default
        for line in response_text.split("\n"):
            if line.startswith("SCORE:"):
                try:
                    score = float(line.split(":")[1].strip())
                except ValueError:
                    pass
                break
        
        return score, response_text
    
    def _format_assertions(self, assertions: list[str]) -> str:
        """Format assertions for the grading prompt."""
        if not assertions:
            return ""
        
        formatted = "Check the following assertions:\n"
        for i, assertion in enumerate(assertions, 1):
            formatted += f"{i}. {assertion}\n"
        
        return formatted
