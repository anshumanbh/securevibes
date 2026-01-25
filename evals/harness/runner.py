"""Evaluation runner - executes tasks and aggregates results.

This module provides the main evaluation infrastructure for SecureVibes.
It handles task loading, trial execution, grading, and result aggregation.

Reference: https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents
"""

import asyncio
import json
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import click
import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from harness.graders import get_grader


@dataclass
class GradeResult:
    """Result from a single grader."""
    
    grader_type: str
    passed: bool
    score: Optional[float] = None
    details: dict = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class TaskResult:
    """Result from running a single task trial."""
    
    task_id: str
    task_name: str
    trial_number: int
    passed: bool
    grades: list[GradeResult] = field(default_factory=list)
    scan_time_seconds: float = 0.0
    cost_usd: float = 0.0
    error: Optional[str] = None
    transcript_path: Optional[str] = None


@dataclass
class EvalResult:
    """Aggregated results from an evaluation run."""
    
    run_id: str
    model: str
    timestamp: str
    total_tasks: int
    passed: int
    failed: int
    pass_rate: float
    task_results: list[TaskResult] = field(default_factory=list)
    total_cost_usd: float = 0.0
    total_time_seconds: float = 0.0
    metrics: dict = field(default_factory=dict)


class EvalRunner:
    """Main evaluation runner.
    
    Loads tasks, executes trials, applies graders, and aggregates results.
    """
    
    def __init__(
        self,
        evals_dir: Path,
        model: str = "sonnet",
        trials: int = 1,
        verbose: bool = False,
    ):
        """Initialize the eval runner.
        
        Args:
            evals_dir: Path to the evals/ directory
            model: Claude model to use (sonnet, haiku, opus)
            trials: Number of trials per task (for pass@k metrics)
            verbose: Enable verbose output
        """
        self.evals_dir = Path(evals_dir)
        self.model = model
        self.trials = trials
        self.verbose = verbose
        self.console = Console()
        
        self.tasks_dir = self.evals_dir / "tasks"
        self.fixtures_dir = self.evals_dir / "fixtures"
        self.schemas_dir = self.evals_dir / "schemas"
        self.results_dir = self.evals_dir / "results"
        
        self.results_dir.mkdir(exist_ok=True)
    
    def load_task(self, task_path: Path) -> dict:
        """Load a task definition from YAML."""
        with open(task_path) as f:
            return yaml.safe_load(f)
    
    def discover_tasks(
        self,
        category: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> list[Path]:
        """Discover all task files matching criteria.
        
        Args:
            category: Filter by category (capability, regression)
            tags: Filter by tags
            
        Returns:
            List of paths to task.yaml files
        """
        tasks = []
        
        search_dir = self.tasks_dir
        if category:
            search_dir = self.tasks_dir / category
        
        for task_file in search_dir.rglob("task.yaml"):
            if tags:
                task = self.load_task(task_file)
                task_tags = task.get("tags", [])
                if not any(t in task_tags for t in tags):
                    continue
            tasks.append(task_file)
        
        return sorted(tasks)
    
    async def run_task_trial(
        self,
        task: dict,
        trial_number: int,
    ) -> TaskResult:
        """Run a single trial of a task.
        
        Args:
            task: Task definition dict
            trial_number: Which trial this is (1-indexed)
            
        Returns:
            TaskResult with grades and metadata
        """
        task_id = task["id"]
        task_name = task["name"]
        
        # Create isolated temp directory for this trial
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Copy fixture to temp directory
            fixture_source = task.get("fixture", {}).get("source")
            if fixture_source:
                fixture_path = self.fixtures_dir / fixture_source
                if fixture_path.exists():
                    # Copy fixture contents to temp dir
                    for item in fixture_path.iterdir():
                        if item.is_file():
                            shutil.copy2(item, temp_path / item.name)
                        elif item.is_dir():
                            shutil.copytree(item, temp_path / item.name)
            
            # Run SecureVibes scan
            start_time = time.time()
            scan_error = None
            
            try:
                from securevibes import Scanner
                
                scanner_options = task.get("scanner_options", {})
                scanner = Scanner(model=self.model, debug=self.verbose)
                
                if scanner_options.get("agentic"):
                    scanner.configure_agentic_detection(True)
                elif scanner_options.get("agentic") is False:
                    scanner.configure_agentic_detection(False)
                
                result = await scanner.scan(str(temp_path))
                cost_usd = result.total_cost_usd
                
            except Exception as e:
                scan_error = str(e)
                cost_usd = 0.0
            
            scan_time = time.time() - start_time
            
            # Run graders
            grades = []
            all_passed = True
            
            if not scan_error:
                for grader_config in task.get("graders", []):
                    grader_type = grader_config.get("type")
                    grader = get_grader(grader_type)
                    
                    if grader:
                        grade = await grader.grade(
                            task=task,
                            scan_dir=temp_path / ".securevibes",
                            config=grader_config,
                            schemas_dir=self.schemas_dir,
                        )
                        grades.append(grade)
                        if not grade.passed:
                            all_passed = False
                    else:
                        grades.append(GradeResult(
                            grader_type=grader_type,
                            passed=False,
                            error=f"Unknown grader type: {grader_type}",
                        ))
                        all_passed = False
            else:
                all_passed = False
            
            return TaskResult(
                task_id=task_id,
                task_name=task_name,
                trial_number=trial_number,
                passed=all_passed,
                grades=grades,
                scan_time_seconds=scan_time,
                cost_usd=cost_usd,
                error=scan_error,
            )
    
    async def run_task(self, task_path: Path) -> list[TaskResult]:
        """Run all trials for a task.
        
        Args:
            task_path: Path to task.yaml
            
        Returns:
            List of TaskResults, one per trial
        """
        task = self.load_task(task_path)
        results = []
        
        for trial in range(1, self.trials + 1):
            result = await self.run_task_trial(task, trial)
            results.append(result)
        
        return results
    
    def calculate_metrics(self, task_results: list[TaskResult]) -> dict:
        """Calculate pass@k and pass^k metrics.
        
        Reference: Anthropic guide section on non-determinism
        """
        # Group by task_id
        by_task: dict[str, list[TaskResult]] = {}
        for result in task_results:
            if result.task_id not in by_task:
                by_task[result.task_id] = []
            by_task[result.task_id].append(result)
        
        # Calculate metrics
        pass_at_1 = []
        pass_at_k = []
        pass_pow_k = []
        
        for task_id, results in by_task.items():
            passed = [r.passed for r in results]
            
            # pass@1: First trial success
            pass_at_1.append(passed[0] if passed else False)
            
            # pass@k: At least one success
            pass_at_k.append(any(passed))
            
            # pass^k: All trials succeed
            pass_pow_k.append(all(passed))
        
        return {
            "pass@1": sum(pass_at_1) / len(pass_at_1) if pass_at_1 else 0.0,
            f"pass@{self.trials}": sum(pass_at_k) / len(pass_at_k) if pass_at_k else 0.0,
            f"pass^{self.trials}": sum(pass_pow_k) / len(pass_pow_k) if pass_pow_k else 0.0,
        }
    
    async def run(
        self,
        category: Optional[str] = None,
        tags: Optional[list[str]] = None,
        task_id: Optional[str] = None,
    ) -> EvalResult:
        """Run evaluation suite.
        
        Args:
            category: Filter by category
            tags: Filter by tags
            task_id: Run single task by ID
            
        Returns:
            Aggregated EvalResult
        """
        run_id = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        start_time = time.time()
        
        # Discover tasks
        if task_id:
            # Find specific task
            tasks = [
                t for t in self.discover_tasks()
                if self.load_task(t).get("id") == task_id
            ]
        else:
            tasks = self.discover_tasks(category=category, tags=tags)
        
        if not tasks:
            self.console.print("[yellow]No tasks found matching criteria[/yellow]")
            return EvalResult(
                run_id=run_id,
                model=self.model,
                timestamp=datetime.now().isoformat(),
                total_tasks=0,
                passed=0,
                failed=0,
                pass_rate=0.0,
            )
        
        self.console.print(f"[bold]Running {len(tasks)} tasks × {self.trials} trials[/bold]")
        self.console.print(f"Model: {self.model}")
        self.console.print()
        
        all_results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            task_progress = progress.add_task("Running evals...", total=len(tasks))
            
            for task_path in tasks:
                task = self.load_task(task_path)
                progress.update(task_progress, description=f"Running: {task['name']}")
                
                results = await self.run_task(task_path)
                all_results.extend(results)
                
                progress.advance(task_progress)
        
        # Calculate aggregates
        total_time = time.time() - start_time
        total_cost = sum(r.cost_usd for r in all_results)
        
        # Count unique task passes (pass if any trial passed)
        task_passes = {}
        for r in all_results:
            if r.task_id not in task_passes:
                task_passes[r.task_id] = False
            if r.passed:
                task_passes[r.task_id] = True
        
        passed = sum(task_passes.values())
        failed = len(task_passes) - passed
        
        metrics = self.calculate_metrics(all_results)
        
        return EvalResult(
            run_id=run_id,
            model=self.model,
            timestamp=datetime.now().isoformat(),
            total_tasks=len(task_passes),
            passed=passed,
            failed=failed,
            pass_rate=passed / len(task_passes) if task_passes else 0.0,
            task_results=all_results,
            total_cost_usd=total_cost,
            total_time_seconds=total_time,
            metrics=metrics,
        )
    
    def print_results(self, result: EvalResult):
        """Print eval results to console."""
        self.console.print()
        self.console.print("[bold]═══ Evaluation Results ═══[/bold]")
        self.console.print()
        
        # Summary table
        table = Table(title="Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Run ID", result.run_id)
        table.add_row("Model", result.model)
        table.add_row("Total Tasks", str(result.total_tasks))
        table.add_row("Passed", str(result.passed))
        table.add_row("Failed", str(result.failed))
        table.add_row("Pass Rate", f"{result.pass_rate:.1%}")
        table.add_row("Total Cost", f"${result.total_cost_usd:.4f}")
        table.add_row("Total Time", f"{result.total_time_seconds:.1f}s")
        
        self.console.print(table)
        
        # Metrics
        if result.metrics:
            self.console.print()
            metrics_table = Table(title="Metrics")
            metrics_table.add_column("Metric", style="cyan")
            metrics_table.add_column("Value", style="green")
            
            for name, value in result.metrics.items():
                metrics_table.add_row(name, f"{value:.1%}")
            
            self.console.print(metrics_table)
        
        # Failed tasks
        failed_results = [r for r in result.task_results if not r.passed]
        if failed_results:
            self.console.print()
            self.console.print("[bold red]Failed Tasks:[/bold red]")
            for r in failed_results:
                self.console.print(f"  • {r.task_id}: {r.task_name}")
                if r.error:
                    self.console.print(f"    Error: {r.error}")
                for grade in r.grades:
                    if not grade.passed:
                        self.console.print(f"    - {grade.grader_type}: {grade.error or 'Failed'}")
    
    def save_results(self, result: EvalResult):
        """Save results to JSON file."""
        output_path = self.results_dir / f"{result.run_id}.json"
        
        # Convert to dict for JSON serialization
        data = {
            "run_id": result.run_id,
            "model": result.model,
            "timestamp": result.timestamp,
            "total_tasks": result.total_tasks,
            "passed": result.passed,
            "failed": result.failed,
            "pass_rate": result.pass_rate,
            "total_cost_usd": result.total_cost_usd,
            "total_time_seconds": result.total_time_seconds,
            "metrics": result.metrics,
            "task_results": [
                {
                    "task_id": r.task_id,
                    "task_name": r.task_name,
                    "trial_number": r.trial_number,
                    "passed": r.passed,
                    "scan_time_seconds": r.scan_time_seconds,
                    "cost_usd": r.cost_usd,
                    "error": r.error,
                    "grades": [
                        {
                            "grader_type": g.grader_type,
                            "passed": g.passed,
                            "score": g.score,
                            "details": g.details,
                            "error": g.error,
                        }
                        for g in r.grades
                    ],
                }
                for r in result.task_results
            ],
        }
        
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        
        self.console.print(f"\n[dim]Results saved to: {output_path}[/dim]")


@click.command()
@click.option("--all", "run_all", is_flag=True, help="Run all tasks")
@click.option("--category", type=str, help="Filter by category (capability, regression)")
@click.option("--tag", "tags", multiple=True, help="Filter by tag (can specify multiple)")
@click.option("--task", "task_id", type=str, help="Run single task by ID")
@click.option("--model", default="sonnet", help="Claude model to use")
@click.option("--trials", default=1, type=int, help="Number of trials per task")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
def cli(run_all, category, tags, task_id, model, trials, verbose):
    """Run SecureVibes evaluations."""
    # Find evals directory
    evals_dir = Path(__file__).parent.parent
    
    runner = EvalRunner(
        evals_dir=evals_dir,
        model=model,
        trials=trials,
        verbose=verbose,
    )
    
    if not (run_all or category or tags or task_id):
        click.echo("Specify --all, --category, --tag, or --task")
        return
    
    result = asyncio.run(runner.run(
        category=category,
        tags=list(tags) if tags else None,
        task_id=task_id,
    ))
    
    runner.print_results(result)
    runner.save_results(result)


if __name__ == "__main__":
    cli()
