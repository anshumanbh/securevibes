"""Sub-agent execution manager with artifact detection and dependency resolution"""

import json
from pathlib import Path
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

import click
from rich.console import Console
from rich.table import Table

console = Console()


class ScanMode(Enum):
    """Scan execution modes"""

    USE_EXISTING = "use_existing"  # Use existing artifacts
    FULL_RESCAN = "full_rescan"  # Re-run entire scan
    CANCEL = "cancel"  # User cancelled


@dataclass
class ArtifactStatus:
    """Status of an artifact file"""

    exists: bool
    path: Optional[Path] = None
    valid: bool = False
    age_hours: Optional[float] = None
    size_bytes: Optional[int] = None
    issue_count: Optional[int] = None
    error: Optional[str] = None


# Sub-agent artifact dependencies
SUBAGENT_ARTIFACTS = {
    "assessment": {
        "creates": "SECURITY.md",
        "requires": None,
        "description": "Architecture analysis and security documentation",
    },
    "threat-modeling": {
        "creates": "THREAT_MODEL.json",
        "requires": "SECURITY.md",
        "description": "STRIDE threat analysis",
    },
    "code-review": {
        "creates": "VULNERABILITIES.json",
        "requires": "THREAT_MODEL.json",
        "description": "Security vulnerability detection",
    },
    "report-generator": {
        "creates": "scan_results.json",
        "requires": "VULNERABILITIES.json",
        "description": "Consolidated scan report",
    },
    "dast": {
        "creates": "DAST_VALIDATION.json",
        "requires": "VULNERABILITIES.json",
        "description": "Dynamic security validation",
    },
}

# Sub-agent execution order
SUBAGENT_ORDER = ["assessment", "threat-modeling", "code-review", "report-generator", "dast"]


class SubAgentManager:
    """Manages sub-agent execution, artifact detection, and dependencies"""

    def __init__(self, repo_path: Path, quiet: bool = False):
        self.repo_path = repo_path
        self.securevibes_dir = repo_path / ".securevibes"
        self.quiet = quiet

    def check_artifact(self, filename: str) -> ArtifactStatus:
        """
        Check if an artifact file exists and is valid.

        Args:
            filename: Name of artifact file (e.g., "VULNERABILITIES.json")

        Returns:
            ArtifactStatus with existence, validity, age, and metadata
        """
        artifact_path = self.securevibes_dir / filename

        if not artifact_path.exists():
            return ArtifactStatus(exists=False)

        # Get file age
        mtime = artifact_path.stat().st_mtime
        age = datetime.now() - datetime.fromtimestamp(mtime)
        age_hours = age.total_seconds() / 3600

        # Get file size
        size_bytes = artifact_path.stat().st_size

        # Validate content based on file type
        valid = True
        issue_count = None
        error = None

        if filename.endswith(".json"):
            try:
                data = json.loads(artifact_path.read_text())

                # Extract issue count if available
                if filename == "VULNERABILITIES.json":
                    if isinstance(data, list):
                        issue_count = len(data)
                    elif isinstance(data, dict) and "vulnerabilities" in data:
                        issue_count = len(data["vulnerabilities"])

                elif filename == "scan_results.json":
                    if isinstance(data, dict) and "issues" in data:
                        issue_count = len(data["issues"])

            except json.JSONDecodeError as e:
                valid = False
                error = f"Invalid JSON: {e}"

        elif filename.endswith(".md"):
            # Basic validation for markdown
            content = artifact_path.read_text()
            if len(content.strip()) == 0:
                valid = False
                error = "Empty file"

        return ArtifactStatus(
            exists=True,
            path=artifact_path,
            valid=valid,
            age_hours=age_hours,
            size_bytes=size_bytes,
            issue_count=issue_count,
            error=error,
        )

    def get_subagent_dependencies(self, subagent: str) -> Dict[str, Optional[str]]:
        """
        Get artifact dependencies for a sub-agent.

        Args:
            subagent: Sub-agent name

        Returns:
            Dict with 'creates' and 'requires' artifact filenames
        """
        if subagent not in SUBAGENT_ARTIFACTS:
            raise ValueError(f"Unknown sub-agent: {subagent}")

        return {
            "creates": SUBAGENT_ARTIFACTS[subagent]["creates"],
            "requires": SUBAGENT_ARTIFACTS[subagent]["requires"],
        }

    def get_resume_subagents(self, from_subagent: str) -> List[str]:
        """
        Get list of sub-agents to run when resuming from a specific sub-agent.

        Args:
            from_subagent: Sub-agent to resume from

        Returns:
            List of sub-agent names to execute
        """
        if from_subagent not in SUBAGENT_ORDER:
            raise ValueError(f"Unknown sub-agent: {from_subagent}")

        start_index = SUBAGENT_ORDER.index(from_subagent)
        return SUBAGENT_ORDER[start_index:]

    def validate_prerequisites(self, subagent: str) -> Tuple[bool, Optional[str]]:
        """
        Validate that all prerequisites for a sub-agent exist.

        Args:
            subagent: Sub-agent to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        deps = self.get_subagent_dependencies(subagent)
        required = deps["requires"]

        if required is None:
            return True, None

        status = self.check_artifact(required)

        if not status.exists:
            return False, f"Missing prerequisite: {required}"

        if not status.valid:
            return False, f"Invalid prerequisite {required}: {status.error}"

        return True, None

    def prompt_user_choice(
        self, subagent: str, artifact_status: ArtifactStatus, force: bool = False
    ) -> ScanMode:
        """
        Prompt user for action when artifacts already exist.

        Args:
            subagent: Sub-agent being run
            artifact_status: Status of prerequisite artifact
            force: Skip prompts if True

        Returns:
            ScanMode indicating user choice
        """
        if force:
            return ScanMode.USE_EXISTING

        deps = self.get_subagent_dependencies(subagent)
        required = deps["requires"]

        console.print(f"\n🔍 Checking prerequisites for '{subagent}' sub-agent...")

        # Show artifact details
        if artifact_status.exists and artifact_status.valid:
            age_str = self._format_age(artifact_status.age_hours)
            console.print(
                f"✓ Found: .securevibes/{required} (modified: {age_str}", style="green", end=""
            )

            if artifact_status.issue_count is not None:
                console.print(f", {artifact_status.issue_count} issues)", style="green")
            else:
                console.print(")", style="green")

            # Warn if old
            if artifact_status.age_hours and artifact_status.age_hours > 24:
                console.print(
                    f"  ⚠️  Warning: Artifact is {int(artifact_status.age_hours)}h old",
                    style="yellow",
                )

        console.print(f"\n⚠️  Re-running {subagent} will overwrite existing results.\n")

        # Show options
        console.print("Options:")
        console.print(f"  1. Use existing {required} and run {subagent} only [default]")
        console.print("  2. Re-run entire scan (all sub-agents)")
        console.print("  3. Cancel")

        choice = click.prompt("\nChoice", type=int, default=1, show_default=False)

        if choice == 1:
            return ScanMode.USE_EXISTING
        elif choice == 2:
            return ScanMode.FULL_RESCAN
        else:
            return ScanMode.CANCEL

    def display_artifact_summary(self, artifact_status: ArtifactStatus, filename: str):
        """Display a summary table of artifact details"""
        if not artifact_status.exists:
            return

        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Property", style="dim")
        table.add_column("Value")

        table.add_row("File", filename)
        table.add_row("Status", "✓ Valid" if artifact_status.valid else "❌ Invalid")

        if artifact_status.age_hours is not None:
            table.add_row("Age", self._format_age(artifact_status.age_hours))

        if artifact_status.size_bytes is not None:
            table.add_row("Size", self._format_size(artifact_status.size_bytes))

        if artifact_status.issue_count is not None:
            table.add_row("Issues", str(artifact_status.issue_count))

        if artifact_status.error:
            table.add_row("Error", artifact_status.error)

        console.print(table)

    def _format_age(self, hours: float) -> str:
        """Format age in human-readable format"""
        if hours < 1:
            return f"{int(hours * 60)}m ago"
        elif hours < 24:
            return f"{int(hours)}h ago"
        else:
            days = int(hours / 24)
            return f"{days}d ago"

    def _format_size(self, bytes: int) -> str:
        """Format file size in human-readable format"""
        if bytes < 1024:
            return f"{bytes}B"
        elif bytes < 1024 * 1024:
            return f"{bytes / 1024:.1f}KB"
        else:
            return f"{bytes / (1024 * 1024):.1f}MB"
