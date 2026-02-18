"""Real-time progress tracking for scan operations."""

import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from rich.console import Console

# Artifact file names referenced during phase-completion logging.
SECURITY_FILE = "SECURITY.md"
THREAT_MODEL_FILE = "THREAT_MODEL.json"
VULNERABILITIES_FILE = "VULNERABILITIES.json"
PR_VULNERABILITIES_FILE = "PR_VULNERABILITIES.json"
SCAN_RESULTS_FILE = "scan_results.json"


class ProgressTracker:
    """
    Real-time progress tracking for scan operations.

    Tracks tool usage, file operations, and sub-agent lifecycle events
    to provide detailed progress feedback during long-running scans.
    """

    def __init__(
        self, console: Console, debug: bool = False, single_subagent: Optional[str] = None
    ):
        self.console = console
        self.debug = debug
        self.current_phase = None
        self.tool_count = 0
        self.files_read = set()
        self.files_written = set()
        self.subagent_stack = []  # Track nested subagents
        self.last_update = datetime.now()
        self.phase_start_time = None
        self.single_subagent = single_subagent

        # Phase display names (DAST is optional, added dynamically)
        self.phase_display = {
            "assessment": "1/4: Architecture Assessment",
            "threat-modeling": "2/4: Threat Modeling (STRIDE Analysis)",
            "code-review": "3/4: Code Review (Security Analysis)",
            "pr-code-review": "PR Review: Code Review",
            "report-generator": "4/4: Report Generation",
            "dast": "5/5: DAST Validation",
        }

        # Override display for single sub-agent mode
        if single_subagent:
            self.phase_display[single_subagent] = (
                f"Sub-Agent 1/1: {self._get_subagent_title(single_subagent)}"
            )

    def _get_subagent_title(self, subagent: str) -> str:
        """Get human-readable title for sub-agent"""
        titles = {
            "assessment": "Architecture Assessment",
            "threat-modeling": "Threat Modeling (STRIDE Analysis)",
            "code-review": "Code Review (Security Analysis)",
            "pr-code-review": "PR Review (Security Analysis)",
            "report-generator": "Report Generation",
            "dast": "DAST Validation",
        }
        return titles.get(subagent, subagent)

    def announce_phase(self, phase_name: str):
        """Announce the start of a new phase"""
        self.current_phase = phase_name
        self.phase_start_time = time.time()
        self.tool_count = 0
        self.files_read.clear()
        self.files_written.clear()

        display_name = self.phase_display.get(phase_name, phase_name)
        self.console.print(f"\n━━━ Phase {display_name} ━━━\n", style="bold cyan")

    def on_tool_start(self, tool_name: str, tool_input: dict):
        """Called when a tool execution begins"""
        self.tool_count += 1
        self.last_update = datetime.now()

        # Show meaningful progress based on tool type
        if tool_name == "Read":
            file_path = tool_input.get("file_path") or tool_input.get("path") or ""
            if file_path:
                self.files_read.add(file_path)

        elif tool_name == "Grep":
            pattern = tool_input.get("pattern", "")
            if pattern:
                self.console.print(f"  🔍 Searching: {pattern[:60]}", style="dim")

        elif tool_name == "Glob":
            patterns = tool_input.get("patterns", [])
            if patterns:
                self.console.print(f"  🗂️  Finding files: {', '.join(patterns[:3])}", style="dim")

        elif tool_name == "Write":
            file_path = tool_input.get("file_path", "")
            if file_path:
                self.files_written.add(file_path)

        elif tool_name == "Task":
            # Sub-agent orchestration
            agent = tool_input.get("agent_name") or tool_input.get("subagent_type")
            goal = tool_input.get("prompt", "")

            # Show more detail in debug mode, truncate intelligently
            max_length = 200 if self.debug else 100
            if len(goal) > max_length:
                # Truncate at word boundary
                truncated = goal[:max_length].rsplit(" ", 1)[0]
                goal_display = f"{truncated}..."
            else:
                goal_display = goal

            if agent:
                self.console.print(f"  🤖 Starting {agent}: {goal_display}", style="bold yellow")
                self.subagent_stack.append(agent)
                self.announce_phase(agent)

        elif tool_name == "LS":
            path = tool_input.get("directory_path", "")
            if path:
                self.console.print("  📂 Listing directory", style="dim")

        # Note: Skill tool logging removed - SDK auto-loads skills from .claude/skills/
        # without explicit Skill tool calls. Skill sync is logged in _setup_*_skills().

        # Show progress every 20 tools for activity indicator
        if self.tool_count % 20 == 0 and not self.debug:
            self.console.print(
                f"  ⏳ Processing... ({self.tool_count} tools, "
                f"{len(self.files_read)} files read)",
                style="dim",
            )

    def on_tool_complete(self, tool_name: str, success: bool, error_msg: Optional[str] = None):
        """Called when a tool execution completes"""
        if not success:
            if error_msg:
                self.console.print(
                    f"  ⚠️  Tool {tool_name} failed: {error_msg[:80]}", style="yellow"
                )
            else:
                self.console.print(f"  ⚠️  Tool {tool_name} failed", style="yellow")

    def on_subagent_stop(self, agent_name: str, duration_ms: int):
        """
        Called when a sub-agent completes - DETERMINISTIC phase completion marker.

        This provides reliable phase boundary detection without file polling.
        """
        if self.subagent_stack and self.subagent_stack[-1] == agent_name:
            self.subagent_stack.pop()

        duration_sec = duration_ms / 1000
        display_name = self.phase_display.get(agent_name, agent_name)

        # Show completion summary
        self.console.print(f"\n✅ Phase {display_name} Complete", style="bold green")
        self.console.print(
            f"   Duration: {duration_sec:.1f}s | "
            f"Tools: {self.tool_count} | "
            f"Files: {len(self.files_read)} read, {len(self.files_written)} written",
            style="green",
        )

        # Show what was created
        if agent_name == "assessment" and SECURITY_FILE in [
            Path(f).name for f in self.files_written
        ]:
            self.console.print(f"   Created: {SECURITY_FILE}", style="green")
        elif agent_name == "threat-modeling" and THREAT_MODEL_FILE in [
            Path(f).name for f in self.files_written
        ]:
            self.console.print(f"   Created: {THREAT_MODEL_FILE}", style="green")
        elif agent_name == "code-review" and VULNERABILITIES_FILE in [
            Path(f).name for f in self.files_written
        ]:
            self.console.print(f"   Created: {VULNERABILITIES_FILE}", style="green")
        elif agent_name == "report-generator" and SCAN_RESULTS_FILE in [
            Path(f).name for f in self.files_written
        ]:
            self.console.print(f"   Created: {SCAN_RESULTS_FILE}", style="green")
        elif agent_name == "pr-code-review" and PR_VULNERABILITIES_FILE in [
            Path(f).name for f in self.files_written
        ]:
            self.console.print(f"   Created: {PR_VULNERABILITIES_FILE}", style="green")
        elif agent_name == "dast" and "DAST_VALIDATION.json" in [
            Path(f).name for f in self.files_written
        ]:
            self.console.print("   Created: DAST_VALIDATION.json", style="green")

    def on_assistant_text(self, text: str):
        """Called when the assistant produces text output"""
        if self.debug and text.strip():
            # Show agent narration in debug mode
            text_preview = text[:120].replace("\n", " ")
            if len(text) > 120:
                text_preview += "..."
            self.console.print(f"  💭 {text_preview}", style="dim italic")

    def get_summary(self) -> Dict[str, Any]:
        """Get current progress summary"""
        return {
            "current_phase": self.current_phase,
            "tool_count": self.tool_count,
            "files_read": len(self.files_read),
            "files_written": len(self.files_written),
            "subagent_depth": len(self.subagent_stack),
        }
