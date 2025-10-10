"""Security scanner with real-time progress tracking using ClaudeSDKClient"""

import os
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from rich.console import Console

from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions
from claude_agent_sdk.types import (
    AssistantMessage,
    ToolUseBlock,
    ToolResultBlock,
    TextBlock,
    ResultMessage
)

from securevibes.agents.definitions import SECUREVIBES_AGENTS
from securevibes.models.result import ScanResult
from securevibes.models.issue import SecurityIssue, Severity
from securevibes.prompts.loader import load_prompt
from securevibes.config import config

# Constants for artifact paths
SECUREVIBES_DIR = ".securevibes"
SECURITY_FILE = "SECURITY.md"
THREAT_MODEL_FILE = "THREAT_MODEL.json"
VULNERABILITIES_FILE = "VULNERABILITIES.json"
SCAN_RESULTS_FILE = "scan_results.json"


class ProgressTracker:
    """
    Real-time progress tracking for scan operations.
    
    Tracks tool usage, file operations, and sub-agent lifecycle events
    to provide detailed progress feedback during long-running scans.
    """
    
    def __init__(self, console: Console, debug: bool = False):
        self.console = console
        self.debug = debug
        self.current_phase = None
        self.tool_count = 0
        self.files_read = set()
        self.files_written = set()
        self.subagent_stack = []  # Track nested subagents
        self.last_update = datetime.now()
        self.phase_start_time = None
        
        # Phase display names
        self.phase_display = {
            "assessment": "1/4: Architecture Assessment",
            "threat-modeling": "2/4: Threat Modeling (STRIDE Analysis)",
            "code-review": "3/4: Code Review (Security Analysis)",
            "report-generator": "4/4: Report Generation"
        }
    
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
            file_path = tool_input.get("file_path", "")
            if file_path:
                self.files_read.add(file_path)
                filename = Path(file_path).name
                self.console.print(f"  📖 Reading {filename}", style="dim")
        
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
                filename = Path(file_path).name
                self.console.print(f"  💾 Writing {filename}", style="cyan")
        
        elif tool_name == "Task":
            # Sub-agent orchestration
            agent = tool_input.get("agent_name") or tool_input.get("subagent_type")
            goal = tool_input.get("prompt", "")
            
            # Show more detail in debug mode, truncate intelligently
            max_length = 200 if self.debug else 100
            if len(goal) > max_length:
                # Truncate at word boundary
                truncated = goal[:max_length].rsplit(' ', 1)[0]
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
                self.console.print(f"  📂 Listing directory", style="dim")
        
        # Show progress every 20 tools for activity indicator
        if self.tool_count % 20 == 0 and not self.debug:
            self.console.print(
                f"  ⏳ Processing... ({self.tool_count} tools, "
                f"{len(self.files_read)} files read)",
                style="dim"
            )
    
    def on_tool_complete(self, tool_name: str, success: bool, error_msg: Optional[str] = None):
        """Called when a tool execution completes"""
        if not success:
            if error_msg:
                self.console.print(
                    f"  ⚠️  Tool {tool_name} failed: {error_msg[:80]}",
                    style="yellow"
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
        self.console.print(
            f"\n✅ Phase {display_name} Complete",
            style="bold green"
        )
        self.console.print(
            f"   Duration: {duration_sec:.1f}s | "
            f"Tools: {self.tool_count} | "
            f"Files: {len(self.files_read)} read, {len(self.files_written)} written",
            style="green"
        )
        
        # Show what was created
        if agent_name == "assessment" and SECURITY_FILE in [Path(f).name for f in self.files_written]:
            self.console.print(f"   Created: {SECURITY_FILE}", style="green")
        elif agent_name == "threat-modeling" and THREAT_MODEL_FILE in [Path(f).name for f in self.files_written]:
            self.console.print(f"   Created: {THREAT_MODEL_FILE}", style="green")
        elif agent_name == "code-review" and VULNERABILITIES_FILE in [Path(f).name for f in self.files_written]:
            self.console.print(f"   Created: {VULNERABILITIES_FILE}", style="green")
        elif agent_name == "report-generator" and SCAN_RESULTS_FILE in [Path(f).name for f in self.files_written]:
            self.console.print(f"   Created: {SCAN_RESULTS_FILE}", style="green")
    
    def on_assistant_text(self, text: str):
        """Called when the assistant produces text output"""
        if self.debug and text.strip():
            # Show agent narration in debug mode
            text_preview = text[:120].replace('\n', ' ')
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
            "subagent_depth": len(self.subagent_stack)
        }


class Scanner:
    """
    Security scanner using ClaudeSDKClient with real-time progress tracking.
    
    Provides progress updates via hooks, eliminating silent periods during
    long-running scans. Uses deterministic sub-agent lifecycle events instead of
    file polling for phase detection.
    """

    def __init__(
        self,
        model: str = "sonnet",
        debug: bool = False
    ):
        """
        Initialize streaming scanner.

        Args:
            model: Claude model name (e.g., sonnet, haiku)
            debug: Enable verbose debug output including agent narration
        """
        self.model = model
        self.debug = debug
        self.total_cost = 0.0
        self.console = Console()

    async def scan(self, repo_path: str) -> ScanResult:
        """
        Run complete security scan with real-time progress streaming.

        Args:
            repo_path: Path to repository to scan

        Returns:
            ScanResult with all findings
        """
        repo = Path(repo_path).resolve()
        if not repo.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        # Ensure .securevibes directory exists
        securevibes_dir = repo / SECUREVIBES_DIR
        try:
            securevibes_dir.mkdir(exist_ok=True)
        except (OSError, PermissionError) as e:
            raise RuntimeError(f"Failed to create output directory {securevibes_dir}: {e}")

        # Track scan timing
        scan_start_time = time.time()
        
        # Count files for reporting
        files_scanned = len(list(repo.glob('**/*.py'))) + len(list(repo.glob('**/*.ts'))) + \
                       len(list(repo.glob('**/*.js'))) + len(list(repo.glob('**/*.tsx'))) + \
                       len(list(repo.glob('**/*.jsx')))

        # Show scan info (banner already printed by CLI)
        self.console.print(f"📁 Scanning: {repo}")
        self.console.print(f"🤖 Model: {self.model}")
        self.console.print("="*60)

        # Initialize progress tracker
        tracker = ProgressTracker(self.console, debug=self.debug)

        # Create hooks as closures that capture the tracker
        async def pre_tool_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
            """Hook that fires before any tool executes"""
            tool_name = input_data.get("tool_name")
            tool_input = input_data.get("tool_input", {})
            tracker.on_tool_start(tool_name, tool_input)
            return {}

        async def post_tool_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
            """Hook that fires after a tool completes"""
            tool_name = input_data.get("tool_name")
            tool_response = input_data.get("tool_response", {})
            is_error = tool_response.get("is_error", False)
            error_msg = tool_response.get("content", "") if is_error else None
            tracker.on_tool_complete(tool_name, not is_error, error_msg)
            return {}

        async def subagent_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
            """Hook that fires when a sub-agent completes"""
            agent_name = input_data.get("agent_name") or input_data.get("subagent_type")
            duration_ms = input_data.get("duration_ms", 0)
            if agent_name:
                tracker.on_subagent_stop(agent_name, duration_ms)
            return {}

        # Configure agent options with hooks
        from claude_agent_sdk.types import HookMatcher
        
        options = ClaudeAgentOptions(
            agents=SECUREVIBES_AGENTS,
            cwd=str(repo),
            max_turns=config.get_max_turns(),
            permission_mode='bypassPermissions',
            model=self.model,
            hooks={
                "PreToolUse": [HookMatcher(hooks=[pre_tool_hook])],
                "PostToolUse": [HookMatcher(hooks=[post_tool_hook])],
                "SubagentStop": [HookMatcher(hooks=[subagent_hook])]
            }
        )

        # Load orchestration prompt
        orchestration_prompt = load_prompt("main", category="orchestration")

        # Execute scan with streaming progress
        try:
            async with ClaudeSDKClient(options=options) as client:
                await client.query(orchestration_prompt)

                # Stream messages for real-time progress
                async for message in client.receive_messages():
                    if isinstance(message, AssistantMessage):
                        for block in message.content:
                            if isinstance(block, TextBlock):
                                # Show agent narration if in debug mode
                                tracker.on_assistant_text(block.text)
                            
                            elif isinstance(block, ToolUseBlock):
                                # Tool execution tracked via hooks
                                pass
                    
                    elif isinstance(message, ResultMessage):
                        # Track costs in real-time
                        if message.total_cost_usd:
                            self.total_cost = message.total_cost_usd
                            if self.debug:
                                self.console.print(
                                    f"  💰 Cost update: ${self.total_cost:.4f}",
                                    style="cyan"
                                )
                        # ResultMessage indicates scan completion - exit the loop
                        break

            self.console.print("\n" + "=" * 80)

        except Exception as e:
            self.console.print(f"\n❌ Scan failed: {e}", style="bold red")
            raise

        # Load and parse results
        try:
            return self._load_scan_results(securevibes_dir, repo, files_scanned, scan_start_time)
        except RuntimeError as e:
            self.console.print(f"❌ Error loading scan results: {e}", style="bold red")
            raise

    def _load_scan_results(
        self,
        securevibes_dir: Path,
        repo: Path,
        files_scanned: int,
        scan_start_time: float
    ) -> ScanResult:
        """
        Load and parse scan results from agent-generated files.
        
        Reuses the same loading logic as SecurityScanner for consistency.
        """
        results_file = securevibes_dir / SCAN_RESULTS_FILE
        vulnerabilities_file = securevibes_dir / VULNERABILITIES_FILE

        scan_result = None

        # Try scan_results.json first
        if results_file.exists():
            try:
                with open(results_file) as f:
                    results_data = json.load(f)
                
                issues_data = results_data.get("issues") or results_data.get("vulnerabilities")
                
                if issues_data and isinstance(issues_data, list):
                    issues = []
                    for idx, issue_data in enumerate(issues_data):
                        try:
                            issue_id = issue_data.get("threat_id") or issue_data.get("id") or f"ISSUE-{idx + 1}"
                            severity_str = issue_data["severity"].upper()
                            
                            issues.append(SecurityIssue(
                                id=issue_id,
                                title=issue_data["title"],
                                description=issue_data["description"],
                                severity=Severity[severity_str],
                                file_path=issue_data["file_path"],
                                line_number=issue_data.get("line_number"),
                                code_snippet=issue_data.get("code_snippet"),
                                cwe_id=issue_data.get("cwe_id"),
                                recommendation=issue_data.get("recommendation")
                            ))
                        except (KeyError, ValueError) as e:
                            if self.debug:
                                self.console.print(
                                    f"⚠️  Warning: Failed to parse issue #{idx + 1}: {e}",
                                    style="yellow"
                                )
                            continue

                    scan_duration = time.time() - scan_start_time
                    scan_result = ScanResult(
                        repository_path=str(repo),
                        issues=issues,
                        files_scanned=files_scanned,
                        scan_time_seconds=round(scan_duration, 2),
                        total_cost_usd=self.total_cost
                    )
                    return scan_result
                    
            except (OSError, PermissionError, json.JSONDecodeError) as e:
                if self.debug:
                    self.console.print(
                        f"⚠️  Warning: Cannot load {SCAN_RESULTS_FILE}: {e}",
                        style="yellow"
                    )

        # Fallback to VULNERABILITIES.json
        if scan_result is None and vulnerabilities_file.exists():
            try:
                with open(vulnerabilities_file) as f:
                    vulnerabilities_data = json.load(f)
                
                if isinstance(vulnerabilities_data, list):
                    vulnerabilities = vulnerabilities_data
                elif isinstance(vulnerabilities_data, dict) and "vulnerabilities" in vulnerabilities_data:
                    vulnerabilities = vulnerabilities_data["vulnerabilities"]
                else:
                    raise ValueError(f"Unexpected format in {VULNERABILITIES_FILE}")

                issues = []
                for idx, vuln in enumerate(vulnerabilities):
                    try:
                        issue_id = vuln.get("threat_id") or vuln.get("id") or f"VULN-{idx + 1}"
                        severity_str = vuln["severity"].upper()
                        
                        issues.append(SecurityIssue(
                            id=issue_id,
                            title=vuln["title"],
                            description=vuln["description"],
                            severity=Severity[severity_str],
                            file_path=vuln["file_path"],
                            line_number=vuln.get("line_number"),
                            code_snippet=vuln.get("code_snippet"),
                            cwe_id=vuln.get("cwe_id"),
                            recommendation=vuln.get("recommendation")
                        ))
                    except (KeyError, ValueError) as e:
                        if self.debug:
                            self.console.print(
                                f"⚠️  Warning: Failed to parse vulnerability #{idx + 1}: {e}",
                                style="yellow"
                            )
                        continue

                scan_duration = time.time() - scan_start_time
                scan_result = ScanResult(
                    repository_path=str(repo),
                    issues=issues,
                    files_scanned=files_scanned,
                    scan_time_seconds=round(scan_duration, 2),
                    total_cost_usd=self.total_cost
                )
                return scan_result
                
            except (OSError, PermissionError, json.JSONDecodeError, ValueError) as e:
                raise RuntimeError(f"Failed to load {VULNERABILITIES_FILE}: {e}")

        # No results found
        raise RuntimeError(
            f"Scan failed to generate results. Expected files not found:\n"
            f"  - {results_file}\n"
            f"  - {vulnerabilities_file}\n"
            f"Check {securevibes_dir}/ for partial artifacts."
        )
