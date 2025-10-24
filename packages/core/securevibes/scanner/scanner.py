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

from securevibes.agents.definitions import create_agent_definitions
from securevibes.models.result import ScanResult
from securevibes.models.issue import SecurityIssue, Severity
from securevibes.prompts.loader import load_prompt
from securevibes.config import config
from securevibes.scanner.subagent_manager import SubAgentManager, ScanMode

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
    
    def __init__(self, console: Console, debug: bool = False, single_subagent: Optional[str] = None):
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
            "report-generator": "4/4: Report Generation",
            "dast": "5/5: DAST Validation"
        }
        
        # Override display for single sub-agent mode
        if single_subagent:
            self.phase_display[single_subagent] = f"Sub-Agent 1/1: {self._get_subagent_title(single_subagent)}"
    
    def _get_subagent_title(self, subagent: str) -> str:
        """Get human-readable title for sub-agent"""
        titles = {
            "assessment": "Architecture Assessment",
            "threat-modeling": "Threat Modeling (STRIDE Analysis)",
            "code-review": "Code Review (Security Analysis)",
            "report-generator": "Report Generation",
            "dast": "DAST Validation"
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
        elif agent_name == "dast" and "DAST_VALIDATION.json" in [Path(f).name for f in self.files_written]:
            self.console.print(f"   Created: DAST_VALIDATION.json", style="green")
    
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
        
        # DAST configuration
        self.dast_enabled = False
        self.dast_config = {}
    
    def configure_dast(
        self,
        target_url: str,
        timeout: int = 120,
        accounts_path: Optional[str] = None
    ):
        """
        Configure DAST validation settings.
        
        Args:
            target_url: Target URL for DAST testing
            timeout: Timeout in seconds for DAST validation
            accounts_path: Optional path to test accounts JSON file
        """
        self.dast_enabled = True
        self.dast_config = {
            "target_url": target_url,
            "timeout": timeout,
            "accounts_path": accounts_path
        }
    
    async def scan_subagent(
        self,
        repo_path: str,
        subagent: str,
        force: bool = False,
        skip_checks: bool = False
    ) -> ScanResult:
        """
        Run a single sub-agent with artifact validation.
        
        Args:
            repo_path: Path to repository to scan
            subagent: Sub-agent name to execute
            force: Skip confirmation prompts
            skip_checks: Skip artifact validation
        
        Returns:
            ScanResult with findings
        """
        repo = Path(repo_path).resolve()
        manager = SubAgentManager(repo, quiet=False)
        
        # Validate prerequisites unless skipped
        if not skip_checks:
            is_valid, error = manager.validate_prerequisites(subagent)
            
            if not is_valid:
                deps = manager.get_subagent_dependencies(subagent)
                required = deps["requires"]
                
                self.console.print(f"[bold red]❌ Error:[/bold red] '{subagent}' requires {required}")
                self.console.print(f"\n.securevibes/{required} not found.\n")
                
                # Offer to run prerequisites
                self.console.print("Options:")
                self.console.print(f"  1. Run from prerequisite sub-agents (includes {subagent})")
                self.console.print("  2. Run full scan (all sub-agents)")
                self.console.print("  3. Cancel")
                
                import click
                choice = click.prompt("\nChoice", type=int, default=3, show_default=False)
                
                if choice == 1:
                    # Find which sub-agent creates the required artifact
                    from securevibes.scanner.subagent_manager import SUBAGENT_ARTIFACTS, SUBAGENT_ORDER
                    for sa_name in SUBAGENT_ORDER:
                        if SUBAGENT_ARTIFACTS[sa_name]["creates"] == required:
                            return await self.scan_resume(repo_path, sa_name, force, skip_checks)
                    raise RuntimeError(f"Could not find sub-agent that creates {required}")
                elif choice == 2:
                    return await self.scan(repo_path)
                else:
                    raise RuntimeError("Scan cancelled by user")
            
            # Check if prerequisite exists and prompt user
            deps = manager.get_subagent_dependencies(subagent)
            if deps["requires"]:
                artifact_status = manager.check_artifact(deps["requires"])
                if artifact_status.exists and artifact_status.valid:
                    mode = manager.prompt_user_choice(subagent, artifact_status, force)
                    
                    if mode == ScanMode.CANCEL:
                        raise RuntimeError("Scan cancelled by user")
                    elif mode == ScanMode.FULL_RESCAN:
                        # Run full scan
                        return await self.scan(repo_path)
                    # else: ScanMode.USE_EXISTING - continue with single sub-agent
        
        # Set environment variable to run only this sub-agent
        os.environ["RUN_ONLY_SUBAGENT"] = subagent
        
        # Auto-enable DAST if running dast sub-agent
        if subagent == "dast" and self.dast_enabled:
            os.environ["DAST_ENABLED"] = "true"
            os.environ["DAST_TARGET_URL"] = self.dast_config["target_url"]
            os.environ["DAST_TIMEOUT"] = str(self.dast_config["timeout"])
            if self.dast_config.get("accounts_path"):
                accounts_file = Path(self.dast_config["accounts_path"])
                if accounts_file.exists():
                    os.environ["DAST_TEST_ACCOUNTS"] = accounts_file.read_text()
        
        # Run scan with single sub-agent
        return await self._execute_scan(repo, single_subagent=subagent)
    
    async def scan_resume(
        self,
        repo_path: str,
        from_subagent: str,
        force: bool = False,
        skip_checks: bool = False
    ) -> ScanResult:
        """
        Resume scan from a specific sub-agent onwards.
        
        Args:
            repo_path: Path to repository to scan
            from_subagent: Sub-agent to resume from
            force: Skip confirmation prompts
            skip_checks: Skip artifact validation
        
        Returns:
            ScanResult with findings
        """
        repo = Path(repo_path).resolve()
        manager = SubAgentManager(repo, quiet=False)
        
        # Get list of sub-agents to run
        subagents_to_run = manager.get_resume_subagents(from_subagent)
        
        # Validate prerequisites unless skipped
        if not skip_checks:
            is_valid, error = manager.validate_prerequisites(from_subagent)
            
            if not is_valid:
                self.console.print(f"[bold red]❌ Error:[/bold red] {error}")
                raise RuntimeError(error)
            
            # Show what will be run
            self.console.print(f"\n🔍 Resuming from '{from_subagent}' sub-agent...")
            deps = manager.get_subagent_dependencies(from_subagent)
            if deps["requires"]:
                artifact_status = manager.check_artifact(deps["requires"])
                if artifact_status.exists:
                    self.console.print(f"✓ Found: .securevibes/{deps['requires']} (prerequisite for {from_subagent})", style="green")
            
            self.console.print(f"\nWill run: {' → '.join(subagents_to_run)}")
            if "dast" not in subagents_to_run and not self.dast_enabled:
                self.console.print("(DAST not enabled - use --dast --target-url to include)")
            
            if not force:
                import click
                if not click.confirm("\nProceed?", default=True):
                    raise RuntimeError("Scan cancelled by user")
        
        # Set environment variables for resume mode
        os.environ["RESUME_FROM_SUBAGENT"] = from_subagent
        
        # Calculate which sub-agents to skip
        from securevibes.scanner.subagent_manager import SUBAGENT_ORDER
        skip_index = SUBAGENT_ORDER.index(from_subagent)
        skip_subagents = SUBAGENT_ORDER[:skip_index]
        if skip_subagents:
            os.environ["SKIP_SUBAGENTS"] = ",".join(skip_subagents)
        
        # Configure DAST if enabled and in resume list
        if "dast" in subagents_to_run and self.dast_enabled:
            os.environ["DAST_ENABLED"] = "true"
            os.environ["DAST_TARGET_URL"] = self.dast_config["target_url"]
            os.environ["DAST_TIMEOUT"] = str(self.dast_config["timeout"])
            if self.dast_config.get("accounts_path"):
                accounts_file = Path(self.dast_config["accounts_path"])
                if accounts_file.exists():
                    os.environ["DAST_TEST_ACCOUNTS"] = accounts_file.read_text()
        
        # Run scan from this sub-agent onwards
        return await self._execute_scan(repo, resume_from=from_subagent)
    
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
        
        # Configure DAST environment variables if enabled
        if self.dast_enabled:
            os.environ["DAST_ENABLED"] = "true"
            os.environ["DAST_TARGET_URL"] = self.dast_config["target_url"]
            os.environ["DAST_TIMEOUT"] = str(self.dast_config["timeout"])
            
            if self.dast_config.get("accounts_path"):
                accounts_file = Path(self.dast_config["accounts_path"])
                if accounts_file.exists():
                    os.environ["DAST_TEST_ACCOUNTS"] = accounts_file.read_text()
        
        return await self._execute_scan(repo)
    
    async def _execute_scan(
        self,
        repo: Path,
        single_subagent: Optional[str] = None,
        resume_from: Optional[str] = None
    ) -> ScanResult:
        """
        Internal method to execute scan with optional sub-agent filtering.
        
        Args:
            repo: Repository path (already resolved)
            single_subagent: If set, run only this sub-agent
            resume_from: If set, resume from this sub-agent onwards
        
        Returns:
            ScanResult with findings
        """
        # Ensure .securevibes directory exists
        securevibes_dir = repo / SECUREVIBES_DIR
        try:
            securevibes_dir.mkdir(exist_ok=True)
        except (OSError, PermissionError) as e:
            raise RuntimeError(f"Failed to create output directory {securevibes_dir}: {e}")

        # Track scan timing
        scan_start_time = time.time()
        
        # Directories to exclude from scanning (infrastructure, not application code)
        exclude_dirs = {'.claude', 'env', 'venv', '.venv', 'node_modules', '.git', 
                       '__pycache__', '.pytest_cache', 'dist', 'build', '.eggs'}
        
        # Count files for reporting (exclude infrastructure directories)
        def should_scan(file_path: Path) -> bool:
            """Check if file should be included in security scan"""
            return not any(excluded in file_path.parts for excluded in exclude_dirs)
        
        all_py = [f for f in repo.glob('**/*.py') if should_scan(f)]
        all_ts = [f for f in repo.glob('**/*.ts') if should_scan(f)]
        all_js = [f for f in repo.glob('**/*.js') if should_scan(f)]
        all_tsx = [f for f in repo.glob('**/*.tsx') if should_scan(f)]
        all_jsx = [f for f in repo.glob('**/*.jsx') if should_scan(f)]
        
        files_scanned = len(all_py) + len(all_ts) + len(all_js) + len(all_tsx) + len(all_jsx)

        # Show scan info (banner already printed by CLI)
        self.console.print(f"📁 Scanning: {repo}")
        self.console.print(f"🤖 Model: {self.model}")
        self.console.print("="*60)

        # Initialize progress tracker
        tracker = ProgressTracker(self.console, debug=self.debug, single_subagent=single_subagent)

        # Define infrastructure directories to exclude
        exclude_dirs = {'.claude', 'env', 'venv', '.venv', 'node_modules', '.git', 
                       '__pycache__', '.pytest_cache', 'dist', 'build', '.eggs'}
        
        # Create hooks as closures that capture the tracker
        async def pre_tool_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
            """Hook that fires before any tool executes"""
            tool_name = input_data.get("tool_name")
            tool_input = input_data.get("tool_input", {})
            
            # Block reads from infrastructure directories
            if tool_name in ["Read", "Grep", "Glob", "LS"]:
                # Extract path from tool input (different tools use different param names)
                path = (tool_input.get("file_path") or 
                       tool_input.get("path") or 
                       tool_input.get("directory_path") or "")
                
                if path:
                    # Check if path contains any excluded directory
                    path_parts = Path(path).parts if path else []
                    if any(excluded in path_parts for excluded in exclude_dirs):
                        # Return empty result to skip this tool execution
                        if self.debug:
                            self.console.print(
                                f"  ⏭️  Skipped: {path} (infrastructure directory)",
                                style="dim yellow"
                            )
                        return {
                            "override_result": {
                                "content": f"Skipped: Infrastructure directory excluded from scan ({path})",
                                "is_error": False
                            }
                        }
                
                # For Grep, inject excludePatterns to filter out infrastructure directories
                if tool_name == "Grep":
                    # Add exclude patterns for infrastructure directories
                    exclude_patterns = [f"{excluded}/**" for excluded in exclude_dirs]
                    
                    # Add to existing excludePatterns if any, or create new
                    existing_excludes = tool_input.get("excludePatterns", [])
                    tool_input["excludePatterns"] = existing_excludes + exclude_patterns
                    
                    if self.debug:
                        self.console.print(
                            f"  🔍 Grep with exclusions: {len(exclude_patterns)} patterns",
                            style="dim"
                        )
                
                # For Glob, inject excludePatterns
                if tool_name == "Glob":
                    exclude_patterns = [f"{excluded}/**" for excluded in exclude_dirs]
                    existing_excludes = tool_input.get("excludePatterns", [])
                    tool_input["excludePatterns"] = existing_excludes + exclude_patterns
            
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
        
        # Create agent definitions with CLI model override
        # This allows --model flag to cascade to all agents while respecting env vars
        agents = create_agent_definitions(cli_model=self.model)
        
        # Note: Skills are auto-discovered from .claude/skills/ in cwd
        # The SDK will find skills at {repo}/.claude/skills/dast/ automatically
        
        options = ClaudeAgentOptions(
            agents=agents,
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
