"""Security scanner using proper Claude Agent SDK architecture"""

import os
import json
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
from claude_agent_sdk import query, ClaudeAgentOptions
from claude_agent_sdk.types import (
    AssistantMessage,
    TextBlock,
    ResultMessage,
    ToolUseBlock,
    StreamEvent
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

# Query timeout in seconds (10 minutes for full scan)
QUERY_TIMEOUT = 600


class AgentOutputCapture:
    """
    Tracks scan progress and phase completion through file-based polling.
    
    Monitors phase transitions by detecting when agents write their output files
    (SECURITY.md, THREAT_MODEL.json, etc.) and provides progress updates.
    """
    
    def __init__(self, securevibes_dir: Path):
        self.securevibes_dir = securevibes_dir
        
        # Map output files to phases
        self.file_to_phase = {
            SECURITY_FILE: "assessment",
            THREAT_MODEL_FILE: "threat_modeling",
            VULNERABILITIES_FILE: "code_review",
            SCAN_RESULTS_FILE: "report"
        }
        
        self.phase_order = ["assessment", "threat_modeling", "code_review", "report"]
        self.current_phase_idx = 0
        self.completed_phases = set()
        self.phase_announced = set()  # Track which phases we've announced
    
    def get_current_phase(self) -> Optional[str]:
        """Get the current phase name"""
        if self.current_phase_idx < len(self.phase_order):
            return self.phase_order[self.current_phase_idx]
        return None
    
    def mark_phase_complete(self, phase: str) -> Optional[str]:
        """
        Mark a phase as complete and advance to next phase.
        
        Returns:
            Next phase name if available, None otherwise
        """
        if phase in self.completed_phases:
            return None  # Already completed
        
        self.completed_phases.add(phase)
        self.current_phase_idx += 1
        
        return self.get_current_phase()
    
    def should_announce_phase(self, phase: str) -> bool:
        """Check if we should announce this phase starting"""
        return (phase == self.get_current_phase() and 
                phase not in self.completed_phases and
                phase not in self.phase_announced)
    
    def mark_phase_announced(self, phase: str):
        """Mark that we've announced this phase"""
        self.phase_announced.add(phase)
    
    def get_progress_summary(self) -> Dict[str, str]:
        """Get summary of all phase statuses"""
        summary = {}
        for phase in self.phase_order:
            if phase in self.completed_phases:
                summary[phase] = "completed"
            elif phase == self.get_current_phase():
                summary[phase] = "in_progress"
            else:
                summary[phase] = "pending"
        return summary


class SecurityScanner:
    """Main scanner that orchestrates security analysis via Claude agents"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "sonnet", 
        debug: bool = False
    ):
        """
        Initialize scanner

        Args:
            api_key: Claude API key (reads from CLAUDE_API_KEY if not provided)
            model: Claude model name (e.g., sonnet)
            debug: Enable debug output
        """
        if api_key:
            os.environ["CLAUDE_API_KEY"] = api_key

        self.model = model
        self.debug = debug
        self.total_cost = 0.0

    async def scan(self, repo_path: str) -> ScanResult:
        """
        Run complete security scan using Claude's agent orchestration

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

        # Track scan timing and file count
        import time
        scan_start_time = time.time()
        files_scanned = len(list(repo.glob('**/*.py')))

        print(f"📁 Scanning: {repo}")
        print(f"🤖 Model: {self.model}")
        print("="*60)

        # Initialize output capture for phase detection
        output_capture = AgentOutputCapture(securevibes_dir)

        # Configure agent options with partial message streaming for real-time progress
        options = ClaudeAgentOptions(
            agents=SECUREVIBES_AGENTS,
            cwd=str(repo),
            max_turns=config.get_max_turns(),
            permission_mode='bypassPermissions',  # Required for Write tool to work without user prompts
            model=self.model,  # Use the configured model
            include_partial_messages=True  # Enable real-time streaming of agent actions
        )

        # Load orchestration prompt from centralized prompts
        orchestration_prompt = load_prompt("main", category="orchestration")
        
        # Track metadata
        files_analyzed = set()
        file_types_found = set()
        last_activity_time = datetime.now()
        activity_counter = 0
        last_phase_check = datetime.now()
        
        # Track which phases have been announced
        announced_phases = set()

        # Execute orchestrated scan
        try:
            async for message in query(prompt=orchestration_prompt, options=options):
                # Check for phase completions every 2 seconds (file-based detection)
                now = datetime.now()
                if (now - last_phase_check).seconds >= 2:
                    last_phase_check = now
                    current_phase = output_capture.get_current_phase()
                    
                    # Check if current phase output file was created
                    phase_files = {
                        "assessment": securevibes_dir / SECURITY_FILE,
                        "threat_modeling": securevibes_dir / THREAT_MODEL_FILE,
                        "code_review": securevibes_dir / VULNERABILITIES_FILE,
                        "report": securevibes_dir / SCAN_RESULTS_FILE
                    }
                    
                    if current_phase and current_phase in phase_files:
                        phase_file = phase_files[current_phase]
                        if phase_file.exists():
                            # Phase completed!
                            phase_display = {
                                "assessment": ("1/4: Architecture Assessment", SECURITY_FILE),
                                "threat_modeling": ("2/4: Threat Modeling (STRIDE Analysis)", THREAT_MODEL_FILE),
                                "code_review": ("3/4: Code Review (Security Analysis)", VULNERABILITIES_FILE),
                                "report": ("4/4: Report Generation", SCAN_RESULTS_FILE)
                            }
                            
                            title, filename = phase_display[current_phase]
                            print(f"\n✅ Phase {title} Complete")
                            if files_analyzed and current_phase == "assessment":
                                print(f"   Analyzed {len(files_analyzed)} files")
                                if file_types_found:
                                    print(f"   Technologies: {', '.join(sorted(file_types_found))}")
                            print(f"   Created: {filename}")
                            
                            # Move to next phase
                            next_phase = output_capture.mark_phase_complete(current_phase)
                            if next_phase and next_phase in phase_display:
                                title, _ = phase_display[next_phase]
                                print(f"\n━━━ Phase {title} ━━━")
                
                # Handle real-time streaming events for better progress visibility
                if isinstance(message, StreamEvent):
                    event = message.event
                    if isinstance(event, dict):
                        event_type = event.get('type')
                        
                        # Track tool usage for activity counter
                        if event_type == 'content_block_start':
                            content_block = event.get('content_block', {})
                            if content_block.get('type') == 'tool_use':
                                activity_counter += 1
                                
                                # Show progress every 10 tools for cleaner output
                                if activity_counter % 10 == 0:
                                    print(f"  ⏳ Analyzing... ({activity_counter} tools used)")
                
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            # Minimal text processing - just for hints about what's happening
                            text_lower = block.text.lower()
                            current_phase = output_capture.get_current_phase()
                            
                            # Announce phase start based on agent mentions (one time only)
                            if current_phase and output_capture.should_announce_phase(current_phase):
                                phase_keywords = {
                                    "assessment": ["assessment agent", "analyze architecture"],
                                    "threat_modeling": ["threat-modeling agent", "threat model", "stride"],
                                    "code_review": ["code-review agent", "review", "vulnerabilit"],
                                    "report": ["report-generator", "final report", "compil"]
                                }
                                
                                keywords = phase_keywords.get(current_phase, [])
                                if any(kw in text_lower for kw in keywords):
                                    phase_display = {
                                        "assessment": "1/4: Architecture Assessment",
                                        "threat_modeling": "2/4: Threat Modeling (STRIDE Analysis)",
                                        "code_review": "3/4: Code Review (Security Analysis)",
                                        "report": "4/4: Report Generation"
                                    }
                                    if current_phase in phase_display:
                                        print(f"\n━━━ Phase {phase_display[current_phase]} ━━━")
                                        output_capture.mark_phase_announced(current_phase)

                        elif isinstance(block, ToolUseBlock):
                            # ToolUseBlock tracking is now handled by StreamEvents above
                            # This keeps the timestamp updated for any other purposes
                            last_activity_time = datetime.now()

                # Track costs
                if isinstance(message, ResultMessage):
                    if message.total_cost_usd:
                        self.total_cost = message.total_cost_usd

            print()
            print("=" * 80)

        except Exception as e:
            # Catch any errors during scan and provide helpful message
            print(f"\n❌ Scan failed: {e}")
            raise

        # Load and parse results from agent-generated files
        try:
            return self._load_scan_results(securevibes_dir, repo, files_scanned, scan_start_time)
        except RuntimeError as e:
            print(f"❌ Error loading scan results: {e}")
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
        
        Tries to load from scan_results.json first, falls back to VULNERABILITIES.json.
        
        Args:
            securevibes_dir: Path to .securevibes directory
            repo: Repository path
            files_scanned: Number of files scanned
            scan_start_time: Start time for duration calculation
            
        Returns:
            ScanResult with parsed issues
            
        Raises:
            RuntimeError: If results cannot be loaded or parsed
        """
        import time
        
        security_file = securevibes_dir / SECURITY_FILE
        threat_file = securevibes_dir / THREAT_MODEL_FILE
        vulnerabilities_file = securevibes_dir / VULNERABILITIES_FILE
        results_file = securevibes_dir / SCAN_RESULTS_FILE

        # Log validation status
        if self.debug:
            print("\n🔍 Validating phase outputs:")
            print(f"  {SECURITY_FILE}: {'✅' if security_file.exists() else '❌'}")
            print(f"  {THREAT_MODEL_FILE}: {'✅' if threat_file.exists() else '❌'}")
            print(f"  {VULNERABILITIES_FILE}: {'✅' if vulnerabilities_file.exists() else '❌'}")
            print(f"  {SCAN_RESULTS_FILE}: {'✅' if results_file.exists() else '❌'}")
            
            # Validate VULNERABILITIES.json structure
            if vulnerabilities_file.exists():
                try:
                    with open(vulnerabilities_file) as f:
                        vuln_data = json.load(f)
                    if isinstance(vuln_data, list):
                        print(f"  ✅ {VULNERABILITIES_FILE} is a valid array with {len(vuln_data)} items")
                    elif isinstance(vuln_data, dict) and "vulnerabilities" in vuln_data:
                        print(f"  ⚠️  {VULNERABILITIES_FILE} is wrapped object (should be flat array)")
                        print(f"     Contains {len(vuln_data['vulnerabilities'])} vulnerabilities")
                    else:
                        print(f"  ❌ {VULNERABILITIES_FILE} has unexpected format")
                except json.JSONDecodeError:
                    print(f"  ❌ {VULNERABILITIES_FILE} is invalid JSON")
                except (OSError, PermissionError) as e:
                    print(f"  ❌ Error reading {VULNERABILITIES_FILE}: {e}")
            print()

        scan_result = None

        # Try to load from scan_results.json first (created by report-generator)
        if results_file.exists():
            try:
                with open(results_file) as f:
                    results_data = json.load(f)
            except (OSError, PermissionError) as e:
                print(f"⚠️  Warning: Cannot read {SCAN_RESULTS_FILE}: {e}")
                print(f"    Falling back to {VULNERABILITIES_FILE}...")
                results_data = None
            except json.JSONDecodeError as e:
                print(f"⚠️  Warning: {SCAN_RESULTS_FILE} contains invalid JSON: {e}")
                print(f"    Falling back to {VULNERABILITIES_FILE}...")
                results_data = None
            
            if results_data:
                try:
                    # Try multiple possible keys for issues array (resilient parsing)
                    issues_data = None
                    if "issues" in results_data:
                        issues_data = results_data["issues"]
                    elif "vulnerabilities" in results_data:
                        # Handle alternate key
                        vulns = results_data["vulnerabilities"]
                        # Check if it's an array or placeholder string
                        if isinstance(vulns, list):
                            if len(vulns) > 0 and isinstance(vulns[0], str):
                                # Placeholder string detected
                                print(f"⚠️  Warning: {SCAN_RESULTS_FILE} contains placeholder string")
                                print(f"    Falling back to {VULNERABILITIES_FILE}...")
                                issues_data = None
                            else:
                                issues_data = vulns
                        else:
                            print(f"⚠️  Warning: {SCAN_RESULTS_FILE} 'vulnerabilities' is not an array")
                            print(f"    Falling back to {VULNERABILITIES_FILE}...")
                            issues_data = None
                    
                    if issues_data is None:
                        print(f"⚠️  Warning: {SCAN_RESULTS_FILE} missing 'issues' key")
                        print(f"    Available keys: {list(results_data.keys())}")
                        print(f"    Falling back to {VULNERABILITIES_FILE}...")
                        raise ValueError(f"No valid issues array found in {SCAN_RESULTS_FILE}")
                    
                    # Convert to SecurityIssue objects with validation
                    issues = []
                    for idx, issue_data in enumerate(issues_data):
                        try:
                            # Validate required fields
                            required_fields = ["title", "description", "severity", "file_path"]
                            missing_fields = [f for f in required_fields if f not in issue_data]
                            if missing_fields:
                                print(f"⚠️  Warning: Issue #{idx + 1} missing required fields: {', '.join(missing_fields)} - skipping")
                                continue
                            
                            # Get ID with warning if missing
                            issue_id = issue_data.get("threat_id") or issue_data.get("id")
                            if not issue_id:
                                issue_id = f"ISSUE-{idx + 1}"
                                print(f"⚠️  Warning: Issue #{idx + 1} missing ID field, using '{issue_id}'")
                            
                            # Validate severity
                            severity_str = issue_data["severity"].upper()
                            if severity_str not in [s.name for s in Severity]:
                                print(f"⚠️  Warning: Issue #{idx + 1} has invalid severity '{severity_str}' - skipping")
                                continue
                            
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
                        except (KeyError, ValueError, TypeError) as e:
                            print(f"⚠️  Warning: Failed to parse issue #{idx + 1}: {e} - skipping")
                            continue

                    if self.debug:
                        print(f"✅ Loaded {len(issues)} vulnerabilities from {SCAN_RESULTS_FILE}")

                    # Calculate scan duration
                    scan_end_time = time.time()
                    scan_duration = scan_end_time - scan_start_time
                    
                    scan_result = ScanResult(
                        repository_path=str(repo),
                        issues=issues,
                        files_scanned=files_scanned,
                        scan_time_seconds=round(scan_duration, 2),
                        total_cost_usd=self.total_cost
                    )
                    
                    return scan_result
                    
                except (ValueError, KeyError, TypeError) as e:
                    print(f"⚠️  Warning: Failed to parse {SCAN_RESULTS_FILE}: {e}")
                    print(f"    Falling back to {VULNERABILITIES_FILE}...")
                    # Will fall through to fallback below
        
        # Fallback to VULNERABILITIES.json if scan_results.json doesn't exist or is invalid
        if scan_result is None and vulnerabilities_file.exists():
            try:
                print(f"📂 Loading from {VULNERABILITIES_FILE}...")
                with open(vulnerabilities_file) as f:
                    vulnerabilities_data = json.load(f)
            except (OSError, PermissionError) as e:
                raise RuntimeError(f"Failed to read {VULNERABILITIES_FILE}: {e}")
            except json.JSONDecodeError as e:
                raise RuntimeError(f"{VULNERABILITIES_FILE} contains invalid JSON: {e}")
            
            try:
                # Handle both array format and wrapped object format
                if isinstance(vulnerabilities_data, list):
                    vulnerabilities = vulnerabilities_data
                elif isinstance(vulnerabilities_data, dict):
                    if "vulnerabilities" in vulnerabilities_data:
                        vulnerabilities = vulnerabilities_data["vulnerabilities"]
                    else:
                        raise ValueError(
                            f"{VULNERABILITIES_FILE} is a dict without 'vulnerabilities' key. "
                            f"Available keys: {list(vulnerabilities_data.keys())}"
                        )
                else:
                    raise ValueError(f"{VULNERABILITIES_FILE} has unexpected format (not array or object)")

                if self.debug:
                    print(f"📊 Found {len(vulnerabilities)} vulnerabilities in {VULNERABILITIES_FILE}")

                # Parse vulnerabilities with validation
                issues = []
                for idx, vuln in enumerate(vulnerabilities):
                    try:
                        # Validate required fields
                        required_fields = ["title", "description", "severity", "file_path"]
                        missing_fields = [f for f in required_fields if f not in vuln]
                        if missing_fields:
                            print(f"⚠️  Warning: Vulnerability #{idx + 1} missing fields: {', '.join(missing_fields)} - skipping")
                            continue
                        
                        # Get ID with warning if missing
                        issue_id = vuln.get("threat_id") or vuln.get("id")
                        if not issue_id:
                            issue_id = f"VULN-{idx + 1}"
                            print(f"⚠️  Warning: Vulnerability #{idx + 1} missing ID field, using '{issue_id}'")
                        
                        # Validate severity
                        severity_str = vuln["severity"].upper()
                        if severity_str not in [s.name for s in Severity]:
                            print(f"⚠️  Warning: Vulnerability #{idx + 1} has invalid severity '{severity_str}' - skipping")
                            continue
                        
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
                    except (KeyError, ValueError, TypeError) as e:
                        print(f"⚠️  Warning: Failed to parse vulnerability #{idx + 1}: {e} - skipping")
                        continue

                # Calculate scan duration
                scan_end_time = time.time()
                scan_duration = scan_end_time - scan_start_time
                
                scan_result = ScanResult(
                    repository_path=str(repo),
                    issues=issues,
                    files_scanned=files_scanned,
                    scan_time_seconds=round(scan_duration, 2),
                    total_cost_usd=self.total_cost
                )

                return scan_result
            
            except (ValueError, KeyError, TypeError) as e:
                raise RuntimeError(f"Failed to parse {VULNERABILITIES_FILE}: {e}")
        
        # If we get here, no results file was created
        if not results_file.exists() and not vulnerabilities_file.exists():
            raise RuntimeError(
                f"Scan failed to generate results. Expected files not found:\n"
                f"  - {results_file}\n"
                f"  - {vulnerabilities_file}\n"
                f"Check {securevibes_dir}/ for partial artifacts."
            )
        else:
            raise RuntimeError(
                f"Scan completed but failed to parse results. "
                f"Check {securevibes_dir}/ for artifacts and review logs above for warnings."
            )

    async def assess_only(self, repo_path: str) -> Dict[str, Any]:
        """Run only assessment phase"""
        repo = Path(repo_path).resolve()
        
        # Ensure output directory exists
        securevibes_dir = repo / SECUREVIBES_DIR
        try:
            securevibes_dir.mkdir(exist_ok=True)
        except (OSError, PermissionError) as e:
            raise RuntimeError(f"Failed to create output directory {securevibes_dir}: {e}")

        options = ClaudeAgentOptions(
            agents={"assessment": SECUREVIBES_AGENTS["assessment"]},
            cwd=str(repo),
            max_turns=config.get_max_turns(),
        )

        prompt = "Use the assessment agent to analyze this codebase and create SECURITY.md"

        print("🤖 Running Assessment Agent...")
        try:
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock) and self.debug:
                            print(f"📝 {block.text[:150]}...")
                
                # Track costs
                if isinstance(message, ResultMessage):
                    if message.total_cost_usd:
                        self.total_cost = message.total_cost_usd
        except Exception as e:
            print(f"\n❌ Assessment failed: {e}")
            raise

        security_file = securevibes_dir / SECURITY_FILE
        if not security_file.exists():
            raise RuntimeError(f"Assessment failed: {SECURITY_FILE} was not created")
        
        print(f"✅ Assessment complete: {security_file}")
        return {"file": str(security_file), "cost_usd": self.total_cost}

    async def threat_model_only(self, repo_path: str) -> Dict[str, Any]:
        """Run only threat modeling phase"""
        repo = Path(repo_path).resolve()
        securevibes_dir = repo / SECUREVIBES_DIR

        # Check for SECURITY.md
        security_file = securevibes_dir / SECURITY_FILE
        if not security_file.exists():
            raise ValueError(f"{SECURITY_FILE} not found. Run assessment first.")

        options = ClaudeAgentOptions(
            agents={"threat-modeling": SECUREVIBES_AGENTS["threat-modeling"]},
            cwd=str(repo),
            max_turns=config.get_max_turns(),
        )

        prompt = "Use the threat-modeling agent to analyze threats based on SECURITY.md"

        print("🤖 Running Threat Modeling Agent...")
        try:
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock) and self.debug:
                            print(f"📝 {block.text[:150]}...")
                
                # Track costs
                if isinstance(message, ResultMessage):
                    if message.total_cost_usd:
                        self.total_cost = message.total_cost_usd
        except Exception as e:
            print(f"\n❌ Threat modeling failed: {e}")
            raise

        threat_file = securevibes_dir / THREAT_MODEL_FILE
        if not threat_file.exists():
            raise RuntimeError(f"Threat modeling failed: {THREAT_MODEL_FILE} was not created")
        
        print(f"✅ Threat modeling complete: {threat_file}")
        return {"file": str(threat_file), "cost_usd": self.total_cost}

    async def review_only(self, repo_path: str) -> Dict[str, Any]:
        """Run only code review phase"""
        repo = Path(repo_path).resolve()
        securevibes_dir = repo / SECUREVIBES_DIR

        # Check for required files
        security_file = securevibes_dir / SECURITY_FILE
        threat_file = securevibes_dir / THREAT_MODEL_FILE

        if not security_file.exists():
            raise ValueError(f"{SECURITY_FILE} not found. Run assessment first.")
        if not threat_file.exists():
            raise ValueError(f"{THREAT_MODEL_FILE} not found. Run threat modeling first.")

        options = ClaudeAgentOptions(
            agents={"code-review": SECUREVIBES_AGENTS["code-review"]},
            cwd=str(repo),
            max_turns=config.get_max_turns(),
        )

        prompt = "Use the code-review agent to validate threats and find vulnerabilities"

        print("🤖 Running Code Review Agent...")
        try:
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock) and self.debug:
                            print(f"📝 {block.text[:150]}...")
                
                # Track costs
                if isinstance(message, ResultMessage):
                    if message.total_cost_usd:
                        self.total_cost = message.total_cost_usd
        except Exception as e:
            print(f"\n❌ Code review failed: {e}")
            raise

        vuln_file = securevibes_dir / VULNERABILITIES_FILE
        if not vuln_file.exists():
            raise RuntimeError(f"Code review failed: {VULNERABILITIES_FILE} was not created")
        
        print(f"✅ Code review complete: {vuln_file}")
        return {"file": str(vuln_file), "cost_usd": self.total_cost}
