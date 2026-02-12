"""Security scanner with real-time progress tracking using ClaudeSDKClient"""

import asyncio
import os
import json
import time
import re
from difflib import SequenceMatcher
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from rich.console import Console

from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions
from claude_agent_sdk.types import (
    AssistantMessage,
    ToolUseBlock,
    TextBlock,
    ResultMessage,
)

from securevibes.agents.definitions import create_agent_definitions
from securevibes.models.result import ScanResult
from securevibes.models.issue import SecurityIssue, Severity
from securevibes.prompts.loader import load_prompt
from securevibes.config import config, LanguageConfig, ScanConfig
from securevibes.scanner.subagent_manager import SubAgentManager, ScanMode
from securevibes.scanner.detection import collect_agentic_detection_files, detect_agentic_patterns
from securevibes.diff.context import (
    extract_relevant_architecture,
    filter_relevant_threats,
    filter_relevant_vulnerabilities,
    normalize_repo_path,
    summarize_threats_for_prompt,
    summarize_vulnerabilities_for_prompt,
    suggest_security_adjacent_files,
)
from securevibes.diff.parser import DiffContext, DiffFile, DiffHunk
from securevibes.scanner.hooks import (
    create_dast_security_hook,
    create_pre_tool_hook,
    create_post_tool_hook,
    create_subagent_hook,
    create_json_validation_hook,
    create_threat_model_validation_hook,
)
from securevibes.scanner.artifacts import update_pr_review_artifacts
from securevibes.scanner.state import (
    build_full_scan_entry,
    get_repo_branch,
    get_repo_head_commit,
    update_scan_state,
    utc_timestamp,
)

# Constants for artifact paths
SECUREVIBES_DIR = ".securevibes"
SECURITY_FILE = "SECURITY.md"
THREAT_MODEL_FILE = "THREAT_MODEL.json"
VULNERABILITIES_FILE = "VULNERABILITIES.json"
PR_VULNERABILITIES_FILE = "PR_VULNERABILITIES.json"
DIFF_CONTEXT_FILE = "DIFF_CONTEXT.json"
SCAN_RESULTS_FILE = "scan_results.json"
SCAN_STATE_FILE = "scan_state.json"

_FOCUSED_DIFF_MAX_FILES = 16
_FOCUSED_DIFF_MAX_HUNK_LINES = 200
_PROMPT_HUNK_MAX_FILES = 12
_PROMPT_HUNK_MAX_HUNKS_PER_FILE = 4
_PROMPT_HUNK_MAX_LINES_PER_HUNK = 80
_SECURITY_PATH_HINTS = (
    "auth",
    "permission",
    "policy",
    "guard",
    "gateway",
    "config",
    "update",
    "session",
    "token",
    "websocket",
    "rpc",
)
_NON_CODE_SUFFIXES = {
    ".md",
    ".txt",
    ".rst",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".gif",
    ".pdf",
    ".jsonl",
    ".lock",
}


def _summarize_diff_line_anchors(
    diff_context: DiffContext,
    max_files: int = 16,
    max_lines_per_file: int = 48,
    max_chars: int = 12000,
) -> str:
    """Build concise changed-line anchors for prompt context."""
    if not diff_context.files:
        return "- No changed files."

    lines: list[str] = []
    for diff_file in diff_context.files[:max_files]:
        path = _diff_file_path(diff_file)
        if not path:
            continue
        added = [
            (int(line.new_line_num or 0), line.content.strip())
            for hunk in diff_file.hunks
            for line in hunk.lines
            if line.type == "add" and isinstance(line.content, str) and line.content.strip()
        ]
        removed_count = sum(
            1 for hunk in diff_file.hunks for line in hunk.lines if line.type == "remove"
        )
        lines.append(f"- {path}")
        for line_no, content in added[:max_lines_per_file]:
            snippet = content.replace("\t", " ").strip()
            if len(snippet) > 180:
                snippet = f"{snippet[:177]}..."
            lines.append(f"  + L{line_no}: {snippet}")
        if len(added) > max_lines_per_file:
            lines.append(f"  + ... {len(added) - max_lines_per_file} more added lines")
        if removed_count:
            lines.append(f"  - removed lines: {removed_count}")

    summary = "\n".join(lines).strip() or "- No changed lines."
    if len(summary) <= max_chars:
        return summary
    return f"{summary[: max_chars - 15].rstrip()}...[truncated]"


def _diff_file_path(diff_file: DiffFile) -> str:
    return str(diff_file.new_path or diff_file.old_path or "")


def _summarize_diff_hunk_snippets(
    diff_context: DiffContext,
    max_files: int = _PROMPT_HUNK_MAX_FILES,
    max_hunks_per_file: int = _PROMPT_HUNK_MAX_HUNKS_PER_FILE,
    max_lines_per_hunk: int = _PROMPT_HUNK_MAX_LINES_PER_HUNK,
    max_chars: int = 22000,
) -> str:
    """Build diff-style snippets for changed hunks to ground PR analysis."""
    if not diff_context.files:
        return "- No changed hunks."

    output: list[str] = []
    for diff_file in diff_context.files[:max_files]:
        path = _diff_file_path(diff_file)
        if not path:
            continue

        file_meta: list[str] = []
        if diff_file.is_new:
            file_meta.append("new")
        if diff_file.is_deleted:
            file_meta.append("deleted")
        if diff_file.is_renamed:
            file_meta.append("renamed")
        meta_suffix = f" ({', '.join(file_meta)})" if file_meta else ""
        output.append(f"--- {path}{meta_suffix}")

        for hunk in diff_file.hunks[:max_hunks_per_file]:
            output.append(
                f"@@ -{hunk.old_start},{hunk.old_count} +{hunk.new_start},{hunk.new_count} @@"
            )
            for line in hunk.lines[:max_lines_per_hunk]:
                prefix = "+"
                if line.type == "remove":
                    prefix = "-"
                elif line.type == "context":
                    prefix = " "

                content = line.content.rstrip("\n")
                if len(content) > 220:
                    content = f"{content[:217]}..."
                output.append(f"{prefix}{content}")

            if len(hunk.lines) > max_lines_per_hunk:
                output.append(f"... [truncated {len(hunk.lines) - max_lines_per_hunk} hunk lines]")

        if len(diff_file.hunks) > max_hunks_per_file:
            output.append(
                f"... [truncated {len(diff_file.hunks) - max_hunks_per_file} hunks for {path}]"
            )

    summary = "\n".join(output).strip() or "- No changed hunks."
    if len(summary) <= max_chars:
        return summary
    return f"{summary[: max_chars - 15].rstrip()}...[truncated]"


def _derive_pr_default_grep_scope(diff_context: DiffContext) -> str:
    """Choose a safe default grep scope from changed file directories."""
    dir_counts: dict[str, int] = {}
    for raw_path in diff_context.changed_files:
        normalized = normalize_repo_path(raw_path)
        if not normalized:
            continue
        parts = [part for part in normalized.split("/") if part]
        if len(parts) < 2:
            continue
        top_level = parts[0]
        dir_counts[top_level] = dir_counts.get(top_level, 0) + 1

    if not dir_counts:
        return "src"
    if "src" in dir_counts:
        return "src"
    return sorted(dir_counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def _normalize_hypothesis_output(
    raw_text: str,
    max_items: int = 8,
    max_chars: int = 5000,
) -> str:
    """Normalize free-form LLM output into concise bullet hypotheses."""
    stripped = raw_text.strip()
    if not stripped:
        return "- None generated."

    bullets: list[str] = []
    for line in stripped.splitlines():
        text = line.strip()
        if not text:
            continue
        if text.startswith("- "):
            bullets.append(text)
            continue
        if text.startswith("* "):
            bullets.append(f"- {text[2:].strip()}")
            continue
        if len(text) > 2 and text[0].isdigit() and text[1] in {".", ")"}:
            bullets.append(f"- {text[2:].strip()}")
            continue

    if not bullets:
        first_line = stripped.splitlines()[0].strip()
        if len(first_line) > 280:
            first_line = f"{first_line[:277]}..."
        bullets = [f"- {first_line}"]

    normalized = "\n".join(bullets[:max_items]).strip() or "- None generated."
    if len(normalized) <= max_chars:
        return normalized
    return f"{normalized[: max_chars - 15].rstrip()}...[truncated]"


async def _generate_pr_hypotheses(
    *,
    repo: Path,
    model: str,
    changed_files: list[str],
    diff_line_anchors: str,
    diff_hunk_snippets: str,
    threat_context_summary: str,
    vuln_context_summary: str,
    architecture_context: str,
) -> str:
    """Generate exploit hypotheses from diff+baseline context using the LLM."""
    hypothesis_prompt = f"""You are a security exploit hypothesis generator for code review.

Generate 3-8 high-impact exploit hypotheses grounded in the changed diff.
These are hypotheses to validate, NOT confirmed vulnerabilities.

Return ONLY bullet lines. Each bullet should include:
- potential exploit chain
- changed file/line anchor reference
- why impact could be high
- which files/functions should be validated

Focus on chains such as:
- auth/trust-boundary bypass + privileged action
- command/shell/option injection
- file path traversal/exfiltration
- token/credential exfiltration leading to privileged access

CHANGED FILES:
{changed_files}

CHANGED LINE ANCHORS:
{diff_line_anchors}

CHANGED HUNK SNIPPETS:
{diff_hunk_snippets}

RELEVANT THREATS:
{threat_context_summary}

RELEVANT BASELINE VULNERABILITIES:
{vuln_context_summary}

ARCHITECTURE CONTEXT:
{architecture_context}
"""

    options = ClaudeAgentOptions(
        cwd=str(repo),
        setting_sources=["project"],
        allowed_tools=[],
        max_turns=8,
        permission_mode="bypassPermissions",
        model=model,
    )

    collected_text: list[str] = []
    try:
        async with ClaudeSDKClient(options=options) as client:
            await asyncio.wait_for(client.query(hypothesis_prompt), timeout=30)
            async for message in client.receive_messages():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            collected_text.append(block.text)
                elif isinstance(message, ResultMessage):
                    break
    except Exception:
        return "- Unable to generate hypotheses."

    return _normalize_hypothesis_output("\n".join(collected_text))


async def _refine_pr_findings_with_llm(
    *,
    repo: Path,
    model: str,
    diff_line_anchors: str,
    diff_hunk_snippets: str,
    findings: list[dict],
    severity_threshold: str,
) -> Optional[list[dict]]:
    """Use an LLM-only quality pass to keep concrete exploit-primitive findings."""
    if not findings:
        return None

    finding_json = json.dumps(findings, indent=2, ensure_ascii=False)
    refinement_prompt = f"""You are an exploit-chain quality auditor for PR security findings.

Rewrite the candidate findings into a final canonical set using these rules:
- Keep one canonical finding per exploit chain.
- Prefer concrete exploit primitives over generic hardening framing.
- Drop speculative findings ("might", "if bypass exists", "testing needed") unless concrete code proof exists.
- Preserve only findings at or above severity threshold: {severity_threshold}.
- Never invent vulnerabilities not supported by diff context.

Special command-builder review requirements:
- For command/CLI helper diffs, verify whether attacker-controlled host/target values can become CLI options.
- If positional host/target arguments are appended without robust dash-prefixed rejection or `--` separation, treat as option injection chain (CWE-88) when supported by the diff.
- Do not classify explicit option-value pairs (such as `-i <value>`) as option injection unless the value is proven to be reinterpreted as a flag.
- If command injection is claimed, ensure scenario includes concrete payload and sink reachability.

Return ONLY a JSON array of findings using the existing schema fields.

CHANGED LINE ANCHORS:
{diff_line_anchors}

CHANGED HUNK SNIPPETS:
{diff_hunk_snippets}

CANDIDATE FINDINGS JSON:
{finding_json}
"""

    options = ClaudeAgentOptions(
        cwd=str(repo),
        setting_sources=["project"],
        allowed_tools=[],
        max_turns=10,
        permission_mode="bypassPermissions",
        model=model,
    )

    collected_text: list[str] = []
    try:
        async with ClaudeSDKClient(options=options) as client:
            await asyncio.wait_for(client.query(refinement_prompt), timeout=30)
            async for message in client.receive_messages():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            collected_text.append(block.text)
                elif isinstance(message, ResultMessage):
                    break
    except Exception:
        return None

    raw_output = "\n".join(collected_text).strip()
    if not raw_output:
        return None

    from securevibes.models.schemas import fix_pr_vulnerabilities_json

    fixed_content, _ = fix_pr_vulnerabilities_json(raw_output)
    try:
        parsed = json.loads(fixed_content)
    except json.JSONDecodeError:
        return None

    if not isinstance(parsed, list):
        return None
    return [entry for entry in parsed if isinstance(entry, dict)]


def _score_diff_file_for_security_review(diff_file: DiffFile) -> int:
    path = _diff_file_path(diff_file).lower()
    if not path:
        return 0

    score = 0
    suffix = Path(path).suffix.lower()

    if suffix not in _NON_CODE_SUFFIXES:
        score += 60
    if "/docs/" in path or path.startswith("docs/"):
        score -= 35
    if "/test/" in path or "/tests/" in path or ".test." in path or ".spec." in path:
        score -= 20

    score += sum(12 for hint in _SECURITY_PATH_HINTS if hint in path)
    if path.startswith("src/"):
        score += 20
    if diff_file.is_new:
        score += 8
    if diff_file.is_renamed:
        score += 4

    return score


def _build_focused_diff_context(diff_context: DiffContext) -> DiffContext:
    """Prioritize security-relevant code changes and trim oversized hunk context."""
    if not diff_context.files:
        return diff_context

    scored_files = sorted(
        diff_context.files,
        key=lambda f: (_score_diff_file_for_security_review(f), _diff_file_path(f)),
        reverse=True,
    )

    top_files = [
        f
        for f in scored_files[:_FOCUSED_DIFF_MAX_FILES]
        if _score_diff_file_for_security_review(f) > 0
    ]
    if not top_files:
        top_files = scored_files[: min(len(scored_files), _FOCUSED_DIFF_MAX_FILES)]

    focused_files: list[DiffFile] = []
    for diff_file in top_files:
        focused_hunks: list[DiffHunk] = []
        for hunk in diff_file.hunks:
            if len(hunk.lines) <= _FOCUSED_DIFF_MAX_HUNK_LINES:
                focused_hunks.append(hunk)
                continue

            focused_hunks.append(
                DiffHunk(
                    old_start=hunk.old_start,
                    old_count=hunk.old_count,
                    new_start=hunk.new_start,
                    new_count=hunk.new_count,
                    lines=hunk.lines[:_FOCUSED_DIFF_MAX_HUNK_LINES],
                )
            )

        focused_files.append(
            DiffFile(
                old_path=diff_file.old_path,
                new_path=diff_file.new_path,
                hunks=focused_hunks,
                is_new=diff_file.is_new,
                is_deleted=diff_file.is_deleted,
                is_renamed=diff_file.is_renamed,
            )
        )

    changed_files = [path for path in (_diff_file_path(file) for file in focused_files) if path]
    added_lines = sum(
        1
        for file in focused_files
        for hunk in file.hunks
        for line in hunk.lines
        if line.type == "add"
    )
    removed_lines = sum(
        1
        for file in focused_files
        for hunk in file.hunks
        for line in hunk.lines
        if line.type == "remove"
    )

    return DiffContext(
        files=focused_files,
        added_lines=added_lines,
        removed_lines=removed_lines,
        changed_files=changed_files,
    )


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


class Scanner:
    """
    Security scanner using ClaudeSDKClient with real-time progress tracking.

    Provides progress updates via hooks, eliminating silent periods during
    long-running scans. Uses deterministic sub-agent lifecycle events instead of
    file polling for phase detection.
    """

    def __init__(self, model: str = "sonnet", debug: bool = False):
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

        # Agentic detection override (None = auto-detect)
        self.agentic_override: Optional[bool] = None

    def configure_dast(
        self, target_url: str, timeout: int = 120, accounts_path: Optional[str] = None
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
            "accounts_path": accounts_path,
        }

    def configure_agentic_detection(self, override: Optional[bool]) -> None:
        """Override agentic detection behavior.

        Args:
            override: True/False to force agentic/non-agentic classification; None for auto.
        """

        self.agentic_override = override

    def _setup_dast_skills(self, repo: Path):
        """
        Sync DAST skills to target project for SDK discovery.

        Skills are bundled with SecureVibes package and automatically
        synced to each project's .claude/skills/dast/ directory.
        Always syncs to ensure new skills are available.

        Args:
            repo: Target repository path
        """
        import shutil

        target_skills_dir = repo / ".claude" / "skills" / "dast"

        # Get skills from package installation
        package_skills_dir = Path(__file__).parent.parent / "skills" / "dast"

        if not package_skills_dir.exists():
            raise RuntimeError(
                f"DAST skills not found at {package_skills_dir}. "
                "Package installation may be corrupted."
            )

        # Count skills in package
        package_skills = [d.name for d in package_skills_dir.iterdir() if d.is_dir()]

        # Sync skills to target project (always sync to pick up new skills)
        try:
            target_skills_dir.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(package_skills_dir, target_skills_dir, dirs_exist_ok=True)

            if self.debug:
                self.console.print(
                    f"  📦 Synced {len(package_skills)} DAST skill(s) to .claude/skills/dast/",
                    style="dim green",
                )
                for skill in package_skills:
                    self.console.print(f"      - {skill}", style="dim")

        except (OSError, PermissionError) as e:
            raise RuntimeError(f"Failed to sync DAST skills: {e}")

    def _setup_threat_modeling_skills(self, repo: Path):
        """
        Sync threat modeling skills to target project for SDK discovery.

        Skills are bundled with SecureVibes package and automatically
        synced to each project's .claude/skills/threat-modeling/ directory.
        Always syncs to ensure new skills are available.

        Args:
            repo: Target repository path
        """
        import shutil

        target_skills_dir = repo / ".claude" / "skills" / "threat-modeling"

        # Get skills from package installation
        package_skills_dir = Path(__file__).parent.parent / "skills" / "threat-modeling"

        if not package_skills_dir.exists():
            if self.debug:
                self.console.print(
                    f"  ℹ️  No threat modeling skills found at {package_skills_dir}", style="dim"
                )
            return

        # Count skills in package
        package_skills = [d.name for d in package_skills_dir.iterdir() if d.is_dir()]

        if not package_skills:
            return

        # Sync skills to target project (always sync to pick up new skills)
        try:
            target_skills_dir.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(package_skills_dir, target_skills_dir, dirs_exist_ok=True)

            if self.debug:
                self.console.print(
                    f"  📦 Synced {len(package_skills)} threat modeling skill(s) to .claude/skills/threat-modeling/",
                    style="dim green",
                )
                for skill in package_skills:
                    self.console.print(f"      - {skill}", style="dim")

        except (OSError, PermissionError) as e:
            if self.debug:
                self.console.print(
                    f"  ⚠️  Warning: Failed to sync threat modeling skills: {e}", style="yellow"
                )

    async def scan_subagent(
        self, repo_path: str, subagent: str, force: bool = False, skip_checks: bool = False
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

                self.console.print(
                    f"[bold red]❌ Error:[/bold red] '{subagent}' requires {required}"
                )
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
                    from securevibes.scanner.subagent_manager import (
                        SUBAGENT_ARTIFACTS,
                        SUBAGENT_ORDER,
                    )

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
                    # Copy to .securevibes/ where agent can read it
                    securevibes_dir = repo / ".securevibes"
                    target_accounts = securevibes_dir / "DAST_TEST_ACCOUNTS.json"
                    target_accounts.write_text(accounts_file.read_text())

        # Run scan with single sub-agent
        return await self._execute_scan(repo, single_subagent=subagent)

    async def scan_resume(
        self, repo_path: str, from_subagent: str, force: bool = False, skip_checks: bool = False
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
                    self.console.print(
                        f"✓ Found: .securevibes/{deps['requires']} (prerequisite for {from_subagent})",
                        style="green",
                    )

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
                    # Copy to .securevibes/ where agent can read it
                    securevibes_dir = repo / ".securevibes"
                    target_accounts = securevibes_dir / "DAST_TEST_ACCOUNTS.json"
                    target_accounts.write_text(accounts_file.read_text())

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
                    # Copy to .securevibes/ where agent can read it
                    securevibes_dir = repo / ".securevibes"
                    target_accounts = securevibes_dir / "DAST_TEST_ACCOUNTS.json"
                    target_accounts.write_text(accounts_file.read_text())

        return await self._execute_scan(repo)

    async def pr_review(
        self,
        repo_path: str,
        diff_context: DiffContext,
        known_vulns_path: Optional[Path],
        severity_threshold: str,
        update_artifacts: bool = False,
    ) -> ScanResult:
        """
        Run context-aware PR security review.

        Args:
            repo_path: Path to repository to scan
            diff_context: Parsed diff context
            known_vulns_path: Optional path to VULNERABILITIES.json for dedupe
            severity_threshold: Minimum severity to report
        """
        repo = Path(repo_path).resolve()
        if not repo.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        securevibes_dir = repo / SECUREVIBES_DIR
        try:
            securevibes_dir.mkdir(exist_ok=True)
        except (OSError, PermissionError) as e:
            raise RuntimeError(f"Failed to create output directory {securevibes_dir}: {e}")

        scan_start_time = time.time()

        focused_diff_context = _build_focused_diff_context(diff_context)
        diff_context_path = securevibes_dir / DIFF_CONTEXT_FILE
        diff_context_path.write_text(json.dumps(focused_diff_context.to_json(), indent=2))

        architecture_context = extract_relevant_architecture(
            securevibes_dir / SECURITY_FILE,
            focused_diff_context.changed_files,
        )

        relevant_threats = filter_relevant_threats(
            securevibes_dir / THREAT_MODEL_FILE,
            focused_diff_context.changed_files,
        )

        known_vulns = []
        if known_vulns_path and known_vulns_path.exists():
            try:
                raw_known = known_vulns_path.read_text(encoding="utf-8")
                parsed = json.loads(raw_known)
                if isinstance(parsed, list):
                    known_vulns = parsed
            except (OSError, json.JSONDecodeError):
                known_vulns = []

        baseline_vulns = filter_baseline_vulns(known_vulns)
        relevant_baseline_vulns = filter_relevant_vulnerabilities(
            baseline_vulns,
            focused_diff_context.changed_files,
        )
        threat_context_summary = summarize_threats_for_prompt(relevant_threats)
        vuln_context_summary = summarize_vulnerabilities_for_prompt(relevant_baseline_vulns)
        security_adjacent_files = suggest_security_adjacent_files(
            repo,
            focused_diff_context.changed_files,
            max_items=20,
        )
        adjacent_file_hints = (
            "\n".join(f"- {file_path}" for file_path in security_adjacent_files)
            if security_adjacent_files
            else "- None identified from changed-file neighborhoods"
        )
        diff_line_anchors = _summarize_diff_line_anchors(focused_diff_context)
        diff_hunk_snippets = _summarize_diff_hunk_snippets(focused_diff_context)
        command_builder_signals = _diff_has_command_builder_signals(focused_diff_context)
        pr_grep_default_scope = _derive_pr_default_grep_scope(focused_diff_context)
        pr_hypotheses = "- None generated."
        if focused_diff_context.files:
            pr_hypotheses = await _generate_pr_hypotheses(
                repo=repo,
                model=self.model,
                changed_files=focused_diff_context.changed_files,
                diff_line_anchors=diff_line_anchors,
                diff_hunk_snippets=diff_hunk_snippets,
                threat_context_summary=threat_context_summary,
                vuln_context_summary=vuln_context_summary,
                architecture_context=architecture_context,
            )
        if self.debug:
            self.console.print("  🧠 PR exploit hypotheses prepared", style="dim")

        base_agents = create_agent_definitions(cli_model=self.model)
        base_pr_prompt = base_agents["pr-code-review"].prompt

        contextualized_prompt = f"""{base_pr_prompt}

## ARCHITECTURE CONTEXT (from SECURITY.md)
{architecture_context}

## RELEVANT EXISTING THREATS (from THREAT_MODEL.json)
{threat_context_summary}

## RELEVANT BASELINE VULNERABILITIES (from VULNERABILITIES.json)
{vuln_context_summary}

## SECURITY-ADJACENT FILES TO CHECK FOR REACHABILITY
{adjacent_file_hints}

## DIFF TO ANALYZE
Use the prompt-provided changed files and line anchors below as authoritative diff context.
This scan may run against a pre-change snapshot where new/modified PR code is not present on disk.
Changed files: {diff_context.changed_files}
Prioritized changed files: {focused_diff_context.changed_files}

## CHANGED LINE ANCHORS (authoritative)
{diff_line_anchors}

## CHANGED HUNK SNIPPETS (authoritative diff code)
{diff_hunk_snippets}

## HYPOTHESES TO VALIDATE (LLM-generated)
Validate or falsify each hypothesis before final output:
You may output [] only if every hypothesis is disproved with concrete code evidence.
{pr_hypotheses}

## SEVERITY THRESHOLD
Only report findings at or above: {severity_threshold}
"""

        from claude_agent_sdk.types import HookMatcher

        warnings: list[str] = []
        pr_timeout_seconds = config.get_pr_review_timeout_seconds()
        pr_review_attempts = config.get_pr_review_attempts()
        pr_vulns_path = securevibes_dir / PR_VULNERABILITIES_FILE
        detected_languages = LanguageConfig.detect_languages(repo) if repo else set()

        pr_vulns: list[dict] = []
        collected_pr_vulns: list[dict] = []
        artifact_loaded = False
        attempts_run = 0

        for attempt_idx in range(pr_review_attempts):
            attempt_num = attempt_idx + 1
            attempts_run = attempt_num
            retry_suffix = ""
            if attempt_num > 1:
                retry_suffix = _build_pr_review_retry_suffix(
                    attempt_num,
                    command_builder_signals=command_builder_signals,
                )
                try:
                    pr_vulns_path.unlink()
                except OSError:
                    pass

            agents = create_agent_definitions(cli_model=self.model)
            attempt_prompt = f"{contextualized_prompt}{retry_suffix}"
            agents["pr-code-review"].prompt = attempt_prompt

            tracker = ProgressTracker(
                self.console, debug=self.debug, single_subagent="pr-code-review"
            )
            tracker.current_phase = "pr-code-review"
            pre_tool_hook = create_pre_tool_hook(
                tracker,
                self.console,
                self.debug,
                detected_languages,
                pr_grep_default_path=pr_grep_default_scope,
            )
            post_tool_hook = create_post_tool_hook(tracker, self.console, self.debug)
            subagent_hook = create_subagent_hook(tracker)
            json_validation_hook = create_json_validation_hook(self.console, self.debug)

            options = ClaudeAgentOptions(
                agents=agents,
                cwd=str(repo),
                setting_sources=["project"],
                allowed_tools=["Read", "Write", "Grep", "Glob", "LS"],
                max_turns=config.get_max_turns(),
                permission_mode="bypassPermissions",
                model=self.model,
                hooks={
                    "PreToolUse": [
                        HookMatcher(hooks=[json_validation_hook]),
                        HookMatcher(hooks=[pre_tool_hook]),
                    ],
                    "PostToolUse": [HookMatcher(hooks=[post_tool_hook])],
                    "SubagentStop": [HookMatcher(hooks=[subagent_hook])],
                },
            )

            try:
                async with ClaudeSDKClient(options=options) as client:
                    await asyncio.wait_for(client.query(attempt_prompt), timeout=30)

                    async def consume_messages() -> None:
                        async for message in client.receive_messages():
                            if isinstance(message, AssistantMessage):
                                for block in message.content:
                                    if isinstance(block, TextBlock):
                                        tracker.on_assistant_text(block.text)
                            elif isinstance(message, ResultMessage):
                                if message.total_cost_usd:
                                    self.total_cost = message.total_cost_usd
                                break

                    await asyncio.wait_for(consume_messages(), timeout=pr_timeout_seconds)
            except asyncio.TimeoutError:
                timeout_warning = (
                    f"PR code review attempt {attempt_num}/{pr_review_attempts} timed out after "
                    f"{pr_timeout_seconds}s."
                )
                warnings.append(timeout_warning)
                self.console.print(f"\n[bold yellow]WARNING:[/bold yellow] {timeout_warning}\n")
                loaded_vulns, load_warning = _load_pr_vulnerabilities_artifact(
                    pr_vulns_path=pr_vulns_path,
                    console=self.console,
                )
                if not load_warning:
                    artifact_loaded = True
                    if loaded_vulns:
                        collected_pr_vulns.extend(loaded_vulns)
                continue
            except Exception as e:
                attempt_warning = (
                    f"PR code review attempt {attempt_num}/{pr_review_attempts} failed: {e}"
                )
                warnings.append(attempt_warning)
                self.console.print(f"\n[bold yellow]WARNING:[/bold yellow] {attempt_warning}\n")
                loaded_vulns, load_warning = _load_pr_vulnerabilities_artifact(
                    pr_vulns_path=pr_vulns_path,
                    console=self.console,
                )
                if not load_warning:
                    artifact_loaded = True
                    if loaded_vulns:
                        collected_pr_vulns.extend(loaded_vulns)
                continue

            loaded_vulns, load_warning = _load_pr_vulnerabilities_artifact(
                pr_vulns_path=pr_vulns_path,
                console=self.console,
            )
            if load_warning:
                warnings.append(
                    f"PR code review attempt {attempt_num}/{pr_review_attempts}: {load_warning}"
                )
                continue

            artifact_loaded = True
            attempt_finding_count = len(loaded_vulns)
            if attempt_finding_count:
                collected_pr_vulns.extend(loaded_vulns)
                if self.debug:
                    self.console.print(
                        f"  PR pass {attempt_num}/{pr_review_attempts}: "
                        f"{attempt_finding_count} finding(s), "
                        f"cumulative {len(collected_pr_vulns)}",
                        style="dim",
                    )
                if attempt_num < pr_review_attempts and self.debug:
                    self.console.print(
                        "  🔁 Running additional focused PR pass for broader chain coverage",
                        style="dim",
                    )
                continue

            if attempt_num < pr_review_attempts:
                cumulative_findings = len(collected_pr_vulns)
                if cumulative_findings > 0:
                    if self.debug:
                        self.console.print(
                            f"  PR pass {attempt_num}/{pr_review_attempts}: no new findings; "
                            f"cumulative remains {cumulative_findings}. "
                            "Continuing with chain-focused prompt.",
                            style="dim",
                        )
                else:
                    retry_warning = (
                        f"PR code review attempt {attempt_num}/{pr_review_attempts} returned no findings "
                        "yet; retrying with chain-focused prompt."
                    )
                    warnings.append(retry_warning)
                    self.console.print(f"\n[bold yellow]WARNING:[/bold yellow] {retry_warning}\n")

        if not artifact_loaded and not collected_pr_vulns:
            warning_msg = (
                "PR code review agent did not produce a readable PR_VULNERABILITIES.json after "
                f"{pr_review_attempts} attempt(s). Results may be incomplete."
            )
            warnings.append(warning_msg)
            self.console.print(f"\n[bold yellow]WARNING:[/bold yellow] {warning_msg}\n")
            return ScanResult(
                repository_path=str(repo),
                issues=[],
                files_scanned=len(diff_context.changed_files),
                scan_time_seconds=round(time.time() - scan_start_time, 2),
                total_cost_usd=round(self.total_cost, 4),
                warnings=warnings,
            )

        raw_pr_finding_count = len(collected_pr_vulns)
        pr_vulns = _merge_pr_attempt_findings(collected_pr_vulns)
        if command_builder_signals and pr_vulns:
            refined_pr_vulns = await _refine_pr_findings_with_llm(
                repo=repo,
                model=self.model,
                diff_line_anchors=diff_line_anchors,
                diff_hunk_snippets=diff_hunk_snippets,
                findings=pr_vulns,
                severity_threshold=severity_threshold,
            )
            if refined_pr_vulns:
                refined_canonical = _merge_pr_attempt_findings(refined_pr_vulns)
                if refined_canonical:
                    if self.debug:
                        self.console.print(
                            "  PR exploit-quality refinement pass updated canonical findings: "
                            f"{len(pr_vulns)} -> {len(refined_canonical)}",
                            style="dim",
                        )
                    pr_vulns = refined_canonical
        merged_pr_finding_count = len(pr_vulns)

        if baseline_vulns and pr_vulns:
            pr_vulns = dedupe_pr_vulns(pr_vulns, baseline_vulns)
            try:
                pr_vulns_path.write_text(json.dumps(pr_vulns, indent=2), encoding="utf-8")
            except OSError as e:
                warnings.append(f"Unable to persist deduped PR findings to {pr_vulns_path}: {e}")

        final_pr_finding_count = len(pr_vulns)
        if self.debug:
            self.console.print(
                "  PR review attempt summary: "
                f"{attempts_run}/{pr_review_attempts} attempts, "
                f"{raw_pr_finding_count} raw finding(s), "
                f"{merged_pr_finding_count} canonical chain(s), "
                f"{final_pr_finding_count} final finding(s) after baseline dedupe",
                style="dim",
            )

        if update_artifacts and isinstance(pr_vulns, list):
            update_result = update_pr_review_artifacts(securevibes_dir, pr_vulns)
            if update_result.new_components_detected:
                self.console.print(
                    "⚠️  New components detected. Consider running full scan.",
                    style="yellow",
                )

        return ScanResult(
            repository_path=str(repo),
            issues=_issues_from_pr_vulns(pr_vulns if isinstance(pr_vulns, list) else []),
            files_scanned=len(diff_context.changed_files),
            scan_time_seconds=round(time.time() - scan_start_time, 2),
            total_cost_usd=round(self.total_cost, 4),
            warnings=warnings,
        )

    async def _execute_scan(
        self, repo: Path, single_subagent: Optional[str] = None, resume_from: Optional[str] = None
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

        # Detect languages in repository for smart exclusions
        detected_languages = LanguageConfig.detect_languages(repo)
        if self.debug:
            self.console.print(
                f"  📋 Detected languages: {', '.join(sorted(detected_languages)) or 'none'}",
                style="dim",
            )

        # Get language-aware exclusions
        exclude_dirs = ScanConfig.get_excluded_dirs(detected_languages)

        # Count files for reporting (exclude infrastructure directories)
        def should_scan(file_path: Path) -> bool:
            """Check if file should be included in security scan"""
            return not any(excluded in file_path.parts for excluded in exclude_dirs)

        # Collect all supported code files
        all_code_files = []
        for lang, extensions in LanguageConfig.SUPPORTED_LANGUAGES.items():
            for ext in extensions:
                files = [f for f in repo.glob(f"**/*{ext}") if should_scan(f)]
                all_code_files.extend(files)

        files_scanned = len(all_code_files)

        # Deterministic agentic detection (used for prompt steering + conditional ASI enforcement)
        detection_files = collect_agentic_detection_files(
            repo, all_code_files, exclude_dirs=exclude_dirs
        )
        detection_result = detect_agentic_patterns(repo, detection_files)
        is_agentic = detection_result.is_agentic
        if self.agentic_override is not None:
            is_agentic = self.agentic_override

        signals_preview = "\n".join(f"- {s}" for s in detection_result.signals[:8]) or "- (none)"
        if is_agentic:
            threat_modeling_context = (
                "<deterministic_agentic_detection>\n"
                "SecureVibes deterministic agentic detection: is_agentic = true\n"
                "Matched signals:\n"
                f"{signals_preview}\n\n"
                "HARD REQUIREMENTS:\n"
                "- THREAT_MODEL.json MUST include ASI threats (THREAT-ASI{XX}-{NNN}).\n"
                "- Include at least one ASI01 threat and one ASI03 threat.\n"
                "</deterministic_agentic_detection>"
            )
        else:
            threat_modeling_context = (
                "<deterministic_agentic_detection>\n"
                "SecureVibes deterministic agentic detection: is_agentic = false\n"
                "Matched signals:\n"
                f"{signals_preview}\n\n"
                "Guidance:\n"
                "- ASI threats are OPTIONAL for non-agentic applications.\n"
                "- Prioritize STRIDE threats grounded in the architecture.\n"
                "</deterministic_agentic_detection>"
            )

        if self.debug:
            if is_agentic:
                self.console.print(
                    f"  🤖 Agentic application detected ({len(detection_result.matched_categories)} category matches)",
                    style="dim green",
                )
            else:
                self.console.print("  📦 Non-agentic application detected", style="dim")

        # Setup DAST skills if DAST will be executed
        if single_subagent:
            needs_dast = single_subagent == "dast"
        elif resume_from:
            from securevibes.scanner.subagent_manager import SubAgentManager

            manager = SubAgentManager(repo, quiet=False)
            needs_dast = "dast" in manager.get_resume_subagents(resume_from)
        else:
            needs_dast = self.dast_enabled

        if needs_dast:
            self._setup_dast_skills(repo)

        # Setup threat modeling skills if threat-modeling will be executed
        if single_subagent:
            needs_threat_modeling = single_subagent == "threat-modeling"
        elif resume_from:
            from securevibes.scanner.subagent_manager import SubAgentManager

            manager = SubAgentManager(repo, quiet=False)
            needs_threat_modeling = "threat-modeling" in manager.get_resume_subagents(resume_from)
        else:
            needs_threat_modeling = True  # Always needed for full scans

        if needs_threat_modeling:
            self._setup_threat_modeling_skills(repo)

        # Verify skills are available (debug mode)
        if self.debug:
            skills_dir = repo / ".claude" / "skills"
            if skills_dir.exists():
                skills = [d.name for d in skills_dir.iterdir() if d.is_dir()]
                if skills:
                    self.console.print(
                        f"  ✅ Skills directory found: {len(skills)} skill(s) available: {', '.join(skills)}",
                        style="dim green",
                    )
                else:
                    self.console.print(
                        "  ⚠️  Skills directory exists but is empty", style="dim yellow"
                    )
            else:
                self.console.print("  ℹ️  No skills directory found (.claude/skills/)", style="dim")

        # Show scan info (banner already printed by CLI)
        self.console.print(f"📁 Scanning: {repo}")
        self.console.print(f"🤖 Model: {self.model}")
        self.console.print("=" * 60)

        # Initialize progress tracker
        tracker = ProgressTracker(self.console, debug=self.debug, single_subagent=single_subagent)

        # Store detected languages for phase-specific exclusions
        detected_languages = LanguageConfig.detect_languages(repo) if repo else set()

        # Create hooks using hook creator functions
        dast_security_hook = create_dast_security_hook(tracker, self.console, self.debug)
        pre_tool_hook = create_pre_tool_hook(tracker, self.console, self.debug, detected_languages)
        post_tool_hook = create_post_tool_hook(tracker, self.console, self.debug)
        subagent_hook = create_subagent_hook(tracker)
        json_validation_hook = create_json_validation_hook(self.console, self.debug)
        threat_model_validation_hook = create_threat_model_validation_hook(
            self.console,
            self.debug,
            require_asi=is_agentic,
            max_retries=1,
        )

        # Configure agent options with hooks
        from claude_agent_sdk.types import HookMatcher

        # Create agent definitions with CLI model override and DAST target URL
        # This allows --model flag to cascade to all agents while respecting env vars
        # The DAST target URL is passed to substitute {target_url} placeholders in the prompt
        dast_url = self.dast_config.get("target_url") if self.dast_enabled else None
        agents = create_agent_definitions(
            cli_model=self.model,
            dast_target_url=dast_url,
            threat_modeling_context=threat_modeling_context,
        )

        # Skills configuration:
        # - Skills must be explicitly enabled via setting_sources=["project"]
        # - Skills are discovered from {repo}/.claude/skills/ when settings are enabled
        # - The DAST agent has "Skill" in its tools to access loaded skills

        options = ClaudeAgentOptions(
            agents=agents,
            cwd=str(repo),
            # REQUIRED: Enable filesystem settings to load skills from .claude/skills/
            setting_sources=["project"],
            # Explicit global tools (recommended for clarity)
            # Individual agents may have more restrictive tool lists
            # Task is required for the orchestrator to dispatch to subagents defined via --agents
            allowed_tools=["Task", "Skill", "Read", "Write", "Edit", "Bash", "Grep", "Glob", "LS"],
            max_turns=config.get_max_turns(),
            permission_mode="bypassPermissions",
            model=self.model,
            hooks={
                "PreToolUse": [
                    HookMatcher(
                        hooks=[dast_security_hook]
                    ),  # DAST security - blocks database tools
                    HookMatcher(
                        hooks=[json_validation_hook]
                    ),  # JSON validation - fixes VULNERABILITIES.json format
                    HookMatcher(
                        hooks=[threat_model_validation_hook]
                    ),  # Threat model validation - enforce ASI when required
                    HookMatcher(hooks=[pre_tool_hook]),  # General pre-tool processing
                ],
                "PostToolUse": [HookMatcher(hooks=[post_tool_hook])],
                "SubagentStop": [HookMatcher(hooks=[subagent_hook])],
            },
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
                                    f"  💰 Cost update: ${self.total_cost:.4f}", style="cyan"
                                )
                        # ResultMessage indicates scan completion - exit the loop
                        break

            self.console.print("\n" + "=" * 80)

        except Exception as e:
            self.console.print(f"\n❌ Scan failed: {e}", style="bold red")
            raise

        # Load and parse results based on scan mode
        try:
            if single_subagent:
                return self._load_subagent_results(
                    securevibes_dir, repo, files_scanned, scan_start_time, single_subagent
                )
            else:
                return self._load_scan_results(
                    securevibes_dir,
                    repo,
                    files_scanned,
                    scan_start_time,
                    single_subagent,
                    resume_from,
                )
        except RuntimeError as e:
            self.console.print(f"❌ Error loading scan results: {e}", style="bold red")
            raise

    def _regenerate_artifacts(self, scan_result: ScanResult, securevibes_dir: Path):
        """
        Regenerate JSON and Markdown reports with merged DAST validation data.

        Args:
            scan_result: Scan result with merged DAST data
            securevibes_dir: Path to .securevibes directory
        """
        try:
            # Regenerate JSON report
            from securevibes.reporters.json_reporter import JSONReporter

            json_file = securevibes_dir / SCAN_RESULTS_FILE
            JSONReporter.save(scan_result, json_file)

            # Regenerate Markdown report
            from securevibes.reporters.markdown_reporter import MarkdownReporter

            md_output = MarkdownReporter.generate(scan_result)
            md_file = securevibes_dir / "scan_report.md"
            with open(md_file, "w", encoding="utf-8") as f:
                f.write(md_output)

            if self.debug:
                self.console.print(
                    "✅ Regenerated reports with DAST validation data", style="green"
                )

        except Exception as e:
            if self.debug:
                self.console.print(
                    f"⚠️  Warning: Failed to regenerate artifacts: {e}", style="yellow"
                )

    def _merge_dast_results(self, scan_result: ScanResult, securevibes_dir: Path) -> ScanResult:
        """
        Merge DAST validation data into scan results.

        Args:
            scan_result: The base scan result with issues
            securevibes_dir: Path to .securevibes directory

        Returns:
            Updated ScanResult with DAST validation merged
        """
        dast_file = securevibes_dir / "DAST_VALIDATION.json"
        if not dast_file.exists():
            return scan_result

        try:
            with open(dast_file) as f:
                dast_data = json.load(f)

            # Extract DAST metadata
            metadata = dast_data.get("dast_scan_metadata", {})
            validations = dast_data.get("validations", [])

            if not validations:
                return scan_result

            # Build lookup map: vulnerability_id -> validation data
            validation_map = {}
            for validation in validations:
                vuln_id = validation.get("vulnerability_id")
                if vuln_id:
                    validation_map[vuln_id] = validation

            # Merge validation data into issues
            from securevibes.models.issue import ValidationStatus

            updated_issues = []
            validated_count = 0
            false_positive_count = 0
            unvalidated_count = 0

            for issue in scan_result.issues:
                # Try to find matching validation by issue ID
                validation = validation_map.get(issue.id)

                if validation:
                    # Parse validation status
                    status_str = validation.get("validation_status", "UNVALIDATED")
                    try:
                        validation_status = ValidationStatus[status_str]
                    except KeyError:
                        validation_status = ValidationStatus.UNVALIDATED

                    # Update issue with DAST data
                    issue.validation_status = validation_status
                    issue.validated_at = validation.get("tested_at")
                    issue.exploitability_score = validation.get("exploitability_score")

                    # Build evidence dict from DAST data
                    if validation.get("evidence"):
                        issue.dast_evidence = validation["evidence"]
                    elif (
                        validation.get("test_steps")
                        or validation.get("reason")
                        or validation.get("notes")
                    ):
                        # Create evidence from available fields
                        evidence = {}
                        if validation.get("test_steps"):
                            evidence["test_steps"] = validation["test_steps"]
                        if validation.get("reason"):
                            evidence["reason"] = validation["reason"]
                        if validation.get("notes"):
                            evidence["notes"] = validation["notes"]
                        issue.dast_evidence = evidence

                    # Track counts
                    if validation_status == ValidationStatus.VALIDATED:
                        validated_count += 1
                    elif validation_status == ValidationStatus.FALSE_POSITIVE:
                        false_positive_count += 1
                    else:
                        unvalidated_count += 1

                updated_issues.append(issue)

            # Update scan result
            scan_result.issues = updated_issues

            # Update DAST metrics
            total_tested = metadata.get("total_vulnerabilities_tested", len(validations))
            if total_tested > 0:
                scan_result.dast_enabled = True
                scan_result.dast_validation_rate = validated_count / total_tested
                scan_result.dast_false_positive_rate = false_positive_count / total_tested
                scan_result.dast_scan_time_seconds = metadata.get("scan_duration_seconds", 0)

            if self.debug:
                self.console.print(
                    f"✅ Merged DAST results: {validated_count} validated, "
                    f"{false_positive_count} false positives, {unvalidated_count} unvalidated",
                    style="green",
                )

            return scan_result

        except (OSError, json.JSONDecodeError) as e:
            if self.debug:
                self.console.print(f"⚠️  Warning: Failed to merge DAST results: {e}", style="yellow")
            return scan_result

    def _load_subagent_results(
        self,
        securevibes_dir: Path,
        repo: Path,
        files_scanned: int,
        scan_start_time: float,
        subagent: str,
    ) -> ScanResult:
        """
        Load results for a single subagent run.

        Different subagents produce different artifacts, so we need to
        check for the appropriate file and return a partial result.

        Args:
            securevibes_dir: Path to .securevibes directory
            repo: Repository path
            files_scanned: Number of files scanned
            scan_start_time: Scan start timestamp
            subagent: Name of the subagent that was run

        Returns:
            ScanResult with appropriate data for the subagent
        """
        from securevibes.scanner.subagent_manager import SUBAGENT_ARTIFACTS

        artifact_info = SUBAGENT_ARTIFACTS.get(subagent)
        if not artifact_info:
            raise RuntimeError(f"Unknown subagent: {subagent}")

        expected_artifact = artifact_info["creates"]
        artifact_path = securevibes_dir / expected_artifact

        if not artifact_path.exists():
            raise RuntimeError(
                f"Subagent '{subagent}' failed to create expected artifact:\n"
                f"  - {artifact_path}\n"
                f"Check {securevibes_dir}/ for partial artifacts."
            )

        scan_duration = time.time() - scan_start_time

        # For subagents that produce JSON with vulnerabilities, load them
        if subagent in ("code-review", "report-generator"):
            # These produce files we can parse for issues
            return self._load_scan_results(securevibes_dir, repo, files_scanned, scan_start_time)

        # For assessment and threat-modeling, return partial result
        if subagent == "assessment":
            self.console.print(
                f"\n✅ Assessment complete. Created {expected_artifact}", style="bold green"
            )
            self.console.print(
                "   Run 'securevibes scan . --subagent threat-modeling' to continue.", style="dim"
            )
        elif subagent == "threat-modeling":
            # Count threats from THREAT_MODEL.json
            threat_count = 0
            try:
                with open(artifact_path, "r") as f:
                    data = json.load(f)
                    # Handle both flat array and wrapped object formats
                    if isinstance(data, list):
                        threat_count = len(data)
                    elif isinstance(data, dict) and "threats" in data:
                        threat_count = len(data["threats"])
            except (json.JSONDecodeError, OSError):
                pass

            self.console.print(
                f"\n✅ Threat modeling complete. Created {expected_artifact} ({threat_count} threats)",
                style="bold green",
            )
            self.console.print(
                "   Run 'securevibes scan . --subagent code-review' to continue.", style="dim"
            )
        elif subagent == "dast":
            # Count validations from DAST_VALIDATION.json
            validation_count = 0
            try:
                with open(artifact_path, "r") as f:
                    validations = json.load(f)
                    if isinstance(validations, list):
                        validation_count = len(validations)
            except (json.JSONDecodeError, OSError):
                pass

            self.console.print(
                f"\n✅ DAST validation complete. Created {expected_artifact} ({validation_count} validations)",
                style="bold green",
            )

        # Return partial result with no issues (issues come from code-review)
        return ScanResult(
            repository_path=str(repo),
            files_scanned=files_scanned,
            scan_time_seconds=round(scan_duration, 2),
            total_cost_usd=round(self.total_cost, 4),
            issues=[],
        )

    def _load_scan_results(
        self,
        securevibes_dir: Path,
        repo: Path,
        files_scanned: int,
        scan_start_time: float,
        single_subagent: Optional[str] = None,
        resume_from: Optional[str] = None,
    ) -> ScanResult:
        """
        Load and parse scan results from agent-generated files.

        Reuses the same loading logic as SecurityScanner for consistency.
        """
        results_file = securevibes_dir / SCAN_RESULTS_FILE
        vulnerabilities_file = securevibes_dir / VULNERABILITIES_FILE

        issues = []

        # Helper to load file content safely
        def load_json_file(path: Path) -> Optional[Any]:
            if not path.exists():
                return None
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError) as e:
                if self.debug:
                    self.console.print(
                        f"⚠️  Warning: Failed to load {path.name}: {e}", style="yellow"
                    )
                return None

        # Try loading from files
        data = load_json_file(results_file)
        if data is None:
            data = load_json_file(vulnerabilities_file)

        if data is None:
            raise RuntimeError(
                f"Scan failed to generate results. Expected files not found:\n"
                f"  - {results_file}\n"
                f"  - {vulnerabilities_file}\n"
                f"Check {securevibes_dir}/ for partial artifacts."
            )

        try:
            # Use Pydantic to validate and parse
            from securevibes.models.scan_output import ScanOutput

            scan_output = ScanOutput.validate_input(data)

            for idx, vuln in enumerate(scan_output.vulnerabilities):
                # Map Pydantic model to domain model

                # Determine primary file info
                file_path = vuln.file_path
                line_number = vuln.line_number
                code_snippet = vuln.code_snippet

                # Fallback to affected_files if specific fields are empty
                if (not file_path or not line_number) and vuln.affected_files:
                    first = vuln.affected_files[0]
                    file_path = file_path or first.file_path

                    # Handle line number being list or int
                    ln = first.line_number
                    if isinstance(ln, list) and ln:
                        ln = ln[0]
                    line_number = line_number or ln

                    code_snippet = code_snippet or first.code_snippet

                issues.append(
                    SecurityIssue(
                        id=vuln.threat_id,
                        title=vuln.title,
                        description=vuln.description,
                        severity=vuln.severity,
                        file_path=file_path or "N/A",
                        line_number=int(line_number) if line_number is not None else 0,
                        code_snippet=code_snippet or "",
                        cwe_id=vuln.cwe_id,
                        recommendation=vuln.recommendation,
                        evidence=str(vuln.evidence) if vuln.evidence is not None else None,
                    )
                )

        except Exception as e:
            if self.debug:
                self.console.print(
                    f"❌ Error validating scan results schema: {e}", style="bold red"
                )
            raise RuntimeError(f"Failed to parse scan results: {e}")

        scan_duration = time.time() - scan_start_time
        scan_result = ScanResult(
            repository_path=str(repo),
            issues=issues,
            files_scanned=files_scanned,
            scan_time_seconds=round(scan_duration, 2),
            total_cost_usd=self.total_cost,
        )

        # Merge DAST validation results if available
        scan_result = self._merge_dast_results(scan_result, securevibes_dir)

        # Regenerate artifacts with merged validation data
        if scan_result.dast_enabled:
            self._regenerate_artifacts(scan_result, securevibes_dir)

        # Update scan state only for full scans (not subagent/resume)
        if single_subagent is None and resume_from is None:
            commit = get_repo_head_commit(repo)
            branch = get_repo_branch(repo)
            if commit and branch:
                update_scan_state(
                    securevibes_dir / SCAN_STATE_FILE,
                    full_scan=build_full_scan_entry(
                        commit=commit,
                        branch=branch,
                        timestamp=utc_timestamp(),
                    ),
                )

        return scan_result


_PR_FINDING_TYPES = frozenset(
    {
        "new_threat",
        "threat_enabler",
        "mitigation_removal",
        "known_vuln",
        "regression",
        "unknown",
    }
)


def filter_baseline_vulns(known_vulns: list[dict]) -> list[dict]:
    """Return only baseline vulnerability entries, excluding PR-derived ones.

    PR-derived entries are identified by:
    - source == "pr_review" (explicit tag added by update_pr_review_artifacts)
    - finding_type in _PR_FINDING_TYPES (normalized; matches PR_VULNERABILITY_SCHEMA enum)
    - threat_id starting with PR- or NEW- (auto-generated or LLM-assigned PR IDs)
    """
    _PR_PREFIXES = ("PR-", "NEW-")
    baseline: list[dict] = []
    for vuln in known_vulns:
        if not isinstance(vuln, dict):
            continue
        if vuln.get("source") == "pr_review":
            continue
        raw_ft = vuln.get("finding_type")
        if raw_ft is not None and str(raw_ft).strip().lower() in _PR_FINDING_TYPES:
            continue
        threat_id = vuln.get("threat_id", "")
        if isinstance(threat_id, str) and threat_id.startswith(_PR_PREFIXES):
            continue
        baseline.append(vuln)
    return baseline


def _normalize_finding_identity(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


def _build_vuln_match_keys(vuln: dict) -> set[tuple[str, str]]:
    identities = {
        identity
        for identity in (
            _normalize_finding_identity(vuln.get("threat_id")),
            _normalize_finding_identity(vuln.get("title")),
        )
        if identity
    }
    if not identities:
        return set()

    raw_path = normalize_repo_path(vuln.get("file_path")).lower()
    path_keys = {raw_path} if raw_path else {""}
    if raw_path:
        basename = raw_path.rsplit("/", 1)[-1]
        path_keys.add(basename)

    return {(path_key, identity) for path_key in path_keys for identity in identities}


def _issues_from_pr_vulns(pr_vulns: list[dict]) -> list[SecurityIssue]:
    """Convert PR vulnerability dict entries to SecurityIssue models."""
    issues: list[SecurityIssue] = []
    for vuln in pr_vulns:
        if not isinstance(vuln, dict):
            continue
        line_value = vuln.get("line_number")
        try:
            line_number = int(line_value) if line_value is not None else 0
        except (TypeError, ValueError):
            line_number = 0
        try:
            severity = Severity(vuln.get("severity", "medium"))
        except ValueError:
            severity = Severity.MEDIUM

        issues.append(
            SecurityIssue(
                id=str(vuln.get("threat_id", "UNKNOWN")),
                title=str(vuln.get("title", "")),
                description=str(vuln.get("description", "")),
                severity=severity,
                file_path=str(vuln.get("file_path", "")),
                line_number=line_number,
                code_snippet=str(vuln.get("code_snippet", "")),
                cwe_id=vuln.get("cwe_id"),
                recommendation=vuln.get("recommendation"),
                finding_type=vuln.get("finding_type"),
                attack_scenario=vuln.get("attack_scenario"),
                evidence=vuln.get("evidence"),
            )
        )
    return issues


def _diff_has_command_builder_signals(diff_context: DiffContext) -> bool:
    """Return True when changed diff hunks look like command/argv construction code."""
    signal_snippets = (
        "ssh",
        "args.append",
        "/bin/sh",
        "sh -c",
        "bash -lc",
        "spawn(",
        "exec(",
        "subprocess",
        "command -v",
    )
    signal_paths = ("command", "shell", "process", "exec", "ssh", "cli", "util")

    for diff_file in diff_context.files:
        path = _diff_file_path(diff_file).lower()
        if path and any(token in path for token in signal_paths):
            return True

        for hunk in diff_file.hunks:
            for line in hunk.lines:
                content = str(line.content or "").lower()
                if any(token in content for token in signal_snippets):
                    return True

    return False


def _build_pr_review_retry_suffix(attempt_num: int, command_builder_signals: bool = False) -> str:
    """Return extra guidance used when retrying PR review with LLM."""
    focus_block = ""
    command_builder_hint = ""
    if command_builder_signals:
        command_builder_hint = """

## COMMAND-BUILDER DELTA DETECTED
Changed hunks appear to build argv/shell commands.
Before other hypotheses, explicitly verify:
- untrusted values cannot become dash-prefixed options
- host/target positional arguments cannot be interpreted as flags
- missing `--` separators do not permit option injection pivots
"""
    if attempt_num == 2:
        focus_block = """

## FOCUS AREA: COMMAND/OPTION INJECTION CHAINS
Prioritize command builder and shell composition changes:
- untrusted env/config/input interpolated into shell fragments (`sh -c`, `bash -lc`)
- CLI option injection via untrusted args that can start with '-' (host/target/remote values)
- parser functions feeding command builders must reject dash-prefixed target/host inputs
- double-quoted interpolation still allows `$()` and backtick command substitution
Validate both local and remote execution surfaces.
"""
    elif attempt_num == 3:
        focus_block = """

## FOCUS AREA: PATH + FILE EXFILTRATION CHAINS
Prioritize changed parser/validator logic for URLs/paths/media tokens.
Look for acceptance of absolute/relative/home/traversal paths that can reach file read/host/upload/render sinks.
Do not dismiss as "refactor-only" if changed code still enables exfiltration.
"""
    elif attempt_num >= 4:
        focus_block = """

## FOCUS AREA: AUTH + PRIVILEGED OPERATION CHAINING
Prioritize trust-boundary changes that expose privileged operations (config/apply/update/exec/policy changes).
Prove end-to-end chain from attacker-controlled entrypoint to privileged sink, including missing controls.
Do not reject a chain only because direct callers are absent in this snapshot when the diff adds exported/shared command helpers.
"""

    return f"""

## FOLLOW-UP ANALYSIS PASS {attempt_num}
Previous attempt was incomplete or inconclusive. Re-run the review with this strict process:

1. Build a threat-delta list from the diff:
   - New/changed capabilities
   - New/changed trust boundaries
   - New/changed privileged sinks
2. Treat prompt-injected changed hunk snippets as authoritative changed code.
   If changed code is missing from the current checkout, analyze from diff snippets directly.
3. Compare that delta against baseline threat/vulnerability summaries as hypotheses.
4. Validate each high-impact hypothesis by reading concrete code paths in changed and adjacent files.
5. Prioritize exploit chains that combine:
   - reachability
   - auth/authorization weaknesses
   - privileged operations (config, updates, execution, policy changes)
6. Do not dismiss findings as "refactor-only" until you verify security semantics of changed helpers.
7. Avoid repetitive broad Grep. Use targeted reads/greps scoped to specific files or changed top-level paths.
8. If and only if no issue is provable, output [] after explicitly checking all prioritized changed files.
{command_builder_hint}
{focus_block}
"""


def _load_pr_vulnerabilities_artifact(
    pr_vulns_path: Path,
    console: Console,
) -> tuple[list[dict], Optional[str]]:
    """Read and normalize PR_VULNERABILITIES.json."""
    if not pr_vulns_path.exists():
        return [], "PR_VULNERABILITIES.json was not produced"

    try:
        raw_content = pr_vulns_path.read_text(encoding="utf-8")
    except OSError as e:
        return [], f"Failed to read PR_VULNERABILITIES.json: {e}"

    from securevibes.models.schemas import fix_pr_vulnerabilities_json

    fixed_content, was_fixed = fix_pr_vulnerabilities_json(raw_content)
    if was_fixed:
        console.print("  Applied PR vulnerability format normalization", style="dim")

    try:
        pr_vulns = json.loads(fixed_content)
    except json.JSONDecodeError:
        try:
            pr_vulns = json.loads(raw_content)
        except json.JSONDecodeError as e:
            return [], f"Failed to parse PR_VULNERABILITIES.json: {e}"

    if not isinstance(pr_vulns, list):
        return [], "PR_VULNERABILITIES.json is not a JSON array"

    normalized = [item for item in pr_vulns if isinstance(item, dict)]
    return normalized, None


def _merge_pr_attempt_findings(vulns: list[dict]) -> list[dict]:
    """Merge findings across attempts and keep one canonical finding per chain."""
    if not vulns:
        return []

    severity_rank = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    finding_type_rank = {
        "known_vuln": 6,
        "regression": 5,
        "threat_enabler": 5,
        "mitigation_removal": 4,
        "new_threat": 3,
        "unknown": 1,
    }
    chain_stopwords = {
        "the",
        "and",
        "with",
        "from",
        "into",
        "via",
        "that",
        "this",
        "allows",
        "allow",
        "enable",
        "enables",
        "enabled",
        "through",
        "using",
        "when",
        "where",
        "code",
        "change",
        "changes",
        "input",
        "output",
        "command",
        "commands",
        "config",
        "configuration",
        "security",
        "vulnerability",
        "attack",
        "path",
        "line",
        "file",
    }
    exploit_primitive_terms = (
        "option injection",
        "argument injection",
        "argv",
        "positional arg",
        "positional argument",
        "dash-prefixed",
        "dash prefixed",
        "missing --",
        "without --",
        "proxycommand",
        "cwe-88",
    )
    concrete_payload_terms = (
        "-o",
        "--",
        "payload",
        "proxycommand=",
        "attacker@",
        "example payload",
        "value starts with -",
    )
    speculative_terms = (
        "if bypass exists",
        "testing needed",
        "edge case",
        "could",
        "might",
        "may",
        "potential",
        "possible",
        "hypothetical",
        "warrant defense-in-depth",
    )
    hardening_terms = (
        "defense-in-depth",
        "hardening",
        "could be improved",
        "security consideration",
    )

    def _entry_text(entry: dict, *, fields: tuple[str, ...]) -> str:
        return " ".join(str(entry.get(field, "")) for field in fields).strip().lower()

    def _proof_score(entry: dict) -> int:
        score = 0
        evidence_text = _entry_text(entry, fields=("evidence",))
        scenario_text = _entry_text(entry, fields=("attack_scenario",))
        core_text = _entry_text(
            entry, fields=("title", "description", "evidence", "attack_scenario")
        )
        cwe_text = str(entry.get("cwe_id", "")).strip().upper()

        if any(term in core_text for term in exploit_primitive_terms):
            score += 4
        if "CWE-88" in cwe_text:
            score += 4
        if "cwe-78" in cwe_text and any(term in core_text for term in ("argv", "option injection")):
            score += 2
        if any(term in scenario_text for term in concrete_payload_terms):
            score += 3
        if "1)" in scenario_text and "2)" in scenario_text:
            score += 1
        if normalize_repo_path(entry.get("file_path")):
            score += 1
        if _coerce_line_number(entry.get("line_number")) > 0:
            score += 1
        if ":" in evidence_text and ("->" in evidence_text or "flow" in evidence_text):
            score += 1
        if "missing `--`" in core_text or "missing --" in core_text:
            score += 2

        return score

    def _speculation_penalty(entry: dict) -> int:
        text = _entry_text(entry, fields=("title", "description", "attack_scenario", "evidence"))
        penalty = 0
        for term in speculative_terms:
            if " " in term:
                if term in text:
                    penalty += 1
                continue
            if re.search(rf"\b{re.escape(term)}\b", text):
                penalty += 1
        if any(term in text for term in hardening_terms):
            penalty += 1
        return min(penalty, 6)

    def _coerce_line_number(value: object) -> int:
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0

    def _coarse_cwe_family(value: object) -> str:
        text = str(value or "").strip().upper()
        match = re.search(r"CWE-(\d+)", text)
        if not match:
            return ""
        return match.group(1)[:2]

    def _finding_tokens(entry: dict) -> set[str]:
        text = " ".join(
            str(entry.get(field, ""))
            for field in ("title", "description", "attack_scenario", "evidence")
        ).lower()
        tokens = re.findall(r"[a-z0-9_]+", text)
        return {
            token
            for token in tokens
            if len(token) >= 4 and token not in chain_stopwords and not token.isdigit()
        }

    def _token_similarity(a: set[str], b: set[str]) -> float:
        if not a or not b:
            return 0.0
        overlap = len(a & b)
        union = len(a | b)
        return overlap / union if union else 0.0

    def _entry_quality(entry: dict) -> tuple[int, int, int, int, int, int]:
        severity = severity_rank.get(str(entry.get("severity", "")).strip().lower(), 0)
        finding_type = finding_type_rank.get(str(entry.get("finding_type", "")).strip().lower(), 0)
        proof_score = _proof_score(entry)
        speculation_penalty = _speculation_penalty(entry)
        evidence_chars = len(str(entry.get("evidence", ""))) + len(
            str(entry.get("attack_scenario", ""))
        )
        description_chars = len(str(entry.get("description", "")))
        return (
            severity,
            finding_type,
            proof_score,
            -speculation_penalty,
            min(evidence_chars, 4000),
            min(description_chars, 2000),
        )

    def _same_chain(candidate: dict, canonical: dict) -> bool:
        candidate_path = normalize_repo_path(candidate.get("file_path"))
        canonical_path = normalize_repo_path(canonical.get("file_path"))
        if not candidate_path or not canonical_path:
            return False

        candidate_line = _coerce_line_number(candidate.get("line_number"))
        canonical_line = _coerce_line_number(canonical.get("line_number"))
        line_gap = (
            abs(candidate_line - canonical_line)
            if candidate_line > 0 and canonical_line > 0
            else 999
        )

        candidate_tokens = _finding_tokens(candidate)
        canonical_tokens = _finding_tokens(canonical)
        token_similarity = _token_similarity(candidate_tokens, canonical_tokens)

        candidate_title = str(candidate.get("title", "")).strip().lower()
        canonical_title = str(canonical.get("title", "")).strip().lower()
        title_similarity = (
            SequenceMatcher(None, candidate_title, canonical_title).ratio()
            if candidate_title and canonical_title
            else 0.0
        )

        candidate_cwe_family = _coarse_cwe_family(candidate.get("cwe_id"))
        canonical_cwe_family = _coarse_cwe_family(canonical.get("cwe_id"))
        same_cwe_family = candidate_cwe_family == canonical_cwe_family

        if candidate_path == canonical_path:
            if line_gap <= 4 and token_similarity >= 0.24:
                return True
            if (
                line_gap <= 4
                and candidate_cwe_family in {"78", "88"}
                and canonical_cwe_family in {"78", "88"}
                and token_similarity >= 0.16
            ):
                return True
            if token_similarity >= 0.52:
                return True
            if title_similarity >= 0.82:
                return True

        candidate_dir = candidate_path.rsplit("/", 1)[0] if "/" in candidate_path else ""
        canonical_dir = canonical_path.rsplit("/", 1)[0] if "/" in canonical_path else ""
        if (
            candidate_dir
            and candidate_dir == canonical_dir
            and same_cwe_family
            and token_similarity >= 0.68
        ):
            return True

        return False

    normalized_vulns = [dict(v) for v in vulns if isinstance(v, dict)]
    normalized_vulns.sort(key=_entry_quality, reverse=True)

    canonical_findings: list[dict] = []
    for candidate in normalized_vulns:
        merged = False
        for idx, existing in enumerate(canonical_findings):
            if not _same_chain(candidate, existing):
                continue
            if _entry_quality(candidate) > _entry_quality(existing):
                canonical_findings[idx] = candidate
            merged = True
            break
        if not merged:
            canonical_findings.append(candidate)

    # Secondary guard: collapse residual near-duplicates and keep the strongest proof-based variant.
    canonical_findings.sort(key=_entry_quality, reverse=True)
    final_findings: list[dict] = []
    for candidate in canonical_findings:
        candidate_path = normalize_repo_path(candidate.get("file_path"))
        candidate_line = _coerce_line_number(candidate.get("line_number"))
        candidate_cwe_family = _coarse_cwe_family(candidate.get("cwe_id"))
        candidate_tokens = _finding_tokens(candidate)
        candidate_title = str(candidate.get("title", "")).strip().lower()

        is_duplicate = False
        for existing in final_findings:
            existing_path = normalize_repo_path(existing.get("file_path"))
            if not candidate_path or candidate_path != existing_path:
                continue
            existing_line = _coerce_line_number(existing.get("line_number"))
            line_gap = (
                abs(candidate_line - existing_line)
                if candidate_line > 0 and existing_line > 0
                else 999
            )
            if line_gap > 8:
                continue

            existing_tokens = _finding_tokens(existing)
            token_similarity = _token_similarity(candidate_tokens, existing_tokens)
            existing_cwe_family = _coarse_cwe_family(existing.get("cwe_id"))
            candidate_proof = _proof_score(candidate)
            existing_proof = _proof_score(existing)
            if (
                line_gap <= 4
                and candidate_cwe_family in {"78", "88"}
                and existing_cwe_family in {"78", "88"}
                and abs(candidate_proof - existing_proof) >= 2
            ):
                is_duplicate = True
                break
            title_similarity = SequenceMatcher(
                None,
                candidate_title,
                str(existing.get("title", "")).strip().lower(),
            ).ratio()
            same_cwe_family = candidate_cwe_family and candidate_cwe_family == existing_cwe_family
            if token_similarity >= 0.34 or title_similarity >= 0.58 or same_cwe_family:
                is_duplicate = True
                break

        if not is_duplicate:
            final_findings.append(candidate)

    return final_findings


def dedupe_pr_vulns(pr_vulns: list[dict], known_vulns: list[dict]) -> list[dict]:
    """Tag PR findings as known_vuln when they overlap baseline issues."""
    known_keys: set[tuple[str, str]] = set()
    for vuln in known_vulns:
        if not isinstance(vuln, dict):
            continue
        known_keys.update(_build_vuln_match_keys(vuln))

    normalized: list[dict] = []
    for vuln in pr_vulns:
        if not isinstance(vuln, dict):
            continue
        entry = dict(vuln)
        candidate_keys = _build_vuln_match_keys(entry)
        if candidate_keys and known_keys.intersection(candidate_keys):
            finding_type = str(entry.get("finding_type", "")).strip().lower()
            if not finding_type or finding_type == "unknown":
                entry["finding_type"] = "known_vuln"
        normalized.append(entry)
    return normalized
