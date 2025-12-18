"""
Scanner hooks for ClaudeSDKClient integration.

Provides hook creator functions that return async closures for:
- DAST security restrictions (database tool blocking)
- Pre-tool processing (exclusions, write restrictions, logging)
- Post-tool completion tracking
- Sub-agent lifecycle events
- JSON validation/auto-fix for vulnerability output
"""

from pathlib import Path
from typing import Set
from rich.console import Console

from securevibes.config import ScanConfig
from securevibes.models.schemas import fix_vulnerabilities_json, validate_vulnerabilities_json


def create_dast_security_hook(tracker, console: Console, debug: bool):
    """
    Create DAST security hook that blocks database manipulation tools.
    
    DAST must simulate remote attackers who can only interact via HTTP.
    Direct database access (sqlite3, psql, etc.) is blocked to ensure
    realistic validation that requires proper test credentials.
    
    Args:
        tracker: ProgressTracker instance for phase detection
        console: Rich console for output (unused but kept for consistency)
        debug: Debug mode flag (unused but kept for consistency)
    
    Returns:
        Async hook function compatible with ClaudeSDKClient PreToolUse hook
    """
    async def dast_security_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
        tool_name = input_data.get("tool_name")
        
        # Only apply to DAST phase
        if tracker.current_phase != "dast":
            return {}
        
        # Only filter Bash commands
        if tool_name != "Bash":
            return {}
        
        tool_input = input_data.get("tool_input", {})
        command = tool_input.get("command", "")
        
        # Block database CLI tools (centralized in config)
        for tool in ScanConfig.BLOCKED_DB_TOOLS:
            if tool in command:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": f"DAST cannot use '{tool}' - HTTP testing only",
                        "reason": "Database manipulation not allowed - provide test accounts via --dast-accounts"
                    }
                }
        
        return {}  # Allow command
    
    return dast_security_hook


def create_pre_tool_hook(tracker, console: Console, debug: bool, detected_languages: Set[str]):
    """
    Create pre-tool hook for infrastructure exclusions and DAST restrictions.
    
    Handles:
    - Blocking reads from infrastructure directories (venv, node_modules, etc.)
    - Injecting exclude patterns for Grep/Glob
    - DAST write restrictions (only DAST_VALIDATION.json and /tmp/*)
    - Skill invocation logging (debug mode)
    
    Args:
        tracker: ProgressTracker instance for phase detection and tool tracking
        console: Rich console for debug output
        debug: Whether to show debug messages
        detected_languages: Set of detected languages for exclusion rules
    
    Returns:
        Async hook function compatible with ClaudeSDKClient PreToolUse hook
    """
    async def pre_tool_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
        tool_name = input_data.get("tool_name")
        tool_input = input_data.get("tool_input", {})

        # Log Skill tool invocations (debug mode)
        if tool_name == "Skill" and debug:
            skill_name = tool_input.get("skill_name", "unknown")
            console.print(
                f"  🎯 SKILL INVOKED: {skill_name}",
                style="bold cyan"
            )

        # Block reads from infrastructure directories
        if tool_name in ["Read", "Grep", "Glob", "LS"]:
            # Get phase-specific exclusions (DAST needs .claude/skills/ access)
            active_exclude_dirs = ScanConfig.get_excluded_dirs_for_phase(
                tracker.current_phase or "assessment",
                detected_languages
            )
            # Extract path from tool input (different tools use different param names)
            path = (tool_input.get("file_path") or 
                   tool_input.get("path") or 
                   tool_input.get("directory_path") or "")
            
            if path:
                # Check if path contains any excluded directory
                path_parts = Path(path).parts if path else []
                if any(excluded in path_parts for excluded in active_exclude_dirs):
                    # Return empty result to skip this tool execution
                    if debug:
                        console.print(
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
                exclude_patterns = [f"{excluded}/**" for excluded in active_exclude_dirs]
                
                # Add to existing excludePatterns if any, or create new
                existing_excludes = tool_input.get("excludePatterns", [])
                tool_input["excludePatterns"] = existing_excludes + exclude_patterns
                
                if debug:
                    console.print(
                        f"  🔍 Grep with exclusions: {len(exclude_patterns)} patterns",
                        style="dim"
                    )
            
            # For Glob, inject excludePatterns
            if tool_name == "Glob":
                exclude_patterns = [f"{excluded}/**" for excluded in active_exclude_dirs]
                existing_excludes = tool_input.get("excludePatterns", [])
                tool_input["excludePatterns"] = existing_excludes + exclude_patterns
        
        # Enforce DAST write restrictions: only allow writing DAST_VALIDATION.json or /tmp/*
        if tool_name == "Write" and tracker.current_phase == "dast":
            file_path = tool_input.get("file_path", "")
            if file_path:
                try:
                    p = Path(file_path)
                    # Allow primary artifact write
                    allowed_artifact = p.name == "DAST_VALIDATION.json" and p.parent.name == ".securevibes"
                    # Allow ephemeral temp writes under /tmp for helper code/data
                    allowed_tmp = str(p).startswith("/tmp/")
                    allowed = allowed_artifact or allowed_tmp
                except Exception:
                    allowed = False
                if not allowed:
                    # Block non-artifact writes during DAST phase
                    return {
                        "override_result": {
                            "content": (
                                "DAST phase may only write .securevibes/DAST_VALIDATION.json. "
                                f"Blocked write to: {file_path}"
                            ),
                            "is_error": False
                        }
                    }

        # Track tool start
        tracker.on_tool_start(tool_name, tool_input)
        return {}
    
    return pre_tool_hook


def create_post_tool_hook(tracker, console: Console, debug: bool):
    """
    Create post-tool hook for completion tracking and debug logging.
    
    Args:
        tracker: ProgressTracker instance for completion tracking
        console: Rich console for debug output
        debug: Whether to show detailed file operation logs
    
    Returns:
        Async hook function compatible with ClaudeSDKClient PostToolUse hook
    """
    async def post_tool_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
        tool_name = input_data.get("tool_name")
        tool_input = input_data.get("tool_input", {})
        tool_response = input_data.get("tool_response", {})
        is_error = tool_response.get("is_error", False)
        error_msg = tool_response.get("content", "") if is_error else None
        tracker.on_tool_complete(tool_name, not is_error, error_msg)
        
        # Additional success logs with full paths in debug mode
        if debug and not is_error and tool_name in ("Read", "Write"):
            p = tool_input.get("file_path") or tool_input.get("path")
            if p:
                action = "✅ Read" if tool_name == "Read" else "✅ Wrote"
                console.print(f"  {action} {p}", style="dim green")
        return {}
    
    return post_tool_hook


def create_subagent_hook(tracker):
    """
    Create sub-agent lifecycle hook for phase completion tracking.
    
    Args:
        tracker: ProgressTracker instance for lifecycle events
    
    Returns:
        Async hook function compatible with ClaudeSDKClient SubagentStop hook
    """
    async def subagent_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
        agent_name = input_data.get("agent_name") or input_data.get("subagent_type")
        duration_ms = input_data.get("duration_ms", 0)
        if agent_name:
            tracker.on_subagent_stop(agent_name, duration_ms)
        return {}
    
    return subagent_hook


def create_json_validation_hook(console: Console, debug: bool):
    """
    Create PreToolUse hook that validates and auto-fixes vulnerability JSON output.
    
    This hook intercepts Write operations to VULNERABILITIES.json and:
    1. Validates the JSON conforms to the expected flat array schema
    2. Auto-fixes common issues like wrapper objects {"vulnerabilities": [...]}
    3. Logs warnings when fixes are applied
    
    This provides deterministic output enforcement complementing prompt-based guidance,
    ensuring the code review agent's output always matches the expected schema.
    
    Args:
        console: Rich console for output
        debug: Whether to show debug messages
    
    Returns:
        Async hook function compatible with ClaudeSDKClient PreToolUse hook
    """
    async def json_validation_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
        tool_name = input_data.get("tool_name")
        
        # Only intercept Write operations
        if tool_name != "Write":
            return {}
        
        tool_input = input_data.get("tool_input", {})
        file_path = tool_input.get("file_path", "")
        
        # Only validate VULNERABILITIES.json writes
        if not file_path or "VULNERABILITIES.json" not in file_path:
            return {}
        
        content = tool_input.get("content", "")
        if not content:
            return {}
        
        # Attempt to fix common format issues
        fixed_content, was_modified = fix_vulnerabilities_json(content)
        
        if was_modified:
            if debug:
                console.print(
                    "  🔧 Auto-fixed VULNERABILITIES.json format (unwrapped wrapper object)",
                    style="yellow"
                )
            else:
                console.print(
                    "  ⚠️  Fixed JSON format in VULNERABILITIES.json",
                    style="yellow"
                )
        
        # Validate the (potentially fixed) content
        is_valid, error_msg = validate_vulnerabilities_json(fixed_content)
        
        if not is_valid:
            console.print(
                f"  ❌ VULNERABILITIES.json validation failed: {error_msg}",
                style="bold red"
            )
            # Don't block - let it write but warn
            # The Pydantic validation in scanner.py will catch it later
        elif debug:
            console.print(
                "  ✅ VULNERABILITIES.json schema validated",
                style="green"
            )
        
        # If content was modified, return updated input
        if was_modified:
            return {
                "updatedInput": {
                    **tool_input,
                    "content": fixed_content
                }
            }
        
        return {}
    
    return json_validation_hook
