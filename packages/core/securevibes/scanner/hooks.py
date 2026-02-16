"""
Scanner hooks for ClaudeSDKClient integration.

Provides hook creator functions that return async closures for:
- DAST security restrictions (database tool blocking)
- Pre-tool processing (exclusions, write restrictions, logging)
- Post-tool completion tracking
- Sub-agent lifecycle events
- JSON validation/auto-fix for vulnerability output
"""

import json
import re
from pathlib import Path
from typing import Any, Optional, Set
from rich.console import Console

from securevibes.config import ScanConfig
from securevibes.models.schemas import (
    fix_threat_model_json,
    fix_pr_vulnerabilities_json,
    fix_vulnerabilities_json,
    validate_threat_model_json,
    validate_pr_vulnerabilities_json,
    validate_vulnerabilities_json,
)


_COMMAND_TOKEN_RE = re.compile(r"[a-z0-9._-]+")


def _normalize_hook_path(file_path: object) -> str:
    """Normalize path-like values for robust hook path comparisons."""
    return str(file_path or "").strip().replace("\\", "/")


def _is_securevibes_artifact_path(file_path: object, artifact_name: str) -> bool:
    """Return True for exact artifact targets under `.securevibes/`."""
    normalized = _normalize_hook_path(file_path)
    if not normalized:
        return False

    relative_target = f".securevibes/{artifact_name}"
    return normalized == relative_target or normalized.endswith(f"/{relative_target}")


def _classify_vulnerability_artifact_path(file_path: object) -> tuple[bool, bool]:
    """Return (is_supported_artifact, is_pr_artifact) for vulnerability writes."""
    is_pr = _is_securevibes_artifact_path(file_path, "PR_VULNERABILITIES.json")
    is_vulns = _is_securevibes_artifact_path(file_path, "VULNERABILITIES.json")
    return (is_pr or is_vulns, is_pr)


def _path_contains_excluded(path: object, excluded_dirs: Set[str]) -> bool:
    """Return True when a path contains any excluded segment sequence."""
    normalized_path = _normalize_hook_path(path)
    if not normalized_path:
        return False

    path_parts = tuple(part for part in Path(normalized_path).parts if part and part != "/")
    if not path_parts:
        return False

    for excluded in excluded_dirs:
        excluded_norm = _normalize_hook_path(excluded).strip("/")
        if not excluded_norm:
            continue

        excluded_parts = tuple(part for part in excluded_norm.split("/") if part)
        if not excluded_parts:
            continue

        if len(excluded_parts) == 1:
            if excluded_parts[0] in path_parts:
                return True
            continue

        window = len(excluded_parts)
        for idx in range(0, len(path_parts) - window + 1):
            if path_parts[idx : idx + window] == excluded_parts:
                return True

    return False


def _merge_exclude_patterns(tool_input: dict[str, Any], exclude_patterns: list[str]) -> None:
    """Safely merge hook exclude patterns into tool_input."""
    existing = tool_input.get("excludePatterns")
    if isinstance(existing, list):
        merged = existing
    elif isinstance(existing, tuple):
        merged = list(existing)
    elif isinstance(existing, str):
        merged = [existing]
    else:
        merged = []

    tool_input["excludePatterns"] = merged + exclude_patterns


def _sanitize_pr_grep_scope(scope_path: object) -> str:
    """Return a safe repository-relative Grep scope for PR review pathless queries."""
    normalized = _normalize_hook_path(scope_path)
    if not normalized:
        return "src"

    candidate = Path(normalized)
    if candidate.is_absolute():
        return "src"

    parts = [part for part in candidate.parts if part and part != "."]
    if not parts or any(part == ".." for part in parts):
        return "src"

    return "/".join(parts)


def _is_within_tmp_dir(file_path: object) -> bool:
    """Return True when an absolute path resolves under /tmp."""
    normalized = _normalize_hook_path(file_path)
    if not normalized:
        return False

    try:
        candidate = Path(normalized)
        if not candidate.is_absolute():
            return False
        resolved_candidate = candidate.resolve(strict=False)
        tmp_root = Path("/tmp").resolve(strict=False)
        return resolved_candidate == tmp_root or tmp_root in resolved_candidate.parents
    except (OSError, RuntimeError, ValueError, TypeError):
        return False


def _is_repo_artifact_path(
    file_path: object, artifact_name: str, repo_root: Optional[Path]
) -> bool:
    """Return True when file_path points to the exact artifact under repo .securevibes/."""
    normalized = _normalize_hook_path(file_path)
    if not normalized:
        return False

    if not _is_securevibes_artifact_path(normalized, artifact_name):
        return False

    try:
        candidate = Path(normalized)
        if candidate.name != artifact_name or candidate.parent.name != ".securevibes":
            return False

        if repo_root is None:
            return normalized == f".securevibes/{artifact_name}"

        root_path = repo_root.resolve(strict=False)
        if not candidate.is_absolute():
            candidate = root_path / candidate
        resolved_candidate = candidate.resolve(strict=False)
        expected_path = (root_path / ".securevibes" / artifact_name).resolve(strict=False)
        return resolved_candidate == expected_path
    except (OSError, RuntimeError, ValueError, TypeError):
        return False


def _command_uses_blocked_db_tool(command: object, blocked_tools: list[str]) -> Optional[str]:
    """Return matched blocked DB tool when command invokes one, else None."""
    normalized = str(command or "").lower()
    if not normalized.strip():
        return None

    tokens = set(_COMMAND_TOKEN_RE.findall(normalized))
    for tool in blocked_tools:
        candidate = str(tool or "").strip().lower()
        if not candidate:
            continue

        if candidate in tokens:
            return candidate

        if re.search(rf"(?<![a-z0-9._-]){re.escape(candidate)}(?![a-z0-9._-])", normalized):
            return candidate

    return None


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

        matched_tool = _command_uses_blocked_db_tool(command, ScanConfig.BLOCKED_DB_TOOLS)
        if matched_tool:
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        f"DAST cannot use '{matched_tool}' - HTTP testing only"
                    ),
                    "reason": "Database manipulation not allowed - provide test accounts via --dast-accounts",
                }
            }

        return {}  # Allow command

    return dast_security_hook


def create_pre_tool_hook(
    tracker,
    console: Console,
    debug: bool,
    detected_languages: Set[str],
    pr_grep_default_path: str = "src",
    pr_repo_root: Optional[Path] = None,
    pr_tool_guard_observer: Optional[dict[str, Any]] = None,
):
    """
    Create pre-tool hook for infrastructure exclusions and DAST restrictions.

    Handles:
    - Blocking reads from infrastructure directories (venv, node_modules, etc.)
    - Injecting exclude patterns for Grep/Glob
    - DAST write restrictions (only DAST_VALIDATION.json and /tmp/*)
    - PR review path and artifact guardrails

    Args:
        tracker: ProgressTracker instance for phase detection and tool tracking
        console: Rich console for debug output
        debug: Whether to show debug messages
        detected_languages: Set of detected languages for exclusion rules
        pr_grep_default_path: Default path used for pathless Grep calls in PR review
        pr_repo_root: Repository root path for PR review repo-boundary enforcement
        pr_tool_guard_observer: Optional mutable observer for PR review guard telemetry

    Returns:
        Async hook function compatible with ClaudeSDKClient PreToolUse hook
    """

    async def pre_tool_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
        tool_name = input_data.get("tool_name")
        tool_input = input_data.get("tool_input", {})

        # Note: Skill tool logging removed - SDK auto-loads skills from .claude/skills/
        # without explicit Skill tool calls. Skill sync is logged in Scanner._setup_*_skills().

        # Block reads from infrastructure directories
        if tool_name in ["Read", "Grep", "Glob", "LS"]:
            current_phase = tracker.current_phase or "assessment"
            # Get phase-specific exclusions (DAST needs .claude/skills/ access)
            active_exclude_dirs = ScanConfig.get_excluded_dirs_for_phase(
                current_phase, detected_languages
            )
            # Extract path from tool input (different tools use different param names)
            path = (
                tool_input.get("file_path")
                or tool_input.get("path")
                or tool_input.get("directory_path")
                or ""
            )

            if current_phase == "pr-code-review" and pr_repo_root:
                root_path = pr_repo_root.resolve(strict=False)

                def _resolve_candidate(candidate: object) -> Optional[Path]:
                    normalized_candidate = _normalize_hook_path(candidate)
                    if not normalized_candidate:
                        return None
                    try:
                        candidate_path = Path(normalized_candidate)
                        if not candidate_path.is_absolute():
                            candidate_path = root_path / candidate_path
                        return candidate_path.resolve(strict=False)
                    except (OSError, RuntimeError, ValueError, TypeError):
                        return None

                blocked_candidate: Optional[Path] = None
                resolved_path = _resolve_candidate(path)
                if path and resolved_path is not None:
                    is_inside_repo = (
                        resolved_path == root_path or root_path in resolved_path.parents
                    )
                    if not is_inside_repo:
                        blocked_candidate = resolved_path

                # Glob uses "patterns" instead of path/file_path; enforce guard for each pattern.
                if blocked_candidate is None and tool_name == "Glob":
                    raw_patterns = tool_input.get("patterns", [])
                    if isinstance(raw_patterns, str):
                        glob_patterns = [raw_patterns]
                    elif isinstance(raw_patterns, tuple):
                        glob_patterns = list(raw_patterns)
                    elif isinstance(raw_patterns, list):
                        glob_patterns = raw_patterns
                    else:
                        glob_patterns = []

                    for pattern in glob_patterns:
                        resolved_pattern = _resolve_candidate(pattern)
                        if resolved_pattern is None:
                            continue
                        is_inside_repo = (
                            resolved_pattern == root_path or root_path in resolved_pattern.parents
                        )
                        if not is_inside_repo:
                            blocked_candidate = resolved_pattern
                            break

                if blocked_candidate is not None:
                    if pr_tool_guard_observer is not None:
                        blocked_count = int(
                            pr_tool_guard_observer.get("blocked_out_of_repo_count", 0)
                        )
                        pr_tool_guard_observer["blocked_out_of_repo_count"] = blocked_count + 1
                        blocked_paths = pr_tool_guard_observer.setdefault("blocked_paths", [])
                        if isinstance(blocked_paths, list):
                            blocked_paths.append(str(blocked_candidate))
                    if debug:
                        console.print(
                            f"  🚫 Blocked out-of-repo {tool_name}: {blocked_candidate}",
                            style="dim yellow",
                        )
                    return {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": (
                                "PR review cannot access files outside repository root"
                            ),
                            "reason": (
                                "PR review guard blocked out-of-repo access: "
                                f"{blocked_candidate}"
                            ),
                        }
                    }

            if path:
                # Check if path contains any excluded directory
                if _path_contains_excluded(path, active_exclude_dirs):
                    # Return empty result to skip this tool execution
                    if debug:
                        console.print(
                            f"  ⏭️  Skipped: {path} (infrastructure directory)", style="dim yellow"
                        )
                    return {
                        "override_result": {
                            "content": f"Skipped: Infrastructure directory excluded from scan ({path})",
                            "is_error": False,
                        }
                    }

            if tool_name == "Read" and current_phase == "pr-code-review":
                normalized_path = str(path or "").replace("\\", "/")
                is_diff_context_read = normalized_path.endswith(
                    "/.securevibes/DIFF_CONTEXT.json"
                ) or (normalized_path == ".securevibes/DIFF_CONTEXT.json")
                if is_diff_context_read:
                    return {
                        "override_result": {
                            "content": (
                                "PR review guard: DIFF_CONTEXT.json reads are disabled. "
                                "Use prompt-provided changed files and changed-line anchors."
                            ),
                            "is_error": False,
                        }
                    }

            if tool_name == "Grep" and current_phase == "pr-code-review":
                normalized_path = str(path or "").replace("\\", "/")
                if normalized_path.endswith("/.securevibes/DIFF_CONTEXT.json") or (
                    normalized_path == ".securevibes/DIFF_CONTEXT.json"
                ):
                    return {
                        "override_result": {
                            "content": (
                                "PR review guard: do not grep DIFF_CONTEXT.json. "
                                "Use the prompt-provided changed file lists and inspect source files directly."
                            ),
                            "is_error": False,
                        }
                    }
                if not normalized_path:
                    # Prevent expensive repo-wide Grep loops in PR review.
                    # Scope to an injected top-level directory derived from changed files.
                    scope_path = _sanitize_pr_grep_scope(pr_grep_default_path)
                    if pr_repo_root:
                        root_path = pr_repo_root.resolve(strict=False)
                        try:
                            resolved_scope = (root_path / scope_path).resolve(strict=False)
                        except (OSError, RuntimeError, ValueError, TypeError):
                            resolved_scope = None

                        is_inside_repo = bool(
                            resolved_scope
                            and (resolved_scope == root_path or root_path in resolved_scope.parents)
                        )
                        if not is_inside_repo:
                            if pr_tool_guard_observer is not None:
                                blocked_count = int(
                                    pr_tool_guard_observer.get("blocked_out_of_repo_count", 0)
                                )
                                pr_tool_guard_observer["blocked_out_of_repo_count"] = (
                                    blocked_count + 1
                                )
                                blocked_paths = pr_tool_guard_observer.setdefault(
                                    "blocked_paths", []
                                )
                                if isinstance(blocked_paths, list) and resolved_scope is not None:
                                    blocked_paths.append(str(resolved_scope))
                            return {
                                "hookSpecificOutput": {
                                    "hookEventName": "PreToolUse",
                                    "permissionDecision": "deny",
                                    "permissionDecisionReason": (
                                        "PR review cannot access files outside repository root"
                                    ),
                                    "reason": (
                                        "PR review guard blocked pathless Grep scope: "
                                        f"{scope_path}"
                                    ),
                                }
                            }

                    updated_input = {**tool_input, "path": scope_path}
                    if debug:
                        console.print(
                            f"  🔧 Scoped PR Grep without path to {scope_path}/",
                            style="dim yellow",
                        )
                    return {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "updatedInput": updated_input,
                        }
                    }

            # For Grep, inject excludePatterns to filter out infrastructure directories
            if tool_name == "Grep":
                # Add exclude patterns for infrastructure directories
                exclude_patterns = [f"{excluded}/**" for excluded in active_exclude_dirs]

                # Add to existing excludePatterns if any, or create new
                _merge_exclude_patterns(tool_input, exclude_patterns)

                if debug:
                    console.print(
                        f"  🔍 Grep with exclusions: {len(exclude_patterns)} patterns", style="dim"
                    )

            # For Glob, inject excludePatterns
            if tool_name == "Glob":
                exclude_patterns = [f"{excluded}/**" for excluded in active_exclude_dirs]
                _merge_exclude_patterns(tool_input, exclude_patterns)

        # Enforce DAST write restrictions: only allow writing DAST_VALIDATION.json or /tmp/*
        if tool_name == "Write" and tracker.current_phase == "dast":
            file_path = _normalize_hook_path(tool_input.get("file_path", ""))
            if not file_path:
                return {
                    "override_result": {
                        "content": (
                            "DAST phase write rejected: file_path is required. "
                            "DAST phase may only write .securevibes/DAST_VALIDATION.json or /tmp/*."
                        ),
                        "is_error": True,
                    }
                }

            # Allow primary artifact write only under current repository.
            allowed_artifact = _is_repo_artifact_path(
                file_path, "DAST_VALIDATION.json", pr_repo_root
            )
            # Allow ephemeral temp writes under /tmp for helper code/data
            allowed_tmp = _is_within_tmp_dir(file_path)
            allowed = allowed_artifact or allowed_tmp
            if not allowed:
                # Block non-artifact writes during DAST phase
                return {
                    "override_result": {
                        "content": (
                            "DAST phase may only write .securevibes/DAST_VALIDATION.json or /tmp/*. "
                            f"Blocked write to: {file_path}"
                        ),
                        "is_error": True,
                    }
                }

        # Enforce PR review write restrictions:
        # only allow writing .securevibes/PR_VULNERABILITIES.json
        if tool_name == "Write" and tracker.current_phase == "pr-code-review":
            file_path = _normalize_hook_path(tool_input.get("file_path", ""))
            if not file_path:
                return {
                    "override_result": {
                        "content": (
                            "Write rejected by SecureVibes PR review guard: file_path is required. "
                            "PR code review phase may only write .securevibes/PR_VULNERABILITIES.json."
                        ),
                        "is_error": True,
                    }
                }

            artifact_name = "PR_VULNERABILITIES.json"
            required_relative_path = f".securevibes/{artifact_name}"
            normalized_file_path = file_path
            wants_pr_artifact = False
            try:
                p = Path(file_path)
                wants_pr_artifact = p.name == artifact_name

                # Normalize only truly bare artifact writes so orchestration can find the output.
                # Do not rewrite nested paths like src/.securevibes/PR_VULNERABILITIES.json.
                if wants_pr_artifact and p.parent == Path("."):
                    normalized_file_path = required_relative_path
            except (ValueError, TypeError):
                wants_pr_artifact = False

            # Enforce repo boundary for PR review writes.
            if pr_repo_root and wants_pr_artifact:
                root_path = pr_repo_root.resolve(strict=False)
                candidate_path = Path(normalized_file_path)
                if not candidate_path.is_absolute():
                    candidate_path = root_path / candidate_path
                resolved_candidate = candidate_path.resolve(strict=False)
                is_inside_repo = (
                    resolved_candidate == root_path or root_path in resolved_candidate.parents
                )
                if not is_inside_repo:
                    if pr_tool_guard_observer is not None:
                        blocked_count = int(
                            pr_tool_guard_observer.get("blocked_out_of_repo_count", 0)
                        )
                        pr_tool_guard_observer["blocked_out_of_repo_count"] = blocked_count + 1
                        blocked_paths = pr_tool_guard_observer.setdefault("blocked_paths", [])
                        if isinstance(blocked_paths, list):
                            blocked_paths.append(str(resolved_candidate))
                    return {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": (
                                "PR review cannot write files outside repository root"
                            ),
                            "reason": (
                                "PR review guard blocked out-of-repo write: "
                                f"{resolved_candidate}"
                            ),
                        }
                    }

            if pr_repo_root:
                allowed = _is_repo_artifact_path(normalized_file_path, artifact_name, pr_repo_root)
            else:
                # Fail closed when repo root is unavailable: only allow canonical relative path.
                allowed = normalized_file_path == required_relative_path

            # Normalize legacy/bare artifact path writes (e.g., PR_VULNERABILITIES.json)
            # to the required .securevibes location so orchestration can find the file.
            if wants_pr_artifact and normalized_file_path != file_path:
                if debug:
                    console.print(
                        f"  🔧 Normalized PR artifact path: {file_path} -> {normalized_file_path}",
                        style="dim yellow",
                    )
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "updatedInput": {**tool_input, "file_path": normalized_file_path},
                    }
                }

            if not allowed:
                return {
                    "override_result": {
                        "content": (
                            "Write rejected by SecureVibes PR review guard. "
                            "PR code review phase may only write "
                            ".securevibes/PR_VULNERABILITIES.json. "
                            f"Blocked write to: {file_path}"
                        ),
                        "is_error": True,
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


def create_json_validation_hook(
    console: Console,
    debug: bool,
    write_observer: dict[str, Any] | None = None,
):
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

    pr_invalid_attempts = 0
    max_pr_retries = 1

    def _observe_pr_write(parsed_content: object, normalized_content: str) -> None:
        if write_observer is None:
            return

        write_observer["total_writes"] = int(write_observer.get("total_writes", 0)) + 1
        if not isinstance(parsed_content, list):
            write_observer.setdefault("item_counts", []).append(0)
            return

        normalized_entries = [entry for entry in parsed_content if isinstance(entry, dict)]
        item_count = len(normalized_entries)
        write_observer.setdefault("item_counts", []).append(item_count)
        if item_count > int(write_observer.get("max_items", 0)):
            write_observer["max_items"] = item_count
            write_observer["max_content"] = normalized_content

    async def json_validation_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
        nonlocal pr_invalid_attempts

        tool_name = input_data.get("tool_name")

        # Only intercept Write operations
        if tool_name != "Write":
            return {}

        tool_input = input_data.get("tool_input", {})
        file_path = tool_input.get("file_path", "")

        # Only validate strict SecureVibes vulnerability artifact writes.
        if not file_path:
            return {}

        is_target_artifact, is_pr_review = _classify_vulnerability_artifact_path(file_path)
        if not is_target_artifact:
            return {}

        if debug:
            console.print(
                f"  🔍 [Hook] Intercepted Write to: {file_path}",
                style="dim",
            )

        content = tool_input.get("content", "")
        if not content:
            if debug:
                console.print("  🔍 [Hook] Empty content, skipping", style="dim")
            return {}

        # Log original content analysis
        if debug:
            try:
                original_data = json.loads(content)
                if isinstance(original_data, list) and original_data:
                    first_item = original_data[0] if isinstance(original_data[0], dict) else {}
                    has_finding_type = "finding_type" in first_item
                    has_extra_fields = any(
                        k in first_item
                        for k in ["impact_analysis", "exploitability", "cvss_v3_score"]
                    )
                    console.print(
                        f"  🔍 [Hook] Original: finding_type={has_finding_type}, "
                        f"extra_fields={has_extra_fields}, items={len(original_data)}",
                        style="dim",
                    )
            except (json.JSONDecodeError, TypeError):
                pass

        # Attempt to fix common format issues
        if is_pr_review:
            fixed_content, was_modified = fix_pr_vulnerabilities_json(content)
        else:
            fixed_content, was_modified = fix_vulnerabilities_json(content)

        parsed_fixed_content: object = None
        try:
            parsed_fixed_content = json.loads(fixed_content)
        except (json.JSONDecodeError, TypeError):
            parsed_fixed_content = None

        if is_pr_review:
            _observe_pr_write(parsed_fixed_content, fixed_content)

        # Log normalization result
        if debug:
            if isinstance(parsed_fixed_content, list) and parsed_fixed_content:
                first_item = (
                    parsed_fixed_content[0] if isinstance(parsed_fixed_content[0], dict) else {}
                )
                has_finding_type = "finding_type" in first_item
                finding_type_value = first_item.get("finding_type", "N/A")
                console.print(
                    f"  🔍 [Hook] After fix: was_modified={was_modified}, "
                    f"finding_type={has_finding_type} (value={finding_type_value})",
                    style="dim",
                )

        if was_modified:
            if debug:
                if is_pr_review:
                    console.print(
                        "  🔧 Auto-fixed PR_VULNERABILITIES.json format (unwrapped wrapper object)",
                        style="yellow",
                    )
                else:
                    console.print(
                        "  🔧 Auto-fixed VULNERABILITIES.json format (unwrapped wrapper object)",
                        style="yellow",
                    )
            else:
                console.print(
                    (
                        "  ⚠️  Fixed JSON format in PR_VULNERABILITIES.json"
                        if is_pr_review
                        else "  ⚠️  Fixed JSON format in VULNERABILITIES.json"
                    ),
                    style="yellow",
                )

        # Validate the (potentially fixed) content
        if is_pr_review:
            is_valid, error_msg = validate_pr_vulnerabilities_json(fixed_content)
        else:
            is_valid, error_msg = validate_vulnerabilities_json(fixed_content)

        if not is_valid:
            if is_pr_review:
                pr_invalid_attempts += 1
                remaining = max(0, max_pr_retries - pr_invalid_attempts + 1)
                reason = error_msg or "Unknown validation error"

                if pr_invalid_attempts <= max_pr_retries:
                    console.print(
                        f"  ❌ PR_VULNERABILITIES.json validation failed "
                        f"(retry {pr_invalid_attempts}/{max_pr_retries}): {reason}",
                        style="bold red",
                    )
                    return {
                        "override_result": {
                            "content": (
                                "Write rejected by SecureVibes PR validation.\n"
                                f"Reason: {reason}\n"
                                f"Retries remaining: {remaining}\n\n"
                                "PR_VULNERABILITIES.json rejected: empty evidence fields. "
                                "Read the actual source files and populate file_path, "
                                "line_number, code_snippet, evidence, and cwe_id for every finding."
                            ),
                            "is_error": True,
                        }
                    }

                console.print(
                    "  ❌ PR_VULNERABILITIES.json still failed validation after retry budget; "
                    "rejecting write and failing closed.",
                    style="bold red",
                )
                return {
                    "override_result": {
                        "content": (
                            "Write rejected by SecureVibes PR validation.\n"
                            f"Reason: {reason}\n"
                            "Retry budget exhausted: invalid PR_VULNERABILITIES.json cannot be accepted.\n\n"
                            "Read the actual source files and populate file_path, "
                            "line_number, code_snippet, evidence, and cwe_id for every finding."
                        ),
                        "is_error": True,
                    }
                }
            else:
                console.print(
                    f"  ❌ VULNERABILITIES.json validation failed: {error_msg}",
                    style="bold red",
                )
                # Non-PR code review remains warn-only for compatibility.
        elif debug:
            console.print(
                (
                    "  ✅ PR_VULNERABILITIES.json schema validated"
                    if is_pr_review
                    else "  ✅ VULNERABILITIES.json schema validated"
                ),
                style="green",
            )

        # If content was modified, return updated input
        if was_modified:
            if debug:
                console.print(
                    f"  🔍 [Hook] Returning updatedInput (content_len={len(fixed_content)})",
                    style="dim",
                )
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "updatedInput": {**tool_input, "content": fixed_content},
                }
            }

        if debug:
            console.print("  🔍 [Hook] No modifications, returning empty dict", style="dim")
        return {}

    return json_validation_hook


def create_threat_model_validation_hook(
    console: Console,
    debug: bool,
    *,
    require_asi: bool,
    max_retries: int = 1,
):
    """Create PreToolUse hook that validates THREAT_MODEL.json with optional ASI enforcement.

    Behavior:
    - Auto-fixes common wrapper/code-fence issues.
    - If require_asi=True and no ASI threats are present, the first invalid write is
      rejected with an actionable error (allowing the agent to retry once).
    - After max_retries invalid attempts, the scan fails fast.
    """

    invalid_attempts = 0

    async def threat_model_validation_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
        nonlocal invalid_attempts

        tool_name = input_data.get("tool_name")
        if tool_name != "Write":
            return {}

        tool_input = input_data.get("tool_input", {})
        file_path = tool_input.get("file_path", "")
        if not _is_securevibes_artifact_path(file_path, "THREAT_MODEL.json"):
            return {}

        content = tool_input.get("content", "")
        if not content or not content.strip():
            return {}

        fixed_content, was_modified = fix_threat_model_json(content)
        is_valid, error_msg, warnings = validate_threat_model_json(
            fixed_content,
            require_asi=require_asi,
        )

        if warnings and debug:
            for w in warnings:
                console.print(f"  ⚠️  THREAT_MODEL.json warning: {w}", style="yellow")

        if not is_valid:
            invalid_attempts += 1
            remaining = max(0, max_retries - invalid_attempts + 1)

            if invalid_attempts <= max_retries:
                # Reject write but allow the agent to regenerate.
                reason = error_msg or "Unknown validation error"
                console.print(
                    f"  ❌ THREAT_MODEL.json validation failed (retry {invalid_attempts}/{max_retries}): {reason}",
                    style="bold red",
                )
                if require_asi:
                    guidance = (
                        "This repository was detected as agentic. "
                        "Regenerate THREAT_MODEL.json as a single JSON array and include ASI threats "
                        "with IDs like THREAT-ASI01-001 and THREAT-ASI03-001."
                    )
                else:
                    guidance = "Regenerate THREAT_MODEL.json as a single JSON array (no wrapper objects, no text)."

                return {
                    "override_result": {
                        "content": (
                            "Write rejected by SecureVibes threat-model validation.\n"
                            f"Reason: {reason}\n"
                            f"Retries remaining: {remaining}\n\n"
                            f"Fix: {guidance}"
                        ),
                        "is_error": True,
                    }
                }

            # Fail fast after retry budget.
            raise RuntimeError(
                f"THREAT_MODEL.json validation failed after {max_retries} retry: {error_msg}"
            )

        if was_modified:
            if debug:
                console.print(
                    "  🔧 Auto-fixed THREAT_MODEL.json format (unwrapped wrapper / removed code fences)",
                    style="yellow",
                )
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "updatedInput": {
                        **tool_input,
                        "content": fixed_content,
                    },
                }
            }

        if debug:
            console.print("  ✅ THREAT_MODEL.json schema validated", style="green")
        return {}

    return threat_model_validation_hook
