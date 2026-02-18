"""Exploit-chain identity and consensus helpers for PR review."""

from __future__ import annotations

import re
from typing import Callable, Dict, Optional

from securevibes.diff.context import normalize_repo_path
from securevibes.diff.parser import DiffContext, DiffFile


def diff_file_path(diff_file: DiffFile) -> str:
    return str(diff_file.new_path or diff_file.old_path or "")


CHAIN_STOPWORDS = {
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
    "using",
    "when",
    "where",
    "code",
    "change",
    "changes",
    "input",
    "output",
    "attack",
    "vulnerability",
    "security",
    "through",
    "command",
    "commands",
    "config",
    "configuration",
    "path",
    "line",
    "file",
}
_CHAIN_FAMILY_PATH_TERMS = (
    "path traversal",
    "file exfiltration",
    "local file",
    "file://",
    "copyfile",
    "fs.copyfile",
    "fs.stat",
    "sendfile",
    "/media/",
    "media/:id",
    "download",
    "upload",
)
_CHAIN_FAMILY_COMMAND_TERMS = (
    "option injection",
    "argument injection",
    "argv",
    "proxycommand",
    "missing --",
    "without --",
    "/bin/sh",
    "sh -c",
    "exec(",
    "spawn(",
    "ssh",
    "command injection",
)
_CHAIN_FAMILY_AUTH_TERMS = (
    "unauth",
    "auth bypass",
    "allowfrom",
    "privilege",
    "role check",
    "permission",
    "origin check",
)


def coerce_line_number(value: object) -> int:
    """Parse line number-like values into an integer or 0."""
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0


def extract_cwe_family(value: object) -> str:
    """Extract coarse CWE family prefix used for chain grouping."""
    text = str(value or "").strip().upper()
    match = re.search(r"CWE-(\d+)", text)
    if not match:
        return ""
    return match.group(1)[:2]


def chain_text_tokens(value: object, *, max_tokens: int = 5) -> tuple[str, ...]:
    """Extract stable lowercase tokens for chain identity construction."""
    text = str(value or "").lower()
    tokens = re.findall(r"[a-z0-9_]+", text)
    filtered = [
        token
        for token in tokens
        if len(token) >= 4 and token not in CHAIN_STOPWORDS and not token.isdigit()
    ]
    return tuple(filtered[:max_tokens])


def finding_text(entry: dict, *, fields: tuple[str, ...]) -> str:
    """Return normalized lowercase joined finding fields for identity heuristics."""
    if not isinstance(entry, dict):
        return ""
    return " ".join(str(entry.get(field, "")) for field in fields).strip().lower()


def extract_finding_locations(entry: dict) -> tuple[str, ...]:
    """Extract canonicalized code file locations referenced in finding text."""
    text = finding_text(entry, fields=("evidence", "attack_scenario", "description"))
    if not text:
        return tuple()
    raw_matches = re.findall(r"([a-z0-9_./\\-]+\.[a-z0-9_]+)(?::\d+)?", text)
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_path in raw_matches:
        normalized_path = canonicalize_finding_path(raw_path)
        if not normalized_path or normalized_path in seen:
            continue
        normalized.append(normalized_path)
        seen.add(normalized_path)
    return tuple(normalized)


def extract_finding_routes(entry: dict) -> tuple[str, ...]:
    """Extract route-like anchors referenced in finding text."""
    text = finding_text(entry, fields=("title", "description", "attack_scenario", "evidence"))
    if not text:
        return tuple()
    routes: list[str] = []
    seen: set[str] = set()
    for match in re.findall(r"/[a-z0-9_:\-/.]+", text):
        if len(match) < 3 or match in seen:
            continue
        routes.append(match)
        seen.add(match)
    return tuple(routes)


def extract_chain_sink_anchor(entry: dict) -> str:
    """Return the most stable sink-ish anchor for a finding family."""
    primary_path = canonicalize_finding_path(entry.get("file_path"))
    locations = extract_finding_locations(entry)
    non_primary_locations = [location for location in locations if location != primary_path]
    if non_primary_locations:
        return non_primary_locations[-1]
    if locations:
        return locations[-1]
    routes = extract_finding_routes(entry)
    if routes:
        return routes[-1]
    return ""


def infer_chain_family_class(entry: dict) -> str:
    """Infer a coarse exploit-chain family class from finding content."""
    text = finding_text(entry, fields=("title", "description", "attack_scenario", "evidence"))
    cwe_family = extract_cwe_family(entry.get("cwe_id"))
    if any(term in text for term in _CHAIN_FAMILY_COMMAND_TERMS):
        return "command_chain"
    if any(term in text for term in _CHAIN_FAMILY_PATH_TERMS):
        return "path_file_chain"
    if any(term in text for term in _CHAIN_FAMILY_AUTH_TERMS):
        return "auth_priv_chain"

    if cwe_family in {"22", "23", "36", "61", "73"}:
        return "path_file_chain"
    if cwe_family in {"77", "78", "88"}:
        return "command_chain"
    if cwe_family in {"28", "30", "86"}:
        return "auth_priv_chain"

    return f"cwe_{cwe_family}" if cwe_family else "generic_chain"


def canonicalize_finding_path(value: object) -> str:
    """Normalize finding file path into a repo-style suffix when possible."""
    normalized = normalize_repo_path(value)
    if not normalized:
        return ""

    path = normalized.replace("\\", "/").strip()
    if not path:
        return ""

    if path.startswith("/"):
        roots = ("src", "apps", "packages", "services", "server", "client", "cmd", "internal")
        segments = [segment for segment in path.split("/") if segment]
        for index, segment in enumerate(segments):
            if segment in roots and index < len(segments) - 1:
                return "/".join(segments[index:])
        if len(segments) >= 2:
            return "/".join(segments[-2:])
    return path


def build_chain_identity(entry: dict) -> str:
    """Build a coarse exploit-chain identity for cross-pass support tracking."""
    if not isinstance(entry, dict):
        return ""

    path = canonicalize_finding_path(entry.get("file_path"))
    cwe_family = extract_cwe_family(entry.get("cwe_id"))
    line_number = coerce_line_number(entry.get("line_number"))
    line_bucket = str(line_number // 20) if line_number > 0 else ""
    title_tokens = chain_text_tokens(entry.get("title"))

    if not path and not title_tokens:
        return ""

    token_part = ".".join(title_tokens) if title_tokens else "unknown"
    return "|".join(
        [
            path or "unknown",
            cwe_family or "xx",
            line_bucket or "x",
            token_part,
        ]
    )


def infer_chain_sink_family(entry: dict) -> str:
    """Infer coarse sink family from finding evidence and referenced locations."""
    text = finding_text(entry, fields=("title", "description", "attack_scenario", "evidence"))
    locations = extract_finding_locations(entry)
    routes = extract_finding_routes(entry)
    sink_anchor = extract_chain_sink_anchor(entry)
    combined = " ".join([text, " ".join(locations), " ".join(routes), sink_anchor]).lower()

    file_sink_terms = (
        "copyfile",
        "fs.copyfile",
        "fs.stat",
        "sendfile",
        "send_file",
        "/media/",
        "media/:id",
        "upload",
        "download",
    )
    command_sink_terms = (
        "exec(",
        "spawn(",
        "/bin/sh",
        "sh -c",
        "ssh",
        "proxycommand",
        "argv",
        "option injection",
    )
    auth_sink_terms = (
        "allowfrom",
        "auth",
        "unauth",
        "permission",
        "role",
        "origin",
    )

    if any(term in combined for term in file_sink_terms):
        return "file_host_sink"
    if any(term in combined for term in command_sink_terms):
        return "command_exec_sink"
    if any(term in combined for term in auth_sink_terms):
        return "authz_sink"
    return "generic_sink"


def normalize_chain_class_for_sink(chain_class: str, sink_family: str) -> str:
    """Normalize chain class for consensus using sink family when class is generic."""
    if chain_class in {"path_file_chain", "command_chain", "auth_priv_chain"}:
        return chain_class
    if sink_family == "file_host_sink":
        return "path_file_chain"
    if sink_family == "command_exec_sink":
        return "command_chain"
    if sink_family == "authz_sink":
        return "auth_priv_chain"
    return chain_class or "generic_chain"


def build_chain_family_identity(entry: dict) -> str:
    """Build stable exploit-chain family identity for cross-pass consensus support."""
    if not isinstance(entry, dict):
        return ""

    path = canonicalize_finding_path(entry.get("file_path"))
    chain_class = infer_chain_family_class(entry)

    if not path:
        line_number = coerce_line_number(entry.get("line_number"))
        line_bucket = f"line{line_number // 40}" if line_number > 0 else "line_x"
        sink_anchor = extract_chain_sink_anchor(entry)
        location_anchor = sink_anchor or line_bucket
        if sink_anchor:
            return "|".join(
                [
                    "unknown",
                    location_anchor,
                    chain_class or "generic_chain",
                ]
            )
        title_tokens = chain_text_tokens(entry.get("title"), max_tokens=3)
        if not title_tokens:
            return ""
        location_anchor = ".".join(title_tokens)
        return "|".join(
            [
                "unknown",
                location_anchor,
                chain_class or "generic_chain",
            ]
        )

    return "|".join(
        [
            path,
            chain_class or "generic_chain",
        ]
    )


def build_chain_flow_identity(entry: dict) -> str:
    """Build flow-family identity for consensus fallback across wording/CWE variance."""
    if not isinstance(entry, dict):
        return ""

    path = canonicalize_finding_path(entry.get("file_path"))
    if not path:
        locations = extract_finding_locations(entry)
        path = locations[0] if locations else ""
    if not path:
        return ""

    sink_family = infer_chain_sink_family(entry)
    chain_class = normalize_chain_class_for_sink(infer_chain_family_class(entry), sink_family)
    return "|".join([path, sink_family, chain_class])


def _collect_chain_ids(findings: list[dict], identity_fn: Callable[[dict], str]) -> set[str]:
    """Collect non-empty chain identities using the given identity builder."""
    return {cid for f in findings if (cid := identity_fn(f))}


def collect_chain_exact_ids(findings: list[dict]) -> set[str]:
    """Collect exact chain identities for support diagnostics."""
    return _collect_chain_ids(findings, build_chain_identity)


def collect_chain_family_ids(findings: list[dict]) -> set[str]:
    """Collect stable chain-family identities for consensus support."""
    return _collect_chain_ids(findings, build_chain_family_identity)


def collect_chain_flow_ids(findings: list[dict]) -> set[str]:
    """Collect flow-family identities for consensus fallback support."""
    return _collect_chain_ids(findings, build_chain_flow_identity)


def collect_chain_ids(findings: list[dict]) -> set[str]:
    """Backward-compatible alias to collect chain-family ids."""
    return collect_chain_family_ids(findings)


def count_passes_with_core_chains(core_chain_ids: set[str], pass_chain_ids: list[set[str]]) -> int:
    """Count attempts that independently produced any of the core chains."""
    if not core_chain_ids or not pass_chain_ids:
        return 0
    return sum(1 for ids in pass_chain_ids if ids.intersection(core_chain_ids))


def attempt_contains_core_chain_evidence(
    *,
    attempt_findings: list[dict],
    expected_family_ids: set[str],
    expected_flow_ids: set[str],
) -> bool:
    """Return True when an attempt confirms any expected core-chain family/flow ids."""
    if not attempt_findings:
        return False
    if not expected_family_ids and not expected_flow_ids:
        return True

    attempt_family_ids = collect_chain_family_ids(attempt_findings)
    if expected_family_ids and attempt_family_ids.intersection(expected_family_ids):
        return True

    attempt_flow_ids = collect_chain_flow_ids(attempt_findings)
    if expected_flow_ids and attempt_flow_ids.intersection(expected_flow_ids):
        return True

    return False


def summarize_revalidation_support(
    revalidation_attempted: list[bool],
    core_evidence_present: list[bool],
) -> tuple[int, int, int]:
    """Return (attempts, hits, misses) for passes that required chain revalidation."""
    attempts = 0
    hits = 0
    misses = 0
    for attempted, has_core_evidence in zip(revalidation_attempted, core_evidence_present):
        if not attempted:
            continue
        attempts += 1
        if has_core_evidence:
            hits += 1
        else:
            misses += 1
    return attempts, hits, misses


def summarize_chain_candidates_for_prompt(
    findings: list[dict],
    chain_support_counts: Dict[str, int],
    attempts_observed: int,
    *,
    flow_support_counts: Optional[Dict[str, int]] = None,
    max_items: int = 3,
    max_chars: int = 3200,
) -> str:
    """Summarize top chain candidates for follow-up pass re-validation."""
    if not findings:
        return "- None"

    lines: list[str] = []
    for finding in findings[:max_items]:
        chain_id = build_chain_family_identity(finding)
        flow_id = build_chain_flow_identity(finding)
        support = chain_support_counts.get(chain_id, 0) if chain_id else 0
        if flow_support_counts and flow_id:
            support = max(support, flow_support_counts.get(flow_id, 0))
        path = canonicalize_finding_path(finding.get("file_path")) or "unknown"
        line_no = coerce_line_number(finding.get("line_number"))
        location = f"{path}:{line_no}" if line_no > 0 else path
        title = str(finding.get("title", "")).strip()
        if len(title) > 120:
            title = f"{title[:117]}..."
        cwe_id = str(finding.get("cwe_id", "")).strip() or "N/A"
        lines.append(
            f"- {title} ({location}, {cwe_id}, support={support}/{max(attempts_observed, 1)})"
        )

    summary = "\n".join(lines).strip() or "- None"
    if len(summary) <= max_chars:
        return summary
    return f"{summary[: max_chars - 15].rstrip()}...[truncated]"


def detect_weak_chain_consensus(
    *,
    core_chain_ids: set[str],
    pass_chain_ids: list[set[str]],
    required_support: int,
) -> tuple[bool, str, int]:
    """Determine whether pass-level agreement is too weak for stable finalization."""
    passes_with_core = count_passes_with_core_chains(core_chain_ids, pass_chain_ids)
    if not core_chain_ids:
        return False, "no_core_chains", passes_with_core

    if passes_with_core < required_support:
        reason = f"core_support={passes_with_core}/{len(pass_chain_ids)} (<{required_support})"
        return True, reason, passes_with_core

    non_zero_indexes = [idx for idx, ids in enumerate(pass_chain_ids) if ids]
    if non_zero_indexes and non_zero_indexes[-1] < len(pass_chain_ids) - 1:
        trailing = len(pass_chain_ids) - 1 - non_zero_indexes[-1]
        reason = f"trailing_empty_passes={trailing} after last non-empty pass"
        return True, reason, passes_with_core

    return False, "stable", passes_with_core


def adjudicate_consensus_support(
    *,
    required_support: int,
    core_exact_ids: set[str],
    pass_exact_ids: list[set[str]],
    core_family_ids: set[str],
    pass_family_ids: list[set[str]],
    core_flow_ids: set[str],
    pass_flow_ids: list[set[str]],
) -> tuple[bool, str, int, str, Dict[str, int]]:
    """Adjudicate consensus across exact/family/flow support modes."""
    weak_exact, reason_exact, support_exact = detect_weak_chain_consensus(
        core_chain_ids=core_exact_ids,
        pass_chain_ids=pass_exact_ids,
        required_support=required_support,
    )
    weak_family, reason_family, support_family = detect_weak_chain_consensus(
        core_chain_ids=core_family_ids,
        pass_chain_ids=pass_family_ids,
        required_support=required_support,
    )
    weak_flow, reason_flow, support_flow = detect_weak_chain_consensus(
        core_chain_ids=core_flow_ids,
        pass_chain_ids=pass_flow_ids,
        required_support=required_support,
    )

    support_metrics = {
        "exact": support_exact,
        "family": support_family,
        "flow": support_flow,
    }

    def _mode_is_stable(weak: bool, reason: str, support: int) -> bool:
        if not weak:
            return True
        return reason.startswith("trailing_empty_passes=") and support >= required_support

    stable_priority = (
        ("exact", weak_exact, reason_exact, support_exact),
        ("flow", weak_flow, reason_flow, support_flow),
        ("family", weak_family, reason_family, support_family),
    )
    for mode, weak, reason, support in stable_priority:
        if _mode_is_stable(weak, reason, support):
            normalized_reason = (
                "stable" if weak and reason.startswith("trailing_empty_passes=") else reason
            )
            return False, normalized_reason, support, mode, support_metrics

    fallback_priority = ("flow", "family", "exact")
    selected_mode = max(
        fallback_priority,
        key=lambda mode: (support_metrics.get(mode, 0), -fallback_priority.index(mode)),
    )
    selected_reason = {
        "exact": reason_exact,
        "family": reason_family,
        "flow": reason_flow,
    }.get(selected_mode, "weak_consensus")
    return (
        True,
        f"{selected_mode}:{selected_reason}",
        support_metrics.get(selected_mode, 0),
        selected_mode,
        support_metrics,
    )


def _diff_has_signals(
    diff_context: DiffContext,
    *,
    signal_paths: tuple[str, ...],
    signal_snippets: tuple[str, ...],
) -> bool:
    """Return True when path or hunk content matches supplied signal terms."""
    for diff_file in diff_context.files:
        path = diff_file_path(diff_file).lower()
        if path and any(token in path for token in signal_paths):
            return True

        for hunk in diff_file.hunks:
            for line in hunk.lines:
                content = str(line.content or "").lower()
                if any(token in content for token in signal_snippets):
                    return True

    return False


def diff_has_command_builder_signals(diff_context: DiffContext) -> bool:
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
    signal_paths = ("command", "shell", "process", "exec", "ssh", "cli")
    return _diff_has_signals(
        diff_context,
        signal_paths=signal_paths,
        signal_snippets=signal_snippets,
    )


def diff_has_path_parser_signals(diff_context: DiffContext) -> bool:
    """Return True when changed hunks look like parser/path/file handling logic."""
    signal_snippets = (
        "normalize",
        "resolve(",
        "realpath",
        "sendfile",
        "readfile",
        "copyfile",
        "filepath",
        "path.",
        "file://",
        "../",
        "~/",
        "media",
        "upload",
        "download",
    )
    signal_paths = ("path", "file", "media", "upload", "download", "parse", "store")
    return _diff_has_signals(
        diff_context,
        signal_paths=signal_paths,
        signal_snippets=signal_snippets,
    )


def diff_has_auth_privilege_signals(diff_context: DiffContext) -> bool:
    """Return True when diff hints at trust-boundary or privileged operation changes."""
    signal_snippets = (
        "auth",
        "authorize",
        "permission",
        "session",
        "token",
        "localhost",
        "origin",
        "config.apply",
        "apply(",
        "privilege",
        "admin",
        "role",
        "policy",
        "websocket",
    )
    signal_paths = ("auth", "gateway", "config", "policy", "permission", "session")
    return _diff_has_signals(
        diff_context,
        signal_paths=signal_paths,
        signal_snippets=signal_snippets,
    )
