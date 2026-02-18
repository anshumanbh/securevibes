"""PR review merge, dedupe, and retry helper utilities."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, Optional

from rich.console import Console

from securevibes.models.issue import SEVERITY_RANK, SecurityIssue, Severity
from securevibes.models.schemas import fix_pr_vulnerabilities_json
from securevibes.scanner.chain_analysis import (
    CHAIN_STOPWORDS,
    build_chain_family_identity,
    build_chain_identity,
    canonicalize_finding_path,
    coerce_line_number,
    extract_chain_sink_anchor,
    extract_cwe_family,
    extract_finding_locations,
    finding_text,
    infer_chain_family_class,
    infer_chain_sink_family,
)

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

EXPLOIT_PRIMITIVE_TERMS = (
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
CONCRETE_PAYLOAD_TERMS = (
    "-o",
    "--",
    "payload",
    "proxycommand=",
    "attacker@",
    "example payload",
    "value starts with -",
)
SPECULATIVE_TERMS = (
    "if bypass exists",
    "testing needed",
    "edge case",
    "could",
    "might",
    "may",
    "potential",
    "possible",
    "hypothetical",
    "future",
    "future caller",
    "future callsite",
    "future code path",
    "current pr does not introduce",
    "if future",
    "warrant defense-in-depth",
)
HARDENING_TERMS = (
    "defense-in-depth",
    "hardening",
    "could be improved",
    "security consideration",
)
CHAIN_SOURCE_TERMS = (
    "attacker",
    "unauthenticated",
    "untrusted",
    "user input",
    "query parameter",
    "remote",
    "webhook",
    "ws://",
    "http://",
    "https://",
)
CHAIN_SINK_TERMS = (
    "exec",
    "spawn",
    "sendfile",
    "upload",
    "download",
    "apply",
    "write",
    "read",
    "response",
    "proxycommand",
    "ssh",
    "socket",
    "websocket",
    "render",
    "copyfile",
    "send_file",
    "/media/",
)

# NOTE: these thresholds were tuned against existing SecureVibes PR-review fixtures
# to reduce duplicate chain reports while retaining cross-file exploit-chain recall.
# Keep changes conservative and update tests when adjusting these constants.
# -- _same_chain thresholds (primary dedup: merge findings describing the same exploit chain) --
MAX_LINE_GAP_CLOSE = 4  # Max line distance to treat same-file findings as adjacent
MIN_TOKEN_SIMILARITY_ADJACENT = 0.24  # Token similarity floor for adjacent same-file dedup
MIN_TOKEN_SIMILARITY_CWE78_88 = 0.16  # Relaxed token similarity for adjacent CWE-78/88 (OS command injection) pairs
MIN_TOKEN_SIMILARITY_SAME_FILE = 0.52  # Token similarity floor for same-file dedup within MAX_LINE_GAP_SAME_FILE_SIM
MIN_TITLE_SIMILARITY_SAME_FILE = 0.82  # Title similarity floor for same-file dedup within MAX_LINE_GAP_SAME_FILE_SIM
MAX_LINE_GAP_SAME_FILE_SIM = 120  # Max line distance for similarity-based same-file dedup
MIN_TOKEN_SIMILARITY_SAME_DIR = 0.68  # Token similarity floor for cross-file dedup within the same directory
# -- _same_subchain_family thresholds (collapse subchain variants in the same file) --
MAX_LINE_GAP_SUBCHAIN = 40  # Max line distance to consider two findings part of the same subchain
MIN_TOKEN_SIMILARITY_SUBCHAIN_SHARED_LOC = 0.20  # Token similarity floor when subchain findings share referenced locations
MAX_LINE_GAP_SUBCHAIN_E2E = 30  # Max line distance for collapsing end-to-end chain variants in same CWE family
MIN_TOKEN_SIMILARITY_SUBCHAIN_E2E = 0.16  # Token similarity floor for end-to-end subchain variant collapse
MAX_LINE_GAP_SUBCHAIN_ENABLER = 30  # Max line distance for collapsing enabler/mitigation-removal pairs across CWE families
MIN_TOKEN_SIMILARITY_ENABLER_SHARED_LOC = 0.18  # Token similarity floor for enabler pairs that share referenced locations
MIN_TOKEN_SIMILARITY_ENABLER_E2E = 0.28  # Token similarity floor for enabler pairs with an end-to-end variant
# -- Secondary guard thresholds (collapse residual near-duplicates after primary dedup) --
MAX_LINE_GAP_SECONDARY_GUARD = 8  # Max line distance to enter secondary same-path dedup
MIN_TOKEN_SIMILARITY_SECONDARY_SAME_PATH = 0.34  # Token similarity floor for secondary same-path near-duplicate collapse
MIN_TITLE_SIMILARITY_SECONDARY_SAME_PATH = 0.58  # Title similarity floor for secondary same-path near-duplicate collapse
MIN_TOKEN_SIMILARITY_CROSS_FILE_NEAR_DUP = 0.62  # Token similarity floor for cross-file near-duplicate collapse
MIN_TITLE_SIMILARITY_CROSS_FILE_NEAR_DUP = 0.66  # Title similarity floor for cross-file near-duplicate collapse
MAX_LINE_GAP_SECONDARY_CHAIN = 120  # Max line distance for dropping weaker secondary chains in the same file

def filter_baseline_vulns(known_vulns: list[dict]) -> list[dict]:
    """Return only baseline vulnerability entries, excluding PR-derived ones.

    PR-derived entries are identified by:
    - source == "pr_review" (case-insensitive; explicit tag added by update_pr_review_artifacts)
    - finding_type in _PR_FINDING_TYPES (normalized; matches PR_VULNERABILITY_SCHEMA enum)
    - threat_id starting with PR- or NEW- (case-insensitive; auto-generated or LLM-assigned IDs)
    """
    _PR_PREFIXES = ("PR-", "NEW-")
    baseline: list[dict] = []
    for vuln in known_vulns:
        if not isinstance(vuln, dict):
            continue
        source = vuln.get("source")
        if isinstance(source, str) and source.strip().lower() == "pr_review":
            continue
        raw_ft = vuln.get("finding_type")
        if raw_ft is not None and str(raw_ft).strip().lower() in _PR_FINDING_TYPES:
            continue
        threat_id = vuln.get("threat_id", "")
        if isinstance(threat_id, str) and threat_id.strip().upper().startswith(_PR_PREFIXES):
            continue
        baseline.append(vuln)
    return baseline

def _normalize_finding_identity(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lower()

def _build_vuln_match_keys(
    vuln: dict,
    *,
    include_basename: bool = True,
) -> set[tuple[str, str]]:
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

    raw_path = canonicalize_finding_path(vuln.get("file_path")).lower()
    path_keys = {raw_path} if raw_path else {""}
    if raw_path:
        basename = raw_path.rsplit("/", 1)[-1]
        if include_basename:
            path_keys.add(basename)

    return {(path_key, identity) for path_key in path_keys for identity in identities}

def issues_from_pr_vulns(pr_vulns: list[dict]) -> list[SecurityIssue]:
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

_PR_RETRY_FOCUS_LABELS = {
    "command_option": "COMMAND/OPTION INJECTION CHAINS",
    "path_exfiltration": "PATH + FILE EXFILTRATION CHAINS",
    "auth_privileged": "AUTH + PRIVILEGED OPERATION CHAINING",
}

_PR_RETRY_FOCUS_BLOCKS = {
    "command_option": """

## FOCUS AREA: COMMAND/OPTION INJECTION CHAINS
Prioritize command builder and shell composition changes:
- untrusted env/config/input interpolated into shell fragments (`sh -c`, `bash -lc`)
- CLI option injection via untrusted args that can start with '-' (host/target/remote values)
- parser functions feeding command builders must reject dash-prefixed target/host inputs
- double-quoted interpolation still allows `$()` and backtick command substitution
Validate both local and remote execution surfaces.
""",
    "path_exfiltration": """

## FOCUS AREA: PATH + FILE EXFILTRATION CHAINS
Prioritize changed parser/validator logic for URLs/paths/media tokens.
Look for acceptance of absolute/relative/home/traversal paths that can reach file read/host/upload/render sinks.
Do not dismiss as "refactor-only" if changed code still enables exfiltration.
""",
    "auth_privileged": """

## FOCUS AREA: AUTH + PRIVILEGED OPERATION CHAINING
Prioritize trust-boundary changes that expose privileged operations (config/apply/update/exec/policy changes).
Prove end-to-end chain from attacker-controlled entrypoint to privileged sink, including missing controls.
Do not reject a chain only because direct callers are absent in this snapshot when the diff adds exported/shared command helpers.
""",
}

_DEFAULT_PR_RETRY_FOCUS_ORDER = (
    "command_option",
    "path_exfiltration",
    "auth_privileged",
)

def focus_area_label(focus_area: str) -> str:
    """Return human-readable label for retry focus area."""
    return _PR_RETRY_FOCUS_LABELS.get(focus_area, focus_area)

def build_pr_retry_focus_plan(
    attempt_count: int,
    *,
    command_builder_signals: bool,
    path_parser_signals: bool,
    auth_privilege_signals: bool,
) -> list[str]:
    """Build adaptive focus areas for retry attempts based on diff signals."""
    if attempt_count <= 1:
        return []

    prioritized: list[str] = []
    if command_builder_signals:
        prioritized.append("command_option")
    if path_parser_signals:
        prioritized.append("path_exfiltration")
    if auth_privilege_signals:
        prioritized.append("auth_privileged")

    for focus_area in _DEFAULT_PR_RETRY_FOCUS_ORDER:
        if focus_area not in prioritized:
            prioritized.append(focus_area)

    retry_plan: list[str] = []
    total_retries = attempt_count - 1
    for idx in range(total_retries):
        retry_plan.append(prioritized[idx % len(prioritized)])
    return retry_plan

def attempts_show_pr_disagreement(attempt_counts: list[int]) -> bool:
    """Return True when attempt outcomes are inconsistent enough to require verification."""
    if len(attempt_counts) < 2:
        return False
    if not any(count > 0 for count in attempt_counts):
        return False
    if any(count == 0 for count in attempt_counts):
        return True
    return len(set(attempt_counts)) > 1

def should_run_pr_verifier(*, has_findings: bool, weak_consensus: bool) -> bool:
    """Single verifier gate based on canonical finding presence and consensus strength."""
    return has_findings and weak_consensus

def extract_observed_pr_findings(write_observer: Optional[Dict[str, Any]]) -> list[dict]:
    """Extract highest-volume observed PR findings captured by write-observer hook state."""
    if not write_observer:
        return []

    raw_content = write_observer.get("max_content")
    if not isinstance(raw_content, str) or not raw_content.strip():
        return []

    try:
        parsed = json.loads(raw_content)
    except json.JSONDecodeError:
        return []

    if not isinstance(parsed, list):
        return []
    return [entry for entry in parsed if isinstance(entry, dict)]

def build_pr_review_retry_suffix(
    attempt_num: int,
    command_builder_signals: bool = False,
    *,
    focus_area: Optional[str] = None,
    path_parser_signals: bool = False,
    auth_privilege_signals: bool = False,
    candidate_summary: str = "",
    require_candidate_revalidation: bool = False,
) -> str:
    """Return extra guidance used when retrying PR review with LLM."""
    selected_focus = focus_area
    if not selected_focus:
        if attempt_num == 2:
            selected_focus = "command_option"
        elif attempt_num == 3:
            selected_focus = "path_exfiltration"
        else:
            selected_focus = "auth_privileged"

    focus_block = _PR_RETRY_FOCUS_BLOCKS.get(selected_focus, "")
    command_builder_hint = ""
    path_parser_hint = ""
    auth_privileged_hint = ""
    candidate_hint = ""
    required_revalidation_hint = ""
    unresolved_hypothesis_hint = ""
    if command_builder_signals:
        command_builder_hint = """

## COMMAND-BUILDER DELTA DETECTED
Changed hunks appear to build argv/shell commands.
Before other hypotheses, explicitly verify:
- untrusted values cannot become dash-prefixed options
- host/target positional arguments cannot be interpreted as flags
- missing `--` separators do not permit option injection pivots
"""
    if path_parser_signals:
        path_parser_hint = """

## PATH-PARSER DELTA DETECTED
Changed hunks touch path or parser logic.
Explicitly validate source->path parser->file read/host/upload->response/exfil chains.
"""
    if auth_privilege_signals:
        auth_privileged_hint = """

## AUTH/PRIVILEGE DELTA DETECTED
Changed hunks touch trust boundaries or privileged operations.
Explicitly validate who can reach privileged sinks and whether auth/origin/role checks actually enforce policy.
"""
    if candidate_summary.strip():
        candidate_hint = f"""

## PRIOR HIGH-IMPACT CHAIN CANDIDATES TO RE-VALIDATE
{candidate_summary}

For each candidate above:
- either CONFIRM it with concrete source->sink evidence from code, or
- REFUTE it with concrete contradictory code evidence.
Do not ignore previously validated candidates.
"""
        unresolved_hypothesis_hint = """

## UNRESOLVED HYPOTHESIS DISPOSITION (MANDATORY)
For each carried hypothesis/candidate, provide one explicit disposition:
- CONFIRMED: report a finding with concrete exploit-chain evidence.
- DISPROVED: cite concrete contradictory code evidence.
Do not conclude "refactor-only" or "no findings" while any carried candidate remains unresolved.
"""
    if require_candidate_revalidation:
        required_revalidation_hint = """

## CORE CHAIN REVALIDATION REQUIREMENT
This pass must explicitly CONFIRM or REFUTE at least one carried candidate chain with concrete code evidence.
Do not return [] unless each carried candidate is explicitly disproved.
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
{path_parser_hint}
{auth_privileged_hint}
{candidate_hint}
{required_revalidation_hint}
{unresolved_hypothesis_hint}
{focus_block}
"""

def load_pr_vulnerabilities_artifact(
    pr_vulns_path: Path,
    console: Console,
) -> tuple[list[dict], Optional[str]]:
    """Read and normalize PR_VULNERABILITIES.json."""
    if not pr_vulns_path.exists():
        return [], "PR_VULNERABILITIES.json was not produced (write may have been rejected)"

    try:
        raw_content = pr_vulns_path.read_text(encoding="utf-8")
    except OSError as e:
        return [], f"Failed to read PR_VULNERABILITIES.json: {e}"

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

_FINDING_TYPE_RANK = {
    "known_vuln": 6,
    "regression": 5,
    "threat_enabler": 5,
    "mitigation_removal": 4,
    "new_threat": 3,
    "unknown": 1,
}

@dataclass(order=True)
class _EntryQuality:
    """Composite quality ranking for a PR finding entry.

    Fields are ordered by comparison priority (leftmost = highest priority).
    Negative values for penalties ensure lower-penalty entries rank higher.
    """

    severity: int
    finding_type: int
    chain_support: int
    proof_score: int
    contradiction_penalty: int
    speculation_penalty: int
    evidence_length: int
    description_length: int

@dataclass(order=True)
class _SubchainQuality:
    """Composite quality ranking for subchain collapse decisions.

    Extends _EntryQuality with chain-structural fields.
    """

    role_bonus: int
    anchor_bonus: int
    location_count: int
    severity: int
    finding_type: int
    chain_support: int
    proof_score: int
    contradiction_penalty: int
    speculation_penalty: int
    evidence_length: int
    description_length: int

def _chain_role(entry: dict) -> str:
    """Classify a finding as end-to-end or step-level based on evidence structure."""
    evidence_text = finding_text(entry, fields=("evidence",))
    scenario_text = finding_text(entry, fields=("attack_scenario",))
    core_text = finding_text(entry, fields=("title", "description", "attack_scenario", "evidence"))
    locations = extract_finding_locations(entry)
    has_multi_location = len(locations) >= 2
    has_flow_arrow = "->" in evidence_text
    has_step_markers = len(re.findall(r"\b[1-4][\)\.\:]", scenario_text)) >= 2
    has_source = any(term in core_text for term in CHAIN_SOURCE_TERMS)
    has_sink = any(term in core_text for term in CHAIN_SINK_TERMS) or bool(
        extract_chain_sink_anchor(entry)
    )
    if (has_multi_location and has_step_markers and has_sink) or (
        has_flow_arrow and has_source and has_sink
    ):
        return "end_to_end"
    return "step_level"

def _proof_score(entry: dict) -> int:
    """Score the concreteness of a finding's exploit-chain evidence."""
    score = 0
    evidence_text = finding_text(entry, fields=("evidence",))
    scenario_text = finding_text(entry, fields=("attack_scenario",))
    core_text = finding_text(entry, fields=("title", "description", "evidence", "attack_scenario"))
    cwe_text = str(entry.get("cwe_id", "")).strip().upper()

    if any(term in core_text for term in EXPLOIT_PRIMITIVE_TERMS):
        score += 4
    if "CWE-88" in cwe_text:
        score += 4
    if "CWE-78" in cwe_text and any(term in core_text for term in ("argv", "option injection")):
        score += 2
    if any(term in scenario_text for term in CONCRETE_PAYLOAD_TERMS):
        score += 3
    if "1)" in scenario_text and "2)" in scenario_text:
        score += 1
    if canonicalize_finding_path(entry.get("file_path")):
        score += 1
    if coerce_line_number(entry.get("line_number")) > 0:
        score += 1
    if ":" in evidence_text and ("->" in evidence_text or "flow" in evidence_text):
        score += 1
    if "missing `--`" in core_text or "missing --" in core_text:
        score += 2

    return score

def _speculation_penalty(entry: dict) -> int:
    """Count speculative/hedging language in a finding's text fields."""
    text = finding_text(entry, fields=("title", "description", "attack_scenario", "evidence"))
    penalty = 0
    for term in SPECULATIVE_TERMS:
        if " " in term:
            if term in text:
                penalty += 1
            continue
        if re.search(rf"\b{re.escape(term)}\b", text):
            penalty += 1
    if any(term in text for term in HARDENING_TERMS):
        penalty += 1
    return min(penalty, 6)

def _finding_tokens(entry: dict) -> set[str]:
    """Extract normalized content tokens for similarity comparison."""
    text = " ".join(
        str(entry.get(field, ""))
        for field in ("title", "description", "attack_scenario", "evidence")
    ).lower()
    tokens = re.findall(r"[a-z0-9_]+", text)
    return {
        token
        for token in tokens
        if len(token) >= 4 and token not in CHAIN_STOPWORDS and not token.isdigit()
    }

def _token_similarity(a: set[str], b: set[str]) -> float:
    """Jaccard similarity between two token sets."""
    if not a or not b:
        return 0.0
    overlap = len(a & b)
    union = len(a | b)
    return overlap / union if union else 0.0

def _entry_quality(
    entry: dict,
    *,
    chain_support_counts: Optional[Dict[str, int]] = None,
    total_attempts: int = 0,
) -> _EntryQuality:
    """Build composite quality ranking for a finding entry."""
    severity = SEVERITY_RANK.get(str(entry.get("severity", "")).strip().lower(), 0)
    ft = _FINDING_TYPE_RANK.get(str(entry.get("finding_type", "")).strip().lower(), 0)
    chain_support = 0
    if chain_support_counts:
        chain_family_id = build_chain_family_identity(entry)
        chain_identity = build_chain_identity(entry)
        chain_support = chain_support_counts.get(chain_family_id, 0) or chain_support_counts.get(
            chain_identity, 0
        )
    contradiction_penalty = (
        max(total_attempts - chain_support, 0) if total_attempts > 0 and chain_support > 0 else 0
    )
    proof = _proof_score(entry)
    speculation = _speculation_penalty(entry)
    evidence_chars = len(str(entry.get("evidence", ""))) + len(
        str(entry.get("attack_scenario", ""))
    )
    description_chars = len(str(entry.get("description", "")))
    return _EntryQuality(
        severity=severity,
        finding_type=ft,
        chain_support=chain_support,
        proof_score=proof,
        contradiction_penalty=-contradiction_penalty,
        speculation_penalty=-speculation,
        evidence_length=min(evidence_chars, 4000),
        description_length=min(description_chars, 2000),
    )

def _chain_support(
    entry: dict,
    chain_support_counts: Optional[Dict[str, int]],
) -> int:
    """Look up cross-attempt support count for a finding's chain identity."""
    if not chain_support_counts:
        return 0
    chain_family_id = build_chain_family_identity(entry)
    if chain_family_id and chain_family_id in chain_support_counts:
        return chain_support_counts[chain_family_id]
    chain_identity = build_chain_identity(entry)
    if not chain_identity:
        return 0
    return chain_support_counts.get(chain_identity, 0)

def _has_concrete_chain_structure(entry: dict) -> bool:
    """Return True when a finding has file path, line number, and evidence flow markers."""
    normalized_path = canonicalize_finding_path(entry.get("file_path"))
    line_number = coerce_line_number(entry.get("line_number"))
    evidence_text = finding_text(entry, fields=("evidence",))
    scenario_text = finding_text(entry, fields=("attack_scenario",))
    if not normalized_path or line_number <= 0:
        return False
    if not evidence_text or not scenario_text:
        return False

    has_flow_anchor = "->" in evidence_text or "flow" in evidence_text
    has_step_markers = len(re.findall(r"\b[1-4][\)\.\:]", scenario_text)) >= 2
    return has_flow_anchor or has_step_markers

def _same_chain(candidate: dict, canonical: dict) -> bool:
    """Return True when two findings describe the same exploit chain."""
    candidate_path = canonicalize_finding_path(candidate.get("file_path"))
    canonical_path = canonicalize_finding_path(canonical.get("file_path"))
    if not candidate_path or not canonical_path:
        return False

    candidate_line = coerce_line_number(candidate.get("line_number"))
    canonical_line = coerce_line_number(canonical.get("line_number"))
    line_gap = (
        abs(candidate_line - canonical_line) if candidate_line > 0 and canonical_line > 0 else 999
    )

    candidate_tokens = _finding_tokens(candidate)
    canonical_tokens = _finding_tokens(canonical)
    token_sim = _token_similarity(candidate_tokens, canonical_tokens)

    candidate_title = str(candidate.get("title", "")).strip().lower()
    canonical_title = str(canonical.get("title", "")).strip().lower()
    title_sim = (
        SequenceMatcher(None, candidate_title, canonical_title).ratio()
        if candidate_title and canonical_title
        else 0.0
    )

    candidate_cwe_family = extract_cwe_family(candidate.get("cwe_id"))
    canonical_cwe_family = extract_cwe_family(canonical.get("cwe_id"))
    same_cwe_family = candidate_cwe_family == canonical_cwe_family

    if candidate_path == canonical_path:
        if line_gap <= MAX_LINE_GAP_CLOSE and token_sim >= MIN_TOKEN_SIMILARITY_ADJACENT:
            return True
        if (
            line_gap <= MAX_LINE_GAP_CLOSE
            and candidate_cwe_family in {"78", "88"}
            and canonical_cwe_family in {"78", "88"}
            and token_sim >= MIN_TOKEN_SIMILARITY_CWE78_88
        ):
            return True
        if line_gap <= MAX_LINE_GAP_SAME_FILE_SIM and token_sim >= MIN_TOKEN_SIMILARITY_SAME_FILE:
            return True
        if line_gap <= MAX_LINE_GAP_SAME_FILE_SIM and title_sim >= MIN_TITLE_SIMILARITY_SAME_FILE:
            return True

    candidate_dir = candidate_path.rsplit("/", 1)[0] if "/" in candidate_path else ""
    canonical_dir = canonical_path.rsplit("/", 1)[0] if "/" in canonical_path else ""
    if (
        candidate_path != canonical_path
        and candidate_dir
        and candidate_dir == canonical_dir
        and same_cwe_family
        and token_sim >= MIN_TOKEN_SIMILARITY_SAME_DIR
    ):
        return True

    return False

def _same_subchain_family(candidate: dict, canonical: dict) -> bool:
    """Return True when candidate is a subchain variant of canonical."""
    candidate_path = canonicalize_finding_path(candidate.get("file_path"))
    canonical_path = canonicalize_finding_path(canonical.get("file_path"))
    if not candidate_path or candidate_path != canonical_path:
        return False

    candidate_cwe_family = extract_cwe_family(candidate.get("cwe_id"))
    canonical_cwe_family = extract_cwe_family(canonical.get("cwe_id"))
    same_cwe_family = bool(
        candidate_cwe_family
        and canonical_cwe_family
        and candidate_cwe_family == canonical_cwe_family
    )

    candidate_line = coerce_line_number(candidate.get("line_number"))
    canonical_line = coerce_line_number(canonical.get("line_number"))
    line_gap = (
        abs(candidate_line - canonical_line) if candidate_line > 0 and canonical_line > 0 else 999
    )
    if line_gap > MAX_LINE_GAP_SUBCHAIN:
        return False

    candidate_tokens = _finding_tokens(candidate)
    canonical_tokens = _finding_tokens(canonical)
    token_sim = _token_similarity(candidate_tokens, canonical_tokens)

    candidate_locations = set(extract_finding_locations(candidate))
    canonical_locations = set(extract_finding_locations(canonical))
    shared_locations = {
        location
        for location in candidate_locations.intersection(canonical_locations)
        if location not in {candidate_path, canonical_path}
    }

    candidate_anchor = extract_chain_sink_anchor(candidate)
    canonical_anchor = extract_chain_sink_anchor(canonical)
    shared_anchor = bool(candidate_anchor and candidate_anchor == canonical_anchor)

    candidate_role = _chain_role(candidate)
    canonical_role = _chain_role(canonical)
    has_end_to_end_variant = "end_to_end" in {candidate_role, canonical_role}
    candidate_type = str(candidate.get("finding_type", "")).strip().lower()
    canonical_type = str(canonical.get("finding_type", "")).strip().lower()
    enabler_types = {"threat_enabler", "mitigation_removal"}
    is_enabler_pair = candidate_type in enabler_types or canonical_type in enabler_types

    if same_cwe_family and shared_anchor:
        return True
    if (
        same_cwe_family
        and shared_locations
        and (
            line_gap <= MAX_LINE_GAP_SUBCHAIN
            or token_sim >= MIN_TOKEN_SIMILARITY_SUBCHAIN_SHARED_LOC
        )
    ):
        return True
    if same_cwe_family and has_end_to_end_variant and line_gap <= MAX_LINE_GAP_SUBCHAIN_E2E:
        if token_sim >= MIN_TOKEN_SIMILARITY_SUBCHAIN_E2E:
            return True
        candidate_is_self_anchor = candidate_anchor in {candidate_path, canonical_path}
        canonical_is_self_anchor = canonical_anchor in {candidate_path, canonical_path}
        if candidate_is_self_anchor != canonical_is_self_anchor:
            return True

    if not same_cwe_family and is_enabler_pair and line_gap <= MAX_LINE_GAP_SUBCHAIN_ENABLER:
        if shared_anchor:
            return True
        if shared_locations and token_sim >= MIN_TOKEN_SIMILARITY_ENABLER_SHARED_LOC:
            return True
        if has_end_to_end_variant and token_sim >= MIN_TOKEN_SIMILARITY_ENABLER_E2E:
            candidate_is_self_anchor = candidate_anchor in {candidate_path, canonical_path}
            canonical_is_self_anchor = canonical_anchor in {candidate_path, canonical_path}
            if candidate_is_self_anchor != canonical_is_self_anchor:
                return True
    return False

def _subchain_quality(
    entry: dict,
    *,
    chain_support_counts: Optional[Dict[str, int]] = None,
    total_attempts: int = 0,
) -> _SubchainQuality:
    """Build composite quality ranking for subchain collapse decisions."""
    role_bonus = 1 if _chain_role(entry) == "end_to_end" else 0
    anchor_bonus = 1 if extract_chain_sink_anchor(entry) else 0
    location_count = min(len(extract_finding_locations(entry)), 6)
    quality = _entry_quality(
        entry, chain_support_counts=chain_support_counts, total_attempts=total_attempts
    )
    return _SubchainQuality(
        role_bonus=role_bonus,
        anchor_bonus=anchor_bonus,
        location_count=location_count,
        severity=quality.severity,
        finding_type=quality.finding_type,
        chain_support=quality.chain_support,
        proof_score=quality.proof_score,
        contradiction_penalty=quality.contradiction_penalty,
        speculation_penalty=quality.speculation_penalty,
        evidence_length=quality.evidence_length,
        description_length=quality.description_length,
    )

def merge_pr_attempt_findings(
    vulns: list[dict],
    merge_stats: Optional[Dict[str, int]] = None,
    chain_support_counts: Optional[Dict[str, int]] = None,
    total_attempts: int = 0,
) -> list[dict]:
    """Merge findings across attempts and keep one canonical finding per chain."""
    if not vulns:
        if merge_stats is not None:
            merge_stats["input_count"] = 0
            merge_stats["canonical_count"] = 0
            merge_stats["canonical_chain_count"] = 0
            merge_stats["final_count"] = 0
            merge_stats["speculative_dropped"] = 0
            merge_stats["subchain_collapsed"] = 0
            merge_stats["low_support_dropped"] = 0
            merge_stats["dropped_as_secondary_chain"] = 0
            merge_stats["max_chain_support"] = 0
        return []

    def _quality(entry: dict) -> _EntryQuality:
        return _entry_quality(
            entry, chain_support_counts=chain_support_counts, total_attempts=total_attempts
        )

    def _sub_quality(entry: dict) -> _SubchainQuality:
        return _subchain_quality(
            entry, chain_support_counts=chain_support_counts, total_attempts=total_attempts
        )

    normalized_vulns = [dict(v) for v in vulns if isinstance(v, dict)]
    normalized_vulns.sort(key=_quality, reverse=True)

    canonical_findings: list[dict] = []
    for candidate in normalized_vulns:
        merged = False
        for idx, existing in enumerate(canonical_findings):
            if not _same_chain(candidate, existing):
                continue
            if _quality(candidate) > _quality(existing):
                canonical_findings[idx] = candidate
            merged = True
            break
        if not merged:
            canonical_findings.append(candidate)

    # Secondary guard: collapse residual near-duplicates and keep the strongest proof-based variant.
    canonical_findings.sort(key=_quality, reverse=True)
    final_findings: list[dict] = []
    for candidate in canonical_findings:
        candidate_path = canonicalize_finding_path(candidate.get("file_path"))
        candidate_line = coerce_line_number(candidate.get("line_number"))
        candidate_cwe_family = extract_cwe_family(candidate.get("cwe_id"))
        candidate_tokens = _finding_tokens(candidate)
        candidate_title = str(candidate.get("title", "")).strip().lower()

        is_duplicate = False
        for existing in final_findings:
            existing_path = canonicalize_finding_path(existing.get("file_path"))
            existing_tokens = _finding_tokens(existing)
            token_sim = _token_similarity(candidate_tokens, existing_tokens)
            existing_cwe_family = extract_cwe_family(existing.get("cwe_id"))
            candidate_proof = _proof_score(candidate)
            existing_proof = _proof_score(existing)
            title_sim = SequenceMatcher(
                None,
                candidate_title,
                str(existing.get("title", "")).strip().lower(),
            ).ratio()
            same_cwe_family = candidate_cwe_family and candidate_cwe_family == existing_cwe_family
            same_path = bool(candidate_path and candidate_path == existing_path)
            if same_path:
                existing_line = coerce_line_number(existing.get("line_number"))
                line_gap = (
                    abs(candidate_line - existing_line)
                    if candidate_line > 0 and existing_line > 0
                    else 999
                )
                if line_gap > MAX_LINE_GAP_SECONDARY_GUARD:
                    continue
                if (
                    line_gap <= MAX_LINE_GAP_CLOSE
                    and candidate_cwe_family in {"78", "88"}
                    and existing_cwe_family in {"78", "88"}
                    and abs(candidate_proof - existing_proof) >= 2
                    and (
                        token_sim >= MIN_TOKEN_SIMILARITY_SECONDARY_SAME_PATH
                        or title_sim >= MIN_TITLE_SIMILARITY_SECONDARY_SAME_PATH
                    )
                ):
                    is_duplicate = True
                    break
                high_similarity = (
                    token_sim >= MIN_TOKEN_SIMILARITY_SECONDARY_SAME_PATH
                    and title_sim >= MIN_TITLE_SIMILARITY_SECONDARY_SAME_PATH
                )
                if (
                    same_cwe_family
                    and (
                        token_sim >= MIN_TOKEN_SIMILARITY_SECONDARY_SAME_PATH
                        or title_sim >= MIN_TITLE_SIMILARITY_SECONDARY_SAME_PATH
                    )
                ) or high_similarity:
                    is_duplicate = True
                    break
                continue

            # Cross-file near-duplicate collapse for the same chain across neighboring steps.
            if (
                same_cwe_family
                and token_sim >= MIN_TOKEN_SIMILARITY_CROSS_FILE_NEAR_DUP
                and title_sim >= MIN_TITLE_SIMILARITY_CROSS_FILE_NEAR_DUP
                and abs(candidate_proof - existing_proof) <= 3
            ):
                is_duplicate = True
                break

        if not is_duplicate:
            final_findings.append(candidate)

    compacted_findings: list[dict] = []
    subchain_collapsed = 0
    for candidate in final_findings:
        merged = False
        for idx, existing in enumerate(compacted_findings):
            if not _same_subchain_family(candidate, existing):
                continue
            if _sub_quality(candidate) > _sub_quality(existing):
                compacted_findings[idx] = candidate
            subchain_collapsed += 1
            merged = True
            break
        if not merged:
            compacted_findings.append(candidate)

    compacted_findings.sort(key=_quality, reverse=True)

    secondary_chain_dropped = 0
    secondary_filtered_findings: list[dict] = []
    for candidate in compacted_findings:
        suppress_as_secondary = False
        candidate_path = canonicalize_finding_path(candidate.get("file_path"))
        candidate_class = infer_chain_family_class(candidate)
        candidate_sink_family = infer_chain_sink_family(candidate)
        candidate_line = coerce_line_number(candidate.get("line_number"))
        candidate_role = _chain_role(candidate)
        candidate_proof = _proof_score(candidate)

        for existing in secondary_filtered_findings:
            existing_path = canonicalize_finding_path(existing.get("file_path"))
            if not candidate_path or candidate_path != existing_path:
                continue
            existing_class = infer_chain_family_class(existing)
            if candidate_class != existing_class:
                continue
            existing_sink_family = infer_chain_sink_family(existing)
            if candidate_sink_family != existing_sink_family:
                continue

            existing_line = coerce_line_number(existing.get("line_number"))
            line_gap = (
                abs(candidate_line - existing_line)
                if candidate_line > 0 and existing_line > 0
                else 999
            )
            if line_gap > MAX_LINE_GAP_SECONDARY_CHAIN:
                continue

            existing_role = _chain_role(existing)
            existing_proof = _proof_score(existing)
            if (
                existing_role == "end_to_end"
                and candidate_role != "end_to_end"
                and existing_proof >= candidate_proof
            ):
                suppress_as_secondary = True
                break
            if existing_proof - candidate_proof >= 2:
                suppress_as_secondary = True
                break

        if suppress_as_secondary:
            secondary_chain_dropped += 1
            continue
        secondary_filtered_findings.append(candidate)

    filtered_findings = secondary_filtered_findings
    strong_findings = [
        finding
        for finding in secondary_filtered_findings
        if _proof_score(finding) >= 4
        and _speculation_penalty(finding) <= 2
        and _has_concrete_chain_structure(finding)
    ]
    if strong_findings:
        filtered_findings = [
            finding
            for finding in secondary_filtered_findings
            if _proof_score(finding) >= 3
            and _speculation_penalty(finding) <= 2
            and _has_concrete_chain_structure(finding)
        ]
        if not filtered_findings:
            filtered_findings = strong_findings

    low_support_dropped = 0
    if len(filtered_findings) > 1 and total_attempts > 0 and chain_support_counts:
        supports = [_chain_support(finding, chain_support_counts) for finding in filtered_findings]
        max_support = max(supports, default=0)
        if max_support >= 2:
            retained_findings: list[dict] = []
            for finding, support in zip(filtered_findings, supports):
                severity = SEVERITY_RANK.get(str(finding.get("severity", "")).strip().lower(), 0)
                if support >= 2:
                    retained_findings.append(finding)
                    continue
                if (
                    severity >= 3
                    and _proof_score(finding) >= 5
                    and _speculation_penalty(finding) <= 1
                ):
                    retained_findings.append(finding)
                    continue
                low_support_dropped += 1
            if retained_findings:
                filtered_findings = retained_findings

    if merge_stats is not None:
        merge_stats["input_count"] = len(vulns)
        merge_stats["canonical_count"] = len(canonical_findings)
        merge_stats["canonical_chain_count"] = len(compacted_findings)
        merge_stats["final_count"] = len(filtered_findings)
        merge_stats["speculative_dropped"] = max(
            0, len(compacted_findings) - len(filtered_findings)
        )
        merge_stats["subchain_collapsed"] = subchain_collapsed
        merge_stats["low_support_dropped"] = low_support_dropped
        merge_stats["dropped_as_secondary_chain"] = secondary_chain_dropped
        merge_stats["max_chain_support"] = (
            max(chain_support_counts.values(), default=0) if chain_support_counts else 0
        )

    return filtered_findings

def dedupe_pr_vulns(pr_vulns: list[dict], known_vulns: list[dict]) -> list[dict]:
    """Tag PR findings as known_vuln when they overlap baseline issues.

    Dedupe uses exact normalized file paths (not basename-only matches) to reduce
    cross-directory false positives.
    """
    known_keys: set[tuple[str, str]] = set()
    for vuln in known_vulns:
        if not isinstance(vuln, dict):
            continue
        known_keys.update(_build_vuln_match_keys(vuln, include_basename=False))

    normalized: list[dict] = []
    for vuln in pr_vulns:
        if not isinstance(vuln, dict):
            continue
        entry = dict(vuln)
        candidate_keys = _build_vuln_match_keys(entry, include_basename=False)
        if candidate_keys and known_keys.intersection(candidate_keys):
            finding_type = str(entry.get("finding_type", "")).strip().lower()
            if not finding_type or finding_type == "unknown":
                entry["finding_type"] = "known_vuln"
        normalized.append(entry)
    return normalized
