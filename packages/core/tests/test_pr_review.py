"""Tests for PR review helpers."""

import asyncio
import json
from io import StringIO
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from rich.console import Console

from securevibes.diff.context import (
    extract_relevant_architecture,
    filter_relevant_threats,
    filter_relevant_vulnerabilities,
    suggest_security_adjacent_files,
    summarize_threats_for_prompt,
    summarize_vulnerabilities_for_prompt,
)
from securevibes.diff.parser import DiffContext, DiffFile, DiffHunk, DiffLine
from securevibes.scanner.chain_analysis import (
    adjudicate_consensus_support,
    attempt_contains_core_chain_evidence,
    build_chain_family_identity,
    build_chain_flow_identity,
    build_chain_identity,
    canonicalize_finding_path,
    count_passes_with_core_chains,
    detect_weak_chain_consensus,
    diff_has_auth_privilege_signals,
    diff_has_path_parser_signals,
    summarize_chain_candidates_for_prompt,
    summarize_revalidation_support,
)
from securevibes.scanner.pr_review_merge import (
    _attempts_show_pr_disagreement,
    _build_pr_retry_focus_plan,
    _build_pr_review_retry_suffix,
    _extract_observed_pr_findings,
    _merge_pr_attempt_findings,
    _should_run_pr_verifier,
    dedupe_pr_vulns,
    filter_baseline_vulns,
)
from securevibes.scanner.scanner import (
    Scanner,
    _build_focused_diff_context,
    _derive_pr_default_grep_scope,
    _enforce_focused_diff_coverage,
    _generate_pr_hypotheses,
    _normalize_hypothesis_output,
    _refine_pr_findings_with_llm,
    _score_diff_file_for_security_review,
    _summarize_diff_hunk_snippets,
    _summarize_diff_line_anchors,
)
from securevibes.config import config


def test_extract_relevant_architecture_matches_sections(tmp_path: Path):
    """Relevant SECURITY.md sections should be extracted based on changed files."""
    security_md = tmp_path / "SECURITY.md"
    security_md.write_text(
        "# Overview\nGeneral info\n\n# Control UI\nThe UI lives under ui/\n\n# API\nOther notes\n",
        encoding="utf-8",
    )

    result = extract_relevant_architecture(security_md, ["ui/app-settings.ts"])

    assert "Control UI" in result


def test_filter_relevant_threats_matches_tokens(tmp_path: Path):
    """Threats mentioning changed components should be returned."""
    threat_model = tmp_path / "THREAT_MODEL.json"
    threats = [
        {
            "id": "THREAT-001",
            "title": "Token exposure in UI",
            "description": "UI sends tokens",
            "affected_components": ["ui"],
            "severity": "high",
        },
        {
            "id": "THREAT-002",
            "title": "Other threat",
            "description": "Database issue",
            "affected_components": ["db"],
            "severity": "medium",
        },
    ]
    threat_model.write_text(json.dumps(threats), encoding="utf-8")

    relevant = filter_relevant_threats(threat_model, ["ui/app-settings.ts"])

    assert len(relevant) == 1
    assert relevant[0]["id"] == "THREAT-001"


def test_filter_relevant_threats_prioritizes_exact_file_overlap(tmp_path: Path):
    """Exact changed-file threat matches should outrank loose token matches."""
    threat_model = tmp_path / "THREAT_MODEL.json"
    threats = [
        {
            "id": "THREAT-LOOSE",
            "title": "Gateway auth issue",
            "description": "General auth weakness in gateway",
            "affected_components": ["gateway"],
        },
        {
            "id": "THREAT-EXACT",
            "title": "Config apply privilege issue",
            "description": "Direct overlap with changed file",
            "affected_files": [{"file_path": "src/gateway/server-methods/config.ts"}],
        },
    ]
    threat_model.write_text(json.dumps(threats), encoding="utf-8")

    relevant = filter_relevant_threats(
        threat_model,
        ["src/gateway/server-methods/config.ts"],
        max_items=2,
    )

    assert len(relevant) == 2
    assert relevant[0]["id"] == "THREAT-EXACT"


def test_filter_relevant_vulnerabilities_prefers_file_overlap():
    """Vulnerability relevance should prefer exact file overlap over loose text matches."""
    vulnerabilities = [
        {
            "threat_id": "THREAT-1",
            "title": "Gateway issue",
            "description": "General gateway auth concern",
            "file_path": "src/gateway/auth.ts",
        },
        {
            "threat_id": "THREAT-2",
            "title": "Config apply exploit chain",
            "description": "Direct overlap with changed method",
            "file_path": "src/gateway/server-methods/config.ts",
        },
    ]

    relevant = filter_relevant_vulnerabilities(
        vulnerabilities,
        ["src/gateway/server-methods/config.ts"],
        max_items=2,
    )

    assert len(relevant) == 2
    assert relevant[0]["threat_id"] == "THREAT-2"


def test_context_summaries_are_bounded():
    """Prompt summaries should include findings but respect char limits."""
    threats = [
        {
            "id": "THREAT-001",
            "title": "Very long threat title " * 20,
            "description": "Very long threat description " * 40,
            "severity": "high",
            "file_path": "src/gateway/auth.ts",
        }
    ]
    vulns = [
        {
            "threat_id": "THREAT-002",
            "title": "Very long vulnerability title " * 20,
            "description": "Very long vulnerability description " * 40,
            "severity": "critical",
            "file_path": "src/gateway/server.ts",
            "cwe_id": "CWE-306",
        }
    ]

    threat_summary = summarize_threats_for_prompt(threats, max_chars=180)
    vuln_summary = summarize_vulnerabilities_for_prompt(vulns, max_chars=180)

    assert len(threat_summary) <= 180
    assert len(vuln_summary) <= 180
    assert "THREAT-001" in threat_summary
    assert "THREAT-002" in vuln_summary


def test_suggest_security_adjacent_files_returns_ranked_neighbors(tmp_path: Path):
    """Security-adjacent hints should include nearby auth/policy files."""
    repo = tmp_path / "repo"
    (repo / "src/gateway/server-methods").mkdir(parents=True)
    (repo / "src/gateway/server-methods/config.ts").write_text("export const x = 1;\n", "utf-8")
    (repo / "src/gateway/auth.ts").write_text("export const y = 1;\n", "utf-8")
    (repo / "src/gateway/router.ts").write_text("export const z = 1;\n", "utf-8")
    (repo / "src/gateway/notes.txt").write_text("not code\n", "utf-8")

    hints = suggest_security_adjacent_files(
        repo, ["src/gateway/server-methods/config.ts"], max_items=5
    )

    assert "src/gateway/auth.ts" in hints
    assert "src/gateway/router.ts" in hints
    assert "src/gateway/server-methods/config.ts" not in hints


def test_suggest_security_adjacent_files_skips_unreadable_dirs(tmp_path: Path, monkeypatch):
    """Unreadable sibling directories should be skipped instead of crashing."""
    repo = tmp_path / "repo"
    blocked_dir = repo / "src/gateway/server-methods"
    blocked_dir.mkdir(parents=True)
    (blocked_dir / "config.ts").write_text("export const x = 1;\n", "utf-8")
    (repo / "src/gateway/auth.ts").write_text("export const y = 1;\n", "utf-8")

    original_iterdir = Path.iterdir

    def _guarded_iterdir(path_obj: Path):
        if path_obj == blocked_dir:
            raise PermissionError("permission denied for test")
        return original_iterdir(path_obj)

    monkeypatch.setattr(Path, "iterdir", _guarded_iterdir)

    hints = suggest_security_adjacent_files(
        repo, ["src/gateway/server-methods/config.ts"], max_items=5
    )

    assert "src/gateway/auth.ts" in hints


def test_build_focused_diff_context_prioritizes_source_over_docs():
    """Focused diff should prioritize code paths over docs noise."""
    docs_file = DiffFile(
        old_path="docs/readme.md",
        new_path="docs/readme.md",
        is_new=False,
        is_deleted=False,
        is_renamed=False,
        hunks=[
            DiffHunk(
                old_start=1,
                old_count=1,
                new_start=1,
                new_count=1,
                lines=[
                    DiffLine(type="add", content="doc update", old_line_num=None, new_line_num=1)
                ],
            )
        ],
    )
    code_file = DiffFile(
        old_path="src/gateway/server-methods/config.ts",
        new_path="src/gateway/server-methods/config.ts",
        is_new=False,
        is_deleted=False,
        is_renamed=False,
        hunks=[
            DiffHunk(
                old_start=10,
                old_count=1,
                new_start=10,
                new_count=1,
                lines=[
                    DiffLine(type="add", content="config.apply", old_line_num=None, new_line_num=10)
                ],
            )
        ],
    )
    context = DiffContext(
        files=[docs_file, code_file],
        added_lines=2,
        removed_lines=0,
        changed_files=["docs/readme.md", "src/gateway/server-methods/config.ts"],
    )

    focused = _build_focused_diff_context(context)

    assert focused.changed_files
    assert focused.changed_files[0] == "src/gateway/server-methods/config.ts"


def test_build_focused_diff_context_trims_oversized_hunks():
    """Focused diff should cap hunk size to keep prompts tractable."""
    many_lines = [
        DiffLine(type="add", content=f"line {idx}", old_line_num=None, new_line_num=idx)
        for idx in range(1, 280)
    ]
    noisy_file = DiffFile(
        old_path="src/gateway/server.ts",
        new_path="src/gateway/server.ts",
        is_new=False,
        is_deleted=False,
        is_renamed=False,
        hunks=[
            DiffHunk(
                old_start=1,
                old_count=200,
                new_start=1,
                new_count=200,
                lines=many_lines,
            )
        ],
    )
    context = DiffContext(
        files=[noisy_file],
        added_lines=len(many_lines),
        removed_lines=0,
        changed_files=["src/gateway/server.ts"],
    )

    focused = _build_focused_diff_context(context)

    assert len(focused.files) == 1
    assert len(focused.files[0].hunks) == 1
    assert len(focused.files[0].hunks[0].lines) == 200


def test_enforce_focused_diff_coverage_rejects_dropped_files():
    """PR review should fail closed when focused context drops changed files."""
    diff_files = [
        DiffFile(
            old_path=f"src/file_{idx}.py",
            new_path=f"src/file_{idx}.py",
            is_new=False,
            is_deleted=False,
            is_renamed=False,
            hunks=[
                DiffHunk(
                    old_start=1,
                    old_count=1,
                    new_start=1,
                    new_count=1,
                    lines=[
                        DiffLine(type="add", content="x = 1", old_line_num=None, new_line_num=1)
                    ],
                )
            ],
        )
        for idx in range(17)
    ]
    context = DiffContext(
        files=diff_files,
        added_lines=17,
        removed_lines=0,
        changed_files=[f"src/file_{idx}.py" for idx in range(17)],
    )

    focused = _build_focused_diff_context(context)

    with pytest.raises(RuntimeError, match="diff context exceeds safe analysis limits"):
        _enforce_focused_diff_coverage(context, focused)


def test_enforce_focused_diff_coverage_rejects_truncated_hunks():
    """PR review should fail closed when any hunk exceeds safe max lines."""
    many_lines = [
        DiffLine(type="add", content=f"line {idx}", old_line_num=None, new_line_num=idx)
        for idx in range(1, 280)
    ]
    noisy_file = DiffFile(
        old_path="src/gateway/server.ts",
        new_path="src/gateway/server.ts",
        is_new=False,
        is_deleted=False,
        is_renamed=False,
        hunks=[
            DiffHunk(
                old_start=1,
                old_count=200,
                new_start=1,
                new_count=200,
                lines=many_lines,
            )
        ],
    )
    context = DiffContext(
        files=[noisy_file],
        added_lines=len(many_lines),
        removed_lines=0,
        changed_files=["src/gateway/server.ts"],
    )
    focused = _build_focused_diff_context(context)

    with pytest.raises(RuntimeError, match="would be truncated"):
        _enforce_focused_diff_coverage(context, focused)


def test_enforce_focused_diff_coverage_allows_boundary_diff():
    """Focused context at limits should pass coverage checks."""
    diff_files = [
        DiffFile(
            old_path=f"src/file_{idx}.py",
            new_path=f"src/file_{idx}.py",
            is_new=False,
            is_deleted=False,
            is_renamed=False,
            hunks=[
                DiffHunk(
                    old_start=1,
                    old_count=1,
                    new_start=1,
                    new_count=1,
                    lines=[
                        DiffLine(type="add", content="x = 1", old_line_num=None, new_line_num=1)
                    ],
                )
            ],
        )
        for idx in range(16)
    ]
    context = DiffContext(
        files=diff_files,
        added_lines=16,
        removed_lines=0,
        changed_files=[f"src/file_{idx}.py" for idx in range(16)],
    )
    focused = _build_focused_diff_context(context)

    _enforce_focused_diff_coverage(context, focused)


def test_summarize_diff_hunk_snippets_includes_diff_lines():
    """Prompt hunk snippets should preserve +/- diff lines for missing-file analysis."""
    diff_file = DiffFile(
        old_path="src/media/parse.ts",
        new_path="src/media/parse.ts",
        is_new=True,
        is_deleted=False,
        is_renamed=False,
        hunks=[
            DiffHunk(
                old_start=0,
                old_count=0,
                new_start=1,
                new_count=4,
                lines=[
                    DiffLine(
                        type="add",
                        content="export const MEDIA_LINE_RE = /\\\\bMEDIA:/i;",
                        old_line_num=None,
                        new_line_num=1,
                    ),
                    DiffLine(
                        type="add",
                        content='if (candidate.startsWith("/")) return true;',
                        old_line_num=None,
                        new_line_num=2,
                    ),
                    DiffLine(
                        type="remove",
                        content='if (candidate.startsWith("./")) return false;',
                        old_line_num=9,
                        new_line_num=None,
                    ),
                ],
            )
        ],
    )
    context = DiffContext(
        files=[diff_file],
        added_lines=2,
        removed_lines=1,
        changed_files=["src/media/parse.ts"],
    )

    summary = _summarize_diff_hunk_snippets(context, max_chars=4000)

    assert "--- src/media/parse.ts (new)" in summary
    assert '+if (candidate.startsWith("/")) return true;' in summary
    assert '-if (candidate.startsWith("./")) return false;' in summary


def test_derive_pr_default_grep_scope_prefers_non_src_changed_top_level():
    """Pathless PR Grep should scope to changed top-level directory when src is absent."""
    context = DiffContext(
        files=[],
        added_lines=1,
        removed_lines=0,
        changed_files=["apps/macos/Sources/Clawdis/Utilities.swift"],
    )

    scope = _derive_pr_default_grep_scope(context)

    assert scope == "apps"


def test_derive_pr_default_grep_scope_ignores_non_repo_paths():
    """Traversal/absolute diff paths should not become default PR Grep scopes."""
    context = DiffContext(
        files=[],
        added_lines=2,
        removed_lines=0,
        changed_files=["../outside/file.py", "/tmp/evil.py"],
    )

    scope = _derive_pr_default_grep_scope(context)

    assert scope == "src"


def test_dedupe_pr_vulns_tags_known_matches():
    """Baseline overlaps should be retained and tagged as known_vuln."""
    pr_vulns = [
        {"file_path": "ui/app.ts", "threat_id": "THREAT-001", "title": "A"},
        {"file_path": "api/app.ts", "threat_id": "THREAT-002", "title": "B"},
    ]
    known_vulns = [
        {"file_path": "ui/app.ts", "threat_id": "THREAT-001", "title": "A"},
    ]

    filtered = dedupe_pr_vulns(pr_vulns, known_vulns)

    assert len(filtered) == 2
    assert filtered[0]["threat_id"] == "THREAT-001"
    assert filtered[0]["finding_type"] == "known_vuln"
    assert filtered[1]["threat_id"] == "THREAT-002"


def test_merge_pr_attempt_findings_collapses_duplicate_chain_variants():
    """Near-duplicate chain variants from multiple attempts should collapse to one finding."""
    merged = _merge_pr_attempt_findings(
        [
            {
                "title": "Unvalidated gatewayUrl parameter enables credential theft",
                "description": "gatewayUrl from query string is trusted and used for websocket connect.",
                "attack_scenario": "1) Victim opens link 2) token sent to attacker websocket.",
                "evidence": "ui/src/ui/app-settings.ts:98",
                "severity": "critical",
                "finding_type": "threat_enabler",
                "file_path": "ui/src/ui/app-settings.ts",
                "line_number": 98,
                "cwe_id": "CWE-601",
            },
            {
                "title": "Unvalidated gatewayUrl query parameter enables WebSocket hijacking",
                "description": "URL parameter controls websocket endpoint and leaks stored token.",
                "attack_scenario": "1) attacker link 2) browser auto-connects 3) token exfiltration.",
                "evidence": "ui/src/ui/app-settings.ts:99",
                "severity": "high",
                "finding_type": "new_threat",
                "file_path": "ui/src/ui/app-settings.ts",
                "line_number": 99,
                "cwe_id": "CWE-200",
            },
        ]
    )

    assert len(merged) == 1
    assert merged[0]["severity"] == "critical"
    assert "gatewayUrl" in merged[0]["title"]


def test_merge_pr_attempt_findings_preserves_distinct_chains():
    """Different chains in the same file should remain as separate findings."""
    merged = _merge_pr_attempt_findings(
        [
            {
                "title": "Docker bind mount allows host filesystem escape",
                "description": "Unvalidated binds permit mounting host paths into container.",
                "attack_scenario": "1) set binds 2) mount /var/run/docker.sock 3) escape.",
                "evidence": "src/config/zod-schema.agent-runtime.ts:80",
                "severity": "critical",
                "finding_type": "new_threat",
                "file_path": "src/config/zod-schema.agent-runtime.ts",
                "line_number": 80,
                "cwe_id": "CWE-610",
            },
            {
                "title": "Shell command injection via unsanitized PATH export",
                "description": "PATH value is interpolated into shell script without sanitization.",
                "attack_scenario": "1) attacker controls env.PATH 2) command substitution executes.",
                "evidence": "src/agents/bash-tools.shared.ts:67",
                "severity": "high",
                "finding_type": "new_threat",
                "file_path": "src/agents/bash-tools.shared.ts",
                "line_number": 67,
                "cwe_id": "CWE-78",
            },
        ]
    )

    assert len(merged) == 2


def test_merge_pr_attempt_findings_prefers_concrete_exploit_primitive():
    """Concrete exploit-primitive findings should win over speculative hardening variants."""
    merged = _merge_pr_attempt_findings(
        [
            {
                "title": "Potential shell interpolation hardening gap in SSH helper",
                "description": (
                    "The SSH flow could potentially allow bypass in edge cases if bypass exists; "
                    "testing needed for hypothetical quoting issues."
                ),
                "attack_scenario": (
                    "1) Attacker might influence target. 2) If bypass exists, command execution could be "
                    "possible. 3) Consider hardening."
                ),
                "evidence": "apps/macos/Sources/Clawdis/Utilities.swift:373",
                "severity": "medium",
                "finding_type": "new_threat",
                "file_path": "apps/macos/Sources/Clawdis/Utilities.swift",
                "line_number": 373,
                "cwe_id": "CWE-78",
            },
            {
                "title": "SSH option injection via dash-prefixed host positional argument",
                "description": (
                    "Untrusted target host reaches ssh argv positional host argument without `--`, "
                    "allowing option injection (CWE-88)."
                ),
                "attack_scenario": (
                    "1) Attacker sets target host to `-oProxyCommand=touch /tmp/pwned`. "
                    "2) Parser keeps non-empty host value. "
                    "3) Command builder appends userHost as positional arg and ssh treats it as option."
                ),
                "evidence": (
                    "source target -> parse host -> userHost positional argv sink; "
                    "apps/macos/Sources/Clawdis/Utilities.swift:373->374"
                ),
                "severity": "medium",
                "finding_type": "known_vuln",
                "file_path": "apps/macos/Sources/Clawdis/Utilities.swift",
                "line_number": 374,
                "cwe_id": "CWE-88",
            },
        ]
    )

    assert len(merged) == 1
    assert "option injection" in merged[0]["title"].lower()
    assert merged[0]["cwe_id"] == "CWE-88"


def test_merge_pr_attempt_findings_drops_speculative_noise_when_concrete_exists():
    """Strongly-proven chain should suppress separate speculative hardening noise entries."""
    merged = _merge_pr_attempt_findings(
        [
            {
                "title": "Local file exfiltration via media parser path acceptance",
                "description": (
                    "Changed parser accepts attacker-controlled local paths that are copied and served "
                    "without auth checks."
                ),
                "attack_scenario": (
                    "1) Attacker sends media token with /etc/passwd path. "
                    "2) Parser accepts local path and flow reaches save/host route. "
                    "3) Unauthenticated media endpoint serves copied file."
                ),
                "evidence": (
                    "flow: src/media/parse.ts:29 -> src/media/store.ts:91 -> "
                    "src/media/server.ts:28"
                ),
                "severity": "high",
                "finding_type": "known_vuln",
                "file_path": "src/media/parse.ts",
                "line_number": 29,
                "cwe_id": "CWE-22",
            },
            {
                "title": "Exported parser could increase future attack surface",
                "description": (
                    "Potential hardening note: parser export might be misused in the future and could "
                    "benefit from defense-in-depth checks."
                ),
                "attack_scenario": (
                    "1) Future code might call parser differently. "
                    "2) Possible edge case could appear."
                ),
                "evidence": "src/media/parse.ts:1",
                "severity": "medium",
                "finding_type": "threat_enabler",
                "file_path": "src/media/parse.ts",
                "line_number": 1,
                "cwe_id": "CWE-693",
            },
        ]
    )

    assert len(merged) == 1
    assert "exfiltration" in merged[0]["title"].lower()


def test_merge_pr_attempt_findings_collapses_subchain_step_variants():
    """Same exploit chain split into parser steps should collapse to one canonical finding."""
    merge_stats: dict[str, int] = {}
    merged = _merge_pr_attempt_findings(
        [
            {
                "title": "Parser accepts file URI local paths",
                "description": "normalizeMediaSource turns file:// URIs into local absolute paths.",
                "attack_scenario": (
                    "1) Attacker returns MEDIA=file:///etc/passwd in model output. "
                    "2) Parser keeps resulting local path."
                ),
                "evidence": "src/media/parse.ts:6 normalizes file:// values into local paths.",
                "severity": "high",
                "finding_type": "known_vuln",
                "file_path": "src/media/parse.ts",
                "line_number": 6,
                "cwe_id": "CWE-22",
            },
            {
                "title": "Local file exfiltration via media parser to unauthenticated route",
                "description": (
                    "Attacker-controlled local paths are accepted and flow to media copy + unauthenticated "
                    "download route."
                ),
                "attack_scenario": (
                    "1) Attacker sends MEDIA token containing /etc/passwd. "
                    "2) Parser accepts local path and saveMediaSource copies file into media store. "
                    "3) /media/:id serves copied file without auth."
                ),
                "evidence": (
                    "flow: src/media/parse.ts:29 -> src/media/store.ts:91 -> src/media/server.ts:28"
                ),
                "severity": "high",
                "finding_type": "known_vuln",
                "file_path": "src/media/parse.ts",
                "line_number": 29,
                "cwe_id": "CWE-22",
            },
        ],
        merge_stats=merge_stats,
    )

    assert len(merged) == 1
    assert merged[0]["line_number"] == 29
    assert merge_stats["subchain_collapsed"] == 1
    assert merge_stats["canonical_chain_count"] == 1


def test_merge_pr_attempt_findings_preserves_distinct_same_file_same_cwe_chains():
    """Different sinks in same file/CWE should not be collapsed as one chain."""
    merged = _merge_pr_attempt_findings(
        [
            {
                "title": "Shell command injection in startup helper",
                "description": "User controlled env value reaches /bin/sh -c invocation.",
                "attack_scenario": (
                    "1) User controls startup command value. "
                    "2) Value is interpolated into shell command. "
                    "3) /bin/sh executes attacker payload."
                ),
                "evidence": "flow: src/process/exec.ts:40 -> src/process/exec.ts:55",
                "severity": "high",
                "finding_type": "new_threat",
                "file_path": "src/process/exec.ts",
                "line_number": 40,
                "cwe_id": "CWE-78",
            },
            {
                "title": "SSH option injection in deploy helper target argument",
                "description": "Target host reaches positional ssh argv without -- separation.",
                "attack_scenario": (
                    "1) Attacker sets host to -oProxyCommand payload. "
                    "2) deploy helper appends host positional arg. "
                    "3) ssh treats host as option."
                ),
                "evidence": "flow: src/process/exec.ts:220 -> src/process/exec.ts:241",
                "severity": "high",
                "finding_type": "new_threat",
                "file_path": "src/process/exec.ts",
                "line_number": 220,
                "cwe_id": "CWE-78",
            },
        ]
    )

    assert len(merged) == 2


def test_merge_pr_attempt_findings_collapses_cross_cwe_enabler_variant():
    """Threat-enabler variants with same sink chain should collapse under concrete finding."""
    merge_stats: dict[str, int] = {}
    merged = _merge_pr_attempt_findings(
        [
            {
                "title": "Path traversal in parser leads to file exfiltration",
                "description": "Untrusted MEDIA path reaches copy + unauthenticated serve sink.",
                "attack_scenario": (
                    "1) Attacker injects MEDIA:/etc/passwd. "
                    "2) Parser accepts path. "
                    "3) Flow reaches saveMediaSource and /media/:id exfil."
                ),
                "evidence": (
                    "flow: src/media/parse.ts:29 -> src/media/store.ts:91 -> src/media/server.ts:28"
                ),
                "severity": "critical",
                "finding_type": "known_vuln",
                "file_path": "src/media/parse.ts",
                "line_number": 29,
                "cwe_id": "CWE-22",
            },
            {
                "title": "Exported parser could be reused in future unauthenticated contexts",
                "description": (
                    "Future caller risk: parser export may enable similar file exfiltration chain "
                    "through saveMediaSource and /media/:id."
                ),
                "attack_scenario": (
                    "1) Future code might call exported parser. "
                    "2) MEDIA:file://./../../etc/passwd passes parser checks. "
                    "3) Same sink chain copies and serves sensitive file."
                ),
                "evidence": (
                    "src/media/parse.ts:11 export; flow to src/media/store.ts:91 and "
                    "src/media/server.ts:28 in same chain."
                ),
                "severity": "medium",
                "finding_type": "threat_enabler",
                "file_path": "src/media/parse.ts",
                "line_number": 11,
                "cwe_id": "CWE-610",
            },
        ],
        merge_stats=merge_stats,
    )

    assert len(merged) == 1
    assert merged[0]["cwe_id"] == "CWE-22"
    assert merge_stats["subchain_collapsed"] == 1
    assert merge_stats["canonical_chain_count"] == 1


def test_merge_pr_attempt_findings_drops_low_support_noise_when_core_is_repeated():
    """Low-support chains should be dropped when a stronger repeated chain is present."""
    core_finding = {
        "title": "Local file exfiltration via media parser path acceptance",
        "description": "Parser accepts attacker path and chain reaches unauthenticated file serving.",
        "attack_scenario": (
            "1) Attacker injects MEDIA path. 2) Path is accepted and copied. "
            "3) Unauthenticated route serves the copied file."
        ),
        "evidence": "flow: src/media/parse.ts:29 -> src/media/store.ts:91 -> src/media/server.ts:28",
        "severity": "critical",
        "finding_type": "known_vuln",
        "file_path": "src/media/parse.ts",
        "line_number": 29,
        "cwe_id": "CWE-22",
    }
    noisy_finding = {
        "title": "Whitespace normalization behavior changed in parser",
        "description": "Formatting behavior changed and might affect downstream handling.",
        "attack_scenario": (
            "1) Attacker sends output with control chars. "
            "2) Parser preserves some chars. "
            "3) Downstream formatting behavior changes."
        ),
        "evidence": "flow: src/media/format.ts:41 -> src/auto-reply/reply.ts:461",
        "severity": "medium",
        "finding_type": "regression",
        "file_path": "src/media/format.ts",
        "line_number": 41,
        "cwe_id": "CWE-93",
    }
    merge_stats: dict[str, int] = {}
    chain_support_counts = {
        build_chain_family_identity(core_finding): 3,
        build_chain_family_identity(noisy_finding): 1,
    }

    merged = _merge_pr_attempt_findings(
        [core_finding, noisy_finding],
        merge_stats=merge_stats,
        chain_support_counts=chain_support_counts,
        total_attempts=4,
    )

    assert len(merged) == 1
    assert "exfiltration" in merged[0]["title"].lower()
    assert merge_stats["low_support_dropped"] == 1


def test_merge_pr_attempt_findings_drops_secondary_chain_variant():
    """Weaker same-family chain variants should be dropped as secondary findings."""
    merge_stats: dict[str, int] = {}
    merged = _merge_pr_attempt_findings(
        [
            {
                "title": "Local file exfiltration via parser to media route",
                "description": "Untrusted MEDIA path reaches saveMediaSource and /media/:id serving.",
                "attack_scenario": (
                    "1) Attacker injects MEDIA path. "
                    "2) Parser accepts and file is copied. "
                    "3) /media/:id serves exfiltrated file."
                ),
                "evidence": (
                    "flow: src/media/parse.ts:29 -> src/media/store.ts:91 -> src/media/server.ts:28"
                ),
                "severity": "high",
                "finding_type": "known_vuln",
                "file_path": "src/media/parse.ts",
                "line_number": 29,
                "cwe_id": "CWE-22",
            },
            {
                "title": "Additional parser note for same media hosting sink",
                "description": "Parser behavior may impact media hosting security in similar flows.",
                "attack_scenario": "Parser accepts input and may reach media hosting.",
                "evidence": "flow: src/media/parse.ts:109 -> src/media/server.ts:28",
                "severity": "medium",
                "finding_type": "regression",
                "file_path": "src/media/parse.ts",
                "line_number": 109,
                "cwe_id": "CWE-73",
            },
        ],
        merge_stats=merge_stats,
    )

    assert len(merged) == 1
    assert merge_stats["dropped_as_secondary_chain"] == 1


def test_dedupe_pr_vulns_ignores_basename_only_collisions():
    """Same title + basename in different directories should not be deduped."""
    pr_vulns = [
        {
            "file_path": "services/web/handler.py",
            "threat_id": "PR-001",
            "title": "Command injection in handler",
            "finding_type": "unknown",
        }
    ]
    known_vulns = [
        {
            "file_path": "services/api/handler.py",
            "threat_id": "THREAT-001",
            "title": "Command injection in handler",
        }
    ]
    result = dedupe_pr_vulns(pr_vulns, known_vulns)
    assert len(result) == 1
    assert result[0]["finding_type"] == "unknown"


def test_dedupe_with_baseline_filter_preserves_pr_findings():
    """The real regression: THREAT-001 + finding_type in known should NOT suppress."""
    pr_vulns = [{"file_path": "app.ts", "threat_id": "THREAT-001", "title": "SQLi"}]
    known_vulns = [
        {
            "file_path": "app.ts",
            "threat_id": "THREAT-001",
            "title": "SQLi",
            "finding_type": "known_vuln",
        },
    ]
    baseline = filter_baseline_vulns(known_vulns)
    result = dedupe_pr_vulns(pr_vulns, baseline)
    assert len(result) == 1  # NOT deduped


def test_pr_review_retry_suffix_attempt_two_focuses_command_injection():
    """Second pass should prioritize command/option injection chains."""
    suffix = _build_pr_review_retry_suffix(2)
    assert "FOCUS AREA: COMMAND/OPTION INJECTION CHAINS" in suffix


def test_pr_review_retry_suffix_attempt_three_focuses_path_chains():
    """Third pass should prioritize path/file exfiltration chains."""
    suffix = _build_pr_review_retry_suffix(3)
    assert "FOCUS AREA: PATH + FILE EXFILTRATION CHAINS" in suffix


def test_pr_review_retry_suffix_adds_command_builder_hint():
    """When command-builder deltas are detected, retry guidance should call that out."""
    suffix = _build_pr_review_retry_suffix(2, command_builder_signals=True)
    assert "COMMAND-BUILDER DELTA DETECTED" in suffix
    assert "missing `--` separators" in suffix


def test_pr_review_retry_focus_plan_prioritizes_detected_signals():
    """Retry focus should prioritize active diff signals before default ordering."""
    retry_plan = _build_pr_retry_focus_plan(
        4,
        command_builder_signals=False,
        path_parser_signals=True,
        auth_privilege_signals=True,
    )

    assert retry_plan == ["path_exfiltration", "auth_privileged", "command_option"]


def test_pr_review_retry_suffix_respects_explicit_focus_area():
    """Adaptive retry scheduling should be able to set explicit focus area text."""
    suffix = _build_pr_review_retry_suffix(2, focus_area="auth_privileged")
    assert "FOCUS AREA: AUTH + PRIVILEGED OPERATION CHAINING" in suffix


def test_pr_review_retry_suffix_includes_candidate_revalidation_block():
    """Retry guidance should carry forward prior candidate chains when provided."""
    suffix = _build_pr_review_retry_suffix(
        4,
        focus_area="path_exfiltration",
        candidate_summary="- Chain A (src/a.ts:10, CWE-22, support=1/3)",
        require_candidate_revalidation=True,
    )

    assert "PRIOR HIGH-IMPACT CHAIN CANDIDATES TO RE-VALIDATE" in suffix
    assert "CORE CHAIN REVALIDATION REQUIREMENT" in suffix
    assert "UNRESOLVED HYPOTHESIS DISPOSITION (MANDATORY)" in suffix
    assert "support=1/3" in suffix


def test_pr_review_retry_suffix_requires_candidate_revalidation_without_consensus_mode():
    """Candidate revalidation requirement should be enforced even without recovery mode."""
    suffix = _build_pr_review_retry_suffix(
        2,
        focus_area="path_exfiltration",
        candidate_summary="- Chain B (src/b.ts:42, CWE-94, support=2/2)",
        require_candidate_revalidation=True,
    )

    assert "PRIOR HIGH-IMPACT CHAIN CANDIDATES TO RE-VALIDATE" in suffix
    assert "CORE CHAIN REVALIDATION REQUIREMENT" in suffix
    assert "UNRESOLVED HYPOTHESIS DISPOSITION (MANDATORY)" in suffix


def test_diff_signal_detectors_identify_path_and_auth_deltas():
    """Path and auth/privilege signal helpers should detect high-risk changed hunks."""
    context = DiffContext(
        files=[
            DiffFile(
                old_path="src/media/parse.ts",
                new_path="src/media/parse.ts",
                is_new=False,
                is_deleted=False,
                is_renamed=False,
                hunks=[
                    DiffHunk(
                        old_start=20,
                        old_count=1,
                        new_start=20,
                        new_count=1,
                        lines=[
                            DiffLine(
                                type="add",
                                content="const normalized = path.resolve(inputPath)",
                                old_line_num=None,
                                new_line_num=20,
                            )
                        ],
                    )
                ],
            ),
            DiffFile(
                old_path="src/gateway/server-methods/config.ts",
                new_path="src/gateway/server-methods/config.ts",
                is_new=False,
                is_deleted=False,
                is_renamed=False,
                hunks=[
                    DiffHunk(
                        old_start=75,
                        old_count=1,
                        new_start=75,
                        new_count=1,
                        lines=[
                            DiffLine(
                                type="add",
                                content="socket.methods['config.apply'] = applyConfig",
                                old_line_num=None,
                                new_line_num=75,
                            )
                        ],
                    )
                ],
            ),
        ],
        added_lines=2,
        removed_lines=0,
        changed_files=["src/media/parse.ts", "src/gateway/server-methods/config.ts"],
    )

    assert diff_has_path_parser_signals(context)
    assert diff_has_auth_privilege_signals(context)


def test_attempt_disagreement_detector_flags_sparse_attempt_success():
    """Mixed zero/non-zero attempt outputs should be observable as disagreement telemetry."""
    assert _attempts_show_pr_disagreement([0, 2, 0, 1])
    assert not _attempts_show_pr_disagreement([2, 2, 2])


def test_should_run_pr_verifier_only_when_consensus_is_weak():
    """Verifier should run only when canonical findings exist and consensus is weak."""
    assert not _should_run_pr_verifier(has_findings=False, weak_consensus=True)
    assert not _should_run_pr_verifier(has_findings=True, weak_consensus=False)
    assert _should_run_pr_verifier(has_findings=True, weak_consensus=True)


def test_extract_observed_pr_findings_reads_hook_observer_payload():
    """Hook observer payload should be converted into list[dict] findings."""
    observed = _extract_observed_pr_findings(
        {
            "max_items": 2,
            "max_content": json.dumps(
                [
                    {"title": "A", "file_path": "a.ts", "line_number": 1},
                    {"title": "B", "file_path": "b.ts", "line_number": 2},
                ]
            ),
        }
    )

    assert len(observed) == 2
    assert observed[0]["title"] == "A"


def test_chain_identity_and_core_pass_support_tracking():
    """Chain identity helpers should compute pass-level support counts consistently."""
    finding = {
        "title": "Local file exfiltration via media path parsing",
        "file_path": "src/media/parse.ts",
        "line_number": 29,
        "cwe_id": "CWE-22",
    }
    chain_id = build_chain_identity(finding)
    assert chain_id

    pass_chain_ids = [{chain_id}, set(), {chain_id}]
    assert count_passes_with_core_chains({chain_id}, pass_chain_ids) == 2


def test_chain_family_identity_stable_across_wording_and_cwe_variants():
    """Same sink chain should share family identity across wording/CWE drift."""
    finding_a = {
        "title": "Path traversal via parser enables exfiltration",
        "description": "MEDIA path reaches local file copy and unauthenticated media route.",
        "attack_scenario": "1) Inject MEDIA path 2) copied 3) served over /media/:id.",
        "evidence": "flow: src/media/parse.ts:29 -> src/media/store.ts:91 -> src/media/server.ts:28",
        "file_path": "src/media/parse.ts",
        "line_number": 29,
        "cwe_id": "CWE-22",
    }
    finding_b = {
        "title": "Exported parser can be reused in future contexts",
        "description": "Threat enabler chain still reaches saveMediaSource and media server sink.",
        "attack_scenario": "1) Future caller uses parser 2) same sink chain exfiltrates file.",
        "evidence": "src/media/parse.ts:11 export; flow to src/media/store.ts:91 and src/media/server.ts:28",
        "file_path": "src/media/parse.ts",
        "line_number": 11,
        "cwe_id": "CWE-610",
    }

    assert build_chain_family_identity(finding_a)
    assert build_chain_family_identity(finding_a) == build_chain_family_identity(finding_b)


def test_chain_family_support_counts_semantically_equivalent_pass_outputs():
    """Pass support should count semantically equivalent chain variants."""
    finding_a = {
        "title": "Local file exfiltration via parser",
        "file_path": "src/media/parse.ts",
        "line_number": 29,
        "cwe_id": "CWE-22",
        "evidence": "flow: src/media/parse.ts:29 -> src/media/store.ts:91 -> src/media/server.ts:28",
    }
    finding_b = {
        "title": "Parser export threat enabler for same exfil chain",
        "file_path": "src/media/parse.ts",
        "line_number": 11,
        "cwe_id": "CWE-610",
        "evidence": "src/media/parse.ts:11 export; flow to src/media/store.ts:91 and src/media/server.ts:28",
    }
    family_id_a = build_chain_family_identity(finding_a)
    family_id_b = build_chain_family_identity(finding_b)
    assert family_id_a == family_id_b

    pass_chain_ids = [{family_id_a}, {family_id_b}, set(), {family_id_a}]
    assert count_passes_with_core_chains({family_id_a}, pass_chain_ids) == 3


def test_chain_flow_identity_stable_for_same_sink_family():
    """Flow identity should remain stable across wording/CWE drift for same sink family."""
    finding_a = {
        "title": "Local file exfiltration via parser",
        "file_path": "src/media/parse.ts",
        "line_number": 29,
        "cwe_id": "CWE-22",
        "evidence": "flow: src/media/parse.ts:29 -> src/media/store.ts:91 -> src/media/server.ts:28",
    }
    finding_b = {
        "title": "Exported parser misuse for same file host sink",
        "file_path": "src/media/parse.ts",
        "line_number": 11,
        "cwe_id": "CWE-691",
        "evidence": "src/media/parse.ts:11 export; flow to src/media/store.ts:91 and src/media/server.ts:28",
    }

    flow_a = build_chain_flow_identity(finding_a)
    flow_b = build_chain_flow_identity(finding_b)
    assert flow_a
    assert flow_a == flow_b


def test_adjudicate_consensus_support_falls_back_to_flow_mode_when_exact_is_weak():
    """Consensus mode should choose flow when exact support is weak and flow is stable."""
    weak, reason, support, mode, metrics = adjudicate_consensus_support(
        required_support=2,
        core_exact_ids={"exact-core"},
        pass_exact_ids=[{"exact-core"}, set(), set(), set()],
        core_family_ids={"family-core"},
        pass_family_ids=[{"family-core"}, set(), {"family-core"}, set()],
        core_flow_ids={"flow-core"},
        pass_flow_ids=[{"flow-core"}, {"flow-core"}, {"flow-core"}, set()],
    )

    assert not weak
    assert mode == "flow"
    assert support == 3
    assert metrics["exact"] == 1
    assert metrics["family"] == 2
    assert metrics["flow"] == 3
    assert reason == "stable"


def test_canonicalize_finding_path_normalizes_absolute_repo_suffix():
    """Absolute finding paths should normalize to repo-style suffix for dedupe."""
    path = canonicalize_finding_path("/Users/test/repos/openclaw/src/media/parse.ts")
    assert path == "src/media/parse.ts"


def test_merge_pr_attempt_findings_collapses_absolute_relative_path_duplicates():
    """Same chain reported with absolute vs relative path should dedupe to one finding."""
    merged = _merge_pr_attempt_findings(
        [
            {
                "title": "Path traversal via MEDIA token",
                "description": "Parser accepts local file paths without canonicalization.",
                "attack_scenario": "1) Inject MEDIA path 2) file copied 3) served back.",
                "evidence": "flow: parse -> store -> server",
                "severity": "high",
                "finding_type": "known_vuln",
                "file_path": "src/media/parse.ts",
                "line_number": 29,
                "cwe_id": "CWE-22",
            },
            {
                "title": "Path traversal via MEDIA token",
                "description": "Parser accepts local file paths without canonicalization.",
                "attack_scenario": "1) Inject MEDIA path 2) file copied 3) served back.",
                "evidence": "flow: parse -> store -> server",
                "severity": "high",
                "finding_type": "known_vuln",
                "file_path": "/Users/test/repos/openclaw/src/media/parse.ts",
                "line_number": 29,
                "cwe_id": "CWE-22",
            },
        ]
    )
    assert len(merged) == 1


def test_detect_weak_chain_consensus_requires_minimum_support():
    """Weak consensus should trigger when core chains are not independently repeated."""
    core_chain_ids = {"src/media/parse.ts|22|1|local.file.exfiltration"}
    weak, reason, support = detect_weak_chain_consensus(
        core_chain_ids=core_chain_ids,
        pass_chain_ids=[set(core_chain_ids), set(), set()],
        required_support=2,
    )
    assert weak
    assert support == 1
    assert "core_support" in reason

    stable, stable_reason, stable_support = detect_weak_chain_consensus(
        core_chain_ids=core_chain_ids,
        pass_chain_ids=[set(core_chain_ids), set(core_chain_ids), set(core_chain_ids)],
        required_support=2,
    )
    assert not stable
    assert stable_support == 3
    assert stable_reason == "stable"


def test_detect_weak_chain_consensus_accepts_family_variant_agreement():
    """Family-equivalent variants across passes should not trigger weak consensus."""
    core_finding = {
        "title": "Path traversal exfiltration chain",
        "file_path": "src/media/parse.ts",
        "line_number": 29,
        "cwe_id": "CWE-22",
        "evidence": "flow: src/media/parse.ts:29 -> src/media/store.ts:91 -> src/media/server.ts:28",
    }
    variant_finding = {
        "title": "Parser export enables same exfiltration sink",
        "file_path": "src/media/parse.ts",
        "line_number": 11,
        "cwe_id": "CWE-610",
        "evidence": "src/media/parse.ts:11 export; flow to src/media/store.ts:91 and src/media/server.ts:28",
    }
    core_family = build_chain_family_identity(core_finding)
    variant_family = build_chain_family_identity(variant_finding)
    assert core_family == variant_family

    weak, reason, support = detect_weak_chain_consensus(
        core_chain_ids={core_family},
        pass_chain_ids=[{core_family}, {variant_family}, {core_family}, {variant_family}],
        required_support=2,
    )
    assert not weak
    assert support == 4
    assert reason == "stable"


def test_attempt_contains_core_chain_evidence_matches_family_or_flow():
    """Core evidence detection should accept either family or flow overlap."""
    finding = {
        "title": "Local file exfiltration via parser",
        "file_path": "src/media/parse.ts",
        "line_number": 29,
        "cwe_id": "CWE-22",
        "evidence": "flow: src/media/parse.ts:29 -> src/media/store.ts:91 -> src/media/server.ts:28",
    }
    family_id = build_chain_family_identity(finding)
    flow_id = build_chain_flow_identity(finding)

    assert attempt_contains_core_chain_evidence(
        attempt_findings=[finding],
        expected_family_ids={family_id},
        expected_flow_ids=set(),
    )
    assert attempt_contains_core_chain_evidence(
        attempt_findings=[finding],
        expected_family_ids=set(),
        expected_flow_ids={flow_id},
    )
    assert not attempt_contains_core_chain_evidence(
        attempt_findings=[finding],
        expected_family_ids={"src/other.ts|path_file_chain"},
        expected_flow_ids={"src/other.ts|file_host_sink|path_file_chain"},
    )


def test_summarize_revalidation_support_counts_hits_and_misses():
    """Revalidation summary should report attempts, hits, and misses correctly."""
    attempts, hits, misses = summarize_revalidation_support(
        revalidation_attempted=[False, True, True, True],
        core_evidence_present=[False, True, False, True],
    )
    assert attempts == 3
    assert hits == 2
    assert misses == 1


def test_summarize_chain_candidates_for_prompt_includes_support_counts():
    """Candidate summary should include location and pass support for carry-forward prompts."""
    finding = {
        "title": "Local file exfiltration via parser",
        "file_path": "src/media/parse.ts",
        "line_number": 29,
        "cwe_id": "CWE-22",
        "evidence": "flow: src/media/parse.ts:29 -> src/media/store.ts:91 -> src/media/server.ts:28",
    }
    chain_id = build_chain_family_identity(finding)
    flow_id = build_chain_flow_identity(finding)
    summary = summarize_chain_candidates_for_prompt(
        findings=[finding],
        chain_support_counts={chain_id: 2},
        flow_support_counts={flow_id: 3},
        attempts_observed=3,
    )
    assert "support=" in summary
    assert "support=3/3" in summary
    assert "src/media/parse.ts:29" in summary


def test_dedupe_with_baseline_filter_marks_real_baseline_as_known():
    """Baseline THREAT entries without finding_type should be tagged known_vuln."""
    pr_vulns = [{"file_path": "app.ts", "threat_id": "THREAT-001", "title": "SQLi"}]
    known_vulns = [
        {"file_path": "app.ts", "threat_id": "THREAT-001", "title": "SQLi"},  # no finding_type
    ]
    baseline = filter_baseline_vulns(known_vulns)
    result = dedupe_pr_vulns(pr_vulns, baseline)
    assert len(result) == 1
    assert result[0]["finding_type"] == "known_vuln"


@pytest.mark.asyncio
async def test_pr_review_handles_wrapper_format(tmp_path: Path, mock_scanner_claude_client):
    """Wrapper + schema variant should be normalized into proper issue locations/CWE."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    variant_vuln = {
        "id": "PR-VULN-001",
        "title": "SQL Injection",
        "description": "User input in query",
        "severity": "high",
        "location": "src/app.py:42-45",
        "cwe": "89",
        "recommendation": "Use parameterized queries",
    }

    diff_context = DiffContext(files=[], added_lines=1, removed_lines=0, changed_files=["app.py"])

    scanner = Scanner(model="sonnet", debug=False)
    scanner.console = Console(file=StringIO())

    _, mock_instance = mock_scanner_claude_client

    async def write_attempt_artifact(*_args, **_kwargs) -> None:
        # Emulate the PR agent writing a wrapper-format artifact during this attempt.
        (securevibes_dir / "PR_VULNERABILITIES.json").write_text(
            json.dumps({"vulnerabilities": [variant_vuln]}),
            encoding="utf-8",
        )

    mock_instance.query = AsyncMock(side_effect=write_attempt_artifact)

    async def async_gen():
        return
        yield  # pragma: no cover

    mock_instance.receive_messages = async_gen

    result = await scanner.pr_review(
        str(repo),
        diff_context,
        known_vulns_path=None,
        severity_threshold="low",
    )

    assert len(result.issues) > 0, "Wrapper format should produce non-empty issues after unwrap"
    assert result.issues[0].title == "SQL Injection"
    assert result.issues[0].file_path == "src/app.py"
    assert result.issues[0].line_number == 42
    assert result.issues[0].cwe_id == "CWE-89"


@pytest.mark.asyncio
async def test_pr_review_missing_artifact_fails_closed(tmp_path: Path, mock_scanner_claude_client):
    """Missing PR_VULNERABILITIES.json should fail the PR review path."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    diff_context = DiffContext(files=[], added_lines=1, removed_lines=0, changed_files=["app.py"])

    scanner = Scanner(model="sonnet", debug=False)
    scanner.console = Console(file=StringIO())

    _, mock_instance = mock_scanner_claude_client
    mock_instance.query = AsyncMock()

    async def async_gen():
        return
        yield  # pragma: no cover

    mock_instance.receive_messages = async_gen

    with pytest.raises(RuntimeError, match="did not produce a readable PR_VULNERABILITIES"):
        await scanner.pr_review(
            str(repo),
            diff_context,
            known_vulns_path=None,
            severity_threshold="low",
        )


@pytest.mark.asyncio
async def test_pr_review_retries_when_first_attempt_returns_empty(tmp_path: Path):
    """If first attempt returns empty findings, scanner should retry with follow-up pass."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    diff_context = DiffContext(files=[], added_lines=1, removed_lines=0, changed_files=["app.py"])

    scanner = Scanner(model="sonnet", debug=False)
    scanner.console = Console(file=StringIO())

    attempt_counter = {"count": 0}

    with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
        mock_instance.query = AsyncMock()

        async def query_side_effect(_prompt: str):
            if "## HYPOTHESES TO VALIDATE" not in _prompt:
                return
            attempt_counter["count"] += 1
            if attempt_counter["count"] == 1:
                (securevibes_dir / "PR_VULNERABILITIES.json").write_text("[]", encoding="utf-8")
            else:
                (securevibes_dir / "PR_VULNERABILITIES.json").write_text(
                    json.dumps(
                        [
                            {
                                "threat_id": "PR-001",
                                "finding_type": "new_threat",
                                "title": "Follow-up finding",
                                "description": "Second pass produced a finding.",
                                "severity": "high",
                                "file_path": "src/app.py",
                                "line_number": 1,
                                "code_snippet": "danger()",
                                "attack_scenario": "1) Input reaches sink.",
                                "evidence": "src/app.py:1",
                                "cwe_id": "CWE-94",
                                "recommendation": "Add validation.",
                            }
                        ]
                    ),
                    encoding="utf-8",
                )

        mock_instance.query.side_effect = query_side_effect

        async def async_gen():
            return
            yield  # pragma: no cover

        mock_instance.receive_messages = async_gen

        result = await scanner.pr_review(
            str(repo),
            diff_context,
            known_vulns_path=None,
            severity_threshold="low",
        )

    assert result.issues
    assert attempt_counter["count"] == config.get_pr_review_attempts()
    assert any("returned no findings yet" in warning for warning in result.warnings)


@pytest.mark.asyncio
async def test_pr_review_empty_follow_up_attempt_is_logged_without_warning(
    tmp_path: Path, monkeypatch
):
    """No-new-findings follow-up attempts should not emit warning-level retry noise."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    diff_context = DiffContext(files=[], added_lines=1, removed_lines=0, changed_files=["app.py"])

    monkeypatch.setenv("SECUREVIBES_PR_REVIEW_ATTEMPTS", "3")

    console_output = StringIO()
    scanner = Scanner(model="sonnet", debug=True)
    scanner.console = Console(file=console_output)

    attempt_counter = {"count": 0}

    with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
        mock_instance.query = AsyncMock()

        async def query_side_effect(_prompt: str):
            if "## HYPOTHESES TO VALIDATE" not in _prompt:
                return
            attempt_counter["count"] += 1
            if attempt_counter["count"] == 1:
                (securevibes_dir / "PR_VULNERABILITIES.json").write_text(
                    json.dumps(
                        [
                            {
                                "threat_id": "PR-OBS-001",
                                "finding_type": "new_threat",
                                "title": "Initial finding",
                                "description": "First pass produced a finding.",
                                "severity": "high",
                                "file_path": "src/app.py",
                                "line_number": 1,
                                "code_snippet": "danger()",
                                "attack_scenario": "1) Input reaches sink.",
                                "evidence": "src/app.py:1",
                                "cwe_id": "CWE-94",
                                "recommendation": "Add validation.",
                            }
                        ]
                    ),
                    encoding="utf-8",
                )
            else:
                (securevibes_dir / "PR_VULNERABILITIES.json").write_text("[]", encoding="utf-8")

        mock_instance.query.side_effect = query_side_effect

        async def async_gen():
            return
            yield  # pragma: no cover

        mock_instance.receive_messages = async_gen

        result = await scanner.pr_review(
            str(repo),
            diff_context,
            known_vulns_path=None,
            severity_threshold="low",
        )

    console_text = console_output.getvalue()
    assert result.issues
    assert attempt_counter["count"] == config.get_pr_review_attempts()
    assert not any("returned no findings yet" in warning for warning in result.warnings)
    assert "no new findings" in console_text
    assert "cumulative remains 1" in console_text
    assert "PR review attempt summary:" in console_text
    assert "canonical_pre_filter=" in console_text
    assert "final_post_filter=" in console_text
    assert "passes_with_core_chain_exact=" in console_text
    assert "passes_with_core_chain_family=" in console_text
    assert "passes_with_core_chain_flow=" in console_text
    assert "consensus_mode_used=" in console_text
    assert "dropped_as_secondary_chain=" in console_text
    assert "attempt_disagreement=" in console_text
    assert "blocked_out_of_repo_tool_calls=" in console_text
    assert "revalidation_attempts=" in console_text
    assert "revalidation_core_hits=" in console_text
    assert "revalidation_core_misses=" in console_text


@pytest.mark.asyncio
async def test_pr_review_timeout_retries_and_succeeds(tmp_path: Path, monkeypatch):
    """A timeout on first pass should retry and accept a later successful pass."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    diff_context = DiffContext(files=[], added_lines=1, removed_lines=0, changed_files=["app.py"])

    monkeypatch.setenv("SECUREVIBES_PR_REVIEW_TIMEOUT_SECONDS", "1")
    monkeypatch.setenv("SECUREVIBES_PR_REVIEW_ATTEMPTS", "2")

    scanner = Scanner(model="sonnet", debug=False)
    scanner.console = Console(file=StringIO())

    stream_counter = {"count": 0}

    with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
        mock_instance.query = AsyncMock()

        async def query_side_effect(_prompt: str):
            if stream_counter["count"] >= 1:
                (securevibes_dir / "PR_VULNERABILITIES.json").write_text(
                    json.dumps(
                        [
                            {
                                "threat_id": "PR-002",
                                "finding_type": "new_threat",
                                "title": "Recovered finding",
                                "description": "Retry pass produced a finding.",
                                "severity": "high",
                                "file_path": "src/app.py",
                                "line_number": 2,
                                "code_snippet": "eval(x)",
                                "attack_scenario": "1) User input controls eval.",
                                "evidence": "src/app.py:2",
                                "cwe_id": "CWE-94",
                                "recommendation": "Avoid eval.",
                            }
                        ]
                    ),
                    encoding="utf-8",
                )

        mock_instance.query.side_effect = query_side_effect

        def receive_messages_side_effect():
            async def _stream():
                if stream_counter["count"] == 0:
                    stream_counter["count"] += 1
                    await asyncio.sleep(2)
                    return
                    yield  # pragma: no cover
                stream_counter["count"] += 1
                return
                yield  # pragma: no cover

            return _stream()

        mock_instance.receive_messages = receive_messages_side_effect

        result = await scanner.pr_review(
            str(repo),
            diff_context,
            known_vulns_path=None,
            severity_threshold="low",
        )

    assert result.issues
    assert any("timed out" in warning.lower() for warning in result.warnings)


@pytest.mark.asyncio
async def test_pr_review_query_timeout_uses_configured_timeout(tmp_path: Path, monkeypatch):
    """Query timeout should respect configured timeout and fail closed when artifact is missing."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
    diff_context = DiffContext(files=[], added_lines=1, removed_lines=0, changed_files=["app.py"])

    monkeypatch.setenv("SECUREVIBES_PR_REVIEW_TIMEOUT_SECONDS", "1")
    monkeypatch.setenv("SECUREVIBES_PR_REVIEW_ATTEMPTS", "1")

    scanner = Scanner(model="sonnet", debug=False)
    scanner.console = Console(file=StringIO())

    with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)

        async def delayed_query(_prompt: str):
            await asyncio.sleep(2)

        mock_instance.query = AsyncMock(side_effect=delayed_query)

        async def async_gen():
            return
            yield  # pragma: no cover

        mock_instance.receive_messages = async_gen

        with pytest.raises(RuntimeError, match="Refusing fail-open PR review result"):
            await scanner.pr_review(
                str(repo),
                diff_context,
                known_vulns_path=None,
                severity_threshold="low",
            )


@pytest.mark.asyncio
async def test_pr_review_uses_direct_tools_without_task(tmp_path: Path):
    """PR review should run with direct Read/Write/Grep tools and not require Task."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    diff_context = DiffContext(files=[], added_lines=1, removed_lines=0, changed_files=["app.py"])

    scanner = Scanner(model="sonnet", debug=False)
    scanner.console = Console(file=StringIO())

    with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
        mock_instance.query = AsyncMock()

        async def async_gen():
            return
            yield  # pragma: no cover

        mock_instance.receive_messages = async_gen

        with pytest.raises(RuntimeError, match="Refusing fail-open PR review result"):
            await scanner.pr_review(
                str(repo),
                diff_context,
                known_vulns_path=None,
                severity_threshold="low",
            )

    # Verify direct tool execution surface for PR review
    options = mock_client.call_args[1]["options"]
    assert "Read" in options.allowed_tools
    assert "Write" in options.allowed_tools
    assert "Grep" in options.allowed_tools
    assert "Task" not in options.allowed_tools


@pytest.mark.asyncio
async def test_generate_pr_hypotheses_uses_no_tools_and_default_permissions(tmp_path: Path):
    """Hypothesis generation helper should run LLM-only with safe default permissions."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
        mock_instance.query = AsyncMock()

        async def async_gen():
            return
            yield  # pragma: no cover

        mock_instance.receive_messages = async_gen

        await _generate_pr_hypotheses(
            repo=repo,
            model="sonnet",
            changed_files=["app.py"],
            diff_line_anchors="- app.py",
            diff_hunk_snippets="--- app.py",
            threat_context_summary="- none",
            vuln_context_summary="- none",
            architecture_context="- none",
        )

    options = mock_client.call_args[1]["options"]
    assert options.allowed_tools == []
    assert options.permission_mode == "default"


@pytest.mark.asyncio
async def test_refine_pr_findings_uses_no_tools_and_default_permissions(tmp_path: Path):
    """PR refinement helper should run LLM-only with safe default permissions."""
    repo = tmp_path / "repo"
    repo.mkdir()

    with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
        mock_instance.query = AsyncMock()

        async def async_gen():
            return
            yield  # pragma: no cover

        mock_instance.receive_messages = async_gen

        await _refine_pr_findings_with_llm(
            repo=repo,
            model="sonnet",
            diff_line_anchors="- app.py",
            diff_hunk_snippets="--- app.py",
            findings=[
                {
                    "title": "Test finding",
                    "description": "test",
                    "severity": "high",
                    "file_path": "app.py",
                    "line_number": 1,
                }
            ],
            severity_threshold="low",
        )

    options = mock_client.call_args[1]["options"]
    assert options.allowed_tools == []
    assert options.permission_mode == "default"


@pytest.mark.asyncio
async def test_pr_review_has_subagent_hook(tmp_path: Path):
    """PR review must wire up SubagentStop hook for subagent lifecycle tracking."""
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    (securevibes_dir / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")

    diff_context = DiffContext(files=[], added_lines=1, removed_lines=0, changed_files=["app.py"])

    scanner = Scanner(model="sonnet", debug=False)
    scanner.console = Console(file=StringIO())

    with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
        mock_instance.query = AsyncMock()

        async def async_gen():
            return
            yield  # pragma: no cover

        mock_instance.receive_messages = async_gen

        with pytest.raises(RuntimeError, match="Refusing fail-open PR review result"):
            await scanner.pr_review(
                str(repo),
                diff_context,
                known_vulns_path=None,
                severity_threshold="low",
            )

    options = mock_client.call_args[1]["options"]
    assert "SubagentStop" in options.hooks, "SubagentStop hook must be configured"
    assert len(options.hooks["SubagentStop"]) > 0, "SubagentStop must have at least one hook"


def test_pr_code_review_prompt_requires_chain_analysis_text():
    """Prompt must explicitly require trust-boundary exploit chain reasoning."""
    prompt_path = (
        Path(__file__).resolve().parents[1]
        / "securevibes"
        / "prompts"
        / "agents"
        / "pr_code_review.txt"
    )
    prompt = prompt_path.read_text(encoding="utf-8")

    assert "existing auth/trust-boundary weaknesses" in prompt
    assert "do not auto-cap local access or localhost-only paths at MEDIUM" in prompt


def test_pr_code_review_prompt_requires_concrete_injection_proof():
    """Prompt should enforce concrete proof for command/option injection claims."""
    prompt_path = (
        Path(__file__).resolve().parents[1]
        / "securevibes"
        / "prompts"
        / "agents"
        / "pr_code_review.txt"
    )
    prompt = prompt_path.read_text(encoding="utf-8")

    assert "MANDATORY PROOF CHECKLIST for CWE-88/CWE-78 findings" in prompt
    assert "Do not report hypothetical bypasses" in prompt
    assert "keep the most concrete exploit-primitive framing" in prompt
    assert "appended as positional argv without `--`" in prompt
    assert "explicit option arguments" in prompt


def test_pr_code_review_prompt_disables_diff_context_file_reads():
    """PR review prompt must align with hooks and disallow DIFF_CONTEXT reads/greps."""
    prompt_path = (
        Path(__file__).resolve().parents[1]
        / "securevibes"
        / "prompts"
        / "agents"
        / "pr_code_review.txt"
    )
    prompt = prompt_path.read_text(encoding="utf-8")

    assert "Do not read or grep DIFF_CONTEXT.json" in prompt


# ---------------------------------------------------------------------------
# _normalize_hypothesis_output tests
# ---------------------------------------------------------------------------


def test_normalize_hypothesis_output_empty_input():
    """Empty or whitespace-only input should return fallback."""
    assert _normalize_hypothesis_output("") == "- None generated."
    assert _normalize_hypothesis_output("   \n  ") == "- None generated."


def test_normalize_hypothesis_output_preserves_dash_bullets():
    """Lines starting with '- ' should be kept as-is."""
    raw = "- First hypothesis\n- Second hypothesis"
    result = _normalize_hypothesis_output(raw)
    assert result == "- First hypothesis\n- Second hypothesis"


def test_normalize_hypothesis_output_converts_asterisk_bullets():
    """Lines starting with '* ' should be converted to dash bullets."""
    raw = "* Asterisk item one\n* Asterisk item two"
    result = _normalize_hypothesis_output(raw)
    assert result == "- Asterisk item one\n- Asterisk item two"


def test_normalize_hypothesis_output_converts_numbered_lists():
    """Numbered list items (1. or 1)) should be converted to dash bullets."""
    raw = "1. First item\n2) Second item"
    result = _normalize_hypothesis_output(raw)
    assert result == "- First item\n- Second item"


def test_normalize_hypothesis_output_converts_multi_digit_numbered_lists():
    """Multi-digit numbered list items should be converted to dash bullets."""
    raw = "10. Tenth item\n11) Eleventh item"
    result = _normalize_hypothesis_output(raw)
    assert result == "- Tenth item\n- Eleventh item"


def test_normalize_hypothesis_output_fallback_for_prose():
    """Non-bullet prose should fall back to first line as a single bullet."""
    raw = "This is just a paragraph of text without bullets."
    result = _normalize_hypothesis_output(raw)
    assert result == "- This is just a paragraph of text without bullets."


def test_normalize_hypothesis_output_truncates_long_fallback():
    """Fallback first line longer than 280 chars should be truncated."""
    long_line = "A" * 300
    result = _normalize_hypothesis_output(long_line)
    assert result.startswith("- " + "A" * 277)
    assert result.endswith("...")


def test_normalize_hypothesis_output_respects_max_items():
    """Only up to max_items bullets should be kept."""
    raw = "\n".join(f"- Item {i}" for i in range(20))
    result = _normalize_hypothesis_output(raw, max_items=3)
    assert result.count("- Item") == 3
    assert "- Item 0" in result
    assert "- Item 2" in result
    assert "- Item 3" not in result


def test_normalize_hypothesis_output_respects_max_chars():
    """Output exceeding max_chars should be truncated with marker."""
    raw = "\n".join(f"- {'X' * 100} hypothesis {i}" for i in range(10))
    result = _normalize_hypothesis_output(raw, max_chars=200)
    assert len(result) <= 200
    assert result.endswith("...[truncated]")


def test_normalize_hypothesis_output_skips_blank_lines():
    """Blank lines in input should be ignored."""
    raw = "- First\n\n\n- Second\n\n- Third"
    result = _normalize_hypothesis_output(raw)
    assert result == "- First\n- Second\n- Third"


def test_normalize_hypothesis_output_mixed_formats():
    """Mixed bullet formats should all be normalized to dash bullets."""
    raw = "- Dash bullet\n* Asterisk bullet\n1. Numbered bullet"
    result = _normalize_hypothesis_output(raw)
    assert result == "- Dash bullet\n- Asterisk bullet\n- Numbered bullet"


# ---------------------------------------------------------------------------
# _score_diff_file_for_security_review tests
# ---------------------------------------------------------------------------


def _make_diff_file(new_path, is_new=False, is_deleted=False, is_renamed=False):
    """Helper to create a minimal DiffFile."""
    return DiffFile(
        old_path=new_path,
        new_path=new_path,
        hunks=[],
        is_new=is_new,
        is_deleted=is_deleted,
        is_renamed=is_renamed,
    )


def test_score_diff_file_code_file_base_score():
    """A regular source code file should get the base code score."""
    diff_file = _make_diff_file("src/app.py")
    score = _score_diff_file_for_security_review(diff_file)
    # 60 (code) + 20 (src/) = 80
    assert score == 80


def test_score_diff_file_non_code_suffix():
    """Non-code files (markdown, images, etc.) should not get the code bonus."""
    diff_file = _make_diff_file("docs/README.md")
    score = _score_diff_file_for_security_review(diff_file)
    # No 60 (non-code suffix .md), -35 (docs/), = -35
    assert score == -35


def test_score_diff_file_security_path_hints():
    """Files with security-related path segments should score higher."""
    diff_file = _make_diff_file("src/auth/token_guard.py")
    score = _score_diff_file_for_security_review(diff_file)
    # 60 (code) + 20 (src/) + 12 (auth) + 12 (token) + 12 (guard) = 116
    assert score == 116


def test_score_diff_file_test_file_penalty():
    """Test files should receive a score penalty."""
    diff_file = _make_diff_file("src/tests/test_auth.py")
    score = _score_diff_file_for_security_review(diff_file)
    # 60 (code) + 20 (src/) - 20 (/tests/) + 12 (auth) = 72
    assert score == 72


def test_score_diff_file_new_file_bonus():
    """New files should receive a small bonus."""
    regular = _make_diff_file("src/handler.py")
    new = _make_diff_file("src/handler.py", is_new=True)
    assert (
        _score_diff_file_for_security_review(new)
        == _score_diff_file_for_security_review(regular) + 8
    )


def test_score_diff_file_renamed_file_bonus():
    """Renamed files should receive a small bonus."""
    regular = _make_diff_file("src/handler.py")
    renamed = _make_diff_file("src/handler.py", is_renamed=True)
    assert (
        _score_diff_file_for_security_review(renamed)
        == _score_diff_file_for_security_review(regular) + 4
    )


def test_score_diff_file_no_path():
    """A file with no path should score 0."""
    diff_file = DiffFile(
        old_path=None,
        new_path=None,
        hunks=[],
        is_new=False,
        is_deleted=False,
        is_renamed=False,
    )
    assert _score_diff_file_for_security_review(diff_file) == 0


def test_score_diff_file_docs_path():
    """Files in docs/ path should receive the docs penalty."""
    diff_file = _make_diff_file("docs/api-guide.rst")
    score = _score_diff_file_for_security_review(diff_file)
    # No 60 (.rst is non-code), -35 (docs/) = -35
    assert score == -35


def test_score_diff_file_lock_file():
    """Lock files are non-code and should not get the code bonus."""
    diff_file = _make_diff_file("package-lock.lock")
    score = _score_diff_file_for_security_review(diff_file)
    # No 60 (.lock is non-code) = 0
    assert score == 0


# ---------------------------------------------------------------------------
# _summarize_diff_line_anchors tests
# ---------------------------------------------------------------------------


def test_summarize_diff_line_anchors_empty_files():
    """Empty diff context should return a no-change message."""
    context = DiffContext(files=[], added_lines=0, removed_lines=0, changed_files=[])
    result = _summarize_diff_line_anchors(context)
    assert result == "- No changed files."


def test_summarize_diff_line_anchors_basic():
    """Added and removed lines should appear in the summary."""
    diff_file = DiffFile(
        old_path="src/auth.py",
        new_path="src/auth.py",
        hunks=[
            DiffHunk(
                old_start=1,
                old_count=3,
                new_start=1,
                new_count=4,
                lines=[
                    DiffLine(type="add", content="import os", old_line_num=None, new_line_num=2),
                    DiffLine(
                        type="remove", content="import sys", old_line_num=1, new_line_num=None
                    ),
                    DiffLine(type="context", content="# header", old_line_num=2, new_line_num=3),
                ],
            )
        ],
        is_new=False,
        is_deleted=False,
        is_renamed=False,
    )
    context = DiffContext(
        files=[diff_file],
        added_lines=1,
        removed_lines=1,
        changed_files=["src/auth.py"],
    )
    result = _summarize_diff_line_anchors(context)
    assert "- src/auth.py" in result
    assert "+ L2: import os" in result
    assert "removed lines: 1" in result


def test_summarize_diff_line_anchors_truncates_long_snippets():
    """Line content longer than 180 chars should be truncated."""
    long_content = "x" * 200
    diff_file = DiffFile(
        old_path="src/big.py",
        new_path="src/big.py",
        hunks=[
            DiffHunk(
                old_start=1,
                old_count=0,
                new_start=1,
                new_count=1,
                lines=[
                    DiffLine(type="add", content=long_content, old_line_num=None, new_line_num=1),
                ],
            )
        ],
        is_new=False,
        is_deleted=False,
        is_renamed=False,
    )
    context = DiffContext(
        files=[diff_file],
        added_lines=1,
        removed_lines=0,
        changed_files=["src/big.py"],
    )
    result = _summarize_diff_line_anchors(context)
    # The truncated snippet should end with ...
    assert "..." in result
    # Should not contain the full 200-char content
    assert long_content not in result


def test_summarize_diff_line_anchors_respects_max_lines_per_file():
    """Only max_lines_per_file added lines should be shown per file."""
    lines = [
        DiffLine(type="add", content=f"line {i}", old_line_num=None, new_line_num=i)
        for i in range(1, 11)
    ]
    diff_file = DiffFile(
        old_path="src/many.py",
        new_path="src/many.py",
        hunks=[DiffHunk(old_start=0, old_count=0, new_start=1, new_count=10, lines=lines)],
        is_new=False,
        is_deleted=False,
        is_renamed=False,
    )
    context = DiffContext(
        files=[diff_file],
        added_lines=10,
        removed_lines=0,
        changed_files=["src/many.py"],
    )
    result = _summarize_diff_line_anchors(context, max_lines_per_file=3)
    assert "L1:" in result
    assert "L3:" in result
    assert "7 more added lines" in result


def test_summarize_diff_line_anchors_respects_max_chars():
    """Output exceeding max_chars should be truncated."""
    lines = [
        DiffLine(type="add", content=f"content_{i}" * 10, old_line_num=None, new_line_num=i)
        for i in range(1, 20)
    ]
    diff_file = DiffFile(
        old_path="src/large.py",
        new_path="src/large.py",
        hunks=[DiffHunk(old_start=0, old_count=0, new_start=1, new_count=19, lines=lines)],
        is_new=False,
        is_deleted=False,
        is_renamed=False,
    )
    context = DiffContext(
        files=[diff_file],
        added_lines=19,
        removed_lines=0,
        changed_files=["src/large.py"],
    )
    result = _summarize_diff_line_anchors(context, max_chars=200)
    assert len(result) <= 200
    assert result.endswith("...[truncated]")


def test_summarize_diff_line_anchors_respects_max_files():
    """Only max_files files should be included in the summary."""
    files = []
    for i in range(5):
        files.append(
            DiffFile(
                old_path=f"src/file_{i}.py",
                new_path=f"src/file_{i}.py",
                hunks=[
                    DiffHunk(
                        old_start=0,
                        old_count=0,
                        new_start=1,
                        new_count=1,
                        lines=[
                            DiffLine(
                                type="add",
                                content=f"added in file {i}",
                                old_line_num=None,
                                new_line_num=1,
                            ),
                        ],
                    )
                ],
                is_new=False,
                is_deleted=False,
                is_renamed=False,
            )
        )
    context = DiffContext(
        files=files,
        added_lines=5,
        removed_lines=0,
        changed_files=[f"src/file_{i}.py" for i in range(5)],
    )
    result = _summarize_diff_line_anchors(context, max_files=2)
    assert "file_0" in result
    assert "file_1" in result
    assert "file_2" not in result


# ---------------------------------------------------------------------------
# _summarize_diff_hunk_snippets additional tests
# ---------------------------------------------------------------------------


def test_summarize_diff_hunk_snippets_empty_context():
    """Empty diff context should return a no-change message."""
    context = DiffContext(files=[], added_lines=0, removed_lines=0, changed_files=[])
    result = _summarize_diff_hunk_snippets(context)
    assert result == "- No changed hunks."


def test_summarize_diff_hunk_snippets_metadata_flags():
    """Deleted and renamed files should show metadata in the summary."""
    diff_file = DiffFile(
        old_path="src/old.py",
        new_path="src/new.py",
        hunks=[
            DiffHunk(
                old_start=1,
                old_count=1,
                new_start=1,
                new_count=1,
                lines=[DiffLine(type="context", content="pass", old_line_num=1, new_line_num=1)],
            )
        ],
        is_new=False,
        is_deleted=False,
        is_renamed=True,
    )
    context = DiffContext(
        files=[diff_file],
        added_lines=0,
        removed_lines=0,
        changed_files=["src/new.py"],
    )
    result = _summarize_diff_hunk_snippets(context)
    assert "(renamed)" in result


def test_summarize_diff_hunk_snippets_truncates_long_lines():
    """Lines longer than 220 chars should be truncated."""
    long_content = "Z" * 250
    diff_file = DiffFile(
        old_path="src/long.py",
        new_path="src/long.py",
        hunks=[
            DiffHunk(
                old_start=1,
                old_count=0,
                new_start=1,
                new_count=1,
                lines=[
                    DiffLine(type="add", content=long_content, old_line_num=None, new_line_num=1)
                ],
            )
        ],
        is_new=False,
        is_deleted=False,
        is_renamed=False,
    )
    context = DiffContext(
        files=[diff_file],
        added_lines=1,
        removed_lines=0,
        changed_files=["src/long.py"],
    )
    result = _summarize_diff_hunk_snippets(context)
    assert "..." in result
    assert long_content not in result


def test_summarize_diff_hunk_snippets_truncates_hunks():
    """Files with more hunks than max_hunks_per_file should show truncation message."""
    hunks = [
        DiffHunk(
            old_start=i * 10,
            old_count=1,
            new_start=i * 10,
            new_count=1,
            lines=[
                DiffLine(type="add", content=f"line {i}", old_line_num=None, new_line_num=i * 10)
            ],
        )
        for i in range(6)
    ]
    diff_file = DiffFile(
        old_path="src/many_hunks.py",
        new_path="src/many_hunks.py",
        hunks=hunks,
        is_new=False,
        is_deleted=False,
        is_renamed=False,
    )
    context = DiffContext(
        files=[diff_file],
        added_lines=6,
        removed_lines=0,
        changed_files=["src/many_hunks.py"],
    )
    result = _summarize_diff_hunk_snippets(context, max_hunks_per_file=2)
    assert "truncated 4 hunks" in result


# ---------------------------------------------------------------------------
# Tests for _generate_pr_hypotheses (P3.7)
# ---------------------------------------------------------------------------


class TestGeneratePrHypotheses:
    """Tests for _generate_pr_hypotheses with mocked ClaudeSDKClient."""

    _DEFAULT_KWARGS = dict(
        repo=Path("/tmp/repo"),
        model="sonnet",
        changed_files=["src/auth.py"],
        diff_line_anchors="src/auth.py:42",
        diff_hunk_snippets="+ if user.is_admin:",
        threat_context_summary="- Auth bypass",
        vuln_context_summary="- None",
        architecture_context="Flask app",
    )

    @pytest.mark.asyncio
    async def test_timeout_returns_fallback(self):
        """When the LLM exchange times out, the function should return the fallback string."""
        mock_client = AsyncMock()
        mock_client.query = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("securevibes.scanner.scanner.ClaudeSDKClient", return_value=mock_client):
            result = await _generate_pr_hypotheses(**self._DEFAULT_KWARGS)

        assert result == "- Unable to generate hypotheses."

    @pytest.mark.asyncio
    async def test_os_error_returns_fallback(self):
        """OSError during LLM call should gracefully fall back."""
        mock_client = AsyncMock()
        mock_client.query = AsyncMock(side_effect=OSError("connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("securevibes.scanner.scanner.ClaudeSDKClient", return_value=mock_client):
            result = await _generate_pr_hypotheses(**self._DEFAULT_KWARGS)

        assert result == "- Unable to generate hypotheses."

    @pytest.mark.asyncio
    async def test_runtime_error_returns_fallback(self):
        """RuntimeError during LLM call should gracefully fall back."""
        mock_client = AsyncMock()
        mock_client.query = AsyncMock(side_effect=RuntimeError("SDK error"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("securevibes.scanner.scanner.ClaudeSDKClient", return_value=mock_client):
            result = await _generate_pr_hypotheses(**self._DEFAULT_KWARGS)

        assert result == "- Unable to generate hypotheses."

    @pytest.mark.asyncio
    async def test_successful_generation(self):
        """Successful LLM response should be normalized via _normalize_hypothesis_output."""
        from claude_agent_sdk.types import AssistantMessage, TextBlock, ResultMessage

        text_block = TextBlock(text="- Auth bypass via token reuse\n- SSRF in proxy")
        assistant_msg = AssistantMessage(content=[text_block], model="sonnet")
        result_msg = ResultMessage(
            subtype="success",
            total_cost_usd=0.01,
            duration_ms=1000,
            duration_api_ms=800,
            is_error=False,
            num_turns=1,
            session_id="test-session",
        )

        mock_client = AsyncMock()
        mock_client.query = AsyncMock(return_value=None)

        async def mock_receive():
            yield assistant_msg
            yield result_msg

        mock_client.receive_messages = mock_receive
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("securevibes.scanner.scanner.ClaudeSDKClient", return_value=mock_client):
            result = await _generate_pr_hypotheses(**self._DEFAULT_KWARGS)

        assert "Auth bypass via token reuse" in result
        assert "SSRF in proxy" in result

    @pytest.mark.asyncio
    async def test_empty_response_normalizes(self):
        """Empty LLM response should be normalized (empty string from normalizer)."""
        from claude_agent_sdk.types import ResultMessage

        result_msg = ResultMessage(
            subtype="success",
            duration_ms=100,
            duration_api_ms=80,
            is_error=False,
            num_turns=1,
            session_id="test-session",
        )

        mock_client = AsyncMock()
        mock_client.query = AsyncMock(return_value=None)

        async def mock_receive():
            yield result_msg

        mock_client.receive_messages = mock_receive
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("securevibes.scanner.scanner.ClaudeSDKClient", return_value=mock_client):
            result = await _generate_pr_hypotheses(**self._DEFAULT_KWARGS)

        # Empty input -> _normalize_hypothesis_output returns "- None generated."
        assert result == "- None generated."


# ---------------------------------------------------------------------------
# Tests for _refine_pr_findings_with_llm (P3.7)
# ---------------------------------------------------------------------------


class TestRefinePrFindingsWithLlm:
    """Tests for _refine_pr_findings_with_llm with mocked ClaudeSDKClient."""

    _DEFAULT_KWARGS = dict(
        repo=Path("/tmp/repo"),
        model="sonnet",
        diff_line_anchors="src/auth.py:42",
        diff_hunk_snippets="+ if user.is_admin:",
        severity_threshold="medium",
    )

    @pytest.mark.asyncio
    async def test_empty_findings_returns_none(self):
        """Passing an empty findings list should immediately return None."""
        result = await _refine_pr_findings_with_llm(findings=[], **self._DEFAULT_KWARGS)
        assert result is None

    @pytest.mark.asyncio
    async def test_timeout_returns_none(self):
        """When the LLM exchange times out, the function should return None."""
        mock_client = AsyncMock()
        mock_client.query = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("securevibes.scanner.scanner.ClaudeSDKClient", return_value=mock_client):
            result = await _refine_pr_findings_with_llm(
                findings=[{"title": "test"}], **self._DEFAULT_KWARGS
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_os_error_returns_none(self):
        """OSError during LLM call should return None."""
        mock_client = AsyncMock()
        mock_client.query = AsyncMock(side_effect=OSError("fail"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("securevibes.scanner.scanner.ClaudeSDKClient", return_value=mock_client):
            result = await _refine_pr_findings_with_llm(
                findings=[{"title": "test"}], **self._DEFAULT_KWARGS
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_empty_llm_output_returns_none(self):
        """When the LLM produces no text, the function should return None."""
        from claude_agent_sdk.types import ResultMessage

        result_msg = ResultMessage(
            subtype="success",
            duration_ms=100,
            duration_api_ms=80,
            is_error=False,
            num_turns=1,
            session_id="test-session",
        )

        mock_client = AsyncMock()
        mock_client.query = AsyncMock(return_value=None)

        async def mock_receive():
            yield result_msg

        mock_client.receive_messages = mock_receive
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("securevibes.scanner.scanner.ClaudeSDKClient", return_value=mock_client):
            result = await _refine_pr_findings_with_llm(
                findings=[{"title": "test"}], **self._DEFAULT_KWARGS
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_invalid_json_returns_none(self):
        """When the LLM returns non-JSON text, the function should return None."""
        from claude_agent_sdk.types import AssistantMessage, TextBlock, ResultMessage

        text_block = TextBlock(text="This is not valid JSON at all")
        assistant_msg = AssistantMessage(content=[text_block], model="sonnet")
        result_msg = ResultMessage(
            subtype="success",
            total_cost_usd=0.01,
            duration_ms=1000,
            duration_api_ms=800,
            is_error=False,
            num_turns=1,
            session_id="test-session",
        )

        mock_client = AsyncMock()
        mock_client.query = AsyncMock(return_value=None)

        async def mock_receive():
            yield assistant_msg
            yield result_msg

        mock_client.receive_messages = mock_receive
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("securevibes.scanner.scanner.ClaudeSDKClient", return_value=mock_client):
            result = await _refine_pr_findings_with_llm(
                findings=[{"title": "test"}], **self._DEFAULT_KWARGS
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_non_list_json_returns_none(self):
        """When the LLM returns a JSON object (not array), the function should return None."""
        from claude_agent_sdk.types import AssistantMessage, TextBlock, ResultMessage

        text_block = TextBlock(text='{"not": "a list"}')
        assistant_msg = AssistantMessage(content=[text_block], model="sonnet")
        result_msg = ResultMessage(
            subtype="success",
            total_cost_usd=0.01,
            duration_ms=1000,
            duration_api_ms=800,
            is_error=False,
            num_turns=1,
            session_id="test-session",
        )

        mock_client = AsyncMock()
        mock_client.query = AsyncMock(return_value=None)

        async def mock_receive():
            yield assistant_msg
            yield result_msg

        mock_client.receive_messages = mock_receive
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("securevibes.scanner.scanner.ClaudeSDKClient", return_value=mock_client):
            result = await _refine_pr_findings_with_llm(
                findings=[{"title": "test"}], **self._DEFAULT_KWARGS
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_successful_refinement(self):
        """Successful LLM response with valid JSON array should return parsed findings."""
        from claude_agent_sdk.types import AssistantMessage, TextBlock, ResultMessage

        findings_json = json.dumps(
            [
                {"title": "Auth bypass", "severity": "high"},
                {"title": "SSRF", "severity": "medium"},
            ]
        )
        text_block = TextBlock(text=findings_json)
        assistant_msg = AssistantMessage(content=[text_block], model="sonnet")
        result_msg = ResultMessage(
            subtype="success",
            total_cost_usd=0.01,
            duration_ms=1000,
            duration_api_ms=800,
            is_error=False,
            num_turns=1,
            session_id="test-session",
        )

        mock_client = AsyncMock()
        mock_client.query = AsyncMock(return_value=None)

        async def mock_receive():
            yield assistant_msg
            yield result_msg

        mock_client.receive_messages = mock_receive
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("securevibes.scanner.scanner.ClaudeSDKClient", return_value=mock_client):
            result = await _refine_pr_findings_with_llm(
                findings=[{"title": "test"}], **self._DEFAULT_KWARGS
            )

        assert result is not None
        assert len(result) == 2
        assert result[0]["title"] == "Auth bypass"
        assert result[1]["title"] == "SSRF"

    @pytest.mark.asyncio
    async def test_filters_non_dict_entries(self):
        """Non-dict entries in the JSON array should be filtered out."""
        from claude_agent_sdk.types import AssistantMessage, TextBlock, ResultMessage

        mixed_json = json.dumps([{"title": "valid"}, "invalid_string", 42, None])
        text_block = TextBlock(text=mixed_json)
        assistant_msg = AssistantMessage(content=[text_block], model="sonnet")
        result_msg = ResultMessage(
            subtype="success",
            total_cost_usd=0.01,
            duration_ms=1000,
            duration_api_ms=800,
            is_error=False,
            num_turns=1,
            session_id="test-session",
        )

        mock_client = AsyncMock()
        mock_client.query = AsyncMock(return_value=None)

        async def mock_receive():
            yield assistant_msg
            yield result_msg

        mock_client.receive_messages = mock_receive
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("securevibes.scanner.scanner.ClaudeSDKClient", return_value=mock_client):
            result = await _refine_pr_findings_with_llm(
                findings=[{"title": "test"}], **self._DEFAULT_KWARGS
            )

        assert result is not None
        assert len(result) == 1
        assert result[0]["title"] == "valid"
