"""PR review attempt-loop state and orchestration helpers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Type

from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
from claude_agent_sdk.types import AssistantMessage, HookMatcher, ResultMessage, TextBlock

from securevibes.agents.definitions import create_agent_definitions
from securevibes.config import config
from securevibes.diff.parser import DiffContext
from securevibes.scanner.chain_analysis import (
    attempt_contains_core_chain_evidence,
    collect_chain_exact_ids,
    collect_chain_family_ids,
    collect_chain_flow_ids,
    summarize_chain_candidates_for_prompt,
)
from securevibes.scanner.hooks import (
    create_json_validation_hook,
    create_post_tool_hook,
    create_pre_tool_hook,
    create_subagent_hook,
)
from securevibes.scanner.pr_review_merge import (
    _build_pr_review_retry_suffix,
    _extract_observed_pr_findings,
    _focus_area_label,
    _load_pr_vulnerabilities_artifact,
    _merge_pr_attempt_findings,
)


@dataclass
class PRAttemptState:
    """Mutable state container for PR review attempt loop."""

    carry_forward_candidate_summary: str = ""
    carry_forward_candidate_family_ids: set[str] = field(default_factory=set)
    carry_forward_candidate_flow_ids: set[str] = field(default_factory=set)


@dataclass
class PRReviewContext:
    """Prepared context for PR review attempt loop."""

    repo: Path
    securevibes_dir: Path
    focused_diff_context: DiffContext
    diff_context: DiffContext
    contextualized_prompt: str
    baseline_vulns: list[dict]
    pr_review_attempts: int
    pr_timeout_seconds: int
    pr_vulns_path: Path
    detected_languages: set[str]
    command_builder_signals: bool
    path_parser_signals: bool
    auth_privilege_signals: bool
    retry_focus_plan: list[str]
    diff_line_anchors: str
    diff_hunk_snippets: str
    pr_grep_default_scope: str
    scan_start_time: float
    severity_threshold: str


@dataclass
class PRReviewState:
    """Mutable state container for the full PR review lifecycle."""

    warnings: list[str] = field(default_factory=list)
    pr_vulns: list[dict] = field(default_factory=list)
    collected_pr_vulns: list[dict] = field(default_factory=list)
    ephemeral_pr_vulns: list[dict] = field(default_factory=list)
    artifact_loaded: bool = False
    attempts_run: int = 0
    attempts_with_overwritten_artifact: int = 0
    attempt_finding_counts: list[int] = field(default_factory=list)
    attempt_observed_counts: list[int] = field(default_factory=list)
    attempt_focus_areas: list[str] = field(default_factory=list)
    attempt_chain_ids: list[set[str]] = field(default_factory=list)
    attempt_chain_exact_ids: list[set[str]] = field(default_factory=list)
    attempt_chain_family_ids: list[set[str]] = field(default_factory=list)
    attempt_chain_flow_ids: list[set[str]] = field(default_factory=list)
    attempt_revalidation_attempted: list[bool] = field(default_factory=list)
    attempt_core_evidence_present: list[bool] = field(default_factory=list)
    chain_support_counts: dict[str, int] = field(default_factory=dict)
    flow_support_counts: dict[str, int] = field(default_factory=dict)
    attempt_state: PRAttemptState = field(default_factory=PRAttemptState)
    required_core_chain_pass_support: int = 2
    weak_consensus_reason: str = ""
    weak_consensus_triggered: bool = False
    consensus_mode_used: str = "family"
    support_counts_snapshot: dict[str, int] = field(
        default_factory=lambda: {"exact": 0, "family": 0, "flow": 0}
    )
    pr_tool_guard_observer: dict[str, Any] = field(
        default_factory=lambda: {"blocked_out_of_repo_count": 0, "blocked_paths": []}
    )
    merge_stats: dict[str, int] = field(default_factory=dict)
    raw_pr_finding_count: int = 0
    should_run_verifier: bool = False
    passes_with_core_chain: int = 0
    attempt_outcome_counts_snapshot: list[int] = field(default_factory=list)
    attempt_disagreement: bool = False
    blocked_out_of_repo_tool_calls: int = 0
    revalidation_attempts: int = 0
    revalidation_core_hits: int = 0
    revalidation_core_misses: int = 0


class PRReviewAttemptRunner:
    """Runs the multi-pass PR attempt loop while updating shared review state."""

    def __init__(
        self,
        scanner: Any,
        progress_tracker_cls: Type[Any],
        *,
        claude_client_cls: Type[Any] = ClaudeSDKClient,
        hook_matcher_cls: Type[Any] = HookMatcher,
    ) -> None:
        self._scanner = scanner
        self._progress_tracker_cls = progress_tracker_cls
        self._claude_client_cls = claude_client_cls
        self._hook_matcher_cls = hook_matcher_cls

    @property
    def console(self) -> Any:
        return self._scanner.console

    @property
    def debug(self) -> bool:
        return self._scanner.debug

    @property
    def model(self) -> str:
        return self._scanner.model

    def _record_attempt_chains(
        self,
        state: PRReviewState,
        attempt_findings: list,
    ) -> None:
        """Record chain IDs from an attempt's findings into state."""
        canonical_attempt = _merge_pr_attempt_findings(attempt_findings)
        exact_ids = collect_chain_exact_ids(canonical_attempt)
        family_ids = collect_chain_family_ids(canonical_attempt)
        flow_ids = collect_chain_flow_ids(canonical_attempt)
        state.attempt_chain_exact_ids.append(exact_ids)
        state.attempt_chain_family_ids.append(family_ids)
        state.attempt_chain_flow_ids.append(flow_ids)
        # Backward-compatible alias used by existing code paths.
        state.attempt_chain_ids.append(family_ids)
        for chain_id in family_ids:
            state.chain_support_counts[chain_id] = state.chain_support_counts.get(chain_id, 0) + 1
        for chain_id in flow_ids:
            state.flow_support_counts[chain_id] = state.flow_support_counts.get(chain_id, 0) + 1

    def _refresh_carry_forward_candidates(
        self,
        state: PRReviewState,
    ) -> None:
        """Refresh carry-forward candidate summary from cumulative findings."""
        cumulative_candidates = _merge_pr_attempt_findings(
            [*state.collected_pr_vulns, *state.ephemeral_pr_vulns],
            chain_support_counts=state.chain_support_counts,
            total_attempts=len(state.attempt_chain_ids),
        )
        state.attempt_state.carry_forward_candidate_family_ids = collect_chain_family_ids(
            cumulative_candidates
        )
        state.attempt_state.carry_forward_candidate_flow_ids = collect_chain_flow_ids(
            cumulative_candidates
        )
        state.attempt_state.carry_forward_candidate_summary = summarize_chain_candidates_for_prompt(
            cumulative_candidates,
            state.chain_support_counts,
            len(state.attempt_chain_ids),
            flow_support_counts=state.flow_support_counts,
        )

    def _record_attempt_revalidation_observability(
        self,
        state: PRReviewState,
        *,
        attempt_findings: list,
        revalidation_attempted: bool,
        expected_family_ids: set,
        expected_flow_ids: set,
    ) -> bool:
        """Record revalidation observability data and return whether core evidence was present."""
        core_evidence_present = attempt_contains_core_chain_evidence(
            attempt_findings=attempt_findings,
            expected_family_ids=expected_family_ids,
            expected_flow_ids=expected_flow_ids,
        )
        state.attempt_revalidation_attempted.append(revalidation_attempted)
        state.attempt_core_evidence_present.append(core_evidence_present)
        if self.debug and revalidation_attempted and not core_evidence_present:
            self.console.print(
                "  🧪 Revalidation pass did not reproduce carried core-chain evidence",
                style="dim",
            )
        return core_evidence_present

    def _process_attempt_outcome(
        self,
        ctx: PRReviewContext,
        state: PRReviewState,
        *,
        attempt_num: int,
        attempt_write_observer: Dict[str, Any],
        attempt_force_revalidation: bool,
        attempt_expected_family_ids: set,
        attempt_expected_flow_ids: set,
        loaded_vulns: list,
        load_warning: Optional[str],
    ) -> None:
        """Process the outcome of a single PR review attempt."""
        observed_vulns = _extract_observed_pr_findings(attempt_write_observer)
        attempt_finding_count = len(loaded_vulns) if not load_warning else 0
        observed_count = max(attempt_finding_count, len(observed_vulns))
        state.attempt_finding_counts.append(attempt_finding_count)
        state.attempt_observed_counts.append(observed_count)
        if not load_warning:
            state.artifact_loaded = True
            if loaded_vulns:
                state.collected_pr_vulns.extend(loaded_vulns)
        if observed_vulns and len(observed_vulns) > attempt_finding_count:
            state.attempts_with_overwritten_artifact += 1
            state.ephemeral_pr_vulns.extend(observed_vulns)
            if self.debug:
                self.console.print(
                    f"  🔎 PR pass {attempt_num}/{ctx.pr_review_attempts}: "
                    f"captured {len(observed_vulns)} intermediate finding(s) from write logs "
                    f"while final artifact had {attempt_finding_count}.",
                    style="dim",
                )
        effective_attempt_vulns = (
            observed_vulns if len(observed_vulns) > attempt_finding_count else loaded_vulns
        )
        self._record_attempt_chains(state, effective_attempt_vulns)
        core_evidence_present = self._record_attempt_revalidation_observability(
            state,
            attempt_findings=effective_attempt_vulns,
            revalidation_attempted=attempt_force_revalidation,
            expected_family_ids=attempt_expected_family_ids,
            expected_flow_ids=attempt_expected_flow_ids,
        )
        if effective_attempt_vulns:
            self._refresh_carry_forward_candidates(state)
        if attempt_force_revalidation and not core_evidence_present:
            state.weak_consensus_triggered = True
            if not state.weak_consensus_reason:
                state.weak_consensus_reason = "revalidation_core_miss"

    async def _run_attempt_messages(
        self,
        *,
        client: Any,
        attempt_prompt: str,
        tracker: Any,
    ) -> None:
        """Run a single attempt's query + message stream consumption."""
        await client.query(attempt_prompt)
        async for message in client.receive_messages():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        tracker.on_assistant_text(block.text)
            elif isinstance(message, ResultMessage):
                if message.total_cost_usd:
                    self._scanner.total_cost = message.total_cost_usd
                break

    async def run_attempt_loop(
        self,
        ctx: PRReviewContext,
        state: PRReviewState,
    ) -> None:
        """Run the multi-pass PR scanning attempt loop."""
        pr_review_attempts = ctx.pr_review_attempts

        for attempt_idx in range(pr_review_attempts):
            attempt_num = attempt_idx + 1
            state.attempts_run = attempt_num
            retry_suffix = ""
            retry_focus_area = ""
            attempt_write_observer: Dict[str, Any] = {}
            attempt_expected_family_ids: set = set(
                state.attempt_state.carry_forward_candidate_family_ids
            )
            attempt_expected_flow_ids: set = set(
                state.attempt_state.carry_forward_candidate_flow_ids
            )
            attempt_candidate_cores_present = bool(
                attempt_expected_family_ids or attempt_expected_flow_ids
            )
            attempt_force_revalidation = False
            # Clear stale artifacts before every attempt so this pass only consumes fresh output.
            try:
                ctx.pr_vulns_path.unlink()
            except OSError:
                pass

            if attempt_num > 1:
                plan_index = attempt_num - 2
                if plan_index < len(ctx.retry_focus_plan):
                    retry_focus_area = ctx.retry_focus_plan[plan_index]
                    state.attempt_focus_areas.append(retry_focus_area)
                attempt_force_revalidation = attempt_candidate_cores_present
                retry_suffix = _build_pr_review_retry_suffix(
                    attempt_num,
                    command_builder_signals=ctx.command_builder_signals,
                    focus_area=retry_focus_area,
                    path_parser_signals=ctx.path_parser_signals,
                    auth_privilege_signals=ctx.auth_privilege_signals,
                    candidate_summary=state.attempt_state.carry_forward_candidate_summary,
                    require_candidate_revalidation=attempt_candidate_cores_present,
                )
                if self.debug and retry_focus_area:
                    self.console.print(
                        f"  🎯 PR pass {attempt_num}/{pr_review_attempts} focus: "
                        f"{_focus_area_label(retry_focus_area)}",
                        style="dim",
                    )
                if self.debug and attempt_candidate_cores_present:
                    self.console.print(
                        "  🧪 PR pass requires explicit carried-chain revalidation",
                        style="dim",
                    )

            agents = create_agent_definitions(cli_model=self.model)
            attempt_prompt = f"{ctx.contextualized_prompt}{retry_suffix}"
            agents["pr-code-review"].prompt = attempt_prompt

            tracker = self._progress_tracker_cls(
                self.console, debug=self.debug, single_subagent="pr-code-review"
            )
            tracker.current_phase = "pr-code-review"
            pre_tool_hook = create_pre_tool_hook(
                tracker,
                self.console,
                self.debug,
                ctx.detected_languages,
                pr_grep_default_path=ctx.pr_grep_default_scope,
                pr_repo_root=ctx.repo,
                pr_tool_guard_observer=state.pr_tool_guard_observer,
            )
            post_tool_hook = create_post_tool_hook(tracker, self.console, self.debug)
            subagent_hook = create_subagent_hook(tracker)
            json_validation_hook = create_json_validation_hook(
                self.console, self.debug, write_observer=attempt_write_observer
            )

            options = ClaudeAgentOptions(
                agents=agents,
                cwd=str(ctx.repo),
                setting_sources=["project"],
                allowed_tools=["Read", "Write", "Grep", "Glob", "LS"],
                max_turns=config.get_max_turns(),
                permission_mode="default",
                model=self.model,
                hooks={
                    "PreToolUse": [
                        self._hook_matcher_cls(hooks=[json_validation_hook]),
                        self._hook_matcher_cls(hooks=[pre_tool_hook]),
                    ],
                    "PostToolUse": [self._hook_matcher_cls(hooks=[post_tool_hook])],
                    "SubagentStop": [self._hook_matcher_cls(hooks=[subagent_hook])],
                },
            )

            attempt_error: Optional[str] = None
            try:
                async with self._claude_client_cls(options=options) as client:
                    await asyncio.wait_for(
                        self._run_attempt_messages(
                            client=client,
                            attempt_prompt=attempt_prompt,
                            tracker=tracker,
                        ),
                        timeout=ctx.pr_timeout_seconds,
                    )
            except asyncio.TimeoutError:
                attempt_error = (
                    f"PR code review attempt {attempt_num}/{pr_review_attempts} timed out after "
                    f"{ctx.pr_timeout_seconds}s."
                )
            except Exception as exc:
                attempt_error = (
                    f"PR code review attempt {attempt_num}/{pr_review_attempts} failed: "
                    f"{type(exc).__name__}: {exc}"
                )

            if attempt_error:
                state.warnings.append(attempt_error)
                self.console.print(f"\n[bold yellow]WARNING:[/bold yellow] {attempt_error}\n")

            loaded_vulns, load_warning = _load_pr_vulnerabilities_artifact(
                pr_vulns_path=ctx.pr_vulns_path,
                console=self.console,
            )
            if load_warning and not attempt_error:
                state.warnings.append(
                    f"PR code review attempt {attempt_num}/{pr_review_attempts}: {load_warning}"
                )
                observed_vulns = _extract_observed_pr_findings(attempt_write_observer)
                if observed_vulns and self.debug:
                    self.console.print(
                        f"  🔎 PR pass {attempt_num}/{pr_review_attempts}: "
                        f"artifact read failed, but write logs captured "
                        f"{len(observed_vulns)} finding(s).",
                        style="dim",
                    )

            self._process_attempt_outcome(
                ctx,
                state,
                attempt_num=attempt_num,
                attempt_write_observer=attempt_write_observer,
                attempt_force_revalidation=attempt_force_revalidation,
                attempt_expected_family_ids=attempt_expected_family_ids,
                attempt_expected_flow_ids=attempt_expected_flow_ids,
                loaded_vulns=loaded_vulns,
                load_warning=load_warning,
            )

            if attempt_error or load_warning:
                continue

            attempt_finding_count = len(loaded_vulns)
            if attempt_finding_count:
                if self.debug:
                    self.console.print(
                        f"  PR pass {attempt_num}/{pr_review_attempts}: "
                        f"{attempt_finding_count} finding(s), "
                        f"cumulative {len(state.collected_pr_vulns)}",
                        style="dim",
                    )
                if attempt_num < pr_review_attempts and self.debug:
                    self.console.print(
                        "  🔁 Running additional focused PR pass for broader chain coverage",
                        style="dim",
                    )
                continue

            if attempt_num < pr_review_attempts:
                cumulative_findings = len(state.collected_pr_vulns) + len(state.ephemeral_pr_vulns)
                if cumulative_findings > 0:
                    if self.debug:
                        last_observed = (
                            state.attempt_observed_counts[-1]
                            if state.attempt_observed_counts
                            else 0
                        )
                        no_new_note = (
                            "no new findings in final artifact; "
                            "intermediate write findings are being preserved for verification."
                            if last_observed > attempt_finding_count
                            else "no new findings."
                        )
                        self.console.print(
                            f"  PR pass {attempt_num}/{pr_review_attempts}: {no_new_note} "
                            f"cumulative remains {cumulative_findings}. "
                            "Continuing with chain-focused prompt.",
                            style="dim",
                        )
                else:
                    retry_warning = (
                        f"PR code review attempt {attempt_num}/{pr_review_attempts} returned no findings "
                        "yet; retrying with chain-focused prompt."
                    )
                    state.warnings.append(retry_warning)
                    self.console.print(f"\n[bold yellow]WARNING:[/bold yellow] {retry_warning}\n")
