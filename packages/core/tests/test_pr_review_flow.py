"""Unit tests for pr_review_flow dataclasses and PRReviewAttemptRunner methods."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from claude_agent_sdk.types import AssistantMessage, ResultMessage, TextBlock

from securevibes.scanner.pr_review_flow import (
    PRAttemptState,
    PRReviewAttemptRunner,
    PRReviewContext,
    PRReviewState,
)


def _make_finding(
    *,
    title: str = "SQL Injection in handler",
    file_path: str = "src/api/handler.py",
    line_number: int = 42,
    cwe_id: str = "CWE-89",
    severity: str = "high",
    finding_type: str = "new_threat",
    description: str = "User input flows to query",
    attack_scenario: str = "1) attacker sends payload 2) query executed",
    evidence: str = "handler.py:42 -> db.query(user_input)",
) -> dict:
    return {
        "title": title,
        "file_path": file_path,
        "line_number": line_number,
        "cwe_id": cwe_id,
        "severity": severity,
        "finding_type": finding_type,
        "description": description,
        "attack_scenario": attack_scenario,
        "evidence": evidence,
    }


def _make_scanner(*, debug: bool = False, model: str = "test-model") -> MagicMock:
    scanner = MagicMock()
    scanner.debug = debug
    scanner.model = model
    scanner.console = MagicMock()
    return scanner


def _make_runner(*, debug: bool = False) -> PRReviewAttemptRunner:
    scanner = _make_scanner(debug=debug)
    return PRReviewAttemptRunner(
        scanner,
        progress_tracker_cls=MagicMock,
        claude_client_cls=MagicMock,
        hook_matcher_cls=MagicMock,
    )


def _make_context(tmp_path: Path) -> PRReviewContext:
    """Build a minimal PRReviewContext for testing."""
    diff_ctx = SimpleNamespace(files=[])
    return PRReviewContext(
        repo=tmp_path,
        securevibes_dir=tmp_path / ".securevibes",
        focused_diff_context=diff_ctx,
        diff_context=diff_ctx,
        contextualized_prompt="Review this PR",
        baseline_vulns=[],
        pr_review_attempts=3,
        pr_timeout_seconds=60,
        pr_vulns_path=tmp_path / "PR_VULNERABILITIES.json",
        detected_languages={"python"},
        command_builder_signals=False,
        path_parser_signals=False,
        auth_privilege_signals=False,
        retry_focus_plan=["command_option", "path_exfiltration"],
        diff_line_anchors="",
        diff_hunk_snippets="",
        pr_grep_default_scope=".",
        scan_start_time=0.0,
        severity_threshold="medium",
    )


class TestPRAttemptState:
    def test_defaults(self):
        state = PRAttemptState()

        assert state.carry_forward_candidate_summary == ""
        assert state.carry_forward_candidate_family_ids == set()
        assert state.carry_forward_candidate_flow_ids == set()

    def test_instances_do_not_share_mutable_defaults(self):
        a = PRAttemptState()
        b = PRAttemptState()
        a.carry_forward_candidate_family_ids.add("chain-1")

        assert "chain-1" not in b.carry_forward_candidate_family_ids


class TestPRReviewContext:
    def test_construction(self, tmp_path: Path):
        ctx = _make_context(tmp_path)

        assert ctx.repo == tmp_path
        assert ctx.pr_review_attempts == 3
        assert ctx.detected_languages == {"python"}
        assert ctx.retry_focus_plan == ["command_option", "path_exfiltration"]


class TestPRReviewState:
    def test_defaults(self):
        state = PRReviewState()

        assert state.warnings == []
        assert state.pr_vulns == []
        assert state.collected_pr_vulns == []
        assert state.ephemeral_pr_vulns == []
        assert state.artifact_loaded is False
        assert state.attempts_run == 0
        assert state.attempts_with_overwritten_artifact == 0
        assert state.attempt_finding_counts == []
        assert state.attempt_observed_counts == []
        assert state.attempt_focus_areas == []
        assert state.attempt_chain_ids == []
        assert state.attempt_chain_exact_ids == []
        assert state.attempt_chain_family_ids == []
        assert state.attempt_chain_flow_ids == []
        assert state.attempt_revalidation_attempted == []
        assert state.attempt_core_evidence_present == []
        assert state.chain_support_counts == {}
        assert state.flow_support_counts == {}
        assert isinstance(state.attempt_state, PRAttemptState)
        assert state.required_core_chain_pass_support == 2
        assert state.weak_consensus_reason == ""
        assert state.weak_consensus_triggered is False
        assert state.consensus_mode_used == "family"
        assert state.support_counts_snapshot == {"exact": 0, "family": 0, "flow": 0}
        assert state.pr_tool_guard_observer == {
            "blocked_out_of_repo_count": 0,
            "blocked_paths": [],
        }
        assert state.merge_stats == {}

    def test_instances_do_not_share_mutable_defaults(self):
        a = PRReviewState()
        b = PRReviewState()
        a.warnings.append("oops")
        a.chain_support_counts["chain-1"] = 1

        assert b.warnings == []
        assert b.chain_support_counts == {}


class TestRunnerProperties:
    def test_console_delegates_to_scanner(self):
        runner = _make_runner()
        assert runner.console is runner._scanner.console

    def test_debug_delegates_to_scanner(self):
        runner = _make_runner(debug=True)
        assert runner.debug is True

    def test_model_delegates_to_scanner(self):
        runner = _make_runner()
        assert runner.model == "test-model"


class TestRecordAttemptChains:
    def test_records_ids_and_increments_support(self):
        runner = _make_runner()
        state = PRReviewState()
        finding = _make_finding()

        runner._record_attempt_chains(state, [finding])

        assert len(state.attempt_chain_exact_ids) == 1
        assert len(state.attempt_chain_family_ids) == 1
        assert len(state.attempt_chain_flow_ids) == 1
        # backward-compatible alias
        assert state.attempt_chain_ids == state.attempt_chain_family_ids
        # support counts should have at least one entry
        assert len(state.chain_support_counts) >= 1
        assert all(v >= 1 for v in state.chain_support_counts.values())

    def test_accumulates_across_calls(self):
        runner = _make_runner()
        state = PRReviewState()
        finding = _make_finding()

        runner._record_attempt_chains(state, [finding])
        runner._record_attempt_chains(state, [finding])

        assert len(state.attempt_chain_family_ids) == 2
        # same chain seen twice -> support count = 2
        for count in state.chain_support_counts.values():
            assert count == 2

    def test_empty_findings(self):
        runner = _make_runner()
        state = PRReviewState()

        runner._record_attempt_chains(state, [])

        assert state.attempt_chain_exact_ids == [set()]
        assert state.attempt_chain_family_ids == [set()]
        assert state.attempt_chain_flow_ids == [set()]
        assert state.chain_support_counts == {}


class TestRecordAttemptRevalidationObservability:
    def test_no_revalidation_records_false(self):
        runner = _make_runner()
        state = PRReviewState()
        finding = _make_finding()

        result = runner._record_attempt_revalidation_observability(
            state,
            attempt_findings=[finding],
            revalidation_attempted=False,
            expected_family_ids=set(),
            expected_flow_ids=set(),
        )

        assert state.attempt_revalidation_attempted == [False]
        # With no expected ids, core evidence is considered present
        assert result is True
        assert state.attempt_core_evidence_present == [True]

    def test_revalidation_with_matching_evidence(self):
        runner = _make_runner()
        state = PRReviewState()
        finding = _make_finding()
        # Get the actual family IDs this finding produces
        from securevibes.scanner.chain_analysis import collect_chain_family_ids

        family_ids = collect_chain_family_ids([finding])

        result = runner._record_attempt_revalidation_observability(
            state,
            attempt_findings=[finding],
            revalidation_attempted=True,
            expected_family_ids=family_ids,
            expected_flow_ids=set(),
        )

        assert result is True
        assert state.attempt_revalidation_attempted == [True]
        assert state.attempt_core_evidence_present == [True]

    def test_revalidation_with_no_matching_evidence(self):
        runner = _make_runner(debug=True)
        state = PRReviewState()
        finding = _make_finding()

        result = runner._record_attempt_revalidation_observability(
            state,
            attempt_findings=[finding],
            revalidation_attempted=True,
            expected_family_ids={"nonexistent|chain|id"},
            expected_flow_ids=set(),
        )

        assert result is False
        assert state.attempt_core_evidence_present == [False]

    def test_empty_findings_returns_false(self):
        runner = _make_runner()
        state = PRReviewState()

        result = runner._record_attempt_revalidation_observability(
            state,
            attempt_findings=[],
            revalidation_attempted=True,
            expected_family_ids={"some|chain"},
            expected_flow_ids=set(),
        )

        assert result is False


class TestProcessAttemptOutcome:
    def _call(
        self,
        runner,
        ctx,
        state,
        *,
        loaded_vulns=None,
        load_warning=None,
        attempt_write_observer=None,
        attempt_force_revalidation=False,
    ):
        runner._process_attempt_outcome(
            ctx,
            state,
            attempt_num=1,
            attempt_write_observer=attempt_write_observer or {},
            attempt_force_revalidation=attempt_force_revalidation,
            attempt_expected_family_ids=set(),
            attempt_expected_flow_ids=set(),
            loaded_vulns=loaded_vulns or [],
            load_warning=load_warning,
        )

    def test_successful_load_updates_state(self, tmp_path: Path):
        runner = _make_runner()
        ctx = _make_context(tmp_path)
        state = PRReviewState()
        vulns = [_make_finding()]

        self._call(runner, ctx, state, loaded_vulns=vulns, load_warning=None)

        assert state.artifact_loaded is True
        assert state.collected_pr_vulns == vulns
        assert state.attempt_finding_counts == [1]
        assert state.attempt_observed_counts == [1]

    def test_load_warning_does_not_set_artifact_loaded(self, tmp_path: Path):
        runner = _make_runner()
        ctx = _make_context(tmp_path)
        state = PRReviewState()

        self._call(runner, ctx, state, loaded_vulns=[], load_warning="file not found")

        assert state.artifact_loaded is False
        assert state.attempt_finding_counts == [0]
        assert state.collected_pr_vulns == []

    def test_observed_vulns_larger_than_loaded(self, tmp_path: Path):
        """When write observer captured more findings than the artifact, they become ephemeral."""
        import json

        runner = _make_runner(debug=True)
        ctx = _make_context(tmp_path)
        state = PRReviewState()
        vulns = [_make_finding()]
        observed_data = [_make_finding(), _make_finding(title="XSS in template")]
        write_observer = {"max_content": json.dumps(observed_data)}

        self._call(
            runner,
            ctx,
            state,
            loaded_vulns=vulns,
            load_warning=None,
            attempt_write_observer=write_observer,
        )

        assert state.attempts_with_overwritten_artifact == 1
        assert len(state.ephemeral_pr_vulns) == 2

    def test_force_revalidation_miss_triggers_weak_consensus(self, tmp_path: Path):
        runner = _make_runner()
        ctx = _make_context(tmp_path)
        state = PRReviewState()

        # No findings + force revalidation -> core evidence will be False
        # (empty findings means attempt_contains_core_chain_evidence returns False)
        self._call(
            runner,
            ctx,
            state,
            loaded_vulns=[],
            load_warning=None,
            attempt_force_revalidation=True,
        )

        assert state.weak_consensus_triggered is True
        assert state.weak_consensus_reason == "revalidation_core_miss"

    def test_no_double_refresh_after_fix(self, tmp_path: Path):
        """Verify _refresh_carry_forward_candidates is called exactly once (from _process_attempt_outcome)."""
        runner = _make_runner()
        ctx = _make_context(tmp_path)
        state = PRReviewState()
        vulns = [_make_finding()]

        # Patch _refresh_carry_forward_candidates to count calls
        call_count = 0
        original_refresh = runner._refresh_carry_forward_candidates

        def counting_refresh(s):
            nonlocal call_count
            call_count += 1
            return original_refresh(s)

        runner._refresh_carry_forward_candidates = counting_refresh

        self._call(runner, ctx, state, loaded_vulns=vulns, load_warning=None)

        assert call_count == 1


class TestRefreshCarryForwardCandidates:
    def test_updates_attempt_state(self):
        runner = _make_runner()
        state = PRReviewState()
        state.collected_pr_vulns = [_make_finding()]
        state.attempt_chain_ids = [set()]  # simulate one attempt already recorded

        runner._refresh_carry_forward_candidates(state)

        # Should have populated candidate summary and IDs
        assert state.attempt_state.carry_forward_candidate_summary != ""
        # Family/flow IDs should be populated from the finding
        assert isinstance(state.attempt_state.carry_forward_candidate_family_ids, set)
        assert isinstance(state.attempt_state.carry_forward_candidate_flow_ids, set)

    def test_empty_vulns_produce_none_summary(self):
        runner = _make_runner()
        state = PRReviewState()

        runner._refresh_carry_forward_candidates(state)

        assert state.attempt_state.carry_forward_candidate_summary == "- None"


_MODULE = "securevibes.scanner.pr_review_flow"


class _FakeTracker:
    """Minimal tracker stub that avoids MagicMock spec issues."""

    def __init__(self, *args, **kwargs):
        self.current_phase = None

    def on_assistant_text(self, text):
        pass


def _make_async_client():
    """Build a mock ClaudeSDKClient that works as an async context manager."""
    client = AsyncMock()
    client.query = AsyncMock()

    async def _receive_empty():
        return
        yield  # pragma: no cover – makes this an async generator

    client.receive_messages = MagicMock(return_value=_receive_empty())

    ctx_mgr = AsyncMock()
    ctx_mgr.__aenter__ = AsyncMock(return_value=client)
    ctx_mgr.__aexit__ = AsyncMock(return_value=False)

    cls = MagicMock(return_value=ctx_mgr)
    return cls, client


def _make_loop_runner(*, debug: bool = False):
    """Build a runner wired for run_attempt_loop tests with patched externals."""
    client_cls, client_mock = _make_async_client()
    scanner = _make_scanner(debug=debug)
    runner = PRReviewAttemptRunner(
        scanner,
        progress_tracker_cls=_FakeTracker,
        claude_client_cls=client_cls,
        hook_matcher_cls=MagicMock,
    )
    return runner, client_cls, client_mock


def _make_error_runner(*, error_cls=RuntimeError, error_msg="boom"):
    """Build a runner whose client raises the given exception on __aenter__."""
    client_cls, _ = _make_async_client()
    ctx_mgr = AsyncMock()

    async def _raise():
        raise error_cls(error_msg)

    ctx_mgr.__aenter__ = AsyncMock(side_effect=_raise)
    ctx_mgr.__aexit__ = AsyncMock(return_value=False)
    client_cls.return_value = ctx_mgr

    scanner = _make_scanner()
    runner = PRReviewAttemptRunner(
        scanner,
        progress_tracker_cls=_FakeTracker,
        claude_client_cls=client_cls,
        hook_matcher_cls=MagicMock,
    )
    return runner, client_cls


@pytest.fixture()
def _patch_loop_externals():
    """Patch module-level functions used by run_attempt_loop."""
    agent_def = MagicMock()
    agent_def.prompt = ""
    agents = {"pr-code-review": agent_def}

    with (
        patch(f"{_MODULE}.create_agent_definitions", return_value=agents),
        patch(f"{_MODULE}.config") as mock_config,
        patch(f"{_MODULE}.create_pre_tool_hook", return_value=MagicMock()),
        patch(f"{_MODULE}.create_post_tool_hook", return_value=MagicMock()),
        patch(f"{_MODULE}.create_subagent_hook", return_value=MagicMock()),
        patch(f"{_MODULE}.create_json_validation_hook", return_value=MagicMock()),
    ):
        mock_config.get_max_turns.return_value = 10
        yield


@pytest.mark.usefixtures("_patch_loop_externals")
class TestRunAttemptLoop:
    """Tests for the async run_attempt_loop orchestration method."""

    @pytest.fixture()
    def ctx(self, tmp_path: Path) -> PRReviewContext:
        return _make_context(tmp_path)

    @pytest.fixture()
    def single_attempt_ctx(self, tmp_path: Path) -> PRReviewContext:
        ctx = _make_context(tmp_path)
        ctx.pr_review_attempts = 1
        return ctx

    async def test_happy_path_with_findings(self, single_attempt_ctx):
        """Single attempt that produces findings should populate state correctly."""
        runner, _, _ = _make_loop_runner()
        state = PRReviewState()
        vulns = [_make_finding()]

        with patch(f"{_MODULE}.load_pr_vulnerabilities_artifact", return_value=(vulns, None)):
            await runner.run_attempt_loop(single_attempt_ctx, state)

        assert state.attempts_run == 1
        assert state.artifact_loaded is True
        assert len(state.collected_pr_vulns) == 1
        # Artifact loader normalizes findings, so check key fields
        loaded = state.collected_pr_vulns[0]
        assert loaded["title"] == "SQL Injection in handler"
        assert loaded["cwe_id"] == "CWE-89"
        assert loaded["severity"] == "high"
        assert state.attempt_finding_counts == [1]
        assert state.warnings == []

    async def test_happy_path_no_findings(self, single_attempt_ctx):
        """Single attempt with no artifact file records zero findings."""
        runner, _, _ = _make_loop_runner()
        state = PRReviewState()

        await runner.run_attempt_loop(single_attempt_ctx, state)

        assert state.attempts_run == 1
        assert state.artifact_loaded is False
        assert state.attempt_finding_counts == [0]
        assert len(state.warnings) == 1
        assert "was not produced" in state.warnings[0]

    async def test_timeout_records_warning_and_continues(self, tmp_path):
        """TimeoutError should record a warning and continue to next attempt."""
        ctx = _make_context(tmp_path)
        ctx.pr_review_attempts = 2

        client_cls, _ = _make_async_client()
        ok_ctx_mgr = client_cls.return_value

        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                timeout_mgr = AsyncMock()

                async def _raise_timeout():
                    raise asyncio.TimeoutError()

                timeout_mgr.__aenter__ = AsyncMock(side_effect=_raise_timeout)
                timeout_mgr.__aexit__ = AsyncMock(return_value=False)
                return timeout_mgr
            return ok_ctx_mgr

        client_cls.side_effect = side_effect

        runner = PRReviewAttemptRunner(
            _make_scanner(),
            progress_tracker_cls=_FakeTracker,
            claude_client_cls=client_cls,
            hook_matcher_cls=MagicMock,
        )
        state = PRReviewState()

        await runner.run_attempt_loop(ctx, state)

        assert state.attempts_run == 2
        assert any("timed out" in w for w in state.warnings)

    async def test_timeout_budget_covers_query_and_receive(self, single_attempt_ctx):
        """A single timeout budget should span query and receive work together."""
        single_attempt_ctx.pr_timeout_seconds = 0.1

        class _SlowClient:
            async def query(self, prompt):
                await asyncio.sleep(0.07)

            async def receive_messages(self):
                await asyncio.sleep(0.07)
                if False:  # pragma: no cover
                    yield None

        class _SlowClientCtx:
            async def __aenter__(self):
                return _SlowClient()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        client_cls = MagicMock(return_value=_SlowClientCtx())
        runner = PRReviewAttemptRunner(
            _make_scanner(),
            progress_tracker_cls=_FakeTracker,
            claude_client_cls=client_cls,
            hook_matcher_cls=MagicMock,
        )
        state = PRReviewState()

        await runner.run_attempt_loop(single_attempt_ctx, state)

        assert any("timed out after 0.1s" in warning for warning in state.warnings)
        assert state.attempt_finding_counts == [0]

    async def test_generic_exception_records_warning_with_type(self, single_attempt_ctx):
        """Non-timeout exceptions should include the exception type in the warning."""
        runner, _ = _make_error_runner(error_cls=RuntimeError, error_msg="connection reset")
        state = PRReviewState()

        await runner.run_attempt_loop(single_attempt_ctx, state)

        assert state.attempts_run == 1
        assert len(state.warnings) >= 1
        assert "RuntimeError" in state.warnings[0]
        assert "connection reset" in state.warnings[0]

    async def test_load_warning_without_attempt_error(self, single_attempt_ctx):
        """When attempt succeeds but artifact fails to load, warning is recorded."""
        runner, _, _ = _make_loop_runner()
        state = PRReviewState()

        await runner.run_attempt_loop(single_attempt_ctx, state)

        assert state.attempts_run == 1
        assert state.artifact_loaded is False
        assert any("was not produced" in w for w in state.warnings)

    async def test_multi_attempt_accumulates_findings(self, tmp_path):
        """Multiple attempts with findings should accumulate collected_pr_vulns."""
        ctx = _make_context(tmp_path)
        ctx.pr_review_attempts = 2
        runner, _, _ = _make_loop_runner()
        state = PRReviewState()

        vulns = [_make_finding()]
        with patch(
            f"{_MODULE}.load_pr_vulnerabilities_artifact",
            side_effect=[(vulns, None), (vulns, None)],
        ):
            await runner.run_attempt_loop(ctx, state)

        assert state.attempts_run == 2
        assert len(state.attempt_finding_counts) == 2
        assert state.attempt_finding_counts[0] == 1

    async def test_retry_suffix_applied_on_second_attempt(self, tmp_path):
        """Second attempt should invoke the client twice."""
        ctx = _make_context(tmp_path)
        ctx.pr_review_attempts = 2
        runner, client_cls, _ = _make_loop_runner()
        state = PRReviewState()

        vulns = [_make_finding()]
        with patch(
            f"{_MODULE}.load_pr_vulnerabilities_artifact",
            side_effect=[(vulns, None), (vulns, None)],
        ):
            await runner.run_attempt_loop(ctx, state)

        assert client_cls.call_count == 2

    async def test_retry_focus_plan_exhaustion_stops_appending_after_plan_end(self, tmp_path):
        """Only configured retry focus areas should be appended across many attempts."""
        ctx = _make_context(tmp_path)
        ctx.pr_review_attempts = 4
        ctx.retry_focus_plan = ["command_option", "path_exfiltration"]
        runner, _, _ = _make_loop_runner()
        state = PRReviewState()

        with patch(
            f"{_MODULE}.load_pr_vulnerabilities_artifact",
            side_effect=[
                ([], "not produced"),
                ([], "not produced"),
                ([], "not produced"),
                ([], "not produced"),
            ],
        ):
            await runner.run_attempt_loop(ctx, state)

        assert state.attempts_run == 4
        assert state.attempt_focus_areas == ["command_option", "path_exfiltration"]

    async def test_run_attempt_loop_processes_assistant_and_result_messages(
        self, single_attempt_ctx
    ):
        """Assistant text should be forwarded and ResultMessage cost should update scanner state."""
        scanner = _make_scanner()
        observed_texts: list[str] = []

        class _RecordingTracker:
            def __init__(self, *args, **kwargs):
                self.current_phase = None

            def on_assistant_text(self, text):
                observed_texts.append(text)

        class _MessageClient:
            async def query(self, prompt):
                return None

            async def receive_messages(self):
                yield AssistantMessage(
                    content=[TextBlock(text="assistant evidence summary")],
                    model="sonnet",
                )
                yield ResultMessage(
                    subtype="success",
                    duration_ms=10,
                    duration_api_ms=10,
                    is_error=False,
                    num_turns=1,
                    session_id="session-1",
                    total_cost_usd=1.25,
                )

        class _MessageClientCtx:
            async def __aenter__(self):
                return _MessageClient()

            async def __aexit__(self, exc_type, exc, tb):
                return False

        runner = PRReviewAttemptRunner(
            scanner,
            progress_tracker_cls=_RecordingTracker,
            claude_client_cls=MagicMock(return_value=_MessageClientCtx()),
            hook_matcher_cls=MagicMock,
        )
        state = PRReviewState()

        with patch(
            f"{_MODULE}.load_pr_vulnerabilities_artifact", return_value=([], "not produced")
        ):
            await runner.run_attempt_loop(single_attempt_ctx, state)

        assert observed_texts == ["assistant evidence summary"]
        assert scanner.total_cost == 1.25

    async def test_run_attempt_loop_accumulates_total_cost_across_attempts(self, tmp_path):
        """ResultMessage cost should accumulate across multiple PR review attempts."""
        scanner = _make_scanner()
        scanner.total_cost = 0.0
        ctx = _make_context(tmp_path)
        ctx.pr_review_attempts = 2
        ctx.retry_focus_plan = ["command_option"]

        class _SilentTracker:
            def __init__(self, *args, **kwargs):
                self.current_phase = None

            def on_assistant_text(self, _text):
                return None

        class _CostClient:
            def __init__(self, cost: float):
                self._cost = cost

            async def query(self, prompt):
                return None

            async def receive_messages(self):
                yield ResultMessage(
                    subtype="success",
                    duration_ms=10,
                    duration_api_ms=10,
                    is_error=False,
                    num_turns=1,
                    session_id="session-cost",
                    total_cost_usd=self._cost,
                )

        class _CostClientCtx:
            def __init__(self, cost: float):
                self._client = _CostClient(cost)

            async def __aenter__(self):
                return self._client

            async def __aexit__(self, exc_type, exc, tb):
                return False

        client_cls = MagicMock(side_effect=[_CostClientCtx(1.25), _CostClientCtx(2.75)])
        runner = PRReviewAttemptRunner(
            scanner,
            progress_tracker_cls=_SilentTracker,
            claude_client_cls=client_cls,
            hook_matcher_cls=MagicMock,
        )
        state = PRReviewState()

        with patch(
            f"{_MODULE}.load_pr_vulnerabilities_artifact",
            side_effect=[([], "not produced"), ([], "not produced")],
        ):
            await runner.run_attempt_loop(ctx, state)

        assert scanner.total_cost == pytest.approx(4.0)

    async def test_attempt_error_skips_load_warning_append(self, single_attempt_ctx):
        """When attempt fails, load warning should not be added as a separate warning."""
        runner, _ = _make_error_runner(error_cls=ConnectionError, error_msg="network down")
        state = PRReviewState()

        await runner.run_attempt_loop(single_attempt_ctx, state)

        # Should only have the attempt error warning, not also a load warning
        assert len(state.warnings) == 1
        assert "ConnectionError" in state.warnings[0]

    async def test_first_attempt_error_does_not_reuse_stale_artifact(self, single_attempt_ctx):
        """Stale artifacts from prior runs should not be loaded when attempt 1 fails."""
        stale_vulns = [_make_finding(title="Stale finding")]
        single_attempt_ctx.pr_vulns_path.write_text(json.dumps(stale_vulns), encoding="utf-8")

        runner, _ = _make_error_runner(error_cls=ConnectionError, error_msg="network down")
        state = PRReviewState()

        await runner.run_attempt_loop(single_attempt_ctx, state)

        assert state.artifact_loaded is False
        assert state.collected_pr_vulns == []
        assert state.attempt_finding_counts == [0]
        assert not single_attempt_ctx.pr_vulns_path.exists()
