"""Tests for incremental review-cluster execution."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from securevibes.diff.parser import parse_unified_diff
from securevibes.models.issue import SecurityIssue, Severity
from securevibes.models.result import ScanResult
from securevibes.scanner.incremental_execution import (
    aggregate_incremental_scan_result,
    build_cluster_diff_context,
    ClusterExecutionResult,
    execute_incremental_plan,
    IncrementalExecutionResult,
    split_cluster_diff_context,
    write_incremental_execution_artifacts,
)
from securevibes.scanner.incremental_planning import (
    CommitSynopsis,
    IncrementalPlan,
    ReviewJob,
    ReviewCluster,
)


def _incremental_plan() -> IncrementalPlan:
    return IncrementalPlan(
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
        synopses=(
            CommitSynopsis(
                sha="commit-1",
                subject="Modify auth flow",
                file_paths=("src/auth.py",),
                derived_components=("src:py",),
                matched_baseline_vuln_paths=("src/auth.py",),
                matched_baseline_components=("src:py",),
                coarse_intent="existing_surface_delta",
                route="targeted_pr_review",
                risk_tier="critical",
                reasons=("critical_pattern_match",),
                dependency_files=(),
                new_attack_surface=False,
                insertions=8,
                deletions=2,
            ),
            CommitSynopsis(
                sha="commit-2",
                subject="Bump dependencies",
                file_paths=("package.json",),
                derived_components=(),
                matched_baseline_vuln_paths=(),
                matched_baseline_components=(),
                coarse_intent="dependency_change",
                route="supply_chain_review",
                risk_tier="moderate",
                reasons=("dependency_change_promotion",),
                dependency_files=("package.json",),
                new_attack_surface=False,
                insertions=3,
                deletions=1,
            ),
        ),
        jobs=(
            ReviewJob(
                job_id="job-001",
                job_type="baseline_overlap_review",
                subsystem="src",
                commit_shas=("commit-1",),
                file_paths=("src/auth.py",),
                baseline_vuln_paths=("src/auth.py",),
                baseline_components=("src:py",),
                coarse_intents=("existing_surface_delta",),
                reasons=("critical_pattern_match",),
            ),
            ReviewJob(
                job_id="job-002",
                job_type="dependency_review",
                subsystem="dependency",
                commit_shas=("commit-2",),
                file_paths=("package.json",),
                baseline_vuln_paths=(),
                baseline_components=(),
                coarse_intents=("dependency_change",),
                reasons=("dependency_change_promotion",),
            ),
        ),
        clusters=(
            ReviewCluster(
                cluster_id="cluster-001",
                route="targeted_pr_review",
                commit_shas=("commit-1",),
                file_paths=("src/auth.py",),
                baseline_vuln_paths=("src/auth.py",),
                baseline_components=("src:py",),
                coarse_intents=("existing_surface_delta",),
                reasons=("critical_pattern_match",),
            ),
            ReviewCluster(
                cluster_id="cluster-002",
                route="supply_chain_review",
                commit_shas=("commit-2",),
                file_paths=("package.json",),
                baseline_vuln_paths=(),
                baseline_components=(),
                coarse_intents=("dependency_change",),
                reasons=("dependency_change_promotion",),
            ),
        ),
    )


def _new_surface_plan() -> IncrementalPlan:
    return IncrementalPlan(
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
        synopses=(
            CommitSynopsis(
                sha="commit-1",
                subject="Add plugin runtime",
                file_paths=("plugins/runtime/loader.ts",),
                derived_components=("plugins:ts",),
                matched_baseline_vuln_paths=(),
                matched_baseline_components=(),
                coarse_intent="new_surface",
                route="incremental_threat_model_then_review",
                risk_tier="moderate",
                reasons=("unmapped_new_attack_surface",),
                dependency_files=(),
                new_attack_surface=True,
                insertions=42,
                deletions=0,
            ),
            CommitSynopsis(
                sha="commit-2",
                subject="Modify auth flow",
                file_paths=("src/auth.py",),
                derived_components=("src:py",),
                matched_baseline_vuln_paths=("src/auth.py",),
                matched_baseline_components=("src:py",),
                coarse_intent="existing_surface_delta",
                route="targeted_pr_review",
                risk_tier="critical",
                reasons=("critical_pattern_match",),
                dependency_files=(),
                new_attack_surface=False,
                insertions=8,
                deletions=2,
            ),
        ),
        jobs=(
            ReviewJob(
                job_id="job-001",
                job_type="new_subsystem_review",
                subsystem="plugins/runtime",
                commit_shas=("commit-1",),
                file_paths=("plugins/runtime/loader.ts",),
                baseline_vuln_paths=(),
                baseline_components=(),
                coarse_intents=("new_surface",),
                reasons=("unmapped_new_attack_surface",),
            ),
            ReviewJob(
                job_id="job-002",
                job_type="baseline_overlap_review",
                subsystem="src",
                commit_shas=("commit-2",),
                file_paths=("src/auth.py",),
                baseline_vuln_paths=("src/auth.py",),
                baseline_components=("src:py",),
                coarse_intents=("existing_surface_delta",),
                reasons=("critical_pattern_match",),
            ),
        ),
        clusters=(
            ReviewCluster(
                cluster_id="cluster-001",
                route="incremental_threat_model_then_review",
                commit_shas=("commit-1",),
                file_paths=("plugins/runtime/loader.ts",),
                baseline_vuln_paths=(),
                baseline_components=(),
                coarse_intents=("new_surface",),
                reasons=("unmapped_new_attack_surface",),
            ),
            ReviewCluster(
                cluster_id="cluster-002",
                route="targeted_pr_review",
                commit_shas=("commit-2",),
                file_paths=("src/auth.py",),
                baseline_vuln_paths=("src/auth.py",),
                baseline_components=("src:py",),
                coarse_intents=("existing_surface_delta",),
                reasons=("critical_pattern_match",),
            ),
        ),
    )


def _scan_result(repo: Path, *, issues: int = 0) -> ScanResult:
    return ScanResult(
        repository_path=str(repo),
        issues=[
            SecurityIssue(
                id=f"ISSUE-{index + 1}",
                severity=Severity.HIGH,
                title="Incremental finding",
                description="Synthetic finding for incremental execution tests.",
                file_path="src/auth.py",
                line_number=7,
                code_snippet="danger()",
                cwe_id="CWE-94",
            )
            for index in range(issues)
        ],
        files_scanned=max(issues, 1),
        scan_time_seconds=1.0,
    )


def test_build_cluster_diff_context_filters_to_cluster_files() -> None:
    diff_context = parse_unified_diff("""diff --git a/src/auth.py b/src/auth.py
index 1111111..2222222 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -1 +1,2 @@
-allow(user)
+allow(user)
+audit(user)
diff --git a/package.json b/package.json
index 3333333..4444444 100644
--- a/package.json
+++ b/package.json
@@ -1 +1 @@
-{"name":"app","version":"1.0.0"}
+{"name":"app","version":"1.1.0"}
""")

    subset = build_cluster_diff_context(diff_context, ("src/auth.py",))

    assert subset.changed_files == ["src/auth.py"]
    assert subset.added_lines == 2
    assert subset.removed_lines == 1


def test_split_cluster_diff_context_slices_oversized_single_hunk() -> None:
    lines = "\n".join(f"+line {index}" for index in range(1200))
    diff_context = parse_unified_diff(f"""diff --git a/src/big.ts b/src/big.ts
index 1111111..2222222 100644
--- a/src/big.ts
+++ b/src/big.ts
@@ -0,0 +1,1200 @@
{lines}
""")

    slices = split_cluster_diff_context(diff_context)

    assert len(slices) == 3
    assert all(item.changed_files == ["src/big.ts"] for item in slices)
    assert (
        max(len(hunk.lines) for item in slices for file in item.files for hunk in file.hunks) <= 500
    )
    assert [
        sum(len(hunk.lines) for file in item.files for hunk in file.hunks) for item in slices
    ] == [
        500,
        500,
        200,
    ]


def test_execute_incremental_plan_runs_targeted_and_supply_chain_clusters(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()
    known_vulns_path = securevibes_dir / "VULNERABILITIES.json"
    known_vulns_path.write_text("[]", encoding="utf-8")

    diff_context = parse_unified_diff("""diff --git a/src/auth.py b/src/auth.py
index 1111111..2222222 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -1 +1,2 @@
-allow(user)
+allow(user)
+audit(user)
diff --git a/package.json b/package.json
index 3333333..4444444 100644
--- a/package.json
+++ b/package.json
@@ -1 +1 @@
-{"name":"app","version":"1.0.0"}
+{"name":"app","version":"1.1.0"}
""")

    fake_scanner = SimpleNamespace(
        scan_subagent=AsyncMock(return_value=_scan_result(repo)),
        pr_review=AsyncMock(return_value=_scan_result(repo)),
    )

    def fake_scanner_factory(*, model: str, debug: bool, quiet: bool):
        assert model == "sonnet"
        assert debug is False
        assert quiet is True
        return fake_scanner

    result = asyncio.run(
        execute_incremental_plan(
            repo,
            securevibes_dir,
            _incremental_plan(),
            diff_context,
            model="sonnet",
            quiet=True,
            debug=False,
            known_vulns_path=known_vulns_path,
            severity_threshold="medium",
            update_artifacts=True,
            scanner_factory=fake_scanner_factory,
        )
    )

    assert len(result.cluster_results) == 2
    assert result.cluster_results[0].status == "executed"
    assert result.cluster_results[0].route == "targeted_pr_review"
    assert result.cluster_results[0].findings_count == 0
    assert result.cluster_results[1].status == "executed"
    assert result.cluster_results[1].route == "supply_chain_review"
    assert result.cluster_results[1].findings_count == 0

    assert fake_scanner.pr_review.await_count == 2
    targeted_call = fake_scanner.pr_review.await_args_list[0]
    assert targeted_call.args[0] == str(repo)
    assert targeted_call.args[1].changed_files == ["src/auth.py"]
    assert targeted_call.args[2] == known_vulns_path
    assert targeted_call.args[3] == "medium"
    assert targeted_call.kwargs["update_artifacts"] is True
    assert targeted_call.kwargs["pr_review_attempts"] == 1
    assert targeted_call.kwargs["pr_timeout_seconds"] == 120
    assert targeted_call.kwargs["auto_triage"] is True

    supply_chain_call = fake_scanner.pr_review.await_args_list[1]
    assert supply_chain_call.args[1].changed_files == ["package.json"]
    assert supply_chain_call.args[2] == known_vulns_path
    assert supply_chain_call.kwargs["update_artifacts"] is True
    assert supply_chain_call.kwargs["pr_review_attempts"] == 1
    assert supply_chain_call.kwargs["pr_timeout_seconds"] == 90
    assert supply_chain_call.kwargs["auto_triage"] is True
    fake_scanner.scan_subagent.assert_not_awaited()


def test_execute_incremental_plan_prefers_jobs_when_clusters_are_absent(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()
    known_vulns_path = securevibes_dir / "VULNERABILITIES.json"
    known_vulns_path.write_text("[]", encoding="utf-8")

    diff_context = parse_unified_diff(
        """diff --git a/plugins/runtime/loader.ts b/plugins/runtime/loader.ts
index 1111111..2222222 100644
--- a/plugins/runtime/loader.ts
+++ b/plugins/runtime/loader.ts
@@ -0,0 +1,2 @@
+export function loadPlugin() {}
+export function validatePlugin() {}
"""
    )

    plan = IncrementalPlan(
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
        synopses=(),
        jobs=(
            ReviewJob(
                job_id="job-001",
                job_type="new_subsystem_review",
                subsystem="plugins/runtime",
                commit_shas=("commit-1",),
                file_paths=("plugins/runtime/loader.ts",),
                baseline_vuln_paths=(),
                baseline_components=(),
                coarse_intents=("new_surface",),
                reasons=("unmapped_new_attack_surface",),
            ),
        ),
        clusters=(),
    )

    fake_scanner = SimpleNamespace(
        scan_subagent=AsyncMock(return_value=_scan_result(repo)),
        pr_review=AsyncMock(return_value=_scan_result(repo)),
    )

    result = asyncio.run(
        execute_incremental_plan(
            repo,
            securevibes_dir,
            plan,
            diff_context,
            model="sonnet",
            quiet=True,
            debug=False,
            known_vulns_path=known_vulns_path,
            scanner_factory=lambda **_kwargs: fake_scanner,
        )
    )

    assert len(result.cluster_results) == 1
    assert result.cluster_results[0].cluster_id == "job-001"
    assert result.cluster_results[0].status == "executed"
    fake_scanner.scan_subagent.assert_awaited_once()
    fake_scanner.pr_review.assert_awaited_once()
    assert fake_scanner.pr_review.await_args_list[0].args[1].changed_files == [
        "plugins/runtime/loader.ts"
    ]


def test_execute_incremental_plan_prioritizes_and_caps_targeted_clusters(
    tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()
    known_vulns_path = securevibes_dir / "VULNERABILITIES.json"
    known_vulns_path.write_text("[]", encoding="utf-8")

    diff_context = parse_unified_diff("""diff --git a/src/service.py b/src/service.py
index 1111111..2222222 100644
--- a/src/service.py
+++ b/src/service.py
@@ -1 +1,2 @@
-run()
+run()
+trace()
diff --git a/src/auth.py b/src/auth.py
index 3333333..4444444 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -1 +1,2 @@
-allow(user)
+allow(user)
+audit(user)
diff --git a/src/permission.py b/src/permission.py
index 5555555..6666666 100644
--- a/src/permission.py
+++ b/src/permission.py
@@ -1 +1,2 @@
-check()
+check()
+audit()
""")

    plan = IncrementalPlan(
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
        synopses=(),
        clusters=(
            ReviewCluster(
                cluster_id="cluster-001",
                route="targeted_pr_review",
                commit_shas=("commit-1",),
                file_paths=("src/service.py",),
                baseline_vuln_paths=(),
                baseline_components=("src:py",),
                coarse_intents=("existing_surface_delta",),
                reasons=("critical_pattern_match",),
            ),
            ReviewCluster(
                cluster_id="cluster-002",
                route="targeted_pr_review",
                commit_shas=("commit-2",),
                file_paths=("src/auth.py",),
                baseline_vuln_paths=("src/auth.py",),
                baseline_components=("src:py",),
                coarse_intents=("existing_surface_delta",),
                reasons=("critical_pattern_match", "baseline_component_overlap"),
            ),
            ReviewCluster(
                cluster_id="cluster-003",
                route="targeted_pr_review",
                commit_shas=("commit-3",),
                file_paths=("src/permission.py",),
                baseline_vuln_paths=(),
                baseline_components=("src:py",),
                coarse_intents=("existing_surface_delta",),
                reasons=("critical_pattern_match", "baseline_component_overlap"),
            ),
        ),
    )

    monkeypatch.setattr(
        "securevibes.scanner.incremental_execution._TARGETED_CLUSTER_MAX_EXECUTIONS",
        2,
    )
    monkeypatch.setattr(
        "securevibes.scanner.incremental_execution._TARGETED_CLUSTER_MAX_FILES",
        2,
    )

    fake_scanner = SimpleNamespace(
        scan_subagent=AsyncMock(return_value=_scan_result(repo)),
        pr_review=AsyncMock(return_value=_scan_result(repo)),
    )

    result = asyncio.run(
        execute_incremental_plan(
            repo,
            securevibes_dir,
            plan,
            diff_context,
            model="sonnet",
            quiet=True,
            debug=False,
            known_vulns_path=known_vulns_path,
            scanner_factory=lambda **_kwargs: fake_scanner,
        )
    )

    assert [item.status for item in result.cluster_results] == ["skipped", "executed", "executed"]
    assert result.cluster_results[0].skip_reason == "targeted_budget_exhausted"
    assert fake_scanner.pr_review.await_count == 2
    reviewed_files = [
        call.args[1].changed_files[0] for call in fake_scanner.pr_review.await_args_list
    ]
    assert reviewed_files == ["src/auth.py", "src/permission.py"]


def test_execute_incremental_plan_prioritizes_global_execution_budget_across_routes(
    tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()
    known_vulns_path = securevibes_dir / "VULNERABILITIES.json"
    known_vulns_path.write_text("[]", encoding="utf-8")

    diff_context = parse_unified_diff(
        """diff --git a/plugins/runtime/loader.ts b/plugins/runtime/loader.ts
index 1111111..2222222 100644
--- a/plugins/runtime/loader.ts
+++ b/plugins/runtime/loader.ts
@@ -0,0 +1,2 @@
+export function loadPlugin() {}
+export function validatePlugin() {}
diff --git a/src/auth.py b/src/auth.py
index 3333333..4444444 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -1 +1,2 @@
-allow(user)
+allow(user)
+audit(user)
diff --git a/package.json b/package.json
index 5555555..6666666 100644
--- a/package.json
+++ b/package.json
@@ -1 +1 @@
-{\"name\":\"app\",\"version\":\"1.0.0\"}
+{\"name\":\"app\",\"version\":\"1.1.0\"}
"""
    )

    plan = IncrementalPlan(
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
        synopses=(),
        clusters=(
            ReviewCluster(
                cluster_id="cluster-001",
                route="incremental_threat_model_then_review",
                commit_shas=("commit-1",),
                file_paths=("plugins/runtime/loader.ts",),
                baseline_vuln_paths=(),
                baseline_components=(),
                coarse_intents=("new_surface",),
                reasons=("unmapped_new_attack_surface",),
            ),
            ReviewCluster(
                cluster_id="cluster-002",
                route="targeted_pr_review",
                commit_shas=("commit-2",),
                file_paths=("src/auth.py",),
                baseline_vuln_paths=("src/auth.py",),
                baseline_components=("src:py",),
                coarse_intents=("existing_surface_delta",),
                reasons=("critical_pattern_match", "baseline_component_overlap"),
            ),
            ReviewCluster(
                cluster_id="cluster-003",
                route="supply_chain_review",
                commit_shas=("commit-3",),
                file_paths=("package.json",),
                baseline_vuln_paths=(),
                baseline_components=(),
                coarse_intents=("dependency_change",),
                reasons=("dependency_change_promotion",),
            ),
        ),
    )

    monkeypatch.setattr(
        "securevibes.scanner.incremental_execution._EXECUTABLE_CLUSTER_MAX_EXECUTIONS",
        2,
    )
    monkeypatch.setattr(
        "securevibes.scanner.incremental_execution._EXECUTABLE_CLUSTER_MAX_FILES",
        2,
    )
    monkeypatch.setattr(
        "securevibes.scanner.incremental_execution._TARGETED_CLUSTER_MAX_EXECUTIONS",
        5,
    )
    monkeypatch.setattr(
        "securevibes.scanner.incremental_execution._TARGETED_CLUSTER_MAX_FILES",
        5,
    )

    fake_scanner = SimpleNamespace(
        scan_subagent=AsyncMock(return_value=_scan_result(repo)),
        pr_review=AsyncMock(return_value=_scan_result(repo)),
    )

    result = asyncio.run(
        execute_incremental_plan(
            repo,
            securevibes_dir,
            plan,
            diff_context,
            model="sonnet",
            quiet=True,
            debug=False,
            known_vulns_path=known_vulns_path,
            scanner_factory=lambda **_kwargs: fake_scanner,
        )
    )

    assert [item.status for item in result.cluster_results] == ["executed", "executed", "skipped"]
    assert result.cluster_results[2].skip_reason == "execution_budget_exhausted"
    fake_scanner.scan_subagent.assert_awaited_once()
    assert fake_scanner.pr_review.await_count == 2
    reviewed_files = [
        call.args[1].changed_files[0] for call in fake_scanner.pr_review.await_args_list
    ]
    assert reviewed_files == ["plugins/runtime/loader.ts", "src/auth.py"]


def test_execute_incremental_plan_slices_large_cluster_diff_and_aggregates_results(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()
    known_vulns_path = securevibes_dir / "VULNERABILITIES.json"
    known_vulns_path.write_text("[]", encoding="utf-8")

    lines = "\n".join(f"+line {index}" for index in range(1200))
    diff_context = parse_unified_diff(f"""diff --git a/src/big.ts b/src/big.ts
index 1111111..2222222 100644
--- a/src/big.ts
+++ b/src/big.ts
@@ -0,0 +1,1200 @@
{lines}
""")

    plan = IncrementalPlan(
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
        synopses=(),
        clusters=(
            ReviewCluster(
                cluster_id="cluster-001",
                route="targeted_pr_review",
                commit_shas=("commit-1",),
                file_paths=("src/big.ts",),
                baseline_vuln_paths=(),
                baseline_components=("src:ts",),
                coarse_intents=("existing_surface_delta",),
                reasons=("critical_pattern_match",),
            ),
        ),
    )

    fake_scanner = SimpleNamespace(
        scan_subagent=AsyncMock(return_value=_scan_result(repo)),
        pr_review=AsyncMock(
            side_effect=[
                _scan_result(repo, issues=1),
                _scan_result(repo, issues=1),
                _scan_result(repo, issues=0),
            ]
        ),
    )

    result = asyncio.run(
        execute_incremental_plan(
            repo,
            securevibes_dir,
            plan,
            diff_context,
            model="sonnet",
            quiet=True,
            debug=False,
            known_vulns_path=known_vulns_path,
            severity_threshold="medium",
            update_artifacts=False,
            scanner_factory=lambda **_kwargs: fake_scanner,
        )
    )

    assert len(result.cluster_results) == 1
    cluster_result = result.cluster_results[0]
    assert cluster_result.status == "executed"
    assert cluster_result.findings_count == 2
    assert cluster_result.scan_result is not None
    assert len(cluster_result.scan_result.issues) == 2
    assert fake_scanner.pr_review.await_count == 3
    assert (
        max(
            len(hunk.lines)
            for call in fake_scanner.pr_review.await_args_list
            for file in call.args[1].files
            for hunk in file.hunks
        )
        <= 500
    )


def test_aggregate_incremental_scan_result_merges_cluster_findings(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    execution_result = IncrementalExecutionResult(
        cluster_results=(
            ClusterExecutionResult(
                cluster_id="cluster-001",
                route="targeted_pr_review",
                status="executed",
                scan_result=_scan_result(repo, issues=1),
            ),
            ClusterExecutionResult(
                cluster_id="cluster-002",
                route="custom_route",
                status="skipped",
                skip_reason="route_not_implemented",
            ),
        )
    )

    aggregated = aggregate_incremental_scan_result(repo, execution_result)

    assert aggregated.repository_path == str(repo)
    assert len(aggregated.issues) == 1
    assert "cluster-002" in aggregated.warnings[0]


def test_write_incremental_execution_artifacts_persists_cluster_statuses(
    tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()
    mirror_dir = tmp_path / "mirror"

    monkeypatch.setattr(
        "securevibes.scanner.incremental_execution._INCREMENTAL_TELEMETRY_MIRROR_DIR",
        mirror_dir,
    )

    execution_result = IncrementalExecutionResult(
        cluster_results=(
            ClusterExecutionResult(
                cluster_id="cluster-001",
                route="targeted_pr_review",
                status="executed",
                findings_count=1,
                high_count=1,
                scan_result=_scan_result(repo, issues=1),
                diff_slice_count=2,
                pr_review_duration_seconds=1.5,
                total_duration_seconds=2.0,
            ),
            ClusterExecutionResult(
                cluster_id="cluster-002",
                route="targeted_pr_review",
                status="skipped",
                skip_reason="targeted_budget_exhausted",
                total_duration_seconds=0.0,
            ),
        )
    )

    artifact_path, mirror_path = write_incremental_execution_artifacts(
        repo,
        securevibes_dir,
        _incremental_plan(),
        execution_result,
    )

    payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    mirror_payload = json.loads(mirror_path.read_text(encoding="utf-8"))

    assert payload["base_ref"] == "base123"
    assert payload["head_ref"] == "head456"
    assert payload["repo_name"] == "repo"
    assert payload["clusters"][0]["cluster_id"] == "cluster-001"
    assert payload["clusters"][0]["status"] == "executed"
    assert payload["clusters"][0]["file_paths"] == ["src/auth.py"]
    assert payload["clusters"][0]["commit_shas"] == ["commit-1"]
    assert payload["clusters"][0]["topic"] == []
    assert payload["clusters"][0]["diff_slice_count"] == 2
    assert payload["clusters"][0]["pr_review_duration_seconds"] == 1.5
    assert payload["clusters"][0]["total_duration_seconds"] == 2.0
    assert payload["clusters"][1]["cluster_id"] == "cluster-002"
    assert payload["clusters"][1]["status"] == "skipped"
    assert payload["clusters"][1]["skip_reason"] == "targeted_budget_exhausted"
    assert payload["clusters"][1]["total_duration_seconds"] == 0.0
    assert mirror_payload == payload


def test_aggregate_incremental_scan_result_omits_warning_for_planned_skip(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    execution_result = IncrementalExecutionResult(
        cluster_results=(
            ClusterExecutionResult(
                cluster_id="cluster-001",
                route="skip",
                status="skipped",
                skip_reason="planned_skip",
            ),
        )
    )

    aggregated = aggregate_incremental_scan_result(repo, execution_result)

    assert aggregated.repository_path == str(repo)
    assert aggregated.warnings == []


def test_execute_incremental_plan_respects_planned_skip_route(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()
    diff_context = parse_unified_diff("""diff --git a/README.md b/README.md
index 1111111..2222222 100644
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
-# app
+# app
+docs update
""")

    plan = IncrementalPlan(
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
        synopses=(),
        clusters=(
            ReviewCluster(
                cluster_id="cluster-001",
                route="skip",
                commit_shas=("commit-1",),
                file_paths=("README.md",),
                baseline_vuln_paths=(),
                baseline_components=(),
                coarse_intents=("likely_non_security",),
                reasons=("all_files_matched_skip_patterns",),
            ),
        ),
    )

    fake_scanner = SimpleNamespace(
        scan_subagent=AsyncMock(return_value=_scan_result(repo)),
        pr_review=AsyncMock(return_value=_scan_result(repo)),
    )

    result = asyncio.run(
        execute_incremental_plan(
            repo,
            securevibes_dir,
            plan,
            diff_context,
            model="sonnet",
            quiet=True,
            debug=False,
            scanner_factory=lambda **_kwargs: fake_scanner,
        )
    )

    assert result.cluster_results[0].status == "skipped"
    assert result.cluster_results[0].skip_reason == "planned_skip"
    fake_scanner.scan_subagent.assert_not_awaited()
    fake_scanner.pr_review.assert_not_awaited()


def test_execute_incremental_plan_skips_empty_cluster_subset(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()
    diff_context = parse_unified_diff("""diff --git a/src/auth.py b/src/auth.py
index 1111111..2222222 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -1 +1,2 @@
-allow(user)
+allow(user)
+audit(user)
""")

    plan = IncrementalPlan(
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
        synopses=(),
        clusters=(
            ReviewCluster(
                cluster_id="cluster-001",
                route="targeted_pr_review",
                commit_shas=("commit-1",),
                file_paths=("src/missing.py",),
                baseline_vuln_paths=(),
                baseline_components=(),
                coarse_intents=("existing_surface_delta",),
                reasons=("critical_pattern_match",),
            ),
        ),
    )

    fake_scanner = SimpleNamespace(pr_review=AsyncMock(return_value=_scan_result(repo)))

    result = asyncio.run(
        execute_incremental_plan(
            repo,
            securevibes_dir,
            plan,
            diff_context,
            model="sonnet",
            quiet=True,
            debug=False,
            scanner_factory=lambda **_kwargs: fake_scanner,
        )
    )

    assert result.cluster_results[0].status == "skipped"
    assert result.cluster_results[0].skip_reason == "empty_cluster_diff"
    fake_scanner.pr_review.assert_not_awaited()


def test_execute_incremental_plan_continues_after_cluster_failure(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()
    known_vulns_path = securevibes_dir / "VULNERABILITIES.json"
    known_vulns_path.write_text("[]", encoding="utf-8")

    diff_context = parse_unified_diff("""diff --git a/src/auth.py b/src/auth.py
index 1111111..2222222 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -1 +1,2 @@
-allow(user)
+allow(user)
+audit(user)
diff --git a/src/permission.py b/src/permission.py
index 3333333..4444444 100644
--- a/src/permission.py
+++ b/src/permission.py
@@ -1 +1,2 @@
-check()
+check()
+trace()
""")

    plan = IncrementalPlan(
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
        synopses=(),
        clusters=(
            ReviewCluster(
                cluster_id="cluster-001",
                route="targeted_pr_review",
                commit_shas=("commit-1",),
                file_paths=("src/auth.py",),
                baseline_vuln_paths=("src/auth.py",),
                baseline_components=("src:py",),
                coarse_intents=("existing_surface_delta",),
                reasons=("critical_pattern_match", "baseline_component_overlap"),
            ),
            ReviewCluster(
                cluster_id="cluster-002",
                route="targeted_pr_review",
                commit_shas=("commit-2",),
                file_paths=("src/permission.py",),
                baseline_vuln_paths=(),
                baseline_components=("src:py",),
                coarse_intents=("existing_surface_delta",),
                reasons=("critical_pattern_match", "baseline_component_overlap"),
            ),
        ),
    )

    fake_scanner = SimpleNamespace(
        scan_subagent=AsyncMock(return_value=_scan_result(repo)),
        pr_review=AsyncMock(
            side_effect=[
                RuntimeError("synthetic cluster failure"),
                _scan_result(repo, issues=1),
            ]
        ),
    )

    result = asyncio.run(
        execute_incremental_plan(
            repo,
            securevibes_dir,
            plan,
            diff_context,
            model="sonnet",
            quiet=True,
            debug=False,
            known_vulns_path=known_vulns_path,
            scanner_factory=lambda **_kwargs: fake_scanner,
        )
    )

    assert [item.status for item in result.cluster_results] == ["skipped", "executed"]
    assert result.cluster_results[0].skip_reason == "cluster_execution_failed"
    assert "synthetic cluster failure" in result.cluster_results[0].scan_result.warnings[0]
    assert result.cluster_results[1].findings_count == 1
    assert fake_scanner.pr_review.await_count == 2


def test_execute_incremental_plan_runs_new_surface_route_before_pr_review(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()
    known_vulns_path = securevibes_dir / "VULNERABILITIES.json"
    known_vulns_path.write_text("[]", encoding="utf-8")

    diff_context = parse_unified_diff(
        """diff --git a/plugins/runtime/loader.ts b/plugins/runtime/loader.ts
index 1111111..2222222 100644
--- a/plugins/runtime/loader.ts
+++ b/plugins/runtime/loader.ts
@@ -0,0 +1,2 @@
+export function loadPlugin() {}
+export function validatePlugin() {}
diff --git a/src/auth.py b/src/auth.py
index 3333333..4444444 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -1 +1,2 @@
-allow(user)
+allow(user)
+audit(user)
"""
    )

    fake_scanner = SimpleNamespace(
        scan_subagent=AsyncMock(return_value=_scan_result(repo)),
        pr_review=AsyncMock(return_value=_scan_result(repo)),
    )

    result = asyncio.run(
        execute_incremental_plan(
            repo,
            securevibes_dir,
            _new_surface_plan(),
            diff_context,
            model="sonnet",
            quiet=True,
            debug=False,
            known_vulns_path=known_vulns_path,
            scanner_factory=lambda **_kwargs: fake_scanner,
        )
    )

    assert [item.status for item in result.cluster_results] == ["executed", "executed"]
    fake_scanner.scan_subagent.assert_awaited_once_with(
        str(repo),
        "threat-modeling",
        force=True,
        skip_checks=True,
    )
    assert fake_scanner.pr_review.await_count == 2
    new_surface_call = fake_scanner.pr_review.await_args_list[0]
    assert new_surface_call.args[1].changed_files == ["plugins/runtime/loader.ts"]
    assert new_surface_call.kwargs["pr_review_attempts"] == 1
    assert new_surface_call.kwargs["pr_timeout_seconds"] == 120
    assert new_surface_call.kwargs["auto_triage"] is True
    assert result.cluster_results[0].threat_model_duration_seconds is not None
    assert result.cluster_results[0].pr_review_duration_seconds is not None
    assert result.cluster_results[0].total_duration_seconds is not None


def test_execute_incremental_plan_reuses_threat_modeling_for_same_new_surface_topic(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    plan = IncrementalPlan(
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-25T12:00:00Z",
        synopses=(),
        clusters=(
            ReviewCluster(
                cluster_id="cluster-001",
                route="incremental_threat_model_then_review",
                commit_shas=("commit-1",),
                file_paths=("src/acp/control-plane/manager.core.ts",),
                baseline_vuln_paths=(),
                baseline_components=(),
                coarse_intents=("new_surface",),
                reasons=("new_subsystem_surface",),
                topic=("src/acp",),
            ),
            ReviewCluster(
                cluster_id="cluster-002",
                route="incremental_threat_model_then_review",
                commit_shas=("commit-1",),
                file_paths=("src/acp/runtime/registry.ts",),
                baseline_vuln_paths=(),
                baseline_components=(),
                coarse_intents=("new_surface",),
                reasons=("new_subsystem_surface",),
                topic=("src/acp",),
            ),
        ),
    )
    diff_context = parse_unified_diff(
        """diff --git a/src/acp/control-plane/manager.core.ts b/src/acp/control-plane/manager.core.ts
index 1111111..2222222 100644
--- a/src/acp/control-plane/manager.core.ts
+++ b/src/acp/control-plane/manager.core.ts
@@ -0,0 +1,1 @@
+export const manager = true
diff --git a/src/acp/runtime/registry.ts b/src/acp/runtime/registry.ts
index 3333333..4444444 100644
--- a/src/acp/runtime/registry.ts
+++ b/src/acp/runtime/registry.ts
@@ -0,0 +1,1 @@
+export const registry = true
"""
    )

    fake_scanner = SimpleNamespace(
        scan_subagent=AsyncMock(return_value=_scan_result(repo)),
        pr_review=AsyncMock(return_value=_scan_result(repo)),
    )
    clock_values = iter(float(value) for value in range(20))

    result = asyncio.run(
        execute_incremental_plan(
            repo,
            securevibes_dir,
            plan,
            diff_context,
            model="sonnet",
            quiet=True,
            debug=False,
            scanner_factory=lambda **_kwargs: fake_scanner,
            clock=lambda: next(clock_values),
        )
    )

    fake_scanner.scan_subagent.assert_awaited_once()
    assert fake_scanner.pr_review.await_count == 2
    assert result.cluster_results[0].threat_model_reused is False
    assert result.cluster_results[0].threat_model_duration_seconds == 1.0
    assert result.cluster_results[0].pr_review_duration_seconds == 1.0
    assert result.cluster_results[0].total_duration_seconds is not None
    assert result.cluster_results[1].threat_model_reused is True
    assert result.cluster_results[1].threat_model_duration_seconds == 0.0
    assert result.cluster_results[1].pr_review_duration_seconds == 1.0
    assert result.cluster_results[1].total_duration_seconds is not None


def test_execute_incremental_plan_refreshes_known_vulns_between_clusters(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()
    known_vulns_path = securevibes_dir / "VULNERABILITIES.json"

    diff_context = parse_unified_diff(
        """diff --git a/plugins/runtime/loader.ts b/plugins/runtime/loader.ts
index 1111111..2222222 100644
--- a/plugins/runtime/loader.ts
+++ b/plugins/runtime/loader.ts
@@ -0,0 +1,2 @@
+export function loadPlugin() {}
+export function validatePlugin() {}
diff --git a/src/auth.py b/src/auth.py
index 3333333..4444444 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -1 +1,2 @@
-allow(user)
+allow(user)
+audit(user)
"""
    )

    async def fake_scan_subagent(*_args, **_kwargs):
        known_vulns_path.write_text("[]", encoding="utf-8")
        return _scan_result(repo)

    fake_scanner = SimpleNamespace(
        scan_subagent=AsyncMock(side_effect=fake_scan_subagent),
        pr_review=AsyncMock(return_value=_scan_result(repo)),
    )

    asyncio.run(
        execute_incremental_plan(
            repo,
            securevibes_dir,
            _new_surface_plan(),
            diff_context,
            model="sonnet",
            quiet=True,
            debug=False,
            known_vulns_path=None,
            scanner_factory=lambda **_kwargs: fake_scanner,
        )
    )

    assert fake_scanner.pr_review.await_args_list[0].args[2] == known_vulns_path
    assert fake_scanner.pr_review.await_args_list[1].args[2] == known_vulns_path


def test_execute_incremental_plan_rebuilds_risk_map_after_threat_modeling(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir()

    threat_model_path = securevibes_dir / "THREAT_MODEL.json"
    threat_model_path.write_text("[]", encoding="utf-8")
    risk_map_path = securevibes_dir / "risk_map.json"
    risk_map_path.write_text(
        json.dumps(
            {
                "critical": [],
                "moderate": [],
                "skip": ["docs/*"],
            }
        ),
        encoding="utf-8",
    )

    diff_context = parse_unified_diff(
        """diff --git a/plugins/runtime/loader.ts b/plugins/runtime/loader.ts
index 1111111..2222222 100644
--- a/plugins/runtime/loader.ts
+++ b/plugins/runtime/loader.ts
@@ -0,0 +1,2 @@
+export function loadPlugin() {}
+export function validatePlugin() {}
diff --git a/src/auth.py b/src/auth.py
index 3333333..4444444 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -1 +1,2 @@
-allow(user)
+allow(user)
+audit(user)
"""
    )

    async def fake_scan_subagent(*_args, **_kwargs):
        threat_model_path.write_text(
            json.dumps(
                [
                    {
                        "id": "THREAT-NEW",
                        "severity": "high",
                        "affected_components": ["plugins/runtime/*"],
                    }
                ]
            ),
            encoding="utf-8",
        )
        return _scan_result(repo)

    fake_scanner = SimpleNamespace(
        scan_subagent=AsyncMock(side_effect=fake_scan_subagent),
        pr_review=AsyncMock(return_value=_scan_result(repo)),
    )

    asyncio.run(
        execute_incremental_plan(
            repo,
            securevibes_dir,
            _new_surface_plan(),
            diff_context,
            model="sonnet",
            quiet=True,
            debug=False,
            scanner_factory=lambda **_kwargs: fake_scanner,
        )
    )

    risk_map = json.loads(risk_map_path.read_text(encoding="utf-8"))
    assert "plugins/runtime/*" in risk_map["critical"]
    assert risk_map["_meta"]["generated_from"] == "THREAT_MODEL.json"
