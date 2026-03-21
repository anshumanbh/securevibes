"""Tests for incremental review-cluster execution."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from securevibes.diff.parser import parse_unified_diff
from securevibes.models.result import ScanResult
from securevibes.scanner.incremental_execution import (
    build_cluster_diff_context,
    execute_incremental_plan,
)
from securevibes.scanner.incremental_planning import (
    CommitSynopsis,
    IncrementalPlan,
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
        issues=[],
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

    supply_chain_call = fake_scanner.pr_review.await_args_list[1]
    assert supply_chain_call.args[1].changed_files == ["package.json"]
    assert supply_chain_call.args[2] == known_vulns_path
    assert supply_chain_call.kwargs["update_artifacts"] is True
    fake_scanner.scan_subagent.assert_not_awaited()


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
