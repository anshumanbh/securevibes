"""Execution helpers for incremental review clusters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from securevibes.diff.context import normalize_repo_path
from securevibes.diff.parser import DiffContext, DiffFile
from securevibes.models.result import ScanResult
from securevibes.scanner import Scanner
from securevibes.scanner.chain_analysis import diff_file_path
from securevibes.scanner.incremental_planning import IncrementalPlan, ReviewCluster

ClusterExecutionStatus = Literal["executed", "skipped"]


@dataclass(frozen=True)
class ClusterExecutionResult:
    """Execution outcome for a single planned review cluster."""

    cluster_id: str
    route: str
    status: ClusterExecutionStatus
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    skip_reason: str | None = None


@dataclass(frozen=True)
class IncrementalExecutionResult:
    """Execution summary for an incremental plan."""

    cluster_results: tuple[ClusterExecutionResult, ...]


def build_cluster_diff_context(
    diff_context: DiffContext,
    include_paths: tuple[str, ...],
) -> DiffContext:
    """Build a deterministic DiffContext subset for the selected cluster files."""
    include_set = {
        normalize_repo_path(path)
        for path in include_paths
        if isinstance(path, str) and normalize_repo_path(path)
    }
    if not include_set:
        return DiffContext(files=[], added_lines=0, removed_lines=0, changed_files=[])

    subset_files: list[DiffFile] = []
    for diff_file in diff_context.files:
        path = normalize_repo_path(diff_file_path(diff_file))
        if path and path in include_set:
            subset_files.append(diff_file)

    changed_files: list[str] = []
    seen: set[str] = set()
    for diff_file in subset_files:
        path = normalize_repo_path(diff_file_path(diff_file))
        if not path or path in seen:
            continue
        seen.add(path)
        changed_files.append(path)

    added_lines = sum(
        1
        for diff_file in subset_files
        for hunk in diff_file.hunks
        for line in hunk.lines
        if line.type == "add"
    )
    removed_lines = sum(
        1
        for diff_file in subset_files
        for hunk in diff_file.hunks
        for line in hunk.lines
        if line.type == "remove"
    )

    return DiffContext(
        files=subset_files,
        added_lines=added_lines,
        removed_lines=removed_lines,
        changed_files=changed_files,
    )


async def execute_incremental_plan(
    repo: Path,
    securevibes_dir: Path,
    plan: IncrementalPlan,
    diff_context: DiffContext,
    *,
    model: str,
    quiet: bool,
    debug: bool,
    known_vulns_path: Path | None = None,
    severity_threshold: str = "medium",
    update_artifacts: bool = False,
    scanner_factory: Callable[..., Scanner] | None = None,
) -> IncrementalExecutionResult:
    """Execute supported review clusters from an incremental plan."""
    factory = scanner_factory or (
        lambda *, model, debug, quiet: Scanner(model=model, debug=debug, quiet=quiet)
    )

    cluster_results: list[ClusterExecutionResult] = []
    for cluster in plan.clusters:
        if cluster.route != "targeted_pr_review":
            cluster_results.append(
                ClusterExecutionResult(
                    cluster_id=cluster.cluster_id,
                    route=cluster.route,
                    status="skipped",
                    skip_reason="route_not_implemented",
                )
            )
            continue

        cluster_diff_context = build_cluster_diff_context(diff_context, cluster.file_paths)
        if not cluster_diff_context.changed_files:
            cluster_results.append(
                ClusterExecutionResult(
                    cluster_id=cluster.cluster_id,
                    route=cluster.route,
                    status="skipped",
                    skip_reason="empty_cluster_diff",
                )
            )
            continue

        scanner = factory(model=model, debug=debug, quiet=quiet)
        result = await scanner.pr_review(
            str(repo),
            cluster_diff_context,
            known_vulns_path,
            severity_threshold,
            update_artifacts=update_artifacts,
        )
        cluster_results.append(_execution_result_for_cluster(cluster, result))

    return IncrementalExecutionResult(cluster_results=tuple(cluster_results))


def _execution_result_for_cluster(
    cluster: ReviewCluster,
    result: ScanResult,
) -> ClusterExecutionResult:
    return ClusterExecutionResult(
        cluster_id=cluster.cluster_id,
        route=cluster.route,
        status="executed",
        findings_count=len(result.issues),
        critical_count=result.critical_count,
        high_count=result.high_count,
    )
