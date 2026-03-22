"""Execution helpers for incremental review clusters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from securevibes.diff.context import normalize_repo_path
from securevibes.diff.parser import DiffContext, DiffFile, DiffHunk
from securevibes.models.result import ScanResult
from securevibes.scanner import Scanner
from securevibes.scanner.chain_analysis import diff_file_path
from securevibes.scanner.incremental_planning import IncrementalPlan, ReviewCluster
from securevibes.scanner.risk_scorer import (
    build_risk_map_from_threat_model,
    load_threat_model_entries,
    resolve_component_globs,
    save_risk_map,
)

ClusterExecutionStatus = Literal["executed", "skipped"]
_NON_WARNING_SKIP_REASONS = frozenset({"planned_skip"})
_EXECUTABLE_DIFF_MAX_FILES = 15
_EXECUTABLE_DIFF_MAX_LINES = 500
_EXECUTABLE_DIFF_MAX_HUNK_LINES = 500


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
    scan_result: ScanResult | None = None


@dataclass(frozen=True)
class IncrementalExecutionResult:
    """Execution summary for an incremental plan."""

    cluster_results: tuple[ClusterExecutionResult, ...]


def aggregate_incremental_scan_result(
    repo: Path,
    execution_result: IncrementalExecutionResult,
) -> ScanResult:
    """Aggregate executed cluster scan results into a single CLI-facing result."""
    aggregated = ScanResult(repository_path=str(repo))

    for cluster_result in execution_result.cluster_results:
        if cluster_result.scan_result is None:
            if (
                cluster_result.status == "skipped"
                and cluster_result.skip_reason
                and cluster_result.skip_reason not in _NON_WARNING_SKIP_REASONS
            ):
                aggregated.warnings.append(
                    f"Incremental cluster {cluster_result.cluster_id} skipped: "
                    f"{cluster_result.skip_reason}"
                )
            continue

        aggregated.issues.extend(cluster_result.scan_result.issues)
        aggregated.files_scanned += cluster_result.scan_result.files_scanned
        aggregated.scan_time_seconds += cluster_result.scan_result.scan_time_seconds
        aggregated.total_cost_usd += cluster_result.scan_result.total_cost_usd
        aggregated.warnings.extend(cluster_result.scan_result.warnings)

    return aggregated


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


def split_cluster_diff_context(
    diff_context: DiffContext,
    *,
    max_files: int = _EXECUTABLE_DIFF_MAX_FILES,
    max_total_lines: int = _EXECUTABLE_DIFF_MAX_LINES,
    max_hunk_lines: int = _EXECUTABLE_DIFF_MAX_HUNK_LINES,
) -> tuple[DiffContext, ...]:
    """Split a cluster diff into executable slices that stay within safety budgets."""
    if not diff_context.files:
        return (diff_context,)

    file_slices = [
        file_slice
        for diff_file in diff_context.files
        for file_slice in _split_diff_file_for_execution(
            diff_file,
            max_total_lines=max_total_lines,
            max_hunk_lines=max_hunk_lines,
        )
    ]
    if not file_slices:
        return (DiffContext(files=[], added_lines=0, removed_lines=0, changed_files=[]),)

    contexts: list[DiffContext] = []
    current_files: list[DiffFile] = []
    current_line_count = 0

    for file_slice in file_slices:
        file_line_count = sum(len(hunk.lines) for hunk in file_slice.hunks)
        exceeds_budget = current_files and (
            len(current_files) + 1 > max_files
            or current_line_count + file_line_count > max_total_lines
        )
        if exceeds_budget:
            contexts.append(_build_diff_context(current_files))
            current_files = []
            current_line_count = 0

        current_files.append(file_slice)
        current_line_count += file_line_count

    if current_files:
        contexts.append(_build_diff_context(current_files))

    return tuple(contexts)


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
        if cluster.route == "skip":
            cluster_results.append(
                ClusterExecutionResult(
                    cluster_id=cluster.cluster_id,
                    route=cluster.route,
                    status="skipped",
                    skip_reason="planned_skip",
                )
            )
            continue

        if cluster.route not in {
            "targeted_pr_review",
            "incremental_threat_model_then_review",
            "supply_chain_review",
        }:
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

        current_known_vulns_path = _resolve_known_vulns_path(
            securevibes_dir,
            known_vulns_path,
        )
        scanner = factory(model=model, debug=debug, quiet=quiet)
        if cluster.route == "incremental_threat_model_then_review":
            await scanner.scan_subagent(
                str(repo),
                "threat-modeling",
                force=True,
                skip_checks=True,
            )
            _refresh_incremental_artifacts(repo, securevibes_dir)
            current_known_vulns_path = _resolve_known_vulns_path(
                securevibes_dir,
                known_vulns_path,
            )
        diff_slices = split_cluster_diff_context(cluster_diff_context)
        slice_results: list[ScanResult] = []
        for diff_slice in diff_slices:
            result = await scanner.pr_review(
                str(repo),
                diff_slice,
                current_known_vulns_path,
                severity_threshold,
                update_artifacts=update_artifacts,
            )
            slice_results.append(result)
            if update_artifacts:
                _refresh_incremental_artifacts(repo, securevibes_dir)
                current_known_vulns_path = _resolve_known_vulns_path(
                    securevibes_dir,
                    known_vulns_path,
                )
        cluster_results.append(
            _execution_result_for_cluster(cluster, _aggregate_scan_results(repo, slice_results))
        )

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
        scan_result=result,
    )


def _aggregate_scan_results(repo: Path, results: list[ScanResult]) -> ScanResult:
    aggregated = ScanResult(repository_path=str(repo))
    for result in results:
        aggregated.issues.extend(result.issues)
        aggregated.files_scanned += result.files_scanned
        aggregated.scan_time_seconds += result.scan_time_seconds
        aggregated.total_cost_usd += result.total_cost_usd
        aggregated.warnings.extend(result.warnings)
    return aggregated


def _resolve_known_vulns_path(
    securevibes_dir: Path,
    known_vulns_path: Path | None,
) -> Path | None:
    if known_vulns_path is not None and known_vulns_path.exists():
        return known_vulns_path

    candidate = securevibes_dir / "VULNERABILITIES.json"
    if candidate.exists():
        return candidate
    return None


def _split_diff_file_for_execution(
    diff_file: DiffFile,
    *,
    max_total_lines: int,
    max_hunk_lines: int,
) -> tuple[DiffFile, ...]:
    hunk_slices = [
        hunk_slice
        for hunk in diff_file.hunks
        for hunk_slice in _split_diff_hunk_for_execution(hunk, max_hunk_lines=max_hunk_lines)
    ]
    if not hunk_slices:
        return (diff_file,)

    file_slices: list[DiffFile] = []
    current_hunks: list[DiffHunk] = []
    current_line_count = 0
    for hunk_slice in hunk_slices:
        hunk_line_count = len(hunk_slice.lines)
        exceeds_budget = current_hunks and current_line_count + hunk_line_count > max_total_lines
        if exceeds_budget:
            file_slices.append(_copy_diff_file(diff_file, current_hunks))
            current_hunks = []
            current_line_count = 0

        current_hunks.append(hunk_slice)
        current_line_count += hunk_line_count

    if current_hunks:
        file_slices.append(_copy_diff_file(diff_file, current_hunks))

    return tuple(file_slices)


def _split_diff_hunk_for_execution(
    hunk: DiffHunk,
    *,
    max_hunk_lines: int,
) -> tuple[DiffHunk, ...]:
    if len(hunk.lines) <= max_hunk_lines:
        return (hunk,)

    hunks: list[DiffHunk] = []
    for start in range(0, len(hunk.lines), max_hunk_lines):
        chunk_lines = hunk.lines[start : start + max_hunk_lines]
        old_numbers = [line.old_line_num for line in chunk_lines if line.old_line_num is not None]
        new_numbers = [line.new_line_num for line in chunk_lines if line.new_line_num is not None]
        hunks.append(
            DiffHunk(
                old_start=old_numbers[0] if old_numbers else hunk.old_start,
                old_count=len(old_numbers),
                new_start=new_numbers[0] if new_numbers else hunk.new_start,
                new_count=len(new_numbers),
                lines=chunk_lines,
            )
        )
    return tuple(hunks)


def _copy_diff_file(diff_file: DiffFile, hunks: list[DiffHunk]) -> DiffFile:
    return DiffFile(
        old_path=diff_file.old_path,
        new_path=diff_file.new_path,
        hunks=hunks,
        is_new=diff_file.is_new,
        is_deleted=diff_file.is_deleted,
        is_renamed=diff_file.is_renamed,
    )


def _build_diff_context(files: list[DiffFile]) -> DiffContext:
    changed_files: list[str] = []
    seen: set[str] = set()
    for diff_file in files:
        path = normalize_repo_path(diff_file_path(diff_file))
        if not path or path in seen:
            continue
        seen.add(path)
        changed_files.append(path)

    added_lines = sum(
        1
        for diff_file in files
        for hunk in diff_file.hunks
        for line in hunk.lines
        if line.type == "add"
    )
    removed_lines = sum(
        1
        for diff_file in files
        for hunk in diff_file.hunks
        for line in hunk.lines
        if line.type == "remove"
    )

    return DiffContext(
        files=list(files),
        added_lines=added_lines,
        removed_lines=removed_lines,
        changed_files=changed_files,
    )


def _refresh_incremental_artifacts(repo: Path, securevibes_dir: Path) -> None:
    threat_model_path = securevibes_dir / "THREAT_MODEL.json"
    if not threat_model_path.exists():
        return

    threat_entries = load_threat_model_entries(threat_model_path)
    risk_map = build_risk_map_from_threat_model(
        threat_entries,
        component_resolver=lambda component: resolve_component_globs(repo, component),
    )
    save_risk_map(securevibes_dir / "risk_map.json", risk_map)
