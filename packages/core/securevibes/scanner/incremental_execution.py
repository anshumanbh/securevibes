"""Execution helpers for incremental review jobs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Callable, Literal

from securevibes.diff.context import normalize_repo_path
from securevibes.diff.parser import DiffContext, DiffFile, DiffHunk
from securevibes.models.result import ScanResult
from securevibes.scanner import Scanner
from securevibes.scanner.chain_analysis import diff_file_path
from securevibes.scanner.incremental_planning import IncrementalPlan, ReviewJob
from securevibes.scanner.risk_scorer import (
    SECURITY_KEYWORDS,
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
_TARGETED_CLUSTER_MAX_EXECUTIONS = 12
_TARGETED_CLUSTER_MAX_FILES = 24
_EXECUTABLE_CLUSTER_MAX_EXECUTIONS = 8
_EXECUTABLE_CLUSTER_MAX_FILES = 16
_INCREMENTAL_TARGETED_ATTEMPTS = 1
_INCREMENTAL_TARGETED_TIMEOUT_SECONDS = 120
_INCREMENTAL_NEW_SURFACE_ATTEMPTS = 1
_INCREMENTAL_NEW_SURFACE_TIMEOUT_SECONDS = 120
_INCREMENTAL_SUPPLY_CHAIN_ATTEMPTS = 1
_INCREMENTAL_SUPPLY_CHAIN_TIMEOUT_SECONDS = 90
_BASELINE_OVERLAP_MAX_REVIEW_FILES = 3
_NEW_SUBSYSTEM_MAX_REVIEW_FILES = 4
_SUPPLY_CHAIN_MAX_REVIEW_FILES = 3
_INCREMENTAL_EXECUTION_SCHEMA_VERSION = 1
_INCREMENTAL_TELEMETRY_MIRROR_DIR = Path("/tmp/securevibes-incremental-telemetry")
_EXECUTION_PRIORITY_KEYWORDS = SECURITY_KEYWORDS + (
    "session",
    "runtime",
    "control",
    "plugin",
    "sandbox",
    "spawn",
    "command",
    "router",
    "server",
    "client",
    "api",
    "handler",
    "manager",
    "policy",
)


@dataclass(frozen=True)
class _ExecutionUnit:
    """Primary executable review unit derived from plan jobs or compatibility clusters."""

    result_id: str
    route: str
    file_paths: tuple[str, ...]
    baseline_vuln_paths: tuple[str, ...]
    baseline_components: tuple[str, ...]
    coarse_intents: tuple[str, ...]
    reasons: tuple[str, ...]
    topic: tuple[str, ...]


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
    selected_file_paths: tuple[str, ...] = ()
    deferred_file_paths: tuple[str, ...] = ()
    diff_slice_count: int = 0
    threat_model_reused: bool = False
    threat_model_duration_seconds: float | None = None
    pr_review_duration_seconds: float | None = None
    total_duration_seconds: float | None = None


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


def write_incremental_execution_artifacts(
    repo: Path,
    securevibes_dir: Path,
    plan: IncrementalPlan,
    execution_result: IncrementalExecutionResult,
) -> tuple[Path, Path]:
    """Persist incremental execution telemetry in-repo and in a durable temp mirror."""
    payload = _incremental_execution_payload(repo, plan, execution_result)
    serialized = json.dumps(payload, indent=2) + "\n"

    securevibes_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = securevibes_dir / "incremental_execution.json"
    artifact_path.write_text(serialized, encoding="utf-8")

    mirror_dir = _INCREMENTAL_TELEMETRY_MIRROR_DIR
    mirror_dir.mkdir(parents=True, exist_ok=True)
    mirror_path = mirror_dir / _incremental_telemetry_filename(repo, plan)
    mirror_path.write_text(serialized, encoding="utf-8")

    return artifact_path, mirror_path


def _incremental_execution_payload(
    repo: Path,
    plan: IncrementalPlan,
    execution_result: IncrementalExecutionResult,
) -> dict[str, object]:
    plan_clusters = {cluster.cluster_id: cluster for cluster in plan.clusters}
    plan_jobs = {job.job_id: job for job in plan.jobs}
    compatibility_jobs = _compatibility_jobs_by_cluster_id(plan)
    clusters_payload: list[dict[str, object]] = []

    for result in execution_result.cluster_results:
        cluster = plan_clusters.get(result.cluster_id)
        job = plan_jobs.get(result.cluster_id) or compatibility_jobs.get(result.cluster_id)
        clusters_payload.append(
            {
                "cluster_id": result.cluster_id,
                "job_id": job.job_id if job else None,
                "job_type": job.job_type if job else None,
                "subsystem": job.subsystem if job else None,
                "route": result.route,
                "status": result.status,
                "skip_reason": result.skip_reason,
                "findings_count": result.findings_count,
                "critical_count": result.critical_count,
                "high_count": result.high_count,
                "commit_shas": list(cluster.commit_shas) if cluster else [],
                "file_paths": list(cluster.file_paths) if cluster else [],
                "selected_file_paths": list(result.selected_file_paths),
                "deferred_file_paths": list(result.deferred_file_paths),
                "baseline_vuln_paths": list(cluster.baseline_vuln_paths) if cluster else [],
                "baseline_components": list(cluster.baseline_components) if cluster else [],
                "coarse_intents": list(cluster.coarse_intents) if cluster else [],
                "reasons": list(cluster.reasons) if cluster else [],
                "topic": list(cluster.topic) if cluster else [],
                "warnings": list(result.scan_result.warnings) if result.scan_result else [],
                "diff_slice_count": result.diff_slice_count,
                "threat_model_reused": result.threat_model_reused,
                "threat_model_duration_seconds": result.threat_model_duration_seconds,
                "pr_review_duration_seconds": result.pr_review_duration_seconds,
                "total_duration_seconds": result.total_duration_seconds,
            }
        )

    return {
        "schema_version": _INCREMENTAL_EXECUTION_SCHEMA_VERSION,
        "repo_name": repo.resolve().name,
        "base_ref": plan.base_ref,
        "head_ref": plan.head_ref,
        "generated_at": plan.generated_at,
        "clusters": clusters_payload,
    }


def _compatibility_jobs_by_cluster_id(plan: IncrementalPlan) -> dict[str, ReviewJob]:
    return {cluster.cluster_id: job for cluster, job in zip(plan.clusters, plan.jobs, strict=False)}


def _incremental_telemetry_filename(repo: Path, plan: IncrementalPlan) -> str:
    return (
        f"{_sanitize_telemetry_token(repo.resolve().name)}-"
        f"{_sanitize_telemetry_token(plan.base_ref)[:24]}-"
        f"{_sanitize_telemetry_token(plan.head_ref)[:24]}-incremental-execution.json"
    )


def _sanitize_telemetry_token(value: str) -> str:
    token = "".join(char if char.isalnum() else "_" for char in value.strip())
    return token or "unknown"


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
    clock: Callable[[], float] | None = None,
) -> IncrementalExecutionResult:
    """Execute supported review jobs from an incremental plan."""
    factory = scanner_factory or (
        lambda *, model, debug, quiet: Scanner(model=model, debug=debug, quiet=quiet)
    )
    timer = clock or perf_counter
    execution_units = _execution_units(plan)
    selected_executable_clusters = _select_executable_units(execution_units)
    selected_targeted_clusters = _select_targeted_units(execution_units)
    threat_modeled_topics: set[tuple[str, ...]] = set()

    cluster_results: list[ClusterExecutionResult] = []
    for cluster in execution_units:
        cluster_started_at = timer()
        selected_file_paths = _selected_file_paths_for_execution(cluster)
        deferred_file_paths = tuple(
            path for path in cluster.file_paths if path not in selected_file_paths
        )
        if cluster.route == "skip":
            cluster_results.append(
                ClusterExecutionResult(
                    cluster_id=cluster.result_id,
                    route=cluster.route,
                    status="skipped",
                    skip_reason="planned_skip",
                    selected_file_paths=selected_file_paths,
                    deferred_file_paths=deferred_file_paths,
                    total_duration_seconds=timer() - cluster_started_at,
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
                    cluster_id=cluster.result_id,
                    route=cluster.route,
                    status="skipped",
                    skip_reason="route_not_implemented",
                    selected_file_paths=selected_file_paths,
                    deferred_file_paths=deferred_file_paths,
                    total_duration_seconds=timer() - cluster_started_at,
                )
            )
            continue

        if cluster.result_id not in selected_executable_clusters:
            cluster_results.append(
                ClusterExecutionResult(
                    cluster_id=cluster.result_id,
                    route=cluster.route,
                    status="skipped",
                    skip_reason="execution_budget_exhausted",
                    selected_file_paths=selected_file_paths,
                    deferred_file_paths=deferred_file_paths,
                    total_duration_seconds=timer() - cluster_started_at,
                )
            )
            continue

        if (
            cluster.route == "targeted_pr_review"
            and cluster.result_id not in selected_targeted_clusters
        ):
            cluster_results.append(
                ClusterExecutionResult(
                    cluster_id=cluster.result_id,
                    route=cluster.route,
                    status="skipped",
                    skip_reason="targeted_budget_exhausted",
                    selected_file_paths=selected_file_paths,
                    deferred_file_paths=deferred_file_paths,
                    total_duration_seconds=timer() - cluster_started_at,
                )
            )
            continue

        cluster_diff_context = build_cluster_diff_context(diff_context, selected_file_paths)
        if not cluster_diff_context.changed_files:
            cluster_results.append(
                ClusterExecutionResult(
                    cluster_id=cluster.result_id,
                    route=cluster.route,
                    status="skipped",
                    skip_reason="empty_cluster_diff",
                    selected_file_paths=selected_file_paths,
                    deferred_file_paths=deferred_file_paths,
                    total_duration_seconds=timer() - cluster_started_at,
                )
            )
            continue

        current_known_vulns_path = _resolve_known_vulns_path(
            securevibes_dir,
            known_vulns_path,
        )
        scanner = factory(model=model, debug=debug, quiet=quiet)
        threat_model_duration_seconds = 0.0
        pr_review_duration_seconds = 0.0
        diff_slice_count = 0
        threat_model_reused = False
        slice_results: list[ScanResult] = []
        try:
            if cluster.route == "incremental_threat_model_then_review":
                topic_key = _new_surface_topic_key(cluster)
                if topic_key and topic_key in threat_modeled_topics:
                    threat_model_reused = True
                else:
                    threat_model_started_at = timer()
                    await scanner.scan_subagent(
                        str(repo),
                        "threat-modeling",
                        force=True,
                        skip_checks=True,
                    )
                    threat_model_duration_seconds += timer() - threat_model_started_at
                    _refresh_incremental_artifacts(repo, securevibes_dir)
                    current_known_vulns_path = _resolve_known_vulns_path(
                        securevibes_dir,
                        known_vulns_path,
                    )
                    if topic_key:
                        threat_modeled_topics.add(topic_key)
            diff_slices = split_cluster_diff_context(cluster_diff_context)
            pr_review_kwargs = _pr_review_kwargs_for_cluster(cluster)
            for diff_slice in diff_slices:
                diff_slice_count += 1
                pr_review_started_at = timer()
                result = await scanner.pr_review(
                    str(repo),
                    diff_slice,
                    current_known_vulns_path,
                    severity_threshold,
                    update_artifacts=update_artifacts,
                    **pr_review_kwargs,
                )
                pr_review_duration_seconds += timer() - pr_review_started_at
                slice_results.append(result)
                if update_artifacts:
                    _refresh_incremental_artifacts(repo, securevibes_dir)
                    current_known_vulns_path = _resolve_known_vulns_path(
                        securevibes_dir,
                        known_vulns_path,
                    )
            cluster_results.append(
                _execution_result_for_cluster(
                    cluster,
                    _aggregate_scan_results(repo, slice_results),
                    selected_file_paths=selected_file_paths,
                    deferred_file_paths=deferred_file_paths,
                    diff_slice_count=diff_slice_count,
                    threat_model_reused=threat_model_reused,
                    threat_model_duration_seconds=threat_model_duration_seconds,
                    pr_review_duration_seconds=pr_review_duration_seconds,
                    total_duration_seconds=timer() - cluster_started_at,
                )
            )
        except Exception as exc:
            partial_result = _aggregate_scan_results(repo, slice_results) if slice_results else None
            cluster_results.append(
                _cluster_execution_failure_result(
                    cluster,
                    repo,
                    exc,
                    partial_result=partial_result,
                    selected_file_paths=selected_file_paths,
                    deferred_file_paths=deferred_file_paths,
                    diff_slice_count=diff_slice_count,
                    threat_model_reused=threat_model_reused,
                    threat_model_duration_seconds=threat_model_duration_seconds,
                    pr_review_duration_seconds=pr_review_duration_seconds,
                    total_duration_seconds=timer() - cluster_started_at,
                )
            )

    return IncrementalExecutionResult(cluster_results=tuple(cluster_results))


def _execution_units(plan: IncrementalPlan) -> tuple[_ExecutionUnit, ...]:
    if plan.jobs:
        compatibility_clusters = list(plan.clusters)
        units: list[_ExecutionUnit] = []
        for index, job in enumerate(plan.jobs):
            cluster = compatibility_clusters[index] if index < len(compatibility_clusters) else None
            units.append(
                _ExecutionUnit(
                    result_id=cluster.cluster_id if cluster else job.job_id,
                    route=cluster.route if cluster else _route_for_job(job),
                    file_paths=job.file_paths,
                    baseline_vuln_paths=job.baseline_vuln_paths,
                    baseline_components=job.baseline_components,
                    coarse_intents=job.coarse_intents,
                    reasons=job.reasons,
                    topic=cluster.topic if cluster else ((job.subsystem,) if job.subsystem else ()),
                )
            )
        return tuple(units)

    return tuple(
        _ExecutionUnit(
            result_id=cluster.cluster_id,
            route=cluster.route,
            file_paths=cluster.file_paths,
            baseline_vuln_paths=cluster.baseline_vuln_paths,
            baseline_components=cluster.baseline_components,
            coarse_intents=cluster.coarse_intents,
            reasons=cluster.reasons,
            topic=cluster.topic,
        )
        for cluster in plan.clusters
    )


def _route_for_job(job: ReviewJob) -> str:
    route_by_type = {
        "dependency_review": "supply_chain_review",
        "new_subsystem_review": "incremental_threat_model_then_review",
        "baseline_overlap_review": "targeted_pr_review",
        "skip": "skip",
    }
    return route_by_type[job.job_type]


def _pr_review_kwargs_for_cluster(cluster: _ExecutionUnit) -> dict[str, int | bool]:
    if cluster.route == "supply_chain_review":
        return {
            "pr_review_attempts": _INCREMENTAL_SUPPLY_CHAIN_ATTEMPTS,
            "pr_timeout_seconds": _INCREMENTAL_SUPPLY_CHAIN_TIMEOUT_SECONDS,
            "auto_triage": True,
        }
    if cluster.route == "incremental_threat_model_then_review":
        return {
            "pr_review_attempts": _INCREMENTAL_NEW_SURFACE_ATTEMPTS,
            "pr_timeout_seconds": _INCREMENTAL_NEW_SURFACE_TIMEOUT_SECONDS,
            "auto_triage": True,
        }
    return {
        "pr_review_attempts": _INCREMENTAL_TARGETED_ATTEMPTS,
        "pr_timeout_seconds": _INCREMENTAL_TARGETED_TIMEOUT_SECONDS,
        "auto_triage": True,
    }


def _select_targeted_units(clusters: tuple[_ExecutionUnit, ...]) -> set[str]:
    targeted = [cluster for cluster in clusters if cluster.route == "targeted_pr_review"]
    if len(targeted) <= _TARGETED_CLUSTER_MAX_EXECUTIONS:
        return {cluster.result_id for cluster in targeted}

    ranked = sorted(
        enumerate(targeted),
        key=lambda item: (_targeted_cluster_score(item[1]), -item[0]),
        reverse=True,
    )

    selected_ids: set[str] = set()
    selected_files = 0
    for _index, cluster in ranked:
        next_file_total = selected_files + len(_selected_file_paths_for_execution(cluster))
        if selected_ids and (
            len(selected_ids) + 1 > _TARGETED_CLUSTER_MAX_EXECUTIONS
            or next_file_total > _TARGETED_CLUSTER_MAX_FILES
        ):
            continue

        selected_ids.add(cluster.result_id)
        selected_files = next_file_total

    return selected_ids


def _select_executable_units(clusters: tuple[_ExecutionUnit, ...]) -> set[str]:
    executable = [
        cluster
        for cluster in clusters
        if cluster.route
        in {
            "targeted_pr_review",
            "incremental_threat_model_then_review",
            "supply_chain_review",
        }
    ]
    if len(executable) <= _EXECUTABLE_CLUSTER_MAX_EXECUTIONS:
        return {cluster.result_id for cluster in executable}

    ranked = sorted(
        enumerate(executable),
        key=lambda item: (_cluster_execution_score(item[1]), -item[0]),
        reverse=True,
    )

    selected_ids: set[str] = set()
    selected_files = 0
    for _index, cluster in ranked:
        next_file_total = selected_files + len(_selected_file_paths_for_execution(cluster))
        if selected_ids and (
            len(selected_ids) + 1 > _EXECUTABLE_CLUSTER_MAX_EXECUTIONS
            or next_file_total > _EXECUTABLE_CLUSTER_MAX_FILES
        ):
            continue

        selected_ids.add(cluster.result_id)
        selected_files = next_file_total

    return selected_ids


def _cluster_execution_score(cluster: _ExecutionUnit) -> int:
    route_bonus = {
        "incremental_threat_model_then_review": 200,
        "targeted_pr_review": 100,
        "supply_chain_review": 60,
    }.get(cluster.route, 0)
    return route_bonus + _targeted_cluster_score(cluster)


def _targeted_cluster_score(cluster: _ExecutionUnit) -> int:
    score = 0
    if cluster.baseline_vuln_paths:
        score += 100
    if "policy_file_changed" in cluster.reasons:
        score += 80
    if "baseline_component_overlap" in cluster.reasons:
        score += 40
    if "critical_pattern_match" in cluster.reasons:
        score += 20
    if _cluster_has_security_signal(cluster):
        score += 10
    score -= max(len(cluster.file_paths) - 1, 0)
    return score


def _selected_file_paths_for_execution(cluster: _ExecutionUnit) -> tuple[str, ...]:
    cap = _review_file_cap(cluster)
    if len(cluster.file_paths) <= cap:
        return cluster.file_paths

    ranked = sorted(
        cluster.file_paths,
        key=lambda path: (_file_execution_score(cluster, path), path),
        reverse=True,
    )
    return tuple(ranked[:cap])


def _review_file_cap(cluster: _ExecutionUnit) -> int:
    if cluster.route == "incremental_threat_model_then_review":
        return _NEW_SUBSYSTEM_MAX_REVIEW_FILES
    if cluster.route == "supply_chain_review":
        return _SUPPLY_CHAIN_MAX_REVIEW_FILES
    if cluster.route == "targeted_pr_review":
        return _BASELINE_OVERLAP_MAX_REVIEW_FILES
    return len(cluster.file_paths)


def _file_execution_score(cluster: _ExecutionUnit, path: str) -> int:
    normalized = normalize_repo_path(path).lower()
    score = 0
    if path in cluster.baseline_vuln_paths:
        score += 200
    if _path_has_priority_signal(normalized):
        score += 80
    if "policy_file_changed" in cluster.reasons and any(
        token in normalized for token in ("policy", "config", "permission", "auth")
    ):
        score += 40
    if cluster.route == "incremental_threat_model_then_review" and any(
        token in normalized for token in ("runtime", "session", "control", "router", "manager")
    ):
        score += 30
    if _is_test_or_doc_path(normalized):
        score -= 100
    score -= normalized.count("/")
    return score


def _path_has_priority_signal(path: str) -> bool:
    return any(keyword in path for keyword in _EXECUTION_PRIORITY_KEYWORDS)


def _is_test_or_doc_path(path: str) -> bool:
    return path.startswith(("docs/", "doc/", "tests/", "test/")) or any(
        marker in path for marker in (".test.", ".spec.", "/__tests__/")
    )


def _cluster_has_security_signal(cluster: _ExecutionUnit) -> bool:
    for path in cluster.file_paths:
        normalized = normalize_repo_path(path).lower()
        if any(keyword in normalized for keyword in SECURITY_KEYWORDS):
            return True
    return False


def _execution_result_for_cluster(
    cluster: _ExecutionUnit,
    result: ScanResult,
    *,
    selected_file_paths: tuple[str, ...],
    deferred_file_paths: tuple[str, ...],
    diff_slice_count: int,
    threat_model_reused: bool,
    threat_model_duration_seconds: float,
    pr_review_duration_seconds: float,
    total_duration_seconds: float,
) -> ClusterExecutionResult:
    return ClusterExecutionResult(
        cluster_id=cluster.result_id,
        route=cluster.route,
        status="executed",
        findings_count=len(result.issues),
        critical_count=result.critical_count,
        high_count=result.high_count,
        scan_result=result,
        selected_file_paths=selected_file_paths,
        deferred_file_paths=deferred_file_paths,
        diff_slice_count=diff_slice_count,
        threat_model_reused=threat_model_reused,
        threat_model_duration_seconds=threat_model_duration_seconds,
        pr_review_duration_seconds=pr_review_duration_seconds,
        total_duration_seconds=total_duration_seconds,
    )


def _cluster_execution_failure_result(
    cluster: _ExecutionUnit,
    repo: Path,
    exc: Exception,
    *,
    partial_result: ScanResult | None,
    selected_file_paths: tuple[str, ...],
    deferred_file_paths: tuple[str, ...],
    diff_slice_count: int,
    threat_model_reused: bool,
    threat_model_duration_seconds: float,
    pr_review_duration_seconds: float,
    total_duration_seconds: float,
) -> ClusterExecutionResult:
    result = partial_result or ScanResult(repository_path=str(repo))
    result.warnings.append(
        f"Incremental cluster {cluster.result_id} execution failed: " f"{type(exc).__name__}: {exc}"
    )
    return ClusterExecutionResult(
        cluster_id=cluster.result_id,
        route=cluster.route,
        status="skipped",
        findings_count=len(result.issues),
        critical_count=result.critical_count,
        high_count=result.high_count,
        skip_reason="cluster_execution_failed",
        scan_result=result,
        selected_file_paths=selected_file_paths,
        deferred_file_paths=deferred_file_paths,
        diff_slice_count=diff_slice_count,
        threat_model_reused=threat_model_reused,
        threat_model_duration_seconds=threat_model_duration_seconds,
        pr_review_duration_seconds=pr_review_duration_seconds,
        total_duration_seconds=total_duration_seconds,
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


def _new_surface_topic_key(cluster: _ExecutionUnit) -> tuple[str, ...] | None:
    if cluster.route != "incremental_threat_model_then_review":
        return None
    return cluster.topic or None


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
