"""Range-aware incremental planning helpers."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Sequence

from securevibes.diff.extractor import get_commits_between, validate_git_ref
from securevibes.models.schemas import fix_vulnerabilities_json
from securevibes.scanner.artifacts import _derive_components_from_file_path
from securevibes.scanner.risk_scorer import (
    ChangedFile,
    ChunkRisk,
    SECURITY_KEYWORDS,
    build_risk_map_from_threat_model,
    classify_chunk,
    load_risk_map,
    load_threat_model_entries,
    normalize_path,
    resolve_component_globs,
    save_risk_map,
)
from securevibes.scanner.state import utc_timestamp

CoarseIntent = Literal[
    "new_surface",
    "existing_surface_delta",
    "dependency_change",
    "likely_non_security",
]
JobType = Literal[
    "dependency_review",
    "new_subsystem_review",
    "baseline_overlap_review",
    "skip",
]
ReviewRoute = Literal[
    "targeted_pr_review",
    "incremental_threat_model_then_review",
    "supply_chain_review",
    "skip",
]

_SYNOPSIS_SCHEMA_VERSION = 1
_HYPOTHESES_SCHEMA_VERSION = 2
_NEW_SUBSYSTEM_MIN_ADDED_FILES = 3
_NEW_SUBSYSTEM_NAMESPACE_DEPTH = 2


@dataclass(frozen=True)
class BaselineContext:
    """Baseline artifacts used for incremental routing."""

    risk_map: dict[str, object]
    vuln_paths: frozenset[str]
    affected_components: frozenset[str]


@dataclass(frozen=True)
class CommitMetadata:
    """Commit metadata collected for incremental planning."""

    sha: str
    subject: str
    body: str
    changed_files: tuple[ChangedFile, ...]
    insertions: int
    deletions: int


@dataclass(frozen=True)
class CommitSynopsis:
    """Structured synopsis for a single commit."""

    sha: str
    subject: str
    file_paths: tuple[str, ...]
    derived_components: tuple[str, ...]
    matched_baseline_vuln_paths: tuple[str, ...]
    matched_baseline_components: tuple[str, ...]
    coarse_intent: CoarseIntent
    route: ReviewRoute
    risk_tier: str
    reasons: tuple[str, ...]
    dependency_files: tuple[str, ...]
    new_attack_surface: bool
    insertions: int
    deletions: int
    changed_files: tuple[ChangedFile, ...] = ()
    new_subsystem_roots: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReviewCluster:
    """Cluster of commits routed to the same incremental review strategy."""

    cluster_id: str
    route: ReviewRoute
    commit_shas: tuple[str, ...]
    file_paths: tuple[str, ...]
    baseline_vuln_paths: tuple[str, ...]
    baseline_components: tuple[str, ...]
    coarse_intents: tuple[CoarseIntent, ...]
    reasons: tuple[str, ...]
    topic: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReviewJob:
    """Simplified subsystem-oriented review job."""

    job_id: str
    job_type: JobType
    subsystem: str
    commit_shas: tuple[str, ...]
    file_paths: tuple[str, ...]
    baseline_vuln_paths: tuple[str, ...]
    baseline_components: tuple[str, ...]
    coarse_intents: tuple[CoarseIntent, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class _JobSlice:
    """Internal per-commit job slice used to aggregate subsystem review jobs."""

    commit_sha: str
    job_type: JobType
    subsystem: str
    file_paths: tuple[str, ...]
    baseline_vuln_paths: tuple[str, ...]
    baseline_components: tuple[str, ...]
    coarse_intent: CoarseIntent
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class IncrementalPlan:
    """Planning output for an incremental commit range."""

    base_ref: str
    head_ref: str
    generated_at: str
    synopses: tuple[CommitSynopsis, ...]
    jobs: tuple[ReviewJob, ...] = ()
    clusters: tuple[ReviewCluster, ...] = ()


def load_baseline_context(securevibes_dir: Path, *, repo: Path | None = None) -> BaselineContext:
    """Load baseline artifacts required for incremental routing.

    Args:
        securevibes_dir: Repository `.securevibes` directory.
        repo: Repository root used to rebuild derived artifacts when needed.

    Returns:
        Parsed baseline context.

    Raises:
        FileNotFoundError: If a required baseline artifact is missing.
        ValueError: If an artifact exists but is invalid.
    """
    threat_model_path = securevibes_dir / "THREAT_MODEL.json"
    vulnerabilities_path = securevibes_dir / "VULNERABILITIES.json"
    risk_map_path = securevibes_dir / "risk_map.json"

    for path in (threat_model_path, vulnerabilities_path):
        if not path.exists():
            raise FileNotFoundError(f"Missing required baseline artifact: {path.name}")

    threat_entries = load_threat_model_entries(threat_model_path)
    if risk_map_path.exists():
        risk_map = load_risk_map(risk_map_path)
    elif repo is not None:
        risk_map = build_risk_map_from_threat_model(
            threat_entries,
            component_resolver=lambda component: resolve_component_globs(repo, component),
        )
        save_risk_map(risk_map_path, risk_map)
    else:
        raise FileNotFoundError(f"Missing required baseline artifact: {risk_map_path.name}")

    vulnerabilities = _load_vulnerability_entries(vulnerabilities_path)

    affected_components: set[str] = set()
    for entry in threat_entries:
        components = entry.get("affected_components")
        if isinstance(components, str):
            normalized = components.strip().lower()
            if normalized:
                affected_components.add(normalized)
            continue
        if isinstance(components, list):
            for component in components:
                if isinstance(component, str):
                    normalized = component.strip().lower()
                    if normalized:
                        affected_components.add(normalized)

    vuln_paths: set[str] = set()
    for entry in vulnerabilities:
        file_path = entry.get("file_path")
        if not isinstance(file_path, str):
            continue
        normalized = normalize_path(file_path).lower()
        if normalized:
            vuln_paths.add(normalized)

    return BaselineContext(
        risk_map=risk_map,
        vuln_paths=frozenset(vuln_paths),
        affected_components=frozenset(affected_components),
    )


def collect_commit_range(repo: Path, *, base: str, head: str) -> list[CommitMetadata]:
    """Collect commit metadata for an explicit base/head range."""
    commits = get_commits_between(repo, base, head)
    return [_load_commit_metadata(repo, sha) for sha in commits]


def build_incremental_plan(
    commits: Sequence[CommitMetadata],
    baseline: BaselineContext,
    *,
    base_ref: str,
    head_ref: str,
    generated_at: str | None = None,
) -> IncrementalPlan:
    """Build a deterministic incremental routing plan for a commit range."""
    synopses = tuple(_build_commit_synopsis(commit, baseline) for commit in commits)
    jobs = _build_review_jobs(synopses, baseline)
    clusters = _build_compatibility_clusters(jobs)
    return IncrementalPlan(
        base_ref=base_ref,
        head_ref=head_ref,
        generated_at=generated_at or utc_timestamp(),
        synopses=synopses,
        jobs=jobs,
        clusters=clusters,
    )


def plan_incremental_range(
    repo: Path,
    securevibes_dir: Path,
    *,
    base_ref: str,
    head_ref: str,
    generated_at: str | None = None,
) -> IncrementalPlan:
    """Load, build, and persist an incremental plan for a commit range."""
    baseline = load_baseline_context(securevibes_dir, repo=repo)
    commits = collect_commit_range(repo, base=base_ref, head=head_ref)
    plan = build_incremental_plan(
        commits,
        baseline,
        base_ref=base_ref,
        head_ref=head_ref,
        generated_at=generated_at,
    )
    write_incremental_plan_artifacts(securevibes_dir, plan)
    return plan


def write_incremental_plan_artifacts(securevibes_dir: Path, plan: IncrementalPlan) -> None:
    """Persist synopsis and routing artifacts for an incremental plan."""
    securevibes_dir.mkdir(parents=True, exist_ok=True)

    synopsis_payload = {
        "schema_version": _SYNOPSIS_SCHEMA_VERSION,
        "generated_at": plan.generated_at,
        "base_ref": plan.base_ref,
        "head_ref": plan.head_ref,
        "commit_count": len(plan.synopses),
        "commits": [
            {
                "sha": synopsis.sha,
                "subject": synopsis.subject,
                "file_paths": list(synopsis.file_paths),
                "derived_components": list(synopsis.derived_components),
                "matched_baseline_vuln_paths": list(synopsis.matched_baseline_vuln_paths),
                "matched_baseline_components": list(synopsis.matched_baseline_components),
                "coarse_intent": synopsis.coarse_intent,
                "route": synopsis.route,
                "risk_tier": synopsis.risk_tier,
                "reasons": list(synopsis.reasons),
                "dependency_files": list(synopsis.dependency_files),
                "new_attack_surface": synopsis.new_attack_surface,
                "insertions": synopsis.insertions,
                "deletions": synopsis.deletions,
            }
            for synopsis in plan.synopses
        ],
    }
    hypotheses_payload = {
        "schema_version": _HYPOTHESES_SCHEMA_VERSION,
        "generated_at": plan.generated_at,
        "base_ref": plan.base_ref,
        "head_ref": plan.head_ref,
        "job_count": len(plan.jobs),
        "jobs": [
            {
                "job_id": job.job_id,
                "job_type": job.job_type,
                "subsystem": job.subsystem,
                "commit_shas": list(job.commit_shas),
                "file_paths": list(job.file_paths),
                "baseline_vuln_paths": list(job.baseline_vuln_paths),
                "baseline_components": list(job.baseline_components),
                "coarse_intents": list(job.coarse_intents),
                "reasons": list(job.reasons),
            }
            for job in plan.jobs
        ],
        "cluster_count": len(plan.clusters),
        "clusters": [
            {
                "cluster_id": cluster.cluster_id,
                "route": cluster.route,
                "commit_shas": list(cluster.commit_shas),
                "file_paths": list(cluster.file_paths),
                "baseline_vuln_paths": list(cluster.baseline_vuln_paths),
                "baseline_components": list(cluster.baseline_components),
                "coarse_intents": list(cluster.coarse_intents),
                "reasons": list(cluster.reasons),
                "topic": list(cluster.topic),
            }
            for cluster in plan.clusters
        ],
    }

    (securevibes_dir / "incremental_synopsis.json").write_text(
        json.dumps(synopsis_payload, indent=2),
        encoding="utf-8",
    )
    (securevibes_dir / "incremental_hypotheses.json").write_text(
        json.dumps(hypotheses_payload, indent=2),
        encoding="utf-8",
    )


def _load_commit_metadata(repo: Path, sha: str) -> CommitMetadata:
    validate_git_ref(sha)

    message_result = _run_git_command(
        repo,
        ["git", "show", "--quiet", "--format=%H%x00%s%x00%b", "--no-color", sha],
    )
    message_parts = message_result.split("\0", 2)
    subject = message_parts[1].strip() if len(message_parts) > 1 else ""
    body = message_parts[2].strip() if len(message_parts) > 2 else ""

    status_output = _run_git_command(
        repo,
        [
            "git",
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--name-status",
            "-r",
            "--find-renames",
            sha,
        ],
    )
    numstat_output = _run_git_command(
        repo,
        ["git", "diff-tree", "--root", "--no-commit-id", "--numstat", "-r", "--find-renames", sha],
    )

    file_statuses = _parse_name_status(status_output)
    file_stats = _parse_numstat(numstat_output)

    changed_files: list[ChangedFile] = []
    for path in sorted(set(file_statuses) | set(file_stats)):
        if not path:
            continue
        changed_files.append(
            ChangedFile(
                path=path,
                status=file_statuses.get(path, "M"),
                insertions=file_stats.get(path, (0, 0))[0],
                deletions=file_stats.get(path, (0, 0))[1],
            )
        )

    insertions = sum(insert for insert, _delete in file_stats.values())
    deletions = sum(delete for _insert, delete in file_stats.values())

    return CommitMetadata(
        sha=sha,
        subject=subject,
        body=body,
        changed_files=tuple(changed_files),
        insertions=insertions,
        deletions=deletions,
    )


def _build_commit_synopsis(
    commit: CommitMetadata,
    baseline: BaselineContext,
) -> CommitSynopsis:
    chunk_risk = classify_chunk(commit.changed_files, baseline.risk_map)
    new_subsystem_roots = _detect_new_subsystem_roots(commit.changed_files)
    new_surface_signal = chunk_risk.new_attack_surface or bool(new_subsystem_roots)
    file_paths = tuple(
        sorted(
            {
                normalized
                for changed_file in commit.changed_files
                if (normalized := normalize_path(changed_file.path))
            }
        )
    )
    derived_components = tuple(
        sorted(
            {
                component
                for path in file_paths
                for component in _derive_components_from_file_path(path)
                if component
            }
        )
    )
    matched_baseline_vuln_paths = tuple(
        sorted(path for path in file_paths if path.lower() in baseline.vuln_paths)
    )
    matched_baseline_components = tuple(
        sorted(
            component
            for component in derived_components
            if component.lower() in baseline.affected_components
        )
    )

    coarse_intent = _coarse_intent_for_synopsis(
        chunk_risk,
        new_surface_signal=new_surface_signal,
        file_paths=file_paths,
        matched_baseline_vuln_paths=matched_baseline_vuln_paths,
        matched_baseline_components=matched_baseline_components,
    )
    route = _route_for_intent(coarse_intent)

    reasons = list(chunk_risk.reasons)
    if matched_baseline_vuln_paths:
        reasons.append("baseline_vulnerability_overlap")
    if matched_baseline_components:
        reasons.append("baseline_component_overlap")
    if new_subsystem_roots:
        reasons.append("new_subsystem_surface")

    return CommitSynopsis(
        sha=commit.sha,
        subject=commit.subject,
        file_paths=file_paths,
        derived_components=derived_components,
        matched_baseline_vuln_paths=matched_baseline_vuln_paths,
        matched_baseline_components=matched_baseline_components,
        coarse_intent=coarse_intent,
        route=route,
        risk_tier=chunk_risk.tier,
        reasons=tuple(dict.fromkeys(reasons)),
        dependency_files=chunk_risk.dependency_files,
        new_attack_surface=new_surface_signal,
        new_subsystem_roots=new_subsystem_roots,
        insertions=commit.insertions,
        deletions=commit.deletions,
        changed_files=commit.changed_files,
    )


def _coarse_intent_for_synopsis(
    chunk_risk: ChunkRisk,
    *,
    new_surface_signal: bool,
    file_paths: Sequence[str],
    matched_baseline_vuln_paths: Sequence[str],
    matched_baseline_components: Sequence[str],
) -> CoarseIntent:
    if chunk_risk.dependency_only:
        return "dependency_change"
    if new_surface_signal:
        return "new_surface"
    if chunk_risk.tier == "skip":
        return "likely_non_security"
    if _has_targeted_review_evidence(
        chunk_risk,
        file_paths=file_paths,
        matched_baseline_vuln_paths=matched_baseline_vuln_paths,
        matched_baseline_components=matched_baseline_components,
    ):
        return "existing_surface_delta"
    return "likely_non_security"


def _has_targeted_review_evidence(
    chunk_risk: ChunkRisk,
    *,
    file_paths: Sequence[str],
    matched_baseline_vuln_paths: Sequence[str],
    matched_baseline_components: Sequence[str],
) -> bool:
    if matched_baseline_vuln_paths:
        return True

    reasons = set(chunk_risk.reasons)
    if {"policy_file_changed", "skip_safeguard:script_exec_eval_signal"} & reasons:
        return True

    if not _paths_have_security_signal(file_paths):
        return False

    return chunk_risk.tier == "critical" or bool(matched_baseline_components)


def _paths_have_security_signal(file_paths: Sequence[str]) -> bool:
    for path in file_paths:
        normalized = normalize_path(path).lower()
        if any(keyword in normalized for keyword in SECURITY_KEYWORDS):
            return True
    return False


def _route_for_intent(intent: CoarseIntent) -> ReviewRoute:
    if intent == "new_surface":
        return "incremental_threat_model_then_review"
    if intent == "dependency_change":
        return "supply_chain_review"
    if intent == "likely_non_security":
        return "skip"
    return "targeted_pr_review"


def _build_review_jobs(
    synopses: Sequence[CommitSynopsis],
    baseline: BaselineContext,
) -> tuple[ReviewJob, ...]:
    buckets: dict[tuple[JobType, str], list[_JobSlice]] = {}
    for synopsis in synopses:
        for slice_item in _job_slices_for_synopsis(synopsis, baseline):
            key = (slice_item.job_type, slice_item.subsystem)
            buckets.setdefault(key, []).append(slice_item)

    jobs: list[ReviewJob] = []
    for index, bucket in enumerate(buckets.values(), start=1):
        jobs.append(_build_review_job(job_id=f"job-{index:03d}", slices=tuple(bucket)))
    return tuple(jobs)


def _build_review_job(*, job_id: str, slices: Sequence[_JobSlice]) -> ReviewJob:
    first = slices[0]
    return ReviewJob(
        job_id=job_id,
        job_type=first.job_type,
        subsystem=first.subsystem,
        commit_shas=tuple(dict.fromkeys(item.commit_sha for item in slices)),
        file_paths=tuple(sorted({path for item in slices for path in item.file_paths})),
        baseline_vuln_paths=tuple(
            sorted({path for item in slices for path in item.baseline_vuln_paths})
        ),
        baseline_components=tuple(
            sorted({component for item in slices for component in item.baseline_components})
        ),
        coarse_intents=tuple(dict.fromkeys(item.coarse_intent for item in slices)),
        reasons=tuple(sorted({reason for item in slices for reason in item.reasons})),
    )


def _build_compatibility_clusters(jobs: Sequence[ReviewJob]) -> tuple[ReviewCluster, ...]:
    return tuple(
        ReviewCluster(
            cluster_id=f"cluster-{index:03d}",
            route=_route_for_job_type(job.job_type),
            commit_shas=job.commit_shas,
            file_paths=job.file_paths,
            baseline_vuln_paths=job.baseline_vuln_paths,
            baseline_components=job.baseline_components,
            coarse_intents=job.coarse_intents,
            reasons=job.reasons,
            topic=(job.subsystem,) if job.subsystem else (job.job_type,),
        )
        for index, job in enumerate(jobs, start=1)
    )


def _route_for_job_type(job_type: JobType) -> ReviewRoute:
    if job_type == "new_subsystem_review":
        return "incremental_threat_model_then_review"
    if job_type == "dependency_review":
        return "supply_chain_review"
    if job_type == "baseline_overlap_review":
        return "targeted_pr_review"
    return "skip"


def _coarse_intent_for_job_type(job_type: JobType) -> CoarseIntent:
    if job_type == "new_subsystem_review":
        return "new_surface"
    if job_type == "dependency_review":
        return "dependency_change"
    if job_type == "baseline_overlap_review":
        return "existing_surface_delta"
    return "likely_non_security"


def _job_slices_for_synopsis(
    synopsis: CommitSynopsis,
    baseline: BaselineContext,
) -> tuple[_JobSlice, ...]:
    changed_files = _normalized_changed_files(synopsis)
    if not changed_files:
        subsystem = (
            _structural_subsystem(synopsis.file_paths[0]) if synopsis.file_paths else "empty"
        )
        return (
            _JobSlice(
                commit_sha=synopsis.sha,
                job_type=_job_type_for_synopsis(synopsis),
                subsystem=subsystem,
                file_paths=synopsis.file_paths,
                baseline_vuln_paths=synopsis.matched_baseline_vuln_paths,
                baseline_components=synopsis.matched_baseline_components,
                coarse_intent=synopsis.coarse_intent,
                reasons=synopsis.reasons,
            ),
        )

    dependency_paths = set(synopsis.dependency_files)
    explicit_security_control = _synopsis_has_explicit_security_control_signal(synopsis.reasons)
    buckets: dict[tuple[JobType, str], list[ChangedFile]] = {}

    for changed_file in changed_files:
        path = normalize_path(changed_file.path)
        if not path:
            continue
        job_type, subsystem = _classify_changed_file_job(
            changed_file,
            synopsis=synopsis,
            dependency_paths=dependency_paths,
            explicit_security_control=explicit_security_control,
        )
        buckets.setdefault((job_type, subsystem), []).append(changed_file)

    return tuple(
        _build_job_slice(
            synopsis,
            baseline,
            job_type=job_type,
            subsystem=subsystem,
            changed_files=bucket_files,
        )
        for (job_type, subsystem), bucket_files in buckets.items()
    )


def _job_type_for_synopsis(synopsis: CommitSynopsis) -> JobType:
    if synopsis.coarse_intent == "new_surface":
        return "new_subsystem_review"
    if synopsis.coarse_intent == "dependency_change":
        return "dependency_review"
    if synopsis.coarse_intent == "existing_surface_delta":
        return "baseline_overlap_review"
    return "skip"


def _classify_changed_file_job(
    changed_file: ChangedFile,
    *,
    synopsis: CommitSynopsis,
    dependency_paths: set[str],
    explicit_security_control: bool,
) -> tuple[JobType, str]:
    path = normalize_path(changed_file.path)
    if path in dependency_paths:
        return ("dependency_review", "dependency")

    new_root = _matching_new_subsystem_root(path, synopsis.new_subsystem_roots)
    if new_root:
        return ("new_subsystem_review", new_root)

    if _is_single_file_new_surface(path, changed_file, synopsis):
        return ("new_subsystem_review", _structural_subsystem(path))

    if path in synopsis.matched_baseline_vuln_paths:
        return ("baseline_overlap_review", _structural_subsystem(path))

    if explicit_security_control and not _is_low_signal_new_subsystem_path(path):
        return ("baseline_overlap_review", _structural_subsystem(path))

    if synopsis.matched_baseline_components and _paths_have_security_signal((path,)):
        return ("baseline_overlap_review", _structural_subsystem(path))

    return ("skip", _structural_subsystem(path))


def _is_single_file_new_surface(
    path: str,
    changed_file: ChangedFile,
    synopsis: CommitSynopsis,
) -> bool:
    return (
        synopsis.new_attack_surface
        and changed_file.status.upper().startswith("A")
        and not _is_low_signal_new_subsystem_path(path)
    )


def _build_job_slice(
    synopsis: CommitSynopsis,
    baseline: BaselineContext,
    *,
    job_type: JobType,
    subsystem: str,
    changed_files: Sequence[ChangedFile],
) -> _JobSlice:
    file_paths = tuple(
        sorted(
            {
                normalized
                for changed_file in changed_files
                if (normalized := normalize_path(changed_file.path))
            }
        )
    )
    derived_components = tuple(
        sorted(
            {
                component
                for path in file_paths
                for component in _derive_components_from_file_path(path)
                if component
            }
        )
    )
    chunk_risk = classify_chunk(changed_files, baseline.risk_map)
    matched_baseline_vuln_paths = tuple(
        sorted(path for path in file_paths if path in synopsis.matched_baseline_vuln_paths)
    )
    baseline_components = tuple(
        sorted(
            {
                component
                for component in derived_components
                if component.lower() in baseline.affected_components
            }
        )
    )

    reasons = list(chunk_risk.reasons)
    if matched_baseline_vuln_paths:
        reasons.append("baseline_vulnerability_overlap")
    if baseline_components and job_type == "baseline_overlap_review":
        reasons.append("baseline_component_overlap")
    if job_type == "new_subsystem_review":
        reasons.append("new_subsystem_surface")

    return _JobSlice(
        commit_sha=synopsis.sha,
        job_type=job_type,
        subsystem=subsystem,
        file_paths=file_paths,
        baseline_vuln_paths=matched_baseline_vuln_paths,
        baseline_components=baseline_components,
        coarse_intent=_coarse_intent_for_job_type(job_type),
        reasons=tuple(dict.fromkeys(reasons)),
    )


def _normalized_changed_files(synopsis: CommitSynopsis) -> tuple[ChangedFile, ...]:
    normalized_files = [
        changed_file
        for changed_file in synopsis.changed_files
        if isinstance(changed_file.path, str) and normalize_path(changed_file.path)
    ]
    return tuple(sorted(normalized_files, key=lambda item: normalize_path(item.path)))


def _detect_new_subsystem_roots(changed_files: Sequence[ChangedFile]) -> tuple[str, ...]:
    added_root_counts: dict[str, int] = {}
    for changed_file in changed_files:
        if not changed_file.status.upper().startswith("A"):
            continue
        root = _new_subsystem_root(changed_file.path)
        if not root:
            continue
        added_root_counts[root] = added_root_counts.get(root, 0) + 1

    return tuple(
        sorted(
            root
            for root, count in added_root_counts.items()
            if count >= _NEW_SUBSYSTEM_MIN_ADDED_FILES
        )
    )


def _new_subsystem_root(path: str) -> str | None:
    normalized = normalize_path(path)
    if not normalized or _is_low_signal_new_subsystem_path(normalized):
        return None

    parts = normalized.split("/")
    if len(parts) < _NEW_SUBSYSTEM_NAMESPACE_DEPTH:
        return None
    return "/".join(parts[:_NEW_SUBSYSTEM_NAMESPACE_DEPTH])


def _matching_new_subsystem_root(path: str, new_subsystem_roots: Sequence[str]) -> str | None:
    normalized = normalize_path(path)
    for root in (item.rstrip("/") for item in new_subsystem_roots if item):
        if normalized == root or normalized.startswith(f"{root}/"):
            return root
    return None


def _structural_subsystem(path: str) -> str:
    normalized = normalize_path(path)
    if not normalized:
        return "empty"
    parts = normalized.split("/")
    if len(parts) >= 3:
        return "/".join(parts[:2])
    if len(parts) >= 2:
        return parts[0]
    return normalized


def _synopsis_has_explicit_security_control_signal(reasons: Sequence[str]) -> bool:
    return bool({"policy_file_changed", "skip_safeguard:script_exec_eval_signal"} & set(reasons))


def _is_low_signal_new_subsystem_path(path: str) -> bool:
    normalized = normalize_path(path).lower()
    if not normalized:
        return True
    if normalized.startswith(("docs/", "test/", "tests/", ".github/", "fixtures/")):
        return True
    if any(marker in normalized for marker in (".test.", ".spec.", ".snap.", "/__tests__/")):
        return True
    return normalized.endswith(
        (
            ".md",
            ".mdx",
            ".txt",
            ".rst",
            ".json",
            ".yaml",
            ".yml",
            ".lock",
        )
    )


def _load_vulnerability_entries(path: Path) -> list[dict[str, object]]:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    fixed_content, _ = fix_vulnerabilities_json(raw)
    try:
        parsed = json.loads(fixed_content)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [entry for entry in parsed if isinstance(entry, dict)]


def _run_git_command(repo: Path, cmd: list[str]) -> str:
    result = subprocess.run(
        cmd,
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or "Unknown git error"
        raise RuntimeError(f"{cmd[0]} command failed: {stderr}")
    return result.stdout


def _parse_name_status(output: str) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        raw_status = parts[0].strip()
        status = raw_status[:1] or "M"
        path = parts[-1]
        normalized = normalize_path(path)
        if normalized:
            statuses[normalized] = status
    return statuses


def _parse_numstat(output: str) -> dict[str, tuple[int, int]]:
    stats: dict[str, tuple[int, int]] = {}
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        insertions = 0 if parts[0] == "-" else int(parts[0])
        deletions = 0 if parts[1] == "-" else int(parts[1])
        path = parts[-1]
        normalized = normalize_path(path)
        if normalized:
            stats[normalized] = (insertions, deletions)
    return stats
