"""Tests for range-aware incremental planning."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from securevibes.scanner.incremental_planning import (
    CommitMetadata,
    build_incremental_plan,
    collect_commit_range,
    load_baseline_context,
    plan_incremental_range,
    write_incremental_plan_artifacts,
)
from securevibes.scanner.risk_scorer import ChangedFile


def _write_baseline_artifacts(securevibes_dir: Path) -> None:
    securevibes_dir.mkdir(parents=True, exist_ok=True)
    (securevibes_dir / "THREAT_MODEL.json").write_text(
        json.dumps(
            [
                {
                    "id": "THREAT-001",
                    "severity": "high",
                    "affected_components": ["src:py"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (securevibes_dir / "VULNERABILITIES.json").write_text(
        json.dumps(
            [
                {
                    "file_path": "src/auth.py",
                    "title": "Existing auth flaw",
                    "severity": "high",
                    "line_number": 12,
                }
            ]
        ),
        encoding="utf-8",
    )
    (securevibes_dir / "risk_map.json").write_text(
        json.dumps(
            {
                "critical": ["src/*"],
                "moderate": [],
                "skip": ["docs/*", "package.json"],
            }
        ),
        encoding="utf-8",
    )


def test_plan_incremental_range_rebuilds_missing_risk_map(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir(parents=True, exist_ok=True)
    (repo / "src").mkdir(parents=True, exist_ok=True)
    (repo / "src" / "auth.py").write_text("print('auth')\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text(
        json.dumps(
            [
                {
                    "id": "THREAT-001",
                    "severity": "high",
                    "affected_components": ["src/*"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (securevibes_dir / "VULNERABILITIES.json").write_text("[]\n", encoding="utf-8")

    monkeypatch.setattr(
        "securevibes.scanner.incremental_planning.collect_commit_range",
        lambda *_args, **_kwargs: (),
    )

    plan = plan_incremental_range(
        repo,
        securevibes_dir,
        base_ref="base123",
        head_ref="head456",
    )

    risk_map = json.loads((securevibes_dir / "risk_map.json").read_text(encoding="utf-8"))

    assert plan.synopses == ()
    assert plan.clusters == ()
    assert risk_map["critical"] == ["src/*"]
    assert risk_map["moderate"] == []
    assert "docs/*" in risk_map["skip"]


def test_collect_commit_range_loads_commit_details_in_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_get_commits_between(repo: Path, base: str, head: str) -> list[str]:
        observed["window"] = (repo, base, head)
        return ["c1", "c2"]

    def fake_load_commit_metadata(repo: Path, sha: str) -> CommitMetadata:
        return CommitMetadata(
            sha=sha,
            subject=f"Subject for {sha}",
            body="",
            changed_files=(ChangedFile(path=f"src/{sha}.py", status="M"),),
            insertions=1,
            deletions=0,
        )

    monkeypatch.setattr(
        "securevibes.scanner.incremental_planning.get_commits_between",
        fake_get_commits_between,
    )
    monkeypatch.setattr(
        "securevibes.scanner.incremental_planning._load_commit_metadata",
        fake_load_commit_metadata,
    )

    result = collect_commit_range(Path("/repo"), base="base123", head="head456")

    assert observed["window"] == (Path("/repo"), "base123", "head456")
    assert [commit.sha for commit in result] == ["c1", "c2"]
    assert [commit.subject for commit in result] == ["Subject for c1", "Subject for c2"]


def test_build_incremental_plan_classifies_commit_intents_and_routes(tmp_path: Path) -> None:
    securevibes_dir = tmp_path / ".securevibes"
    _write_baseline_artifacts(securevibes_dir)
    baseline = load_baseline_context(securevibes_dir)

    commits = [
        CommitMetadata(
            sha="commit-existing",
            subject="Modify auth flow",
            body="",
            changed_files=(ChangedFile(path="src/auth.py", status="M"),),
            insertions=8,
            deletions=2,
        ),
        CommitMetadata(
            sha="commit-new-surface",
            subject="Add new plugin service",
            body="",
            changed_files=(ChangedFile(path="plugins/runtime/loader.ts", status="A"),),
            insertions=32,
            deletions=0,
        ),
        CommitMetadata(
            sha="commit-dependency",
            subject="Bump dependencies",
            body="",
            changed_files=(ChangedFile(path="package.json", status="M"),),
            insertions=4,
            deletions=2,
        ),
        CommitMetadata(
            sha="commit-docs",
            subject="Refresh docs",
            body="",
            changed_files=(ChangedFile(path="docs/guide.md", status="M"),),
            insertions=12,
            deletions=3,
        ),
    ]

    plan = build_incremental_plan(
        commits,
        baseline,
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
    )

    synopses = {synopsis.sha: synopsis for synopsis in plan.synopses}

    assert synopses["commit-existing"].coarse_intent == "existing_surface_delta"
    assert synopses["commit-existing"].route == "targeted_pr_review"
    assert synopses["commit-existing"].matched_baseline_vuln_paths == ("src/auth.py",)
    assert synopses["commit-existing"].matched_baseline_components == ("src:py",)

    assert synopses["commit-new-surface"].coarse_intent == "new_surface"
    assert synopses["commit-new-surface"].route == "incremental_threat_model_then_review"

    assert synopses["commit-dependency"].coarse_intent == "dependency_change"
    assert synopses["commit-dependency"].route == "supply_chain_review"
    assert synopses["commit-dependency"].dependency_files == ("package.json",)

    assert synopses["commit-docs"].coarse_intent == "likely_non_security"
    assert synopses["commit-docs"].route == "skip"


def test_build_incremental_plan_skips_generic_component_overlap_without_security_signal(
    tmp_path: Path,
) -> None:
    securevibes_dir = tmp_path / ".securevibes"
    _write_baseline_artifacts(securevibes_dir)
    baseline = load_baseline_context(securevibes_dir)

    plan = build_incremental_plan(
        [
            CommitMetadata(
                sha="commit-generic",
                subject="Refactor generic service helper",
                body="",
                changed_files=(ChangedFile(path="src/service.py", status="M"),),
                insertions=10,
                deletions=4,
            )
        ],
        baseline,
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
    )

    synopsis = plan.synopses[0]

    assert synopsis.matched_baseline_components == ("src:py",)
    assert synopsis.coarse_intent == "likely_non_security"
    assert synopsis.route == "skip"


def test_build_incremental_plan_clusters_existing_surface_commits_by_component(
    tmp_path: Path,
) -> None:
    securevibes_dir = tmp_path / ".securevibes"
    _write_baseline_artifacts(securevibes_dir)
    baseline = load_baseline_context(securevibes_dir)

    commits = [
        CommitMetadata(
            sha="commit-a",
            subject="Auth changes",
            body="",
            changed_files=(ChangedFile(path="src/auth.py", status="M"),),
            insertions=10,
            deletions=2,
        ),
        CommitMetadata(
            sha="commit-b",
            subject="Auth session changes",
            body="",
            changed_files=(ChangedFile(path="src/auth_session.py", status="M"),),
            insertions=7,
            deletions=1,
        ),
    ]

    plan = build_incremental_plan(
        commits,
        baseline,
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
    )

    assert len(plan.clusters) == 1
    cluster = plan.clusters[0]
    assert cluster.route == "targeted_pr_review"
    assert cluster.commit_shas == ("commit-a", "commit-b")
    assert cluster.baseline_components == ("src:py",)
    assert set(cluster.file_paths) == {"src/auth.py", "src/auth_session.py"}


def test_build_incremental_plan_splits_oversized_single_commit_by_file_budget(
    tmp_path: Path,
) -> None:
    securevibes_dir = tmp_path / ".securevibes"
    _write_baseline_artifacts(securevibes_dir)
    baseline = load_baseline_context(securevibes_dir)

    large_commit = CommitMetadata(
        sha="commit-huge",
        subject="Large auth refactor",
        body="",
        changed_files=tuple(
            ChangedFile(
                path=f"src/auth_module_{index:02d}.py",
                status="M",
                insertions=10,
                deletions=0,
            )
            for index in range(20)
        ),
        insertions=200,
        deletions=0,
    )

    plan = build_incremental_plan(
        [large_commit],
        baseline,
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
    )

    assert len(plan.clusters) == 2
    assert plan.clusters[0].route == "targeted_pr_review"
    assert plan.clusters[1].route == "targeted_pr_review"
    assert plan.clusters[0].commit_shas == ("commit-huge",)
    assert plan.clusters[1].commit_shas == ("commit-huge",)
    assert len(plan.clusters[0].file_paths) == 15
    assert len(plan.clusters[1].file_paths) == 5
    assert "split_for_diff_budget" in plan.clusters[0].reasons
    assert "split_for_diff_budget" in plan.clusters[1].reasons


def test_build_incremental_plan_splits_targeted_bucket_by_line_budget(
    tmp_path: Path,
) -> None:
    securevibes_dir = tmp_path / ".securevibes"
    _write_baseline_artifacts(securevibes_dir)
    baseline = load_baseline_context(securevibes_dir)

    commits = [
        CommitMetadata(
            sha="commit-a",
            subject="Auth changes",
            body="",
            changed_files=(
                ChangedFile(path="src/auth.py", status="M", insertions=320, deletions=0),
            ),
            insertions=320,
            deletions=0,
        ),
        CommitMetadata(
            sha="commit-b",
            subject="Auth session changes",
            body="",
            changed_files=(
                ChangedFile(path="src/auth_session.py", status="M", insertions=320, deletions=0),
            ),
            insertions=320,
            deletions=0,
        ),
    ]

    plan = build_incremental_plan(
        commits,
        baseline,
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
    )

    assert len(plan.clusters) == 2
    assert plan.clusters[0].commit_shas == ("commit-a",)
    assert plan.clusters[1].commit_shas == ("commit-b",)
    assert "split_for_diff_budget" in plan.clusters[0].reasons
    assert "split_for_diff_budget" in plan.clusters[1].reasons


def test_build_incremental_plan_reroutes_docs_slice_to_skip_cluster(
    tmp_path: Path,
) -> None:
    securevibes_dir = tmp_path / ".securevibes"
    _write_baseline_artifacts(securevibes_dir)
    baseline = load_baseline_context(securevibes_dir)

    plan = build_incremental_plan(
        [
            CommitMetadata(
                sha="commit-mixed",
                subject="Auth change with docs",
                body="",
                changed_files=(
                    ChangedFile(path="src/auth.py", status="M", insertions=10, deletions=2),
                    ChangedFile(path="docs/guide.md", status="M", insertions=20, deletions=0),
                ),
                insertions=30,
                deletions=2,
            )
        ],
        baseline,
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
    )

    routes_by_paths = {cluster.file_paths: cluster.route for cluster in plan.clusters}

    assert routes_by_paths[("src/auth.py",)] == "targeted_pr_review"
    assert routes_by_paths[("docs/guide.md",)] == "skip"


def test_build_incremental_plan_reroutes_dependency_slice_to_supply_chain_cluster(
    tmp_path: Path,
) -> None:
    securevibes_dir = tmp_path / ".securevibes"
    _write_baseline_artifacts(securevibes_dir)
    baseline = load_baseline_context(securevibes_dir)

    plan = build_incremental_plan(
        [
            CommitMetadata(
                sha="commit-mixed",
                subject="Auth change with dependency bump",
                body="",
                changed_files=(
                    ChangedFile(path="src/auth.py", status="M", insertions=10, deletions=2),
                    ChangedFile(path="package.json", status="M", insertions=4, deletions=1),
                ),
                insertions=14,
                deletions=3,
            )
        ],
        baseline,
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
    )

    routes_by_paths = {cluster.file_paths: cluster.route for cluster in plan.clusters}

    assert routes_by_paths[("src/auth.py",)] == "targeted_pr_review"
    assert routes_by_paths[("package.json",)] == "supply_chain_review"


def test_write_incremental_plan_artifacts_persists_synopsis_and_hypotheses(
    tmp_path: Path,
) -> None:
    securevibes_dir = tmp_path / ".securevibes"
    _write_baseline_artifacts(securevibes_dir)
    baseline = load_baseline_context(securevibes_dir)

    plan = build_incremental_plan(
        [
            CommitMetadata(
                sha="commit-existing",
                subject="Modify auth flow",
                body="",
                changed_files=(ChangedFile(path="src/auth.py", status="M"),),
                insertions=8,
                deletions=2,
            )
        ],
        baseline,
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
    )

    write_incremental_plan_artifacts(securevibes_dir, plan)

    synopsis_path = securevibes_dir / "incremental_synopsis.json"
    hypotheses_path = securevibes_dir / "incremental_hypotheses.json"

    assert synopsis_path.exists()
    assert hypotheses_path.exists()

    synopsis_payload = json.loads(synopsis_path.read_text(encoding="utf-8"))
    hypotheses_payload = json.loads(hypotheses_path.read_text(encoding="utf-8"))

    assert synopsis_payload["schema_version"] == 1
    assert synopsis_payload["base_ref"] == "base123"
    assert synopsis_payload["head_ref"] == "head456"
    assert synopsis_payload["commits"][0]["sha"] == "commit-existing"
    assert synopsis_payload["commits"][0]["coarse_intent"] == "existing_surface_delta"

    assert hypotheses_payload["schema_version"] == 1
    assert hypotheses_payload["base_ref"] == "base123"
    assert hypotheses_payload["head_ref"] == "head456"
    assert hypotheses_payload["clusters"][0]["route"] == "targeted_pr_review"
    assert hypotheses_payload["clusters"][0]["commit_shas"] == ["commit-existing"]


def test_plan_incremental_range_orchestrates_collection_build_and_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    securevibes_dir = repo / ".securevibes"
    repo.mkdir()
    securevibes_dir.mkdir()

    observed: dict[str, object] = {}
    commits = [
        CommitMetadata(
            sha="commit-existing",
            subject="Modify auth flow",
            body="",
            changed_files=(ChangedFile(path="src/auth.py", status="M"),),
            insertions=8,
            deletions=2,
        )
    ]

    def fake_load_baseline_context(path: Path, *, repo: Path | None = None):
        observed["baseline_path"] = path
        observed["baseline_repo"] = repo
        return "baseline"

    def fake_collect_commit_range(path: Path, *, base: str, head: str):
        observed["range"] = (path, base, head)
        return commits

    def fake_build_incremental_plan(
        commit_items,
        baseline,
        *,
        base_ref: str,
        head_ref: str,
        generated_at: str | None = None,
    ):
        observed["build"] = (commit_items, baseline, base_ref, head_ref, generated_at)
        return build_incremental_plan(
            commit_items,
            load_baseline_context(securevibes_dir),
            base_ref=base_ref,
            head_ref=head_ref,
            generated_at=generated_at,
        )

    def fake_write_incremental_plan_artifacts(path: Path, plan) -> None:
        observed["write"] = (path, plan.base_ref, plan.head_ref, len(plan.synopses))

    _write_baseline_artifacts(securevibes_dir)
    monkeypatch.setattr(
        "securevibes.scanner.incremental_planning.load_baseline_context",
        fake_load_baseline_context,
    )
    monkeypatch.setattr(
        "securevibes.scanner.incremental_planning.collect_commit_range",
        fake_collect_commit_range,
    )
    monkeypatch.setattr(
        "securevibes.scanner.incremental_planning.build_incremental_plan",
        fake_build_incremental_plan,
    )
    monkeypatch.setattr(
        "securevibes.scanner.incremental_planning.write_incremental_plan_artifacts",
        fake_write_incremental_plan_artifacts,
    )

    plan = plan_incremental_range(
        repo,
        securevibes_dir,
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
    )

    assert observed["baseline_path"] == securevibes_dir
    assert observed["baseline_repo"] == repo
    assert observed["range"] == (repo, "base123", "head456")
    assert observed["build"][1] == "baseline"
    assert observed["write"] == (securevibes_dir, "base123", "head456", 1)
    assert plan.base_ref == "base123"
    assert plan.head_ref == "head456"


def test_plan_incremental_range_writes_empty_artifacts_for_empty_commit_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    securevibes_dir = repo / ".securevibes"
    repo.mkdir()
    _write_baseline_artifacts(securevibes_dir)

    monkeypatch.setattr(
        "securevibes.scanner.incremental_planning.collect_commit_range",
        lambda *_args, **_kwargs: [],
    )

    plan = plan_incremental_range(
        repo,
        securevibes_dir,
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
    )

    synopsis_payload = json.loads(
        (securevibes_dir / "incremental_synopsis.json").read_text(encoding="utf-8")
    )
    hypotheses_payload = json.loads(
        (securevibes_dir / "incremental_hypotheses.json").read_text(encoding="utf-8")
    )

    assert plan.synopses == ()
    assert plan.clusters == ()
    assert synopsis_payload["commit_count"] == 0
    assert synopsis_payload["commits"] == []
    assert hypotheses_payload["cluster_count"] == 0
    assert hypotheses_payload["clusters"] == []
