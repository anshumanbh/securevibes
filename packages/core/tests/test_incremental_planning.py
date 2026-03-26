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
    assert plan.jobs == ()
    assert plan.clusters == ()
    assert risk_map["critical"] == ["src/*"]
    assert risk_map["moderate"] == []
    assert "docs/*" in risk_map["skip"]


def test_plan_incremental_range_tolerates_malformed_vulnerabilities_json(
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
    (securevibes_dir / "risk_map.json").write_text(
        json.dumps(
            {
                "critical": ["src/*"],
                "moderate": [],
                "skip": ["docs/*"],
            }
        ),
        encoding="utf-8",
    )
    (securevibes_dir / "VULNERABILITIES.json").write_text(
        '[{"file_path":"src/auth.py","title":"bad","severity":"high","code_snippet":"\\\\q"}]\n',
        encoding="utf-8",
    )

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

    assert plan.synopses == ()
    assert plan.jobs == ()
    assert plan.clusters == ()


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


def test_build_incremental_plan_emits_simple_review_jobs(tmp_path: Path) -> None:
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

    jobs_by_type = {job.job_type: job for job in plan.jobs}

    assert jobs_by_type["baseline_overlap_review"].file_paths == ("src/auth.py",)
    assert jobs_by_type["baseline_overlap_review"].subsystem == "src"
    assert jobs_by_type["new_subsystem_review"].file_paths == ("plugins/runtime/loader.ts",)
    assert jobs_by_type["new_subsystem_review"].subsystem == "plugins/runtime"
    assert jobs_by_type["dependency_review"].file_paths == ("package.json",)
    assert jobs_by_type["dependency_review"].subsystem == "dependency"
    assert jobs_by_type["skip"].file_paths == ("docs/guide.md",)
    assert jobs_by_type["skip"].subsystem == "docs"

    assert [cluster.route for cluster in plan.clusters] == [
        "targeted_pr_review",
        "incremental_threat_model_then_review",
        "supply_chain_review",
        "skip",
    ]


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
    assert len(plan.jobs) == 1
    assert plan.jobs[0].job_type == "skip"
    assert plan.clusters[0].route == "skip"


def test_build_incremental_plan_promotes_new_nested_subsystems_to_review_jobs(
    tmp_path: Path,
) -> None:
    securevibes_dir = tmp_path / ".securevibes"
    _write_baseline_artifacts(securevibes_dir)
    baseline = load_baseline_context(securevibes_dir)

    changed_files = (
        ChangedFile(path="src/acp/control-plane/manager.core.ts", status="A", insertions=120),
        ChangedFile(path="src/acp/runtime/registry.ts", status="A", insertions=80),
        ChangedFile(path="src/acp/runtime/session-identity.ts", status="A", insertions=60),
    )

    plan = build_incremental_plan(
        [
            CommitMetadata(
                sha="commit-acp",
                subject="Add ACP runtime",
                body="",
                changed_files=changed_files,
                insertions=260,
                deletions=0,
            )
        ],
        baseline,
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-24T12:00:00Z",
    )

    assert len(plan.jobs) == 1
    assert plan.jobs[0].job_type == "new_subsystem_review"
    assert plan.jobs[0].subsystem == "src/acp"
    assert set(plan.jobs[0].file_paths) == {
        "src/acp/control-plane/manager.core.ts",
        "src/acp/runtime/registry.ts",
        "src/acp/runtime/session-identity.ts",
    }
    assert "new_subsystem_surface" in plan.jobs[0].reasons
    assert plan.clusters[0].route == "incremental_threat_model_then_review"


def test_build_incremental_plan_separates_multiple_new_subsystems(tmp_path: Path) -> None:
    securevibes_dir = tmp_path / ".securevibes"
    _write_baseline_artifacts(securevibes_dir)
    (securevibes_dir / "risk_map.json").write_text(
        json.dumps(
            {
                "critical": ["src/*"],
                "moderate": ["backend/*"],
                "skip": ["docs/*", "package.json"],
            }
        ),
        encoding="utf-8",
    )
    baseline = load_baseline_context(securevibes_dir)

    changed_files = (
        ChangedFile(path="backend/acp/control-plane/manager.core.ts", status="A", insertions=40),
        ChangedFile(path="backend/acp/runtime/registry.ts", status="A", insertions=40),
        ChangedFile(path="backend/acp/runtime/session-identity.ts", status="A", insertions=40),
        ChangedFile(path="backend/mcp/server.ts", status="A", insertions=40),
        ChangedFile(path="backend/mcp/router.ts", status="A", insertions=40),
        ChangedFile(path="backend/mcp/session.ts", status="A", insertions=40),
    )

    plan = build_incremental_plan(
        [
            CommitMetadata(
                sha="commit-backend-subsystems",
                subject="Add ACP and MCP backends",
                body="",
                changed_files=changed_files,
                insertions=240,
                deletions=0,
            )
        ],
        baseline,
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-25T12:00:00Z",
    )

    jobs_by_subsystem = {job.subsystem: job for job in plan.jobs}

    assert set(jobs_by_subsystem) == {"backend/acp", "backend/mcp"}
    assert jobs_by_subsystem["backend/acp"].job_type == "new_subsystem_review"
    assert jobs_by_subsystem["backend/mcp"].job_type == "new_subsystem_review"


def test_build_incremental_plan_groups_baseline_overlap_by_subsystem(tmp_path: Path) -> None:
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

    assert len(plan.jobs) == 1
    job = plan.jobs[0]
    assert job.job_type == "baseline_overlap_review"
    assert job.commit_shas == ("commit-a", "commit-b")
    assert job.subsystem == "src"
    assert set(job.file_paths) == {"src/auth.py", "src/auth_session.py"}
    assert plan.clusters[0].route == "targeted_pr_review"


def test_build_incremental_plan_splits_mixed_commit_into_jobs(tmp_path: Path) -> None:
    securevibes_dir = tmp_path / ".securevibes"
    _write_baseline_artifacts(securevibes_dir)
    baseline = load_baseline_context(securevibes_dir)

    plan = build_incremental_plan(
        [
            CommitMetadata(
                sha="commit-mixed",
                subject="Auth change with dependency and docs",
                body="",
                changed_files=(
                    ChangedFile(path="src/auth.py", status="M", insertions=10, deletions=2),
                    ChangedFile(path="package.json", status="M", insertions=4, deletions=1),
                    ChangedFile(path="docs/guide.md", status="M", insertions=20, deletions=0),
                ),
                insertions=34,
                deletions=3,
            )
        ],
        baseline,
        base_ref="base123",
        head_ref="head456",
        generated_at="2026-03-20T12:00:00Z",
    )

    jobs_by_type = {job.job_type: job for job in plan.jobs}

    assert jobs_by_type["baseline_overlap_review"].file_paths == ("src/auth.py",)
    assert jobs_by_type["dependency_review"].file_paths == ("package.json",)
    assert jobs_by_type["skip"].file_paths == ("docs/guide.md",)


def test_write_incremental_plan_artifacts_persists_synopsis_jobs_and_clusters(
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

    synopsis_payload = json.loads(synopsis_path.read_text(encoding="utf-8"))
    hypotheses_payload = json.loads(hypotheses_path.read_text(encoding="utf-8"))

    assert synopsis_payload["schema_version"] == 1
    assert synopsis_payload["commits"][0]["coarse_intent"] == "existing_surface_delta"

    assert hypotheses_payload["schema_version"] == 2
    assert hypotheses_payload["job_count"] == 1
    assert hypotheses_payload["jobs"][0]["job_type"] == "baseline_overlap_review"
    assert hypotheses_payload["jobs"][0]["subsystem"] == "src"
    assert hypotheses_payload["cluster_count"] == 1
    assert hypotheses_payload["clusters"][0]["route"] == "targeted_pr_review"


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
        observed["write"] = (path, plan.base_ref, plan.head_ref, len(plan.jobs))

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
    assert plan.jobs == ()
    assert plan.clusters == ()
    assert synopsis_payload["commit_count"] == 0
    assert synopsis_payload["commits"] == []
    assert hypotheses_payload["job_count"] == 0
    assert hypotheses_payload["jobs"] == []
    assert hypotheses_payload["cluster_count"] == 0
    assert hypotheses_payload["clusters"] == []
