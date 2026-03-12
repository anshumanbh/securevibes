"""Tests for OpenClaw benchmark orchestration scripts."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
BENCHMARK_SCRIPTS = (
    REPO_ROOT / "docs" / "benchmarks" / "openclaw-ghsa-batch1" / "scripts"
)


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def run_case_module() -> ModuleType:
    return _load_module("openclaw_run_case", BENCHMARK_SCRIPTS / "run_case.py")


@pytest.fixture(scope="module")
def run_sweep_module() -> ModuleType:
    return _load_module("openclaw_run_sweep", BENCHMARK_SCRIPTS / "run_sweep.py")


def test_run_case_intro_only_flag_is_supported(run_case_module: ModuleType) -> None:
    args = run_case_module.parse_args(["--ghsa", "GHSA-test", "--intro-only"])
    assert args.intro_only is True
    assert args.baseline_only is False


def test_run_case_intro_threat_model_refresh_flag_is_supported(
    run_case_module: ModuleType,
) -> None:
    args = run_case_module.parse_args(
        ["--ghsa", "GHSA-test", "--intro-only", "--intro-threat-model-refresh"]
    )
    assert args.intro_threat_model_refresh is True


def test_run_case_pr_budget_flags_are_supported(run_case_module: ModuleType) -> None:
    args = run_case_module.parse_args(
        [
            "--ghsa",
            "GHSA-test",
            "--intro-only",
            "--pr-attempts",
            "2",
            "--pr-timeout",
            "120",
        ]
    )
    assert args.pr_attempts == 2
    assert args.pr_timeout == 120


def test_run_case_auto_intro_threat_model_refresh_flag_is_supported(
    run_case_module: ModuleType,
) -> None:
    args = run_case_module.parse_args(
        ["--ghsa", "GHSA-test", "--intro-only", "--auto-intro-threat-model-refresh"]
    )
    assert args.auto_intro_threat_model_refresh is True


def test_run_case_skip_low_signal_split_shards_flag_is_supported(
    run_case_module: ModuleType,
) -> None:
    args = run_case_module.parse_args(
        ["--ghsa", "GHSA-test", "--intro-only", "--skip-low-signal-split-shards"]
    )
    assert args.skip_low_signal_split_shards is True


def test_run_case_rejects_intro_and_baseline_together(
    run_case_module: ModuleType,
) -> None:
    with pytest.raises(SystemExit) as exc:
        run_case_module.parse_args(
            ["--ghsa", "GHSA-test", "--intro-only", "--baseline-only"]
        )
    assert exc.value.code == 2


def test_run_case_dry_run_payload_includes_intro_only(
    run_case_module: ModuleType,
) -> None:
    payload = run_case_module.build_dry_run_payload(
        ghsa="GHSA-test",
        securevibes_repo=Path("/tmp/sv"),
        securevibes_commit="abc123",
        openclaw_repo=Path("/tmp/openclaw"),
        baseline="base123",
        intro_range="base123..intro456",
        fix_range="intro456..fix789",
        baseline_only=False,
        intro_only=True,
        skip_low_signal_split_shards=True,
        baseline_cache_enabled=True,
        refresh_baseline_cache=False,
        baseline_cache_entry=Path("/tmp/cache-entry"),
        baseline_cmd=["securevibes", "scan"],
        intro_threat_model_cmd=["securevibes", "scan", "--subagent", "threat-modeling"],
        intro_cmd=["securevibes", "pr-review", "--range", "base..intro"],
        fix_cmd=["securevibes", "pr-review", "--range", "intro..fix"],
    )
    assert payload["intro_only"] is True
    assert payload["baseline_only"] is False
    assert payload["skip_low_signal_split_shards"] is True
    assert payload["commands"]["intro_threat_modeling"] == [
        "securevibes",
        "scan",
        "--subagent",
        "threat-modeling",
    ]
    assert payload["commands"]["fix_pr_review"] == [
        "securevibes",
        "pr-review",
        "--range",
        "intro..fix",
    ]


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        (
            {
                "baseline_only": True,
                "intro_only": False,
                "baseline_effective_success": True,
                "intro_effective_success": False,
                "fix_effective_success": False,
            },
            "baseline_only_completed",
        ),
        (
            {
                "baseline_only": False,
                "intro_only": True,
                "baseline_effective_success": True,
                "intro_effective_success": True,
                "fix_effective_success": False,
            },
            "intro_only_completed",
        ),
        (
            {
                "baseline_only": False,
                "intro_only": True,
                "baseline_effective_success": True,
                "intro_effective_success": False,
                "fix_effective_success": False,
            },
            "intro_only_failed",
        ),
        (
            {
                "baseline_only": False,
                "intro_only": False,
                "baseline_effective_success": True,
                "intro_effective_success": True,
                "fix_effective_success": True,
            },
            "completed",
        ),
        (
            {
                "baseline_only": False,
                "intro_only": False,
                "baseline_effective_success": True,
                "intro_effective_success": True,
                "fix_effective_success": False,
            },
            "partial_or_failed",
        ),
    ],
)
def test_run_case_status_resolution(
    run_case_module: ModuleType, kwargs: dict[str, bool], expected: str
) -> None:
    assert run_case_module.determine_run_status(**kwargs) == expected


def test_run_case_commit_shas_from_entries(run_case_module: ModuleType) -> None:
    entries = [
        {"sha": "abc123", "subject": "one"},
        {"sha": "def456", "subject": "two"},
        {"not_sha": "ignored"},
    ]
    assert run_case_module.commit_shas_from_entries(entries) == ["abc123", "def456"]


def test_run_case_replace_range_arg(run_case_module: ModuleType) -> None:
    cmd = ["python3", "-m", "securevibes.cli.main", "pr-review", ".", "--range", "old"]
    updated = run_case_module.replace_range_arg(cmd, "new-range")
    assert "--range" in updated
    assert updated[updated.index("--range") + 1] == "new-range"


def test_run_case_replace_range_with_diff_arg(run_case_module: ModuleType) -> None:
    cmd = ["python3", "-m", "securevibes.cli.main", "pr-review", ".", "--range", "old"]
    updated = run_case_module.replace_range_with_diff_arg(
        cmd,
        Path("/tmp/commit.patch"),
    )
    assert "--range" not in updated
    assert "--diff" in updated
    assert updated[updated.index("--diff") + 1] == "/tmp/commit.patch"


def test_run_case_filter_split_review_files(run_case_module: ModuleType) -> None:
    paths = [
        "docs/guide.md",
        "CHANGELOG.md",
        "src/plugins/install.ts",
        "src/config/schema.ts",
    ]
    filtered = run_case_module.filter_split_review_files(paths)
    assert filtered == ["src/plugins/install.ts", "src/config/schema.ts"]


def test_run_case_patch_has_new_connection_signals(run_case_module: ModuleType) -> None:
    patch = """diff --git a/src/a.ts b/src/a.ts
--- a/src/a.ts
+++ b/src/a.ts
@@ -1,1 +1,2 @@
+import { install } from './plugins/install'
 const x = 1
"""
    assert run_case_module.patch_has_new_connection_signals(patch) is True
    assert (
        run_case_module.patch_has_new_connection_signals(
            "diff --git a/a b/a\n@@ -1 +1 @@\n+const value = 1\n"
        )
        is False
    )


def test_run_case_command_hit_rate_limit_detects_explicit_message(
    run_case_module: ModuleType,
) -> None:
    assert (
        run_case_module.command_hit_rate_limit(
            "You've hit your limit · resets 2am (America/Los_Angeles)", ""
        )
        is True
    )


def test_run_case_command_hit_rate_limit_detects_unreadable_pr_artifact_failure(
    run_case_module: ModuleType,
) -> None:
    stdout = (
        "ERROR: PR code review agent did not produce a readable "
        "PR_VULNERABILITIES.json after 4 attempt(s). Refusing fail-open PR review result."
    )
    assert run_case_module.command_hit_rate_limit(stdout, "") is True


def test_run_case_command_hit_rate_limit_detects_wrapped_unreadable_pr_artifact_failure(
    run_case_module: ModuleType,
) -> None:
    stdout = (
        "ERROR: PR code review agent did not produce a readable PR_VULNERABILITIES.json \n"
        "after 4 attempt(s). Refusing fail-open PR review result."
    )
    assert run_case_module.command_hit_rate_limit(stdout, "") is True


def test_run_case_command_hit_rate_limit_ignores_non_rate_limit_errors(
    run_case_module: ModuleType,
) -> None:
    stdout = "ERROR: PR review aborted: diff context exceeds safe analysis limits."
    assert run_case_module.command_hit_rate_limit(stdout, "") is False


def test_run_case_group_touches_baseline_risk(run_case_module: ModuleType) -> None:
    group = ["src/plugins/install.ts", "src/plugins/loader.ts"]
    assert run_case_module.group_touches_baseline_risk(group, {"src/plugins"}) is True
    assert run_case_module.group_touches_baseline_risk(group, {"src/hooks"}) is False


def test_run_case_group_introduces_component_novel_to_baseline(
    run_case_module: ModuleType,
) -> None:
    group = ["src/plugins/install.ts", "src/plugins/loader.ts"]
    assert (
        run_case_module.group_introduces_component_novel_to_baseline(
            group, {"src/plugins"}
        )
        is False
    )
    assert (
        run_case_module.group_introduces_component_novel_to_baseline(
            group, {"src/hooks"}
        )
        is True
    )
    assert (
        run_case_module.group_introduces_component_novel_to_baseline(group, set())
        is True
    )


def test_run_case_chunk_paths(run_case_module: ModuleType) -> None:
    paths = ["a", "b", "c", "d", "e"]
    chunks = run_case_module.chunk_paths(paths, 2)
    assert chunks == [["a", "b"], ["c", "d"], ["e"]]


def test_run_case_split_component_key(run_case_module: ModuleType) -> None:
    assert (
        run_case_module.split_component_key("src/plugins/install.ts") == "src/plugins"
    )
    assert (
        run_case_module.split_component_key("extensions/foo/index.ts")
        == "extensions/foo"
    )
    assert run_case_module.split_component_key("README.md") == "readme.md"


def test_run_case_build_component_split_groups_prioritizes_risk_components(
    run_case_module: ModuleType,
) -> None:
    groups = run_case_module.build_component_split_groups(
        [
            "src/hooks/install.ts",
            "src/hooks/loader.ts",
            "src/plugins/install.ts",
            "src/plugins/loader.ts",
        ],
        group_size=4,
        prioritized_components={"src/plugins"},
    )
    assert groups
    assert groups[0] == ["src/plugins/install.ts", "src/plugins/loader.ts"]


def test_run_case_should_preemptively_split_commit(run_case_module: ModuleType) -> None:
    changed_paths = [
        "src/a.ts",
        "src/b.ts",
        "src/c.ts",
        "src/d.ts",
        "src/e.ts",
        "src/f.ts",
        "src/g.ts",
        "src/h.ts",
        "src/i.ts",
    ]
    assert run_case_module.should_preemptively_split_commit(changed_paths) is True


def test_run_case_should_not_preemptively_split_small_commit(
    run_case_module: ModuleType,
) -> None:
    changed_paths = ["src/a.ts", "src/b.ts", "src/c.ts"]
    assert run_case_module.should_preemptively_split_commit(changed_paths) is False


def test_run_case_context_limit_detection(run_case_module: ModuleType) -> None:
    stdout = "Error: PR review aborted: diff context exceeds safe analysis limits."
    assert run_case_module.pr_review_hit_context_limits(stdout, "") is True
    assert run_case_module.pr_review_hit_context_limits("normal output", "") is False


def test_run_case_merge_pr_review_reports(
    run_case_module: ModuleType, tmp_path: Path
) -> None:
    report_a = tmp_path / "a.json"
    report_b = tmp_path / "b.json"
    merged = tmp_path / "merged.json"

    shared_issue = {
        "threat_id": "THREAT-001",
        "title": "Path traversal",
        "severity": "critical",
    }
    issue_b = {
        "threat_id": "THREAT-002",
        "title": "Command injection",
        "severity": "high",
    }

    report_a.write_text(
        '{"issues": ['
        '{"threat_id":"THREAT-001","title":"Path traversal","severity":"critical"}'
        "]}",
        encoding="utf-8",
    )
    report_b.write_text(
        '{"issues": ['
        '{"threat_id":"THREAT-001","title":"Path traversal","severity":"critical"},'
        '{"threat_id":"THREAT-002","title":"Command injection","severity":"high"}'
        "]}",
        encoding="utf-8",
    )

    run_case_module.merge_pr_review_reports([report_a, report_b], merged)
    payload = run_case_module.load_json(merged)
    issues = payload.get("issues")
    assert isinstance(issues, list)
    assert len(issues) == 2
    assert shared_issue in issues
    assert issue_b in issues


def test_run_case_run_intro_reviews_by_commit_checks_out_each_commit(
    run_case_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    work_repo = tmp_path / "work_repo"
    run_dir = tmp_path / "run"
    intro_repo_report = work_repo / ".securevibes" / "benchmark-reports" / "intro.json"
    intro_repo_report.parent.mkdir(parents=True)
    run_dir.mkdir()

    checkout_calls: list[str] = []
    review_ranges: list[str] = []

    def fake_checkout_repo_ref(repo: Path, ref: str) -> None:
        assert repo == work_repo
        checkout_calls.append(ref)

    def fake_run(
        cmd: list[str],
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[int, str, str]:
        assert cwd is None
        assert env == {"ENV": "1"}
        review_range = cmd[cmd.index("--range") + 1]
        review_ranges.append(review_range)
        intro_repo_report.write_text(
            json.dumps(
                {
                    "issues": [
                        {
                            "title": review_range,
                            "severity": "high",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return 0, "", ""

    monkeypatch.setattr(run_case_module, "checkout_repo_ref", fake_checkout_repo_ref)
    monkeypatch.setattr(run_case_module, "run", fake_run)
    monkeypatch.setattr(
        run_case_module,
        "should_preemptively_split_commit",
        lambda changed_paths: False,
    )

    reports, ranges, rate_limited, split_summary = (
        run_case_module.run_intro_reviews_by_commit(
            work_repo=work_repo,
            intro_commit_shas=["abc123", "def456"],
            intro_cmd=[
                "python3",
                "-m",
                "securevibes.cli.main",
                "pr-review",
                ".",
                "--range",
                "old",
            ],
            intro_env={"ENV": "1"},
            intro_repo_report=intro_repo_report,
            run_dir=run_dir,
            intro_commit_paths={
                "abc123": ["src/a.ts"],
                "def456": ["src/b.ts"],
            },
            baseline_risk_components=set(),
            skip_low_signal_shards=False,
        )
    )

    assert checkout_calls == ["abc123", "def456"]
    assert review_ranges == ["abc123^..abc123", "def456^..def456"]
    assert ranges == review_ranges
    assert len(reports) == 2
    assert rate_limited is False
    assert split_summary == {
        "total_groups": 0,
        "executed_groups": 0,
        "skipped_groups": 0,
        "baseline_touch_groups": 0,
        "new_surface_groups": 0,
        "skipped_reasons": {},
    }


def test_run_case_run_intro_reviews_by_commit_checks_out_before_split_review(
    run_case_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    work_repo = tmp_path / "work_repo"
    run_dir = tmp_path / "run"
    intro_repo_report = work_repo / ".securevibes" / "benchmark-reports" / "intro.json"
    intro_repo_report.parent.mkdir(parents=True)
    run_dir.mkdir()

    checkout_calls: list[str] = []
    split_calls: list[str] = []

    def fake_checkout_repo_ref(repo: Path, ref: str) -> None:
        assert repo == work_repo
        checkout_calls.append(ref)

    def fake_split_reviews(
        **kwargs: object,
    ) -> tuple[list[Path], bool, dict[str, object]]:
        sha = kwargs["sha"]
        assert checkout_calls[-1] == sha
        split_calls.append(str(sha))
        split_report = run_dir / f"{sha}.split.json"
        split_report.write_text(
            json.dumps(
                {
                    "issues": [
                        {
                            "title": f"split-{sha}",
                            "severity": "high",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return (
            [split_report],
            False,
            {
                "total_groups": 1,
                "executed_groups": 1,
                "skipped_groups": 0,
                "baseline_touch_groups": 1,
                "new_surface_groups": 0,
                "skipped_reasons": {},
            },
        )

    monkeypatch.setattr(run_case_module, "checkout_repo_ref", fake_checkout_repo_ref)
    monkeypatch.setattr(
        run_case_module,
        "should_preemptively_split_commit",
        lambda changed_paths: True,
    )
    monkeypatch.setattr(
        run_case_module,
        "run_commit_split_diff_reviews",
        fake_split_reviews,
    )

    reports, ranges, rate_limited, split_summary = (
        run_case_module.run_intro_reviews_by_commit(
            work_repo=work_repo,
            intro_commit_shas=["abc123"],
            intro_cmd=[
                "python3",
                "-m",
                "securevibes.cli.main",
                "pr-review",
                ".",
                "--range",
                "old",
            ],
            intro_env={"ENV": "1"},
            intro_repo_report=intro_repo_report,
            run_dir=run_dir,
            intro_commit_paths={"abc123": ["src/a.ts", "src/b.ts"]},
            baseline_risk_components={"src"},
            skip_low_signal_shards=True,
        )
    )

    assert checkout_calls == ["abc123"]
    assert split_calls == ["abc123"]
    assert ranges == ["abc123^..abc123"]
    assert len(reports) == 1
    assert rate_limited is False
    assert split_summary == {
        "total_groups": 1,
        "executed_groups": 1,
        "skipped_groups": 0,
        "baseline_touch_groups": 1,
        "new_surface_groups": 0,
        "skipped_reasons": {},
    }


def test_run_case_find_compatible_baseline_cache_entry_prefers_latest(
    run_case_module: ModuleType, tmp_path: Path
) -> None:
    cache_dir = tmp_path / "baseline-cache"
    cache_dir.mkdir()

    older = (
        cache_dir / "baseline-a6ea74f8e6ff__sv-111111111111__model-sonnet__sev-medium"
    )
    newer = (
        cache_dir / "baseline-a6ea74f8e6ff__sv-222222222222__model-sonnet__sev-medium"
    )
    older.mkdir()
    newer.mkdir()

    for entry in (older, newer):
        (entry / "baseline_scan.json").write_text("{}", encoding="utf-8")
        for artifact in run_case_module.BASELINE_ARTIFACTS:
            (entry / artifact).write_text("x", encoding="utf-8")

    older.touch()
    newer.touch()

    selected = run_case_module.find_compatible_baseline_cache_entry(
        cache_dir=cache_dir,
        baseline_commit="a6ea74f8e6ffae13f1de88736b0d47a004b98e54",
        model="sonnet",
        severity="medium",
    )
    assert selected == newer


def test_run_case_find_compatible_baseline_cache_entry_returns_none_when_unusable(
    run_case_module: ModuleType, tmp_path: Path
) -> None:
    cache_dir = tmp_path / "baseline-cache"
    cache_dir.mkdir()
    unusable = (
        cache_dir / "baseline-a6ea74f8e6ff__sv-333333333333__model-sonnet__sev-medium"
    )
    unusable.mkdir()
    # Missing baseline_scan.json and required artifacts => unusable.

    selected = run_case_module.find_compatible_baseline_cache_entry(
        cache_dir=cache_dir,
        baseline_commit="a6ea74f8e6ffae13f1de88736b0d47a004b98e54",
        model="sonnet",
        severity="medium",
    )
    assert selected is None


def test_run_case_derives_risk_components_from_baseline_artifacts(
    run_case_module: ModuleType, tmp_path: Path
) -> None:
    securevibes_dir = tmp_path / ".securevibes"
    securevibes_dir.mkdir()
    threat_model = [
        {
            "id": "THREAT-001",
            "affected_files": [{"file_path": "src/plugins/install.ts"}],
        }
    ]
    vulnerabilities = [
        {"file_path": "src/hooks/install.ts"},
        {"location": "extensions/voice-call/index.ts"},
    ]
    (securevibes_dir / "THREAT_MODEL.json").write_text(
        json.dumps(threat_model), encoding="utf-8"
    )
    (securevibes_dir / "VULNERABILITIES.json").write_text(
        json.dumps(vulnerabilities), encoding="utf-8"
    )

    risk_components = run_case_module.derive_risk_components_from_baseline_artifacts(
        securevibes_dir
    )
    assert "src/plugins" in risk_components
    assert "src/hooks" in risk_components
    assert "extensions/voice-call" in risk_components


def test_run_sweep_intro_only_flag_is_supported(run_sweep_module: ModuleType) -> None:
    args = run_sweep_module.parse_args(["--intro-only"])
    assert args.intro_only is True
    assert args.baseline_only is False


def test_run_sweep_skip_low_signal_split_shards_flag_is_supported(
    run_sweep_module: ModuleType,
) -> None:
    args = run_sweep_module.parse_args(["--skip-low-signal-split-shards"])
    assert args.skip_low_signal_split_shards is True


def test_run_sweep_rejects_intro_and_baseline_together(
    run_sweep_module: ModuleType,
) -> None:
    with pytest.raises(SystemExit) as exc:
        run_sweep_module.parse_args(["--intro-only", "--baseline-only"])
    assert exc.value.code == 2


def test_run_sweep_intro_only_does_not_dedupe_baselines(
    run_sweep_module: ModuleType,
) -> None:
    requested = ["GHSA-a", "GHSA-b", "GHSA-c"]
    case_ids, metadata = run_sweep_module.select_cases_for_execution(
        requested,
        baseline_only=False,
    )
    assert case_ids == requested
    assert metadata["enabled"] is False
    assert metadata["requested_case_count"] == 3
    assert metadata["executed_case_count"] == 3
    assert metadata["skipped_cases"] == {}


def test_run_sweep_baseline_only_uses_dedupe(
    run_sweep_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    requested = ["GHSA-a", "GHSA-b", "GHSA-c"]

    def fake_dedupe(
        case_ids: list[str],
    ) -> tuple[list[str], dict[str, str], dict[str, str]]:
        assert case_ids == requested
        return (
            ["GHSA-a", "GHSA-c"],
            {"base1": "GHSA-a", "base2": "GHSA-c"},
            {"GHSA-b": "GHSA-a"},
        )

    monkeypatch.setattr(
        run_sweep_module, "dedupe_cases_for_baseline_prime", fake_dedupe
    )

    case_ids, metadata = run_sweep_module.select_cases_for_execution(
        requested,
        baseline_only=True,
    )
    assert case_ids == ["GHSA-a", "GHSA-c"]
    assert metadata["enabled"] is True
    assert metadata["requested_case_count"] == 3
    assert metadata["executed_case_count"] == 2
    assert metadata["unique_baseline_count"] == 2
    assert metadata["skipped_cases"] == {"GHSA-b": "GHSA-a"}
