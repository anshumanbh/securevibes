"""Tests for OpenClaw benchmark orchestration scripts."""

from __future__ import annotations

import importlib.util
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
        baseline_cache_enabled=True,
        refresh_baseline_cache=False,
        baseline_cache_entry=Path("/tmp/cache-entry"),
        baseline_cmd=["securevibes", "scan"],
        intro_cmd=["securevibes", "pr-review", "--range", "base..intro"],
        fix_cmd=["securevibes", "pr-review", "--range", "intro..fix"],
    )
    assert payload["intro_only"] is True
    assert payload["baseline_only"] is False
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


def test_run_sweep_intro_only_flag_is_supported(run_sweep_module: ModuleType) -> None:
    args = run_sweep_module.parse_args(["--intro-only"])
    assert args.intro_only is True
    assert args.baseline_only is False


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
