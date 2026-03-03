"""Validation tests for OpenClaw GHSA batch-1 benchmark corpus."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "docs" / "benchmarks" / "openclaw-ghsa-batch1"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_manifest_has_10_cases() -> None:
    manifest = _load_json(CORPUS / "manifest.json")
    cases = manifest.get("cases", [])
    assert len(cases) == 10


def test_all_case_directories_have_required_files() -> None:
    required = {
        "advisory.json",
        "timeline.json",
        "verification.json",
        "detectability.json",
        "analysis.md",
    }
    manifest = _load_json(CORPUS / "manifest.json")
    for case in manifest["cases"]:
        case_dir = CORPUS / "cases" / case["id"]
        assert case_dir.exists(), f"missing case dir: {case['id']}"
        present = {p.name for p in case_dir.iterdir() if p.is_file()}
        missing = required - present
        assert not missing, f"{case['id']} missing files: {sorted(missing)}"


def test_selection_policy_is_pinned() -> None:
    selection = _load_json(CORPUS / "selection.json")
    policy = selection.get("policy", {})
    assert policy.get("ordering") == "all critical first, then high"
    assert policy.get("cap") == 10
