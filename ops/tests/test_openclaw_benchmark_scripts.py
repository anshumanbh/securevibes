"""Smoke tests for benchmark helper scripts."""

from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "docs" / "benchmarks" / "openclaw-ghsa-batch1" / "scripts"


def _run_help(script_name: str) -> str:
    script = SCRIPTS / script_name
    proc = subprocess.run(
        ["python3", str(script), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_run_case_help_includes_commit_override() -> None:
    out = _run_help("run_case.py")
    assert "--securevibes-commit" in out
    assert "--permission-mode" in out
    assert "--baseline-only" in out
    assert "--baseline-cache-dir" in out
    assert "--severity" in out


def test_run_sweep_help_includes_parallel_and_ghsa() -> None:
    out = _run_help("run_sweep.py")
    assert "--parallel" in out
    assert "--permission-mode" in out
    assert "--baseline-only" in out
    assert "--baseline-cache-dir" in out
    assert "--ghsa" in out
