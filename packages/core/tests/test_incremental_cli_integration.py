"""Integration tests for incremental CLI anchor lifecycle."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from click.testing import CliRunner

from securevibes.cli.main import cli


def _run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"git {' '.join(args)} failed in {repo}: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout.strip()


def _append_text(path: Path, text: str) -> None:
    existing = path.read_text(encoding="utf-8")
    path.write_text(f"{existing}{text}", encoding="utf-8")


def _write_baseline_artifacts(repo: Path) -> None:
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir(parents=True, exist_ok=True)
    (securevibes_dir / "SECURITY.md").write_text("# Security Overview\n", encoding="utf-8")
    (securevibes_dir / "THREAT_MODEL.json").write_text("[]\n", encoding="utf-8")
    (securevibes_dir / "VULNERABILITIES.json").write_text("[]\n", encoding="utf-8")
    (securevibes_dir / "risk_map.json").write_text(
        json.dumps(
            {
                "critical": [],
                "moderate": [],
                "skip": ["README.md", "docs/*"],
                "_meta": {
                    "generated_from": "THREAT_MODEL.json",
                    "generated_at": "2026-03-21T00:00:00Z",
                    "overrides_applied": False,
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _configure_clone(repo: Path) -> None:
    _run_git(repo, "config", "user.name", "Integration Test")
    _run_git(repo, "config", "user.email", "integration@example.com")


def _append_excludes(repo: Path) -> None:
    exclude_path = repo / ".git" / "info" / "exclude"
    with exclude_path.open("a", encoding="utf-8") as handle:
        handle.write("/.securevibes/scan_state.json\n")
        handle.write("/.securevibes/incremental_synopsis.json\n")
        handle.write("/.securevibes/incremental_hypotheses.json\n")


def test_incremental_cli_anchor_lifecycle(tmp_path: Path) -> None:
    runner = CliRunner()

    origin = tmp_path / "origin.git"
    publisher = tmp_path / "publisher"
    worker = tmp_path / "worker"

    _run_git(tmp_path, "init", "--bare", str(origin))
    _run_git(tmp_path, "clone", str(origin), str(publisher))
    _configure_clone(publisher)

    (publisher / "README.md").write_text("# Smoke Test Repo\n", encoding="utf-8")
    _write_baseline_artifacts(publisher)
    _run_git(publisher, "add", "README.md", ".securevibes")
    _run_git(publisher, "commit", "-m", "chore: baseline artifacts")
    _run_git(publisher, "branch", "-M", "main")
    _run_git(publisher, "push", "-u", "origin", "main")
    _run_git(origin, "symbolic-ref", "HEAD", "refs/heads/main")
    baseline_commit = _run_git(publisher, "rev-parse", "HEAD")

    _run_git(tmp_path, "clone", str(origin), str(worker))
    _configure_clone(worker)
    _append_excludes(worker)
    worker_state_path = worker / ".securevibes" / "scan_state.json"
    worker_state_path.write_text(
        json.dumps(
            {
                "last_full_scan": {
                    "commit": baseline_commit,
                    "branch": "main",
                    "timestamp": "2026-03-21T00:00:00Z",
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    _append_text(publisher / "README.md", "\nMinor documentation update 1.\n")
    _run_git(publisher, "add", "README.md")
    _run_git(publisher, "commit", "-m", "docs: update readme")
    _run_git(publisher, "push", "origin", "main")
    commit_one = _run_git(publisher, "rev-parse", "HEAD")

    _run_git(worker, "pull", "origin", "main")

    result = runner.invoke(cli, ["incremental-run", str(worker), "--since-last-incremental"])
    assert result.exit_code == 0
    assert "executed 0 cluster" in result.output.lower()
    assert "skipped 1 cluster" in result.output.lower()

    state_payload = json.loads(worker_state_path.read_text(encoding="utf-8"))
    assert state_payload["last_incremental_run"]["commit"] == commit_one
    assert state_payload["last_incremental_run"]["base_commit"] == baseline_commit

    result = runner.invoke(cli, ["incremental-state", "show", str(worker)])
    assert result.exit_code == 0
    assert f"effective anchor: {commit_one}" in result.output.lower()

    result = runner.invoke(cli, ["incremental-state", "reset", str(worker)])
    assert result.exit_code == 0
    state_payload = json.loads(worker_state_path.read_text(encoding="utf-8"))
    assert "last_incremental_run" not in state_payload

    result = runner.invoke(cli, ["incremental-state", "show", str(worker)])
    assert result.exit_code == 0
    assert f"effective anchor: {baseline_commit}" in result.output.lower()

    result = runner.invoke(cli, ["incremental-state", "set", str(worker), "--commit", "HEAD"])
    assert result.exit_code == 0
    state_payload = json.loads(worker_state_path.read_text(encoding="utf-8"))
    assert state_payload["last_incremental_run"]["commit"] == commit_one
    assert state_payload["last_incremental_run"]["base_commit"] == commit_one

    _append_text(publisher / "README.md", "\nMinor documentation update 2.\n")
    _run_git(publisher, "add", "README.md")
    _run_git(publisher, "commit", "-m", "docs: update readme again")
    _run_git(publisher, "push", "origin", "main")
    commit_two = _run_git(publisher, "rev-parse", "HEAD")

    result = runner.invoke(cli, ["catchup", str(worker), "--branch", "main", "--format", "text"])
    assert result.exit_code == 0
    assert "issues found: 0" in result.output.lower()
    assert "route_not_implemented" not in result.output.lower()

    state_payload = json.loads(worker_state_path.read_text(encoding="utf-8"))
    assert state_payload["last_incremental_run"]["commit"] == commit_two
    assert state_payload["last_incremental_run"]["base_commit"] == commit_one

    hypotheses_payload = json.loads(
        (worker / ".securevibes" / "incremental_hypotheses.json").read_text(encoding="utf-8")
    )
    assert hypotheses_payload["base_ref"] == commit_one
    assert hypotheses_payload["head_ref"] == "HEAD"
    assert hypotheses_payload["clusters"][0]["commit_shas"] == [commit_two]

    assert _run_git(worker, "status", "--short") == ""
