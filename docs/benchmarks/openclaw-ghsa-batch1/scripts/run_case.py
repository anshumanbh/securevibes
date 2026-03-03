#!/usr/bin/env python3
"""Run empirical SecureVibes evaluation for one GHSA case."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = ROOT / "cases"


def run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def summarize_issues(report_path: Path) -> dict[str, Any]:
    if not report_path.exists():
        return {"exists": False, "issue_count": None, "severities": {}}

    payload = load_json(report_path)
    issues = payload.get("issues") if isinstance(payload, dict) else None
    if not isinstance(issues, list):
        return {"exists": True, "issue_count": None, "severities": {}}

    severities: dict[str, int] = {}
    for issue in issues:
        sev = str(issue.get("severity", "unknown")).lower()
        severities[sev] = severities.get(sev, 0) + 1
    return {"exists": True, "issue_count": len(issues), "severities": severities}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghsa", required=True)
    parser.add_argument("--openclaw-repo", type=Path, default=Path("../openclaw"))
    parser.add_argument("--model", default="sonnet")
    parser.add_argument(
        "--severity", default="high", choices=["critical", "high", "medium", "low"]
    )
    parser.add_argument("--keep-temp", action="store_true")
    args = parser.parse_args()

    case_dir = CASES_DIR / args.ghsa
    timeline = load_json(case_dir / "timeline.json")
    baseline = timeline["baseline_commit"]
    intro_head = timeline["vulnerable_head"]
    fix_head = timeline["fix_head"]

    runs_dir = case_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=f"securevibes-{args.ghsa}-") as tmp:
        tmp_path = Path(tmp)
        work_repo = tmp_path / "openclaw"

        code, out, err = run(
            [
                "git",
                "clone",
                "--local",
                str(args.openclaw_repo.resolve()),
                str(work_repo),
            ]
        )
        (run_dir / "clone.log").write_text(out + "\n" + err, encoding="utf-8")
        if code != 0:
            raise RuntimeError("git clone failed; see clone.log")

        # 1) Baseline scan at baseline commit.
        run(["git", "checkout", baseline], cwd=work_repo)
        baseline_report = run_dir / "baseline_scan.json"
        code, out, err = run(
            [
                "securevibes",
                "scan",
                str(work_repo),
                "--model",
                args.model,
                "--severity",
                args.severity,
                "--format",
                "json",
                "--output",
                str(baseline_report),
                "--force",
            ]
        )
        (run_dir / "baseline_scan.log").write_text(out + "\n" + err, encoding="utf-8")
        baseline_exit = code

        # 2) PR reviews require a git worktree at a commit that contains both range endpoints.
        run(["git", "checkout", fix_head], cwd=work_repo)
        intro_report = run_dir / "intro_pr_review.json"
        intro_range = f"{baseline}..{intro_head}"
        code, out, err = run(
            [
                "securevibes",
                "pr-review",
                str(work_repo),
                "--range",
                intro_range,
                "--model",
                args.model,
                "--severity",
                args.severity,
                "--format",
                "json",
                "--output",
                str(intro_report),
                "--clean-pr-artifacts",
            ]
        )
        (run_dir / "intro_pr_review.log").write_text(out + "\n" + err, encoding="utf-8")
        intro_exit = code

        fix_report = run_dir / "fix_pr_review.json"
        fix_range = f"{intro_head}..{fix_head}"
        code, out, err = run(
            [
                "securevibes",
                "pr-review",
                str(work_repo),
                "--range",
                fix_range,
                "--model",
                args.model,
                "--severity",
                args.severity,
                "--format",
                "json",
                "--output",
                str(fix_report),
                "--clean-pr-artifacts",
            ]
        )
        (run_dir / "fix_pr_review.log").write_text(out + "\n" + err, encoding="utf-8")
        fix_exit = code

        if args.keep_temp:
            preserved = run_dir / "work_repo"
            if preserved.exists():
                shutil.rmtree(preserved)
            shutil.copytree(work_repo, preserved)

    baseline_summary = summarize_issues(run_dir / "baseline_scan.json")
    intro_summary = summarize_issues(run_dir / "intro_pr_review.json")
    fix_summary = summarize_issues(run_dir / "fix_pr_review.json")

    detectability = {
        "id": args.ghsa,
        "status": (
            "completed"
            if all(code == 0 for code in [baseline_exit, intro_exit, fix_exit])
            else "partial_or_failed"
        ),
        "model": args.model,
        "severity_filter": args.severity,
        "run_id": run_id,
        "baseline_scan": {
            "command_exit": baseline_exit,
            "report": str((run_dir / "baseline_scan.json").resolve()),
            "summary": baseline_summary,
        },
        "intro_pr_review": {
            "command_exit": intro_exit,
            "range": intro_range,
            "report": str((run_dir / "intro_pr_review.json").resolve()),
            "summary": intro_summary,
        },
        "fix_pr_review": {
            "command_exit": fix_exit,
            "range": fix_range,
            "report": str((run_dir / "fix_pr_review.json").resolve()),
            "summary": fix_summary,
        },
        "detected_from_new_commits": (
            (intro_summary.get("issue_count") or 0) > 0
            if intro_summary["exists"]
            else None
        ),
        "could_propose_fix": None,
        "post_fix_regression_status": None,
        "notes": "`could_propose_fix` and `post_fix_regression_status` require manual adjudication against advisory-specific root cause.",
    }

    (case_dir / "detectability.json").write_text(
        json.dumps(detectability, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(detectability, indent=2))


if __name__ == "__main__":
    main()
