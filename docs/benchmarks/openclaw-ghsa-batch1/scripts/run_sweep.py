#!/usr/bin/env python3
"""Run benchmark cases in parallel for a single SecureVibes commit context."""

from __future__ import annotations

import argparse
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = ROOT / "cases"
SCRIPTS_DIR = ROOT / "scripts"
RUN_CASE = SCRIPTS_DIR / "run_case.py"
DEBUG_DIR = ROOT / "debug" / "sweeps"


def load_manifest_case_ids() -> list[str]:
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    return [case["id"] for case in manifest.get("cases", [])]


def load_case_timeline(case_id: str) -> dict[str, Any]:
    """Load case timeline metadata."""
    return json.loads(
        (CASES_DIR / case_id / "timeline.json").read_text(encoding="utf-8")
    )


def dedupe_cases_for_baseline_prime(
    case_ids: list[str],
) -> tuple[list[str], dict[str, str], dict[str, str]]:
    """Dedupe case list so each baseline commit is scanned once."""
    selected: list[str] = []
    baseline_to_case: dict[str, str] = {}
    skipped: dict[str, str] = {}

    for case_id in case_ids:
        timeline = load_case_timeline(case_id)
        baseline_commit = timeline["baseline_commit"]
        if baseline_commit not in baseline_to_case:
            baseline_to_case[baseline_commit] = case_id
            selected.append(case_id)
            continue
        skipped[case_id] = baseline_to_case[baseline_commit]

    return selected, baseline_to_case, skipped


def latest_run_dir(case_id: str) -> Path | None:
    runs_dir = CASES_DIR / case_id / "runs"
    if not runs_dir.exists():
        return None
    candidates = sorted([p for p in runs_dir.iterdir() if p.is_dir()])
    return candidates[-1] if candidates else None


def load_detectability(case_id: str) -> dict[str, Any] | None:
    path = CASES_DIR / case_id / "detectability.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def run_case_subprocess(case_id: str, args: argparse.Namespace) -> dict[str, Any]:
    cmd = [
        str(RUN_CASE),
        "--ghsa",
        case_id,
        "--openclaw-repo",
        str(args.openclaw_repo.resolve()),
        "--model",
        args.model,
        "--severity",
        args.severity,
        "--securevibes-repo",
        str(args.securevibes_repo.resolve()),
        "--python-executable",
        args.python_executable,
        "--permission-mode",
        args.permission_mode,
        "--baseline-cache-dir",
        str(args.baseline_cache_dir.resolve()),
    ]
    if args.securevibes_commit:
        cmd.extend(["--securevibes-commit", args.securevibes_commit])
    if args.keep_temp:
        cmd.append("--keep-temp")
    if args.no_baseline_cache:
        cmd.append("--no-baseline-cache")
    if args.refresh_baseline_cache:
        cmd.append("--refresh-baseline-cache")
    if args.baseline_only:
        cmd.append("--baseline-only")

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    detect = load_detectability(case_id)
    return {
        "ghsa": case_id,
        "command": cmd,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "detectability": detect,
        "latest_run_dir": str(latest_run_dir(case_id) or ""),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openclaw-repo", type=Path, default=Path("../openclaw"))
    parser.add_argument(
        "--securevibes-repo", type=Path, default=Path(__file__).resolve().parents[4]
    )
    parser.add_argument("--securevibes-commit", default=None)
    parser.add_argument("--model", default="sonnet")
    parser.add_argument(
        "--severity",
        default="medium",
        choices=["critical", "high", "medium", "low"],
    )
    parser.add_argument("--python-executable", default="python3")
    parser.add_argument(
        "--permission-mode",
        default="bypassPermissions",
        choices=["default", "acceptEdits", "bypassPermissions"],
    )
    parser.add_argument(
        "--baseline-cache-dir",
        type=Path,
        default=ROOT / "baseline-cache",
    )
    parser.add_argument("--no-baseline-cache", action="store_true")
    parser.add_argument("--refresh-baseline-cache", action="store_true")
    parser.add_argument("--baseline-only", action="store_true")
    parser.add_argument("--parallel", type=int, default=2)
    parser.add_argument("--keep-temp", action="store_true")
    parser.add_argument(
        "--ghsa",
        action="append",
        default=[],
        help="Repeatable GHSA id. If omitted, runs all manifest cases.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    requested_case_ids = args.ghsa or load_manifest_case_ids()
    if not requested_case_ids:
        raise RuntimeError("No benchmark cases selected.")

    baseline_dedupe: dict[str, Any] = {
        "enabled": bool(args.baseline_only),
        "requested_case_count": len(requested_case_ids),
        "executed_case_count": len(requested_case_ids),
        "skipped_cases": {},
    }
    if args.baseline_only:
        case_ids, baseline_to_case, skipped = dedupe_cases_for_baseline_prime(
            requested_case_ids
        )
        baseline_dedupe["executed_case_count"] = len(case_ids)
        baseline_dedupe["unique_baseline_count"] = len(baseline_to_case)
        baseline_dedupe["skipped_cases"] = skipped
        baseline_dedupe["baseline_to_case"] = baseline_to_case
    else:
        case_ids = requested_case_ids

    DEBUG_DIR.mkdir(parents=True, exist_ok=True)
    sweep_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.parallel)) as executor:
        future_map = {
            executor.submit(run_case_subprocess, ghsa, args): ghsa for ghsa in case_ids
        }
        for future in as_completed(future_map):
            ghsa = future_map[future]
            try:
                res = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                res = {
                    "ghsa": ghsa,
                    "command": None,
                    "exit_code": 999,
                    "stdout": "",
                    "stderr": str(exc),
                    "detectability": None,
                    "latest_run_dir": "",
                }
            results.append(res)
            print(f"[{ghsa}] exit={res['exit_code']}")

    results.sort(key=lambda item: item["ghsa"])

    tier1_true = 0
    tier1_false = 0
    tier1_unknown = 0
    for item in results:
        detect = item.get("detectability") or {}
        value = detect.get("tier1_detected_from_new_commits")
        if value is True:
            tier1_true += 1
        elif value is False:
            tier1_false += 1
        else:
            tier1_unknown += 1

    summary = {
        "sweep_id": sweep_id,
        "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "securevibes_repo": str(args.securevibes_repo.resolve()),
        "securevibes_commit_requested": args.securevibes_commit,
        "openclaw_repo": str(args.openclaw_repo.resolve()),
        "model": args.model,
        "severity": args.severity,
        "permission_mode": args.permission_mode,
        "baseline_only": args.baseline_only,
        "baseline_cache_dir": str(args.baseline_cache_dir.resolve()),
        "baseline_cache_disabled": bool(args.no_baseline_cache),
        "baseline_cache_refresh": bool(args.refresh_baseline_cache),
        "parallel": args.parallel,
        "requested_case_count": len(requested_case_ids),
        "executed_case_count": len(case_ids),
        "baseline_dedupe": baseline_dedupe,
        "tier1": {
            "detected_true": tier1_true,
            "detected_false": tier1_false,
            "detected_unknown": tier1_unknown,
        },
        "results": results,
    }

    out_path = DEBUG_DIR / f"{sweep_id}.json"
    out_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"Saved sweep summary: {out_path}")


if __name__ == "__main__":
    main()
