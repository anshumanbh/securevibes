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
    if args.intro_only:
        cmd.append("--intro-only")
    if args.skip_low_signal_split_shards:
        cmd.append("--skip-low-signal-split-shards")

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


def build_parser() -> argparse.ArgumentParser:
    """Build command-line parser for benchmark sweeps."""
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
    run_mode_group = parser.add_mutually_exclusive_group()
    run_mode_group.add_argument("--baseline-only", action="store_true")
    run_mode_group.add_argument("--intro-only", action="store_true")
    parser.add_argument("--parallel", type=int, default=2)
    parser.add_argument("--keep-temp", action="store_true")
    parser.add_argument("--skip-low-signal-split-shards", action="store_true")
    parser.add_argument(
        "--ghsa",
        action="append",
        default=[],
        help="Repeatable GHSA id. If omitted, runs all manifest cases.",
    )
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for benchmark sweeps."""
    return build_parser().parse_args(argv)


def select_cases_for_execution(
    requested_case_ids: list[str],
    *,
    baseline_only: bool,
) -> tuple[list[str], dict[str, Any]]:
    """Select execution case IDs and dedupe metadata for sweep mode."""
    baseline_dedupe: dict[str, Any] = {
        "enabled": baseline_only,
        "requested_case_count": len(requested_case_ids),
        "executed_case_count": len(requested_case_ids),
        "skipped_cases": {},
    }
    if not baseline_only:
        return requested_case_ids, baseline_dedupe

    case_ids, baseline_to_case, skipped = dedupe_cases_for_baseline_prime(
        requested_case_ids
    )
    baseline_dedupe["executed_case_count"] = len(case_ids)
    baseline_dedupe["unique_baseline_count"] = len(baseline_to_case)
    baseline_dedupe["skipped_cases"] = skipped
    baseline_dedupe["baseline_to_case"] = baseline_to_case
    return case_ids, baseline_dedupe


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    requested_case_ids = args.ghsa or load_manifest_case_ids()
    if not requested_case_ids:
        raise RuntimeError("No benchmark cases selected.")

    case_ids, baseline_dedupe = select_cases_for_execution(
        requested_case_ids,
        baseline_only=bool(args.baseline_only),
    )

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
        "intro_only": args.intro_only,
        "baseline_cache_dir": str(args.baseline_cache_dir.resolve()),
        "baseline_cache_disabled": bool(args.no_baseline_cache),
        "baseline_cache_refresh": bool(args.refresh_baseline_cache),
        "parallel": args.parallel,
        "skip_low_signal_split_shards": bool(args.skip_low_signal_split_shards),
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
