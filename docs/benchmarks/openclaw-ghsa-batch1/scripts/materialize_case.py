#!/usr/bin/env python3
"""Materialize baseline/vulnerable/fix snapshots for a GHSA case."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = ROOT / "cases"


def run(cmd: list[str], cwd: Path | None = None) -> None:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr.strip()}"
        )


def export_snapshot(repo: Path, ref: str, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    tar_path = out_dir.parent / f"{out_dir.name}.tar"
    run(["git", "-C", str(repo), "archive", "--format=tar", "-o", str(tar_path), ref])
    run(["tar", "-xf", str(tar_path), "-C", str(out_dir)])
    tar_path.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ghsa", required=True, help="GHSA id, e.g. GHSA-g55j-c2v4-pjcg"
    )
    parser.add_argument(
        "--openclaw-repo",
        type=Path,
        default=Path("../openclaw"),
        help="Path to local OpenClaw checkout",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path("/tmp/openclaw-ghsa-batch1"),
        help="Output workspace root",
    )
    parser.add_argument(
        "--force", action="store_true", help="Overwrite existing case directory"
    )
    args = parser.parse_args()

    timeline_path = CASES_DIR / args.ghsa / "timeline.json"
    if not timeline_path.exists():
        raise RuntimeError(f"Missing timeline: {timeline_path}")

    timeline = json.loads(timeline_path.read_text(encoding="utf-8"))
    baseline = timeline["baseline_commit"]
    vulnerable = timeline["vulnerable_head"]
    fixed = timeline["fix_head"]

    case_root = args.workspace / args.ghsa
    if case_root.exists() and args.force:
        shutil.rmtree(case_root)
    case_root.mkdir(parents=True, exist_ok=True)

    export_snapshot(args.openclaw_repo.resolve(), baseline, case_root / "baseline")
    export_snapshot(args.openclaw_repo.resolve(), vulnerable, case_root / "vulnerable")
    export_snapshot(args.openclaw_repo.resolve(), fixed, case_root / "fixed")

    meta = {
        "ghsa": args.ghsa,
        "openclaw_repo": str(args.openclaw_repo.resolve()),
        "baseline": baseline,
        "vulnerable": vulnerable,
        "fixed": fixed,
        "paths": {
            "baseline": str((case_root / "baseline").resolve()),
            "vulnerable": str((case_root / "vulnerable").resolve()),
            "fixed": str((case_root / "fixed").resolve()),
        },
    }
    (case_root / "materialized.json").write_text(
        json.dumps(meta, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
