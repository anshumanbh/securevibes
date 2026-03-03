#!/usr/bin/env python3
"""Validate structure and minimal semantics of openclaw-ghsa-batch1 corpus."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = ROOT / "cases"

REQUIRED_TOP = ["manifest.json", "selection.json", "summary.md", "README.md"]
REQUIRED_CASE_FILES = [
    "advisory.json",
    "timeline.json",
    "verification.json",
    "detectability.json",
    "analysis.md",
]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(strict: bool) -> int:
    errors: list[str] = []

    for name in REQUIRED_TOP:
        if not (ROOT / name).exists():
            errors.append(f"Missing top-level file: {name}")

    manifest_path = ROOT / "manifest.json"
    if not manifest_path.exists():
        errors.append("Missing manifest.json; cannot continue semantic validation")
        for err in errors:
            print(f"ERROR: {err}")
        return 1

    manifest = load_json(manifest_path)
    cases = manifest.get("cases", [])
    if not isinstance(cases, list) or not cases:
        errors.append("manifest.json missing non-empty `cases` list")
        for err in errors:
            print(f"ERROR: {err}")
        return 1

    for case in cases:
        ghsa = case.get("id")
        if not ghsa:
            errors.append("manifest case entry missing id")
            continue
        case_dir = CASES_DIR / ghsa
        if not case_dir.exists():
            errors.append(f"Missing case directory: {ghsa}")
            continue

        for file_name in REQUIRED_CASE_FILES:
            if not (case_dir / file_name).exists():
                errors.append(f"{ghsa}: missing {file_name}")

        try:
            timeline = load_json(case_dir / "timeline.json")
            verification = load_json(case_dir / "verification.json")
            detectability = load_json(case_dir / "detectability.json")
        except Exception as exc:
            errors.append(f"{ghsa}: invalid JSON file ({exc})")
            continue

        for field in [
            "baseline_commit",
            "introducing_commits",
            "fix_commits",
            "scan_ranges",
        ]:
            if field not in timeline:
                errors.append(f"{ghsa}: timeline missing `{field}`")

        checks = verification.get("checks")
        if not isinstance(checks, list) or not checks:
            errors.append(f"{ghsa}: verification checks missing or empty")

        if "status" not in detectability:
            errors.append(f"{ghsa}: detectability missing status")

        if strict and verification.get("verification_pass") is not True:
            errors.append(f"{ghsa}: verification_pass is not true (strict mode)")

    for err in errors:
        print(f"ERROR: {err}")

    if errors:
        print(f"\nValidation failed with {len(errors)} error(s).")
        return 1

    print("Validation passed.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if any case has verification_pass != true",
    )
    args = parser.parse_args()
    raise SystemExit(validate(strict=args.strict))


if __name__ == "__main__":
    main()
