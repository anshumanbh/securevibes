#!/usr/bin/env python3
"""Explicit risk-map preparation for incremental scanning."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from securevibes.scanner.risk_scorer import (
    build_risk_map_from_threat_model,
    load_threat_model_entries,
    resolve_component_globs,
    save_risk_map,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI args for risk-map preparation."""
    parser = argparse.ArgumentParser(
        description="Prepare .securevibes/risk_map.json from THREAT_MODEL.json."
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Repository root containing .securevibes/THREAT_MODEL.json",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Regenerate risk_map.json even if it already exists.",
    )
    return parser.parse_args(argv)


def prepare_risk_map(repo: Path, *, force: bool = False) -> Path:
    """Generate and persist ``risk_map.json`` from ``THREAT_MODEL.json``."""
    securevibes_dir = repo / ".securevibes"
    risk_map_path = securevibes_dir / "risk_map.json"
    if risk_map_path.exists() and not force:
        return risk_map_path

    threat_model_path = securevibes_dir / "THREAT_MODEL.json"
    try:
        threats = load_threat_model_entries(threat_model_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(
            f"Unable to read THREAT_MODEL.json for risk map generation: {exc}"
        ) from exc

    risk_map = build_risk_map_from_threat_model(
        threats,
        component_resolver=lambda component: _resolve_component_patterns(
            repo, component
        ),
    )
    save_risk_map(risk_map_path, risk_map)
    return risk_map_path


def _resolve_component_patterns(repo: Path, component: str) -> list[str]:
    """Resolve component labels into path globs for risk-map generation."""
    try:
        return resolve_component_globs(repo, component)
    except OSError:
        return []


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    args = parse_args(argv)
    repo = Path(args.repo).resolve()
    try:
        risk_map_path = prepare_risk_map(repo, force=args.force)
    except Exception as exc:  # pragma: no cover - user-facing wrapper
        print(f"[prepare-risk-map] ERROR: {exc}", file=sys.stderr, flush=True)
        return 1

    print(f"[prepare-risk-map] wrote {risk_map_path}", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
