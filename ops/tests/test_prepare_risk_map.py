"""Tests for explicit risk-map preparation."""

from __future__ import annotations

import json
from pathlib import Path

from ops import prepare_risk_map as prep


def test_prepare_risk_map_generates_from_threat_model(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir(parents=True)
    (repo / "src" / "gateway").mkdir(parents=True)
    (securevibes_dir / "THREAT_MODEL.json").write_text(
        json.dumps(
            [
                {
                    "severity": "high",
                    "affected_components": ["src/gateway/*"],
                }
            ]
        ),
        encoding="utf-8",
    )

    risk_map_path = prep.prepare_risk_map(repo)

    assert risk_map_path == securevibes_dir / "risk_map.json"
    payload = json.loads(risk_map_path.read_text(encoding="utf-8"))
    assert "src/gateway/*" in payload["critical"]


def test_prepare_risk_map_preserves_existing_map_without_force(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir(parents=True)
    risk_map_path = securevibes_dir / "risk_map.json"
    risk_map_path.write_text(
        json.dumps({"critical": [], "moderate": [], "skip": []}),
        encoding="utf-8",
    )

    resolved_path = prep.prepare_risk_map(repo)

    assert resolved_path == risk_map_path
    assert json.loads(risk_map_path.read_text(encoding="utf-8")) == {
        "critical": [],
        "moderate": [],
        "skip": [],
    }
