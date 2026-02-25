"""Tests for security triage pre-filter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from securevibes.diff.parser import DiffContext, DiffFile, DiffHunk, DiffLine
from securevibes.scanner.triage import (
    SecuritySurfaceMap,
    TriageResult,
    build_security_surface_map,
    compute_triage_overrides,
    triage_diff,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_diff_file(
    path: str,
    *,
    is_new: bool = False,
    is_deleted: bool = False,
    is_renamed: bool = False,
    hunk_content: list[str] | None = None,
    no_hunks: bool = False,
) -> DiffFile:
    """Build a minimal DiffFile for testing."""
    hunks: list[DiffHunk] = []
    if not no_hunks:
        lines = [
            DiffLine(type="add", content=line, old_line_num=None, new_line_num=i + 1)
            for i, line in enumerate(hunk_content or ["+ some change"])
        ]
        hunks = [DiffHunk(old_start=1, old_count=0, new_start=1, new_count=len(lines), lines=lines)]
    return DiffFile(
        old_path=None if is_new else path,
        new_path=path,
        hunks=hunks,
        is_new=is_new,
        is_deleted=is_deleted,
        is_renamed=is_renamed,
    )


def _make_diff_context(*files: DiffFile) -> DiffContext:
    """Build a DiffContext from DiffFiles."""
    changed = []
    added = removed = 0
    for f in files:
        p = f.new_path or f.old_path
        if p:
            changed.append(p)
        for h in f.hunks:
            for line in h.lines:
                if line.type == "add":
                    added += 1
                elif line.type == "remove":
                    removed += 1
    return DiffContext(files=list(files), added_lines=added, removed_lines=removed, changed_files=changed)


def _empty_surface_map() -> SecuritySurfaceMap:
    return SecuritySurfaceMap(
        vuln_paths=frozenset(),
        affected_components=frozenset(),
    )


# ---------------------------------------------------------------------------
# Classification: low_risk cases
# ---------------------------------------------------------------------------

class TestLowRiskClassification:
    def test_docs_only_diff_is_low_risk(self):
        """Docs-only diff should classify as low_risk."""
        ctx = _make_diff_context(_make_diff_file("docs/README.md"))
        result = triage_diff(ctx, surface_map=_empty_surface_map())
        assert result.classification == "low_risk"
        assert "default:low_risk" in result.reasons

    def test_tests_only_diff_is_low_risk(self):
        """Tests-only diff should classify as low_risk."""
        ctx = _make_diff_context(
            _make_diff_file("tests/test_foo.py"),
            _make_diff_file("src/components/Button.spec.ts"),
        )
        result = triage_diff(ctx, surface_map=_empty_surface_map())
        assert result.classification == "low_risk"

    def test_empty_diff_is_low_risk(self):
        """Empty diff should classify as low_risk."""
        ctx = DiffContext(files=[], added_lines=0, removed_lines=0, changed_files=[])
        result = triage_diff(ctx, surface_map=_empty_surface_map())
        assert result.classification == "low_risk"
        assert "default:low_risk" in result.reasons


# ---------------------------------------------------------------------------
# Classification: security_relevant cases
# ---------------------------------------------------------------------------

class TestSecurityRelevantClassification:
    def test_command_builder_signal_triggers_security_relevant(self):
        """Diff with command builder signals should be security_relevant."""
        ctx = _make_diff_context(
            _make_diff_file("src/runner.py", hunk_content=["+ subprocess.run(cmd)"])
        )
        result = triage_diff(ctx, surface_map=_empty_surface_map())
        assert result.classification == "security_relevant"
        assert "signal:command_builder" in result.reasons

    def test_path_parser_signal_triggers_security_relevant(self):
        """Diff with path parser signals should be security_relevant."""
        ctx = _make_diff_context(
            _make_diff_file("src/file_handler.py", hunk_content=["+ path.resolve()"])
        )
        result = triage_diff(ctx, surface_map=_empty_surface_map())
        assert result.classification == "security_relevant"
        assert "signal:path_parser" in result.reasons

    def test_auth_privilege_signal_triggers_security_relevant(self):
        """Diff with auth/privilege signals should be security_relevant."""
        ctx = _make_diff_context(
            _make_diff_file("src/auth.py", hunk_content=["+ authorize(user, role)"])
        )
        result = triage_diff(ctx, surface_map=_empty_surface_map())
        assert result.classification == "security_relevant"
        assert "signal:auth_privilege" in result.reasons

    def test_new_code_file_triggers_security_relevant(self):
        """New code file triggers fail-closed security_relevant."""
        ctx = _make_diff_context(
            _make_diff_file("src/new_module.py", is_new=True, hunk_content=["+ def main(): pass"])
        )
        result = triage_diff(ctx, surface_map=_empty_surface_map())
        assert result.classification == "security_relevant"
        assert any(r.startswith("fail_closed:new_code_file:") for r in result.reasons)

    def test_new_doc_file_is_not_fail_closed(self):
        """New .md file (docs) should NOT trigger fail_closed:new_code_file."""
        ctx = _make_diff_context(
            _make_diff_file("docs/guide.md", is_new=True, hunk_content=["+ # Guide"])
        )
        result = triage_diff(ctx, surface_map=_empty_surface_map())
        assert not any(r.startswith("fail_closed:new_code_file:") for r in result.reasons)

    def test_new_test_file_is_not_fail_closed(self):
        """New test file should NOT trigger fail_closed:new_code_file."""
        ctx = _make_diff_context(
            _make_diff_file("tests/test_new.py", is_new=True, hunk_content=["+ def test_x(): pass"])
        )
        result = triage_diff(ctx, surface_map=_empty_surface_map())
        assert not any(r.startswith("fail_closed:new_code_file:") for r in result.reasons)

    def test_no_hunk_file_triggers_security_relevant(self):
        """File with zero hunks (parser blind spot) should trigger fail-closed."""
        ctx = _make_diff_context(_make_diff_file("src/binary_blob.bin", no_hunks=True))
        result = triage_diff(ctx, surface_map=_empty_surface_map())
        assert result.classification == "security_relevant"
        assert any(r.startswith("fail_closed:no_hunks:") for r in result.reasons)

    def test_extensionless_non_doc_file_triggers_security_relevant(self):
        """Extensionless file outside docs/tests triggers fail-closed."""
        ctx = _make_diff_context(
            _make_diff_file("src/Makefile", hunk_content=["+ all: build"])
        )
        # Makefile has no extension suffix (Path("Makefile").suffix == "")
        result = triage_diff(ctx, surface_map=_empty_surface_map())
        assert result.classification == "security_relevant"
        assert any(r.startswith("fail_closed:extensionless:") for r in result.reasons)

    def test_extensionless_name_containing_test_substring_still_fail_closed(self):
        """Names like contest_runner must not be misclassified as tests via substring match."""
        ctx = _make_diff_context(
            _make_diff_file("scripts/contest_runner", hunk_content=["+ echo hi"])
        )
        result = triage_diff(ctx, surface_map=_empty_surface_map())
        assert result.classification == "security_relevant"
        assert any(r.startswith("fail_closed:extensionless:") for r in result.reasons)

    def test_extensionless_doc_path_not_fail_closed(self):
        """Extensionless file in docs/ should NOT trigger fail_closed:extensionless."""
        ctx = _make_diff_context(
            _make_diff_file("docs/CHANGELOG", hunk_content=["+ v1.0"])
        )
        result = triage_diff(ctx, surface_map=_empty_surface_map())
        assert not any(r.startswith("fail_closed:extensionless:") for r in result.reasons)

    def test_score_threshold_triggers_security_relevant(self):
        """File with security score >= 72 should be security_relevant."""
        # src/auth.py: code(+60) + src/(+20) + auth hint(+12) = 92
        ctx = _make_diff_context(
            _make_diff_file("src/auth.py", hunk_content=["+ pass"])
        )
        result = triage_diff(ctx, surface_map=_empty_surface_map())
        assert result.classification == "security_relevant"
        assert any(r.startswith("score_threshold:") for r in result.reasons)
        assert result.max_file_score >= 72


# ---------------------------------------------------------------------------
# Baseline matching
# ---------------------------------------------------------------------------

class TestBaselineMatching:
    def test_exact_vuln_path_match_triggers_security_relevant(self):
        """Exact normalized VULNERABILITIES.json file_path match triggers security_relevant."""
        surface = SecuritySurfaceMap(
            vuln_paths=frozenset({"src/auth.py"}),
            affected_components=frozenset(),
        )
        ctx = _make_diff_context(_make_diff_file("src/auth.py", hunk_content=["+ pass"]))
        result = triage_diff(ctx, surface_map=surface)
        assert result.classification == "security_relevant"
        assert any(r.startswith("baseline_vuln_path:") for r in result.reasons)

    def test_exact_component_match_triggers_security_relevant(self):
        """Exact THREAT_MODEL affected_components match triggers security_relevant."""
        surface = SecuritySurfaceMap(
            vuln_paths=frozenset(),
            affected_components=frozenset({"packages:py"}),
        )
        # packages/core/main.py -> _derive_components returns ["packages:py"]
        ctx = _make_diff_context(
            _make_diff_file("packages/core/main.py", hunk_content=["+ pass"])
        )
        result = triage_diff(ctx, surface_map=surface)
        assert result.classification == "security_relevant"
        assert any(r.startswith("baseline_component:") for r in result.reasons)

    def test_component_substring_does_not_match(self):
        """Substring of a component should NOT match (exact match only)."""
        surface = SecuritySurfaceMap(
            vuln_paths=frozenset(),
            affected_components=frozenset({"packages:python"}),  # not "packages:py"
        )
        ctx = _make_diff_context(
            _make_diff_file("packages/core/main.py", hunk_content=["+ pass"])
        )
        result = triage_diff(ctx, surface_map=surface)
        # Should not match "packages:python" when derived component is "packages:py"
        assert not any(r.startswith("baseline_component:") for r in result.reasons)


# ---------------------------------------------------------------------------
# build_security_surface_map
# ---------------------------------------------------------------------------

class TestBuildSecuritySurfaceMap:
    def test_missing_baseline_files_handled_gracefully(self, tmp_path: Path):
        """Missing baseline files should not raise; return empty sets."""
        surface = build_security_surface_map(tmp_path / "nonexistent")
        assert len(surface.vuln_paths) == 0
        assert len(surface.affected_components) == 0

    def test_malformed_json_handled_gracefully(self, tmp_path: Path):
        """Malformed JSON should not raise; return empty/partial sets."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "VULNERABILITIES.json").write_text("{bad-json", encoding="utf-8")
        (securevibes_dir / "THREAT_MODEL.json").write_text("{bad-json", encoding="utf-8")
        surface = build_security_surface_map(securevibes_dir)
        assert len(surface.vuln_paths) == 0
        assert len(surface.affected_components) == 0

    def test_wrapped_threat_model_formats(self, tmp_path: Path):
        """Wrapped THREAT_MODEL.json formats should be handled (dict with threats key)."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")
        threat_model = {
            "threats": [
                {
                    "id": "T1",
                    "affected_components": ["api:py"],
                    "title": "test",
                },
            ]
        }
        (securevibes_dir / "THREAT_MODEL.json").write_text(
            json.dumps(threat_model), encoding="utf-8"
        )
        surface = build_security_surface_map(securevibes_dir)
        assert "api:py" in surface.affected_components

    def test_vuln_paths_normalized(self, tmp_path: Path):
        """Vulnerability file_path values should be normalized and lowercased."""
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        (securevibes_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
        vulns = [
            {"file_path": "./src/Auth.py", "title": "test", "severity": "high"},
        ]
        (securevibes_dir / "VULNERABILITIES.json").write_text(
            json.dumps(vulns), encoding="utf-8"
        )
        surface = build_security_surface_map(securevibes_dir)
        assert "src/auth.py" in surface.vuln_paths


# ---------------------------------------------------------------------------
# compute_triage_overrides
# ---------------------------------------------------------------------------

class TestComputeTriageOverrides:
    def test_low_risk_returns_overrides(self):
        """low_risk triage should return reduced budget overrides."""
        result = TriageResult(
            classification="low_risk",
            reasons=("default:low_risk",),
            max_file_score=10,
            detector_hits=(),
            matched_vuln_paths=(),
            matched_components=(),
        )
        overrides = compute_triage_overrides(result)
        assert overrides is not None
        assert overrides.pr_review_attempts == 1
        assert overrides.pr_timeout_seconds == 60

    def test_security_relevant_returns_none(self):
        """security_relevant triage should return None (no override)."""
        result = TriageResult(
            classification="security_relevant",
            reasons=("signal:command_builder",),
            max_file_score=80,
            detector_hits=("command_builder",),
            matched_vuln_paths=(),
            matched_components=(),
        )
        overrides = compute_triage_overrides(result)
        assert overrides is None
