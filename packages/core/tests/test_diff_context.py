"""Tests for diff.context helpers."""

import json

from securevibes.diff.context import (
    normalize_repo_path,
    extract_relevant_architecture,
    filter_relevant_threats,
    filter_relevant_vulnerabilities,
    summarize_threats_for_prompt,
    summarize_vulnerabilities_for_prompt,
    suggest_security_adjacent_files,
    check_vuln_overlap,
)


# ── normalize_repo_path ──────────────────────────────────────────────


class TestNormalizeRepoPath:
    def test_strips_leading_dot_slash(self):
        assert normalize_repo_path("./src/app.py") == "src/app.py"

    def test_strips_multiple_leading_dot_slash(self):
        assert normalize_repo_path("././src/app.py") == "src/app.py"

    def test_normalizes_backslashes(self):
        assert normalize_repo_path("src\\lib\\utils.py") == "src/lib/utils.py"

    def test_collapses_multiple_slashes(self):
        assert normalize_repo_path("src///lib//utils.py") == "src/lib/utils.py"

    def test_strips_whitespace(self):
        assert normalize_repo_path("  src/app.py  ") == "src/app.py"

    def test_returns_empty_for_non_string(self):
        assert normalize_repo_path(42) == ""
        assert normalize_repo_path(None) == ""

    def test_returns_empty_for_empty_string(self):
        assert normalize_repo_path("") == ""

    def test_preserves_dotdot_components(self):
        """normalize_repo_path does NOT strip '..' — documented limitation."""
        result = normalize_repo_path("../outside/file.py")
        assert ".." in result


# ── extract_relevant_architecture ────────────────────────────────────


class TestExtractRelevantArchitecture:
    def test_returns_empty_when_file_missing(self, tmp_path):
        missing = tmp_path / "SECURITY.md"
        assert extract_relevant_architecture(missing, ["src/app.py"]) == ""

    def test_returns_empty_when_file_is_empty(self, tmp_path):
        md = tmp_path / "SECURITY.md"
        md.write_text("", encoding="utf-8")
        assert extract_relevant_architecture(md, ["src/app.py"]) == ""

    def test_returns_truncated_content_when_no_tokens(self, tmp_path):
        md = tmp_path / "SECURITY.md"
        md.write_text("# Overview\nSome content here.\n", encoding="utf-8")
        result = extract_relevant_architecture(md, [])
        assert "Some content here" in result

    def test_returns_matching_sections(self, tmp_path):
        md = tmp_path / "SECURITY.md"
        md.write_text(
            "# Auth Module\nHandles authentication.\n\n"
            "# Database Layer\nHandles database access.\n",
            encoding="utf-8",
        )
        result = extract_relevant_architecture(md, ["src/auth/handler.py"])
        assert "Auth Module" in result

    def test_returns_fallback_when_no_sections_match(self, tmp_path):
        md = tmp_path / "SECURITY.md"
        content = "# Unrelated\nNothing about changed files.\n"
        md.write_text(content, encoding="utf-8")
        result = extract_relevant_architecture(md, ["src/billing/invoice.py"])
        # Falls back to default truncation
        assert "Unrelated" in result


# ── filter_relevant_threats ──────────────────────────────────────────


class TestFilterRelevantThreats:
    def test_returns_empty_when_file_missing(self, tmp_path):
        missing = tmp_path / "THREAT_MODEL.json"
        assert filter_relevant_threats(missing, ["src/app.py"]) == []

    def test_returns_empty_when_file_is_empty(self, tmp_path):
        tm = tmp_path / "THREAT_MODEL.json"
        tm.write_text("", encoding="utf-8")
        assert filter_relevant_threats(tm, ["src/app.py"]) == []

    def test_returns_empty_when_json_is_invalid(self, tmp_path):
        tm = tmp_path / "THREAT_MODEL.json"
        tm.write_text("not json", encoding="utf-8")
        assert filter_relevant_threats(tm, ["src/app.py"]) == []

    def test_filters_threats_by_changed_files(self, tmp_path):
        tm = tmp_path / "THREAT_MODEL.json"
        threats = [
            {
                "id": "T1",
                "title": "Auth bypass",
                "description": "Bypass in auth module",
                "file_path": "src/auth/handler.py",
                "severity": "high",
            },
            {
                "id": "T2",
                "title": "Data leak",
                "description": "Leak in billing",
                "file_path": "src/billing/invoice.py",
                "severity": "medium",
            },
        ]
        tm.write_text(json.dumps(threats), encoding="utf-8")
        result = filter_relevant_threats(tm, ["src/auth/handler.py"])
        # T1 should be ranked highest due to exact path match
        assert len(result) >= 1
        assert result[0]["id"] == "T1"

    def test_respects_max_items(self, tmp_path):
        tm = tmp_path / "THREAT_MODEL.json"
        threats = [
            {"id": f"T{i}", "title": f"Threat {i}", "file_path": "src/app.py"} for i in range(20)
        ]
        tm.write_text(json.dumps(threats), encoding="utf-8")
        result = filter_relevant_threats(tm, ["src/app.py"], max_items=3)
        assert len(result) <= 3

    def test_handles_wrapped_threat_model(self, tmp_path):
        """Wrapped format like {'threats': [...]} should be handled."""
        tm = tmp_path / "THREAT_MODEL.json"
        data = {
            "threats": [
                {
                    "id": "T1",
                    "title": "Auth bypass",
                    "file_path": "src/auth/handler.py",
                    "severity": "high",
                }
            ]
        }
        tm.write_text(json.dumps(data), encoding="utf-8")
        result = filter_relevant_threats(tm, ["src/auth/handler.py"])
        assert len(result) >= 1


# ── filter_relevant_vulnerabilities ──────────────────────────────────


class TestFilterRelevantVulnerabilities:
    def test_returns_empty_for_empty_input(self):
        assert filter_relevant_vulnerabilities([], ["src/app.py"]) == []

    def test_filters_by_file_path(self):
        vulns = [
            {
                "threat_id": "V1",
                "title": "SQL Injection",
                "file_path": "src/db/query.py",
                "severity": "high",
                "cwe_id": "CWE-89",
            },
            {
                "threat_id": "V2",
                "title": "XSS",
                "file_path": "src/web/render.py",
                "severity": "medium",
                "cwe_id": "CWE-79",
            },
        ]
        result = filter_relevant_vulnerabilities(vulns, ["src/db/query.py"])
        assert len(result) >= 1
        assert result[0]["threat_id"] == "V1"

    def test_respects_max_items(self):
        vulns = [
            {"threat_id": f"V{i}", "title": f"Vuln {i}", "file_path": "src/app.py"}
            for i in range(20)
        ]
        result = filter_relevant_vulnerabilities(vulns, ["src/app.py"], max_items=5)
        assert len(result) <= 5

    def test_skips_non_dict_items(self):
        vulns = [
            "not a dict",
            None,
            {"threat_id": "V1", "title": "Real", "file_path": "src/app.py"},
        ]
        result = filter_relevant_vulnerabilities(vulns, ["src/app.py"])
        assert all(isinstance(v, dict) for v in result)


# ── summarize_threats_for_prompt ─────────────────────────────────────


class TestSummarizeThreatsForPrompt:
    def test_returns_none_marker_for_empty(self):
        assert summarize_threats_for_prompt([]) == "- None"

    def test_formats_single_threat(self):
        threats = [
            {
                "id": "THREAT-001",
                "title": "Auth Bypass",
                "severity": "high",
                "file_path": "src/auth.py",
                "cwe_id": "CWE-287",
            }
        ]
        result = summarize_threats_for_prompt(threats)
        assert "THREAT-001" in result
        assert "Auth Bypass" in result
        assert "high" in result

    def test_respects_max_chars(self):
        threats = [
            {
                "id": f"T-{i:03d}",
                "title": f"Threat number {i} with a longer description for testing",
                "severity": "medium",
                "file_path": f"src/module_{i}.py",
                "description": "A" * 200,
            }
            for i in range(20)
        ]
        result = summarize_threats_for_prompt(threats, max_chars=200)
        assert len(result) <= 200


# ── summarize_vulnerabilities_for_prompt ──────────────────────────────


class TestSummarizeVulnerabilitiesForPrompt:
    def test_returns_none_marker_for_empty(self):
        assert summarize_vulnerabilities_for_prompt([]) == "- None"

    def test_formats_single_vulnerability(self):
        vulns = [
            {
                "threat_id": "THREAT-001",
                "title": "SQL Injection",
                "severity": "high",
                "file_path": "src/db.py",
                "cwe_id": "CWE-89",
            }
        ]
        result = summarize_vulnerabilities_for_prompt(vulns)
        assert "THREAT-001" in result
        assert "SQL Injection" in result


# ── suggest_security_adjacent_files ──────────────────────────────────


class TestSuggestSecurityAdjacentFiles:
    def test_returns_empty_for_empty_changed_files(self, tmp_path):
        assert suggest_security_adjacent_files(tmp_path, []) == []

    def test_returns_empty_when_max_items_zero(self, tmp_path):
        assert suggest_security_adjacent_files(tmp_path, ["src/app.py"], max_items=0) == []

    def test_suggests_security_adjacent_files(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "handler.py").write_text("handler", encoding="utf-8")
        (src / "auth_middleware.py").write_text("auth", encoding="utf-8")
        (src / "policy_guard.py").write_text("guard", encoding="utf-8")

        result = suggest_security_adjacent_files(tmp_path, ["src/handler.py"])
        # auth_middleware.py and policy_guard.py should be suggested
        assert any("auth_middleware" in p for p in result)

    def test_excludes_changed_files_from_suggestions(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "auth.py").write_text("auth", encoding="utf-8")

        result = suggest_security_adjacent_files(tmp_path, ["src/auth.py"])
        assert "src/auth.py" not in result

    def test_excludes_test_files(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "handler.py").write_text("handler", encoding="utf-8")
        (src / "test_auth.py").write_text("test", encoding="utf-8")
        (src / "auth_guard.py").write_text("guard", encoding="utf-8")

        result = suggest_security_adjacent_files(tmp_path, ["src/handler.py"])
        assert all("test_auth" not in p for p in result)

    def test_respects_max_items(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "handler.py").write_text("x", encoding="utf-8")
        for i in range(10):
            (src / f"auth_module_{i}.py").write_text("auth", encoding="utf-8")

        result = suggest_security_adjacent_files(tmp_path, ["src/handler.py"], max_items=3)
        assert len(result) <= 3


# ── check_vuln_overlap ───────────────────────────────────────────────


class TestCheckVulnOverlap:
    def test_returns_empty_when_file_missing(self, tmp_path):
        missing = tmp_path / "VULNERABILITIES.json"
        assert check_vuln_overlap(missing, ["src/app.py"]) == []

    def test_returns_empty_when_file_is_empty(self, tmp_path):
        v = tmp_path / "VULNERABILITIES.json"
        v.write_text("", encoding="utf-8")
        assert check_vuln_overlap(v, ["src/app.py"]) == []

    def test_returns_empty_when_json_is_invalid(self, tmp_path):
        v = tmp_path / "VULNERABILITIES.json"
        v.write_text("not json", encoding="utf-8")
        assert check_vuln_overlap(v, ["src/app.py"]) == []

    def test_returns_overlapping_vulnerabilities(self, tmp_path):
        v = tmp_path / "VULNERABILITIES.json"
        vulns = [
            {"threat_id": "V1", "file_path": "src/app.py", "title": "XSS"},
            {"threat_id": "V2", "file_path": "src/other.py", "title": "SQLi"},
        ]
        v.write_text(json.dumps(vulns), encoding="utf-8")
        result = check_vuln_overlap(v, ["src/app.py"])
        assert len(result) == 1
        assert result[0]["threat_id"] == "V1"

    def test_returns_empty_when_no_overlap(self, tmp_path):
        v = tmp_path / "VULNERABILITIES.json"
        vulns = [{"threat_id": "V1", "file_path": "src/other.py", "title": "XSS"}]
        v.write_text(json.dumps(vulns), encoding="utf-8")
        result = check_vuln_overlap(v, ["src/app.py"])
        assert result == []

    def test_handles_non_list_json(self, tmp_path):
        v = tmp_path / "VULNERABILITIES.json"
        v.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
        assert check_vuln_overlap(v, ["src/app.py"]) == []

    def test_normalizes_paths_for_comparison(self, tmp_path):
        v = tmp_path / "VULNERABILITIES.json"
        vulns = [{"threat_id": "V1", "file_path": "./src/app.py", "title": "XSS"}]
        v.write_text(json.dumps(vulns), encoding="utf-8")
        result = check_vuln_overlap(v, ["src/app.py"])
        assert len(result) == 1
