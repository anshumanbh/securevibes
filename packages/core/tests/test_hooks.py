"""Tests for scanner hooks"""

import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import Mock

import pytest
from rich.console import Console

from securevibes.scanner.hooks import (
    _is_inside_repo,
    _is_within_tmp_dir,
    _MAX_BLOCKED_PATHS,
    _normalize_hook_path,
    _record_blocked_path,
    _sanitize_pr_grep_scope,
    create_json_validation_hook,
    create_dast_security_hook,
    create_post_tool_hook,
    create_pre_tool_hook,
    create_subagent_hook,
)
from securevibes.scanner.progress import ProgressTracker


def test_record_blocked_path_increments_count():
    """_record_blocked_path should increment counter and append path."""
    observer = {"blocked_out_of_repo_count": 0}
    _record_blocked_path(observer, "/some/path")
    assert observer["blocked_out_of_repo_count"] == 1
    assert observer["blocked_paths"] == ["/some/path"]


def test_record_blocked_path_caps_at_max():
    """blocked_paths list should not exceed _MAX_BLOCKED_PATHS entries."""
    observer = {
        "blocked_out_of_repo_count": 0,
        "blocked_paths": [f"/path/{i}" for i in range(_MAX_BLOCKED_PATHS)],
    }
    _record_blocked_path(observer, "/one/more")
    assert observer["blocked_out_of_repo_count"] == 1
    assert len(observer["blocked_paths"]) == _MAX_BLOCKED_PATHS  # not grown


def test_record_blocked_path_none_observer_is_noop():
    """None observer should be silently ignored."""
    _record_blocked_path(None, "/path")  # should not raise


def test_normalize_hook_path_rejects_null_bytes():
    """Paths with null bytes should be rejected (return empty string)."""
    assert _normalize_hook_path("src/app.py\x00trailing") == ""


def test_normalize_hook_path_rejects_embedded_null_byte():
    """Embedded null bytes anywhere in the path should cause rejection."""
    assert _normalize_hook_path("src/\x00app.py") == ""


def test_normalize_hook_path_rejects_leading_null_byte():
    """Leading null byte should cause rejection."""
    assert _normalize_hook_path("\x00src/app.py") == ""


def test_normalize_hook_path_normal_paths_unaffected():
    """Normal paths without null bytes should be normalized correctly."""
    assert _normalize_hook_path("src/app.py") == "src/app.py"
    assert _normalize_hook_path("src\\app.py") == "src/app.py"
    assert _normalize_hook_path("  src/app.py  ") == "src/app.py"


def test_normalize_hook_path_empty_and_none():
    """Empty and None inputs should return empty string."""
    assert _normalize_hook_path("") == ""
    assert _normalize_hook_path(None) == ""


def test_is_within_tmp_dir_rejects_existing_symlink_escape(tmp_path):
    """Paths under /tmp should be denied when a symlinked component escapes tmp root."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    symlink_path = Path(tempfile.gettempdir()) / "securevibes_hook_symlink_escape"
    try:
        try:
            symlink_path.symlink_to(outside_dir, target_is_directory=True)
        except FileExistsError:
            symlink_path.unlink()
            symlink_path.symlink_to(outside_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not supported on this platform")

    try:
        assert _is_within_tmp_dir(str(symlink_path / "payload.json")) is False
    finally:
        symlink_path.unlink(missing_ok=True)


class TestIsInsideRepo:
    """Tests for _is_inside_repo symlink-aware boundary checks."""

    def test_normal_path_inside_repo_accepted(self, tmp_path):
        """Normal path inside repo root should be accepted."""
        repo_root = tmp_path / "repo"
        src_dir = repo_root / "src"
        src_dir.mkdir(parents=True)
        unresolved = repo_root / "src" / "app.py"
        candidate = unresolved.resolve(strict=False)
        assert _is_inside_repo(repo_root, candidate, unresolved) is True

    def test_repo_root_itself_accepted(self, tmp_path):
        """The repo root path itself should be accepted."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir(parents=True)
        assert _is_inside_repo(repo_root, repo_root.resolve(strict=False)) is True

    def test_path_outside_repo_rejected(self, tmp_path):
        """Path outside repo root should be rejected."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir(parents=True)
        outside = (tmp_path / "outside" / "file.py").resolve(strict=False)
        assert _is_inside_repo(repo_root, outside) is False

    def test_none_candidate_rejected(self, tmp_path):
        """None candidate should be rejected."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir(parents=True)
        assert _is_inside_repo(repo_root, None) is False

    def test_symlink_component_inside_repo_pointing_inside_rejected(self, tmp_path):
        """A symlink inside the repo pointing to another repo dir should be rejected."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir(parents=True)
        real_dir = repo_root / "real_dir"
        real_dir.mkdir()

        symlink_path = repo_root / "sneaky_link"
        try:
            symlink_path.symlink_to(real_dir, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("Symlink creation is not supported on this platform")

        # Resolved path looks inside repo (real_dir/file.py), but unresolved
        # path traverses a symlink component (sneaky_link/file.py)
        unresolved = symlink_path / "file.py"
        resolved = unresolved.resolve(strict=False)
        assert _is_inside_repo(repo_root, resolved, unresolved) is False

    def test_symlink_component_pointing_outside_rejected(self, tmp_path):
        """A symlink inside the repo pointing outside should be rejected."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir(parents=True)
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()

        symlink_path = repo_root / "escape_link"
        try:
            symlink_path.symlink_to(outside_dir, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("Symlink creation is not supported on this platform")

        unresolved = symlink_path / "secret.txt"
        resolved = unresolved.resolve(strict=False)
        # Resolved path is outside repo, caught by parent check AND symlink walk
        assert _is_inside_repo(repo_root, resolved, unresolved) is False

    def test_deeply_nested_symlink_in_repo_rejected(self, tmp_path):
        """A symlink deep inside the repo tree should be rejected."""
        repo_root = tmp_path / "repo"
        nested = repo_root / "a" / "b"
        nested.mkdir(parents=True)
        real_target = repo_root / "real"
        real_target.mkdir()

        symlink = nested / "link"
        try:
            symlink.symlink_to(real_target, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("Symlink creation is not supported on this platform")

        unresolved = symlink / "file.py"
        resolved = unresolved.resolve(strict=False)
        assert _is_inside_repo(repo_root, resolved, unresolved) is False

    def test_non_symlink_nested_path_accepted(self, tmp_path):
        """A deeply nested path with no symlinks should be accepted."""
        repo_root = tmp_path / "repo"
        nested = repo_root / "a" / "b" / "c"
        nested.mkdir(parents=True)
        unresolved = nested / "file.py"
        candidate = unresolved.resolve(strict=False)
        assert _is_inside_repo(repo_root, candidate, unresolved) is True

    def test_without_unresolved_falls_back_to_resolved_walk(self, tmp_path):
        """When unresolved is not provided, walks resolved path (backward compat)."""
        repo_root = tmp_path / "repo"
        src_dir = repo_root / "src"
        src_dir.mkdir(parents=True)
        candidate = (repo_root / "src" / "app.py").resolve(strict=False)
        assert _is_inside_repo(repo_root, candidate) is True


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("src", "src"),
        ("apps/service", "apps/service"),
        ("../outside", "src"),
        ("/abs/path", "src"),
        ("", "src"),
        (None, "src"),
    ],
)
def test_sanitize_pr_grep_scope_enforces_repo_relative_defaults(raw, expected):
    """Pathless PR grep scope should stay repo-relative and safe."""
    assert _sanitize_pr_grep_scope(raw) == expected


class TestDASTSecurityHook:
    """Tests for DAST security hook that blocks database tools"""

    @pytest.fixture
    def tracker(self):
        """Create a progress tracker"""
        console = Console(file=StringIO())
        return ProgressTracker(console, debug=False)

    @pytest.fixture
    def console(self):
        """Create a Rich console"""
        return Console(file=StringIO())

    @pytest.mark.asyncio
    async def test_blocks_sqlite3_in_dast_phase(self, tracker, console):
        """Test that sqlite3 is blocked during DAST phase"""
        tracker.current_phase = "dast"
        hook = create_dast_security_hook(tracker, console, debug=False)

        input_data = {
            "tool_name": "Bash",
            "tool_input": {"command": "sqlite3 database.db 'SELECT * FROM users'"},
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "sqlite3" in result["hookSpecificOutput"]["permissionDecisionReason"]

    @pytest.mark.asyncio
    async def test_blocks_psql_in_dast_phase(self, tracker, console):
        """Test that psql is blocked during DAST phase"""
        tracker.current_phase = "dast"
        hook = create_dast_security_hook(tracker, console, debug=False)

        input_data = {"tool_name": "Bash", "tool_input": {"command": "psql -U admin -d production"}}

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    @pytest.mark.asyncio
    async def test_dast_db_block_denial_payload_has_expected_fields(self, tracker, console):
        """DAST denial payload should include structured PreToolUse decision fields."""
        tracker.current_phase = "dast"
        hook = create_dast_security_hook(tracker, console, debug=False)

        input_data = {"tool_name": "Bash", "tool_input": {"command": "mysql -u root -p"}}

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        payload = result["hookSpecificOutput"]
        assert payload["hookEventName"] == "PreToolUse"
        assert payload["permissionDecision"] == "deny"
        assert "mysql" in payload["permissionDecisionReason"]
        assert "HTTP testing only" in payload["permissionDecisionReason"]
        assert "Database manipulation not allowed" in payload["reason"]

    @pytest.mark.asyncio
    async def test_blocks_mixed_case_db_tool_in_dast_phase(self, tracker, console):
        """Mixed-case DB tool invocations should still be blocked."""
        tracker.current_phase = "dast"
        hook = create_dast_security_hook(tracker, console, debug=False)

        input_data = {"tool_name": "Bash", "tool_input": {"command": "/usr/bin/PSQL -U admin"}}

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "psql" in result["hookSpecificOutput"]["permissionDecisionReason"]

    @pytest.mark.asyncio
    async def test_does_not_block_partial_tool_name_tokens(self, tracker, console):
        """Words that only contain blocked tool names as partial substrings should pass."""
        tracker.current_phase = "dast"
        hook = create_dast_security_hook(tracker, console, debug=False)

        input_data = {"tool_name": "Bash", "tool_input": {"command": "echo mysql2-client ready"}}

        result = await hook(input_data, "tool-123", {})

        assert result == {}

    @pytest.mark.asyncio
    async def test_allows_sqlite3_in_other_phases(self, tracker, console):
        """Test that sqlite3 is allowed in non-DAST phases"""
        tracker.current_phase = "code-review"
        hook = create_dast_security_hook(tracker, console, debug=False)

        input_data = {"tool_name": "Bash", "tool_input": {"command": "sqlite3 database.db .schema"}}

        result = await hook(input_data, "tool-123", {})

        # Should return empty dict (allow)
        assert result == {}

    @pytest.mark.asyncio
    async def test_only_filters_bash_commands(self, tracker, console):
        """Test that only Bash commands are filtered"""
        tracker.current_phase = "dast"
        hook = create_dast_security_hook(tracker, console, debug=False)

        # Non-Bash tool should not be filtered
        input_data = {"tool_name": "Read", "tool_input": {"file_path": "sqlite3_script.sh"}}

        result = await hook(input_data, "tool-123", {})

        # Should return empty dict (allow)
        assert result == {}

    @pytest.mark.asyncio
    async def test_allows_safe_bash_commands_in_dast(self, tracker, console):
        """Test that safe Bash commands are allowed in DAST"""
        tracker.current_phase = "dast"
        hook = create_dast_security_hook(tracker, console, debug=False)

        input_data = {
            "tool_name": "Bash",
            "tool_input": {"command": "curl -X POST http://localhost:5000/api/login"},
        }

        result = await hook(input_data, "tool-123", {})

        # Should return empty dict (allow)
        assert result == {}


class TestPreToolHook:
    """Tests for pre-tool hook that handles exclusions and restrictions"""

    @pytest.fixture
    def tracker(self):
        """Create a progress tracker"""
        console = Console(file=StringIO())
        return ProgressTracker(console, debug=False)

    @pytest.fixture
    def console(self):
        """Create a Rich console"""
        return Console(file=StringIO())

    @pytest.mark.asyncio
    async def test_excludes_venv_for_read(self, tracker, console):
        """Test that reads from venv are blocked"""
        tracker.current_phase = "assessment"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Read",
            "tool_input": {
                "file_path": "/project/venv/lib/python3.9/site-packages/django/models.py"
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert "Infrastructure directory" in result["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_excludes_node_modules_for_read(self, tracker, console):
        """Test that reads from node_modules are blocked"""
        tracker.current_phase = "assessment"
        detected_languages = {"javascript"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/node_modules/express/index.js"},
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert "Infrastructure directory" in result["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_excludes_vendor_bundle_for_read(self, tracker, console):
        """Test that reads from Ruby vendor/bundle are blocked."""
        tracker.current_phase = "assessment"
        detected_languages = {"ruby"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/vendor/bundle/gems/rails/lib/railtie.rb"},
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert "Infrastructure directory" in result["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_injects_exclude_patterns_for_grep(self, tracker, console):
        """Test that Grep gets exclude patterns injected"""
        tracker.current_phase = "assessment"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Grep",
            "tool_input": {"pattern": "password", "excludePatterns": []},
        }

        result = await hook(input_data, "tool-123", {})

        # Should inject exclude patterns
        assert len(input_data["tool_input"]["excludePatterns"]) > 0
        assert any("venv" in pattern for pattern in input_data["tool_input"]["excludePatterns"])
        assert result == {}  # No override

    @pytest.mark.asyncio
    async def test_coerces_non_list_exclude_patterns_for_grep(self, tracker, console):
        """Non-list Grep excludePatterns should be normalized and merged safely."""
        tracker.current_phase = "assessment"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Grep",
            "tool_input": {"pattern": "token", "excludePatterns": "legacy/**"},
        }

        result = await hook(input_data, "tool-123", {})

        merged = input_data["tool_input"]["excludePatterns"]
        assert isinstance(merged, list)
        assert "legacy/**" in merged
        assert any("venv" in pattern for pattern in merged)
        assert result == {}

    @pytest.mark.asyncio
    async def test_injects_exclude_patterns_for_glob(self, tracker, console):
        """Test that Glob gets exclude patterns injected"""
        tracker.current_phase = "assessment"
        detected_languages = {"javascript"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Glob",
            "tool_input": {"patterns": ["**/*.js"], "excludePatterns": []},
        }

        result = await hook(input_data, "tool-123", {})

        # Should inject exclude patterns
        assert len(input_data["tool_input"]["excludePatterns"]) > 0
        assert any(
            "node_modules" in pattern for pattern in input_data["tool_input"]["excludePatterns"]
        )
        assert result == {}

    @pytest.mark.asyncio
    async def test_blocks_non_artifact_writes_in_dast(self, tracker, console):
        """Test that non-artifact writes are blocked in DAST phase"""
        tracker.current_phase = "dast"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/project/some_file.txt", "content": "test data"},
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert "DAST phase may only write" in result["override_result"]["content"]
        assert result["override_result"]["is_error"] is True

    @pytest.mark.asyncio
    async def test_allows_dast_validation_write(self, tracker, console):
        """Test that DAST_VALIDATION.json write is allowed"""
        tracker.current_phase = "dast"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": ".securevibes/DAST_VALIDATION.json",
                "content": "{}",
            },
        }

        result = await hook(input_data, "tool-123", {})

        # Should not block (but will call tracker.on_tool_start)
        assert "override_result" not in result

    @pytest.mark.asyncio
    async def test_allows_in_repo_absolute_dast_validation_write_with_repo_root(
        self, tracker, console, tmp_path
    ):
        """Absolute DAST artifact path should be allowed when anchored to repo root."""
        tracker.current_phase = "dast"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        securevibes_dir = repo_root / ".securevibes"
        securevibes_dir.mkdir(parents=True)
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_repo_root=repo_root,
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": str(securevibes_dir / "DAST_VALIDATION.json"),
                "content": "{}",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" not in result

    @pytest.mark.asyncio
    async def test_blocks_out_of_repo_dast_artifact_write_with_repo_root(
        self, tracker, console, tmp_path
    ):
        """DAST artifact writes outside repo root should be blocked."""
        tracker.current_phase = "dast"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_repo_root=repo_root,
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/other/.securevibes/DAST_VALIDATION.json",
                "content": "{}",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert result["override_result"]["is_error"] is True
        assert "/other/.securevibes/DAST_VALIDATION.json" in result["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_allows_tmp_writes_in_dast(self, tracker, console):
        """Test that /tmp/* writes are allowed in DAST"""
        tracker.current_phase = "dast"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/test_script.py", "content": "print('hello')"},
        }

        result = await hook(input_data, "tool-123", {})

        # Should not block
        assert "override_result" not in result

    @pytest.mark.asyncio
    async def test_blocks_tmp_traversal_writes_in_dast(self, tracker, console):
        """DAST should reject /tmp traversal paths that resolve outside /tmp."""
        tracker.current_phase = "dast"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/../etc/passwd", "content": "oops"},
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert result["override_result"]["is_error"] is True
        assert "Blocked write to: /tmp/../etc/passwd" in result["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_blocks_empty_file_path_writes_in_dast(self, tracker, console):
        """DAST should fail closed when file_path is empty."""
        tracker.current_phase = "dast"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": "", "content": "test data"},
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert result["override_result"]["is_error"] is True
        assert "file_path is required" in result["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_blocks_arbitrary_writes_in_pr_code_review(self, tracker, console):
        """PR code review should block arbitrary file writes."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/project/src/agents/pr-code-review.ts", "content": "x"},
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert "PR code review phase may only write" in result["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_allows_pr_vulnerabilities_write_in_pr_code_review(self, tracker, console):
        """PR code review should allow PR_VULNERABILITIES.json artifact write."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": ".securevibes/PR_VULNERABILITIES.json",
                "content": "[]",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" not in result

    @pytest.mark.asyncio
    async def test_allows_in_repo_absolute_pr_artifact_write_in_pr_code_review(
        self, tracker, console, tmp_path
    ):
        """PR code review should allow canonical absolute artifact writes within repo root."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        securevibes_dir = repo_root / ".securevibes"
        securevibes_dir.mkdir(parents=True)
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_repo_root=repo_root,
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": str(securevibes_dir / "PR_VULNERABILITIES.json"),
                "content": "[]",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" not in result

    @pytest.mark.asyncio
    async def test_blocks_absolute_pr_artifact_write_without_repo_root(self, tracker, console):
        """Without repo root, absolute artifact paths should be blocked to fail closed."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": "[]",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert result["override_result"]["is_error"] is True
        assert "PR code review phase may only write" in result["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_blocks_out_of_repo_pr_artifact_write_in_pr_code_review(
        self, tracker, console, tmp_path
    ):
        """PR code review should deny PR artifact writes outside repository root."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        guard_observer = {"blocked_out_of_repo_count": 0}
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_repo_root=repo_root,
            pr_tool_guard_observer=guard_observer,
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/tmp/.securevibes/PR_VULNERABILITIES.json",
                "content": "[]",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "outside repository root" in result["hookSpecificOutput"]["permissionDecisionReason"]
        assert guard_observer["blocked_out_of_repo_count"] == 1

    @pytest.mark.asyncio
    async def test_blocks_path_traversal_pr_artifact_write_in_pr_code_review(
        self, tracker, console, tmp_path
    ):
        """PR code review should deny traversal writes that escape the repository root."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        guard_observer = {"blocked_out_of_repo_count": 0}
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_repo_root=repo_root,
            pr_tool_guard_observer=guard_observer,
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "../../tmp/.securevibes/PR_VULNERABILITIES.json",
                "content": "[]",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert guard_observer["blocked_out_of_repo_count"] == 1

    @pytest.mark.asyncio
    async def test_blocks_nested_securevibes_pr_artifact_write_in_pr_code_review(
        self, tracker, console, tmp_path
    ):
        """PR code review should reject nested .securevibes artifact paths."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        nested_securevibes = repo_root / "src" / ".securevibes"
        nested_securevibes.mkdir(parents=True)
        guard_observer = {"blocked_out_of_repo_count": 0}
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_repo_root=repo_root,
            pr_tool_guard_observer=guard_observer,
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": str(nested_securevibes / "PR_VULNERABILITIES.json"),
                "content": "[]",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert result["override_result"]["is_error"] is True
        assert "PR code review phase may only write" in result["override_result"]["content"]
        assert guard_observer["blocked_out_of_repo_count"] == 0

    @pytest.mark.asyncio
    async def test_blocks_tmp_writes_in_pr_code_review(self, tracker, console):
        """PR code review should not allow /tmp writes."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/pr-review-helper.py", "content": "print('x')"},
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert "/tmp/pr-review-helper.py" in result["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_blocks_edit_writes_in_pr_code_review(self, tracker, console):
        """PR code review should enforce same artifact guard for Edit as Write."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/tmp/pr-review-helper.py",
                "old_string": "",
                "new_string": "",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert "PR code review phase may only write" in result["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_blocks_empty_file_path_writes_in_pr_code_review(self, tracker, console):
        """PR code review should fail closed when file_path is empty."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": "", "content": "[]"},
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert result["override_result"]["is_error"] is True
        assert "file_path is required" in result["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_blocks_other_securevibes_writes_in_pr_code_review(self, tracker, console):
        """PR code review should block non-PR_VULNERABILITIES artifacts."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/VULNERABILITIES.json",
                "content": "[]",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert "PR code review phase may only write" in result["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_normalizes_bare_pr_vulnerabilities_write_path(self, tracker, console):
        """PR code review should normalize bare artifact path to .securevibes location."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "PR_VULNERABILITIES.json",
                "content": "[]",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        updated = result["hookSpecificOutput"]["updatedInput"]
        assert updated["file_path"] == ".securevibes/PR_VULNERABILITIES.json"

    @pytest.mark.asyncio
    async def test_read_operations_unaffected_in_pr_code_review(self, tracker, console):
        """PR code review restrictions should not affect reads."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/src/app.py"},
        }

        result = await hook(input_data, "tool-123", {})

        assert result == {}

    @pytest.mark.asyncio
    async def test_blocks_out_of_repo_read_outside_pr_phase(self, tracker, console, tmp_path):
        """Non-PR phases should also deny out-of-repo read attempts."""
        tracker.current_phase = "assessment"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("x", encoding="utf-8")
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_repo_root=repo_root,
        )

        input_data = {
            "tool_name": "Read",
            "tool_input": {"file_path": str(outside_file)},
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        payload = result["hookSpecificOutput"]
        assert payload["permissionDecision"] == "deny"
        assert (
            "SecureVibes scan cannot access files outside repository root"
            in payload["permissionDecisionReason"]
        )

    @pytest.mark.asyncio
    async def test_blocks_out_of_repo_write_outside_pr_and_dast(self, tracker, console, tmp_path):
        """Non-PR/non-DAST phases should deny out-of-repo write attempts."""
        tracker.current_phase = "assessment"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        guard_observer = {"blocked_out_of_repo_count": 0}
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_repo_root=repo_root,
            pr_tool_guard_observer=guard_observer,
        )

        input_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": str(tmp_path / "outside.json"), "content": "{}"},
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        payload = result["hookSpecificOutput"]
        assert payload["permissionDecision"] == "deny"
        assert (
            "SecureVibes scan cannot write files outside repository root"
            in payload["permissionDecisionReason"]
        )
        assert guard_observer["blocked_out_of_repo_count"] == 1

    @pytest.mark.asyncio
    async def test_blocks_out_of_repo_read_in_pr_code_review(self, tracker, console, tmp_path):
        """PR code review should deny reads outside repository root."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("x", encoding="utf-8")
        guard_observer = {"blocked_out_of_repo_count": 0}
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_repo_root=repo_root,
            pr_tool_guard_observer=guard_observer,
        )

        input_data = {
            "tool_name": "Read",
            "tool_input": {"file_path": str(outside_file)},
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "outside repository root" in result["hookSpecificOutput"]["permissionDecisionReason"]
        assert guard_observer["blocked_out_of_repo_count"] == 1

    @pytest.mark.asyncio
    async def test_out_of_repo_read_denial_payload_has_expected_fields(
        self, tracker, console, tmp_path
    ):
        """PR out-of-repo read denial should include structured PreToolUse payload."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("x", encoding="utf-8")
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_repo_root=repo_root,
            pr_tool_guard_observer={"blocked_out_of_repo_count": 0},
        )

        input_data = {
            "tool_name": "Read",
            "tool_input": {"file_path": str(outside_file)},
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        payload = result["hookSpecificOutput"]
        assert payload["hookEventName"] == "PreToolUse"
        assert payload["permissionDecision"] == "deny"
        assert "outside repository root" in payload["permissionDecisionReason"]
        assert "blocked out-of-repo access" in payload["reason"]

    @pytest.mark.asyncio
    async def test_blocks_out_of_repo_grep_in_pr_code_review(self, tracker, console, tmp_path):
        """PR code review should deny grep paths outside repository root."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        guard_observer = {"blocked_out_of_repo_count": 0}
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_repo_root=repo_root,
            pr_tool_guard_observer=guard_observer,
        )

        input_data = {
            "tool_name": "Grep",
            "tool_input": {"pattern": "secret", "path": str(outside_dir)},
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert guard_observer["blocked_out_of_repo_count"] == 1

    @pytest.mark.asyncio
    async def test_blocks_out_of_repo_glob_patterns_in_pr_code_review(
        self, tracker, console, tmp_path
    ):
        """PR code review should deny glob patterns that target paths outside repository root."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        guard_observer = {"blocked_out_of_repo_count": 0}
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_repo_root=repo_root,
            pr_tool_guard_observer=guard_observer,
        )

        input_data = {
            "tool_name": "Glob",
            "tool_input": {"patterns": [str(outside_dir / "**" / "*.py")]},
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert guard_observer["blocked_out_of_repo_count"] == 1

    @pytest.mark.asyncio
    async def test_blocks_path_traversal_glob_patterns_in_pr_code_review(
        self, tracker, console, tmp_path
    ):
        """PR code review should deny glob traversal patterns that escape repository root."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        guard_observer = {"blocked_out_of_repo_count": 0}
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_repo_root=repo_root,
            pr_tool_guard_observer=guard_observer,
        )

        input_data = {
            "tool_name": "Glob",
            "tool_input": {"patterns": ["../outside/**/*.py"]},
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert guard_observer["blocked_out_of_repo_count"] == 1

    @pytest.mark.asyncio
    async def test_allows_in_repo_glob_patterns_with_repo_guard_in_pr_code_review(
        self, tracker, console, tmp_path
    ):
        """PR code review should allow in-repo glob patterns when guard is enabled."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        source_dir = repo_root / "src"
        source_dir.mkdir(parents=True)
        guard_observer = {"blocked_out_of_repo_count": 0}
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_repo_root=repo_root,
            pr_tool_guard_observer=guard_observer,
        )

        input_data = {
            "tool_name": "Glob",
            "tool_input": {"patterns": [str(source_dir / "**" / "*.py")]},
        }

        result = await hook(input_data, "tool-123", {})

        assert result == {}
        assert guard_observer["blocked_out_of_repo_count"] == 0

    @pytest.mark.asyncio
    async def test_allows_in_repo_read_with_repo_guard_in_pr_code_review(
        self, tracker, console, tmp_path
    ):
        """PR code review should allow reads under repository root when guard is enabled."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        source_dir = repo_root / "src"
        source_dir.mkdir(parents=True)
        app_file = source_dir / "app.py"
        app_file.write_text("print('ok')", encoding="utf-8")
        guard_observer = {"blocked_out_of_repo_count": 0}
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_repo_root=repo_root,
            pr_tool_guard_observer=guard_observer,
        )

        input_data = {
            "tool_name": "Read",
            "tool_input": {"file_path": str(app_file)},
        }

        result = await hook(input_data, "tool-123", {})

        assert result == {}
        assert guard_observer["blocked_out_of_repo_count"] == 0

    @pytest.mark.asyncio
    async def test_blocks_grep_over_diff_context_in_pr_code_review(self, tracker, console):
        """PR code review should block Grep against DIFF_CONTEXT.json."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Grep",
            "tool_input": {
                "pattern": "new_path",
                "path": "/project/.securevibes/DIFF_CONTEXT.json",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert "do not grep DIFF_CONTEXT.json" in result["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_scopes_pathless_grep_to_src_in_pr_code_review(self, tracker, console):
        """PR code review should scope pathless Grep requests to src/."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Grep",
            "tool_input": {
                "pattern": "authorizeGatewayConnect",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        updated = result["hookSpecificOutput"]["updatedInput"]
        assert updated["path"] == "src"

    @pytest.mark.asyncio
    async def test_scopes_pathless_grep_to_configured_path_in_pr_code_review(
        self, tracker, console
    ):
        """PR code review should honor configured default path for pathless Grep."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"swift"}
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_grep_default_path="apps",
        )

        input_data = {
            "tool_name": "Grep",
            "tool_input": {
                "pattern": "sshNodeCommand",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        updated = result["hookSpecificOutput"]["updatedInput"]
        assert updated["path"] == "apps"

    @pytest.mark.asyncio
    async def test_scopes_pathless_grep_falls_back_to_src_for_unsafe_default_path(
        self, tracker, console, tmp_path
    ):
        """Traversal-like default Grep paths should be sanitized to src."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_grep_default_path="../outside",
            pr_repo_root=repo_root,
        )

        input_data = {
            "tool_name": "Grep",
            "tool_input": {
                "pattern": "token",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        updated = result["hookSpecificOutput"]["updatedInput"]
        assert updated["path"] == "src"

    @pytest.mark.asyncio
    async def test_blocks_pathless_grep_scope_that_resolves_outside_repo(
        self, tracker, console, tmp_path
    ):
        """Pathless Grep defaults should be denied when they resolve outside the repo root."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        symlink_scope = repo_root / "outside_link"
        try:
            symlink_scope.symlink_to(outside_dir, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("Directory symlink creation is not supported on this platform")

        guard_observer = {"blocked_out_of_repo_count": 0}
        hook = create_pre_tool_hook(
            tracker,
            console,
            debug=False,
            detected_languages=detected_languages,
            pr_grep_default_path="outside_link",
            pr_repo_root=repo_root,
            pr_tool_guard_observer=guard_observer,
        )

        input_data = {
            "tool_name": "Grep",
            "tool_input": {
                "pattern": "token",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert guard_observer["blocked_out_of_repo_count"] == 1

    @pytest.mark.asyncio
    async def test_blocks_diff_context_reads_in_pr_code_review(self, tracker, console):
        """PR code review should block DIFF_CONTEXT.json reads in favor of prompt anchors."""
        tracker.current_phase = "pr-code-review"
        detected_languages = {"python"}
        hook = create_pre_tool_hook(
            tracker, console, debug=False, detected_languages=detected_languages
        )

        input_data = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/.securevibes/DIFF_CONTEXT.json"},
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert "reads are disabled" in result["override_result"]["content"]

    # Note: test_logs_skill_invocations_in_debug removed - SDK auto-loads skills
    # from .claude/skills/ without explicit Skill tool calls, so the logging
    # code was dead code and has been removed.


class TestPostToolHook:
    """Tests for post-tool hook that tracks completion"""

    @pytest.fixture
    def tracker(self):
        """Create a progress tracker"""
        console = Console(file=StringIO())
        return ProgressTracker(console, debug=False)

    @pytest.fixture
    def console(self):
        """Create a Rich console"""
        return Console(file=StringIO())

    @pytest.mark.asyncio
    async def test_tracks_successful_completion(self, tracker, console):
        """Test that successful tool completion is tracked"""
        hook = create_post_tool_hook(tracker, console, debug=False)

        input_data = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/app.py"},
            "tool_response": {"is_error": False, "content": "file content"},
        }

        result = await hook(input_data, "tool-123", {})

        # Should return empty dict
        assert result == {}

    @pytest.mark.asyncio
    async def test_tracks_error_completion(self, tracker, console):
        """Test that failed tool completion is tracked"""
        hook = create_post_tool_hook(tracker, console, debug=False)

        input_data = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/nonexistent/file.py"},
            "tool_response": {"is_error": True, "content": "File not found"},
        }

        result = await hook(input_data, "tool-123", {})

        # Should return empty dict
        assert result == {}

    @pytest.mark.asyncio
    async def test_logs_file_operations_in_debug(self, tracker, console):
        """Test that file operations are logged in debug mode"""
        hook = create_post_tool_hook(tracker, console, debug=True)

        input_data = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/app.py"},
            "tool_response": {"is_error": False},
        }

        result = await hook(input_data, "tool-123", {})

        # Should log to console
        output = console.file.getvalue()
        assert "Read" in output
        assert "/project/app.py" in output
        assert result == {}

    @pytest.mark.asyncio
    async def test_logs_write_operations_in_debug(self, tracker, console):
        """Test that write operations are logged in debug mode"""
        hook = create_post_tool_hook(tracker, console, debug=True)

        input_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/project/.securevibes/results.json"},
            "tool_response": {"is_error": False},
        }

        result = await hook(input_data, "tool-123", {})

        # Should log to console
        output = console.file.getvalue()
        assert "Wrote" in output
        assert "results.json" in output
        assert result == {}


class TestSubagentHook:
    """Tests for sub-agent lifecycle hook"""

    @pytest.fixture
    def tracker(self):
        """Create a progress tracker"""
        console = Console(file=StringIO())
        return ProgressTracker(console, debug=False)

    @pytest.mark.asyncio
    async def test_calls_tracker_on_subagent_stop(self, tracker):
        """Test that tracker.on_subagent_stop is called"""
        hook = create_subagent_hook(tracker)

        input_data = {"agent_name": "assessment", "duration_ms": 5000}

        # Mock the tracker method
        tracker.on_subagent_stop = Mock()

        result = await hook(input_data, "tool-123", {})

        # Should call tracker
        tracker.on_subagent_stop.assert_called_once_with("assessment", 5000)
        assert result == {}

    @pytest.mark.asyncio
    async def test_handles_subagent_type_field(self, tracker):
        """Test that subagent_type field is also supported"""
        hook = create_subagent_hook(tracker)

        input_data = {"subagent_type": "threat-modeling", "duration_ms": 3000}

        # Mock the tracker method
        tracker.on_subagent_stop = Mock()

        result = await hook(input_data, "tool-123", {})

        # Should call tracker
        tracker.on_subagent_stop.assert_called_once_with("threat-modeling", 3000)
        assert result == {}

    @pytest.mark.asyncio
    async def test_handles_missing_agent_name(self, tracker):
        """Test that missing agent_name is handled gracefully"""
        hook = create_subagent_hook(tracker)

        input_data = {"duration_ms": 1000}

        # Mock the tracker method
        tracker.on_subagent_stop = Mock()

        result = await hook(input_data, "tool-123", {})

        # Should NOT call tracker
        tracker.on_subagent_stop.assert_not_called()
        assert result == {}


class TestJsonValidationHook:
    """Tests for JSON validation hook that fixes VULNERABILITIES.json format"""

    @pytest.fixture
    def console(self):
        """Create a Rich console"""
        return Console(file=StringIO())

    def _make_valid_vuln(self):
        """Helper to create a valid vulnerability dict."""
        return {
            "threat_id": "THREAT-001",
            "title": "SQL Injection",
            "description": "Test vulnerability",
            "severity": "high",
            "file_path": "app.py",
            "line_number": 42,
            "code_snippet": "cursor.execute(query)",
            "cwe_id": "CWE-89",
            "recommendation": "Use parameterized queries",
            "evidence": "User input concatenated into SQL query",
        }

    @pytest.mark.asyncio
    async def test_non_write_tool_passes_through(self, console):
        """Non-Write tools should pass through unchanged."""
        hook = create_json_validation_hook(console, debug=False)

        input_data = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/VULNERABILITIES.json"},
        }

        result = await hook(input_data, "tool-123", {})

        assert result == {}

    @pytest.mark.asyncio
    async def test_non_vulnerabilities_file_passes_through(self, console):
        """Writes to non-VULNERABILITIES.json files should pass through."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/OTHER_FILE.json",
                "content": json.dumps({"some": "data"}),
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert result == {}

    @pytest.mark.asyncio
    async def test_non_securevibes_vulnerabilities_file_passes_through(self, console):
        """Only .securevibes artifact paths should be intercepted."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/tmp/VULNERABILITIES.json",
                "content": json.dumps({"vulnerabilities": [self._make_valid_vuln()]}),
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert result == {}

    @pytest.mark.asyncio
    async def test_similar_vulnerability_filename_is_not_intercepted(self, console):
        """Files with similar names should not be treated as canonical artifacts."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/MY_VULNERABILITIES.json",
                "content": json.dumps({"vulnerabilities": [self._make_valid_vuln()]}),
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert result == {}

    @pytest.mark.asyncio
    async def test_backup_vulnerability_filename_is_not_intercepted(self, console):
        """Backup suffix should not be interpreted as target artifact."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/VULNERABILITIES.json.bak",
                "content": json.dumps({"vulnerabilities": [self._make_valid_vuln()]}),
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert result == {}

    @pytest.mark.asyncio
    async def test_relative_securevibes_vulnerabilities_path_is_intercepted(self, console):
        """Relative canonical artifact path should still be intercepted."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        content = json.dumps({"vulnerabilities": [self._make_valid_vuln()]})
        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": ".securevibes/VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        assert "updatedInput" in result["hookSpecificOutput"]

    @pytest.mark.asyncio
    async def test_valid_flat_array_passes_through(self, console):
        """Valid flat array should pass through without modification."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        vuln = self._make_valid_vuln()
        content = json.dumps([vuln])

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        # Should not modify (no updatedInput)
        assert "updatedInput" not in result

    @pytest.mark.asyncio
    async def test_wrapped_json_gets_fixed(self, console):
        """Wrapped JSON should be fixed and return updatedInput."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        vuln = self._make_valid_vuln()
        content = json.dumps({"vulnerabilities": [vuln]})

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        # Should return hookSpecificOutput with updatedInput
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
        assert "updatedInput" in result["hookSpecificOutput"]
        fixed_content = result["hookSpecificOutput"]["updatedInput"]["content"]
        assert fixed_content.startswith("[")
        assert json.loads(fixed_content) == [vuln]

    @pytest.mark.asyncio
    async def test_issues_wrapper_gets_fixed(self, console):
        """{'issues': [...]} wrapper should be fixed."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        vuln = self._make_valid_vuln()
        content = json.dumps({"issues": [vuln]})

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        fixed_content = result["hookSpecificOutput"]["updatedInput"]["content"]
        assert json.loads(fixed_content) == [vuln]

    @pytest.mark.asyncio
    async def test_empty_content_passes_through(self, console):
        """Empty content should pass through."""
        hook = create_json_validation_hook(console, debug=False)

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/VULNERABILITIES.json",
                "content": "",
            },
        }

        result = await hook(input_data, "tool-123", {})

        # Empty content - just pass through
        assert result == {}

    @pytest.mark.asyncio
    async def test_logs_fix_in_debug_mode(self, console):
        """Should log detailed fix message in debug mode."""
        import json

        hook = create_json_validation_hook(console, debug=True)

        vuln = self._make_valid_vuln()
        content = json.dumps({"vulnerabilities": [vuln]})

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/VULNERABILITIES.json",
                "content": content,
            },
        }

        await hook(input_data, "tool-123", {})

        output = console.file.getvalue()
        assert "Auto-fixed" in output or "unwrapped" in output.lower()

    @pytest.mark.asyncio
    async def test_logs_validation_success_in_debug(self, console):
        """Should log validation success in debug mode."""
        import json

        hook = create_json_validation_hook(console, debug=True)

        vuln = self._make_valid_vuln()
        content = json.dumps([vuln])

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/VULNERABILITIES.json",
                "content": content,
            },
        }

        await hook(input_data, "tool-123", {})

        output = console.file.getvalue()
        assert "validated" in output.lower()

    @pytest.mark.asyncio
    async def test_preserves_other_input_fields(self, console):
        """Should preserve other tool_input fields when fixing."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        vuln = self._make_valid_vuln()
        content = json.dumps({"vulnerabilities": [vuln]})

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/VULNERABILITIES.json",
                "content": content,
                "encoding": "utf-8",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        updated_input = result["hookSpecificOutput"]["updatedInput"]
        assert updated_input["file_path"] == "/project/.securevibes/VULNERABILITIES.json"
        assert updated_input["encoding"] == "utf-8"

    @pytest.mark.asyncio
    async def test_malformed_json_rejected(self, console):
        """Malformed JSON should be rejected (fail-closed)."""
        hook = create_json_validation_hook(console, debug=False)

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/VULNERABILITIES.json",
                "content": "{ invalid json ]]",
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert result["override_result"]["is_error"] is True
        assert "Write rejected by SecureVibes validation" in result["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_invalid_vulnerabilities_json_rejected_fail_closed(self, console):
        """VULNERABILITIES.json with invalid entries should be rejected like PR path."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        vuln = self._make_valid_vuln()
        del vuln["file_path"]  # missing required field makes it invalid
        content = json.dumps([vuln])

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert result["override_result"]["is_error"] is True

    @pytest.mark.asyncio
    async def test_empty_array_passes_through(self, console):
        """Empty array [] passes through unchanged."""
        hook = create_json_validation_hook(console, debug=False)

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/VULNERABILITIES.json",
                "content": "[]",
            },
        }

        result = await hook(input_data, "tool-123", {})

        # No modification needed
        assert "updatedInput" not in result

    @pytest.mark.asyncio
    async def test_array_with_non_dict_items_rejected(self, console):
        """Array containing non-dict items should be rejected (fail-closed)."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        content = json.dumps(["not a dict", {"threat_id": "T1"}])

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert result["override_result"]["is_error"] is True


class TestPRJsonValidationHook:
    """Tests for PR_VULNERABILITIES.json handling in json_validation_hook."""

    @pytest.fixture
    def console(self):
        """Create a Rich console."""
        return Console(file=StringIO())

    def _make_valid_pr_vuln(self):
        """Helper to create a valid PR vulnerability dict."""
        return {
            "threat_id": "THREAT-001",
            "finding_type": "new_threat",
            "title": "SQL Injection in Login",
            "description": "Test vulnerability",
            "severity": "high",
            "file_path": "app.py",
            "line_number": 42,
            "code_snippet": "cursor.execute(query)",
            "attack_scenario": "Attacker provides malicious input",
            "evidence": "User input concatenated into SQL query",
            "cwe_id": "CWE-89",
            "recommendation": "Use parameterized queries",
        }

    @pytest.mark.asyncio
    async def test_pr_vulnerabilities_passes_through_valid_array(self, console):
        """Valid flat array passes through unchanged."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        vuln = self._make_valid_pr_vuln()
        content = json.dumps([vuln])

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        # Should not modify (no updatedInput)
        assert "updatedInput" not in result

    @pytest.mark.asyncio
    async def test_pr_vulnerabilities_edit_is_validated_and_normalized(self, console):
        """Edit operations should be validated like Write for PR artifacts."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        vuln = self._make_valid_pr_vuln()
        content = json.dumps({"vulnerabilities": [vuln]})

        input_data = {
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        assert "updatedInput" in result["hookSpecificOutput"]
        updated_content = result["hookSpecificOutput"]["updatedInput"]["content"]
        assert json.loads(updated_content) == [vuln]

    @pytest.mark.asyncio
    async def test_pr_artifact_backup_filename_is_not_intercepted(self, console):
        """Only exact PR artifact path should be intercepted."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json.bak",
                "content": json.dumps({"findings": [self._make_valid_pr_vuln()]}),
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert result == {}

    @pytest.mark.asyncio
    async def test_pr_write_observer_tracks_largest_nonempty_payload(self, console):
        """Observer should record max payload even if a later write overwrites with empty array."""
        import json

        observer: dict[str, object] = {}
        hook = create_json_validation_hook(console, debug=False, write_observer=observer)

        vuln = self._make_valid_pr_vuln()
        first_input = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": json.dumps([vuln]),
            },
        }
        second_input = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": "[]",
            },
        }

        await hook(first_input, "tool-123", {})
        await hook(second_input, "tool-124", {})

        assert observer["total_writes"] == 2
        assert observer["item_counts"] == [1, 0]
        assert observer["max_items"] == 1
        max_payload = json.loads(str(observer["max_content"]))
        assert isinstance(max_payload, list)
        assert len(max_payload) == 1

    @pytest.mark.asyncio
    async def test_pr_write_observer_does_not_track_invalid_payload(self, console):
        """Observer should only capture payloads that passed PR schema validation."""
        import json

        observer: dict[str, object] = {}
        hook = create_json_validation_hook(console, debug=False, write_observer=observer)

        vuln = self._make_valid_pr_vuln()
        vuln["evidence"] = ""  # invalid by PR schema
        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": json.dumps([vuln]),
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert observer == {}

    @pytest.mark.asyncio
    async def test_pr_wrapped_findings_gets_fixed(self, console):
        """{'findings': [...]} wrapper gets unwrapped."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        vuln = self._make_valid_pr_vuln()
        content = json.dumps({"findings": [vuln]})

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        # Should return hookSpecificOutput with updatedInput
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
        assert "updatedInput" in result["hookSpecificOutput"]
        fixed_content = result["hookSpecificOutput"]["updatedInput"]["content"]
        assert fixed_content.startswith("[")

    @pytest.mark.asyncio
    async def test_pr_wrapped_vulnerabilities_gets_fixed(self, console):
        """{'vulnerabilities': [...]} wrapper gets unwrapped."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        vuln = self._make_valid_pr_vuln()
        content = json.dumps({"vulnerabilities": [vuln]})

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        fixed_content = result["hookSpecificOutput"]["updatedInput"]["content"]
        assert fixed_content.startswith("[")

    @pytest.mark.asyncio
    async def test_pr_single_object_gets_wrapped(self, console):
        """Single vulnerability object gets wrapped in array."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        vuln = self._make_valid_pr_vuln()
        content = json.dumps(vuln)  # Single object, not array

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        fixed_content = result["hookSpecificOutput"]["updatedInput"]["content"]
        fixed_data = json.loads(fixed_content)
        assert isinstance(fixed_data, list)
        assert len(fixed_data) == 1

    @pytest.mark.asyncio
    async def test_pr_hookSpecificOutput_format(self, console):
        """Verify hookSpecificOutput wrapper is returned with correct structure."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        vuln = self._make_valid_pr_vuln()
        content = json.dumps({"findings": [vuln]})

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        # Verify structure
        assert "hookSpecificOutput" in result
        hook_output = result["hookSpecificOutput"]
        assert hook_output["hookEventName"] == "PreToolUse"
        assert "updatedInput" in hook_output
        assert "file_path" in hook_output["updatedInput"]
        assert "content" in hook_output["updatedInput"]

    @pytest.mark.asyncio
    async def test_pr_finding_type_normalization(self, console):
        """Verify finding_type field is normalized during fix."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        # Vulnerability without finding_type but with category
        vuln = self._make_valid_pr_vuln()
        del vuln["finding_type"]
        vuln["category"] = "new"  # Should be normalized to "new_threat"
        content = json.dumps({"findings": [vuln]})

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        fixed_content = result["hookSpecificOutput"]["updatedInput"]["content"]
        fixed_data = json.loads(fixed_content)
        assert fixed_data[0]["finding_type"] == "new_threat"

    @pytest.mark.asyncio
    async def test_pr_threat_id_derivation(self, console):
        """Verify threat_id is derived when missing."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        # Vulnerability without threat_id
        vuln = self._make_valid_pr_vuln()
        del vuln["threat_id"]
        content = json.dumps({"findings": [vuln]})

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        fixed_content = result["hookSpecificOutput"]["updatedInput"]["content"]
        fixed_data = json.loads(fixed_content)
        # Should have a derived PR- prefixed ID
        assert fixed_data[0]["threat_id"].startswith("PR-")

    @pytest.mark.asyncio
    async def test_pr_line_number_extraction(self, console):
        """Verify line_number extraction from line_numbers array."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        # Vulnerability with line_numbers instead of line_number
        vuln = self._make_valid_pr_vuln()
        del vuln["line_number"]
        vuln["line_numbers"] = [10, 20, 30]
        content = json.dumps({"findings": [vuln]})

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "hookSpecificOutput" in result
        fixed_content = result["hookSpecificOutput"]["updatedInput"]["content"]
        fixed_data = json.loads(fixed_content)
        # Should extract first line number
        assert fixed_data[0]["line_number"] == 10

    @pytest.mark.asyncio
    async def test_pr_invalid_empty_evidence_rejected_once(self, console):
        """Invalid PR payload should be rejected on first attempt."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        vuln = self._make_valid_pr_vuln()
        vuln["file_path"] = ""
        content = json.dumps([vuln])

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": content,
            },
        }

        result = await hook(input_data, "tool-123", {})

        assert "override_result" in result
        assert result["override_result"]["is_error"] is True
        assert "Write rejected by SecureVibes PR validation" in result["override_result"]["content"]
        assert "file_path" in result["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_pr_invalid_empty_evidence_rejected_after_retry_budget(self, console):
        """After retry budget is exhausted, invalid PR payload should still be rejected."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        vuln = self._make_valid_pr_vuln()
        vuln["evidence"] = "   "
        content = json.dumps([vuln])

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": content,
            },
        }

        first = await hook(input_data, "tool-123", {})
        second = await hook(input_data, "tool-124", {})

        assert "override_result" in first
        assert "override_result" in second
        assert second["override_result"]["is_error"] is True
        assert "Retry budget exhausted" in second["override_result"]["content"]

    @pytest.mark.asyncio
    async def test_pr_retry_exhaustion_blocks_even_with_wrapper_fixes(self, console):
        """Retry exhaustion should reject writes even if wrapper normalization succeeds."""
        import json

        hook = create_json_validation_hook(console, debug=False)

        vuln = self._make_valid_pr_vuln()
        vuln["evidence"] = ""  # empty evidence → invalid
        # Wrap in a dict — the fixer should unwrap AND the wrapper fix should be in updatedInput
        content = json.dumps({"vulnerabilities": [vuln]})

        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/PR_VULNERABILITIES.json",
                "content": content,
            },
        }

        # First attempt: rejected (retry budget not exhausted)
        first = await hook(input_data, "tool-123", {})
        assert "override_result" in first

        # Second attempt: retry budget exhausted — should remain rejected
        second = await hook(input_data, "tool-124", {})
        assert "override_result" in second
        assert second["override_result"]["is_error"] is True
        assert "Retry budget exhausted" in second["override_result"]["content"]
