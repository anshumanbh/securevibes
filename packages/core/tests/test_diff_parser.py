"""Tests for unified diff parsing and extraction."""

from pathlib import Path

import pytest

from securevibes.diff.extractor import (
    get_diff_from_commits,
    get_diff_from_git_range,
    _validate_git_ref,
)
from securevibes.diff.parser import extract_changed_code_with_context, parse_unified_diff


def test_parse_unified_diff_basic():
    """Basic diff parsing should track added/removed lines and files."""
    diff = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
-print("hello")
+print("hi")
+print("world")
"""
    context = parse_unified_diff(diff)

    assert context.added_lines == 2
    assert context.removed_lines == 1
    assert context.changed_files == ["app.py"]

    file_change = context.files[0]
    assert file_change.old_path == "app.py"
    assert file_change.new_path == "app.py"
    assert file_change.is_new is False
    assert file_change.is_deleted is False
    assert len(file_change.hunks) == 1


def test_parse_unified_diff_new_file():
    """New files should be marked as is_new with /dev/null old path."""
    diff = """diff --git a/dev/null b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+print("hi")
+print("there")
"""
    context = parse_unified_diff(diff)

    assert context.changed_files == ["new.py"]
    file_change = context.files[0]
    assert file_change.is_new is True
    assert file_change.old_path is None
    assert file_change.new_path == "new.py"


def test_extract_changed_code_with_context(tmp_path: Path):
    """Extract changed code should include surrounding context lines."""
    file_path = tmp_path / "app.py"
    file_path.write_text("line1\nline2\nline3\nline4\nline5\n", encoding="utf-8")

    diff = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -2,1 +2,2 @@
-line2
+line2
+line2b
"""
    context = parse_unified_diff(diff)
    snippets = extract_changed_code_with_context(context, tmp_path, context_lines=1)

    assert "app.py" in snippets
    snippet = snippets["app.py"]
    assert "   1: line1" in snippet
    assert "   2: line2" in snippet
    assert "   3: line3" in snippet


def test_get_diff_from_commits_error(monkeypatch):
    """Non-zero git diff exit should raise a RuntimeError."""

    class DummyResult:
        returncode = 1
        stderr = "fatal: bad revision"
        stdout = ""

    def fake_run(*_args, **_kwargs):
        return DummyResult()

    monkeypatch.setattr("securevibes.diff.extractor.subprocess.run", fake_run)

    with pytest.raises(RuntimeError, match="bad revision"):
        get_diff_from_commits(Path("."), "bad..range")


class TestGitRefValidation:
    """Tests for git ref validation to prevent command injection."""

    def test_valid_branch_names(self):
        """Valid branch names should pass validation."""
        valid_refs = [
            "main",
            "feature/add-login",
            "fix-123",
            "release_v1.0",
            "HEAD",
            "HEAD~1",
            "HEAD^2",
            "origin/main",
            "refs/heads/main",
        ]
        for ref in valid_refs:
            _validate_git_ref(ref)  # Should not raise

    def test_valid_commit_ranges(self):
        """Valid commit ranges should pass validation."""
        valid_ranges = [
            "abc123..def456",
            "main...feature",
            "HEAD~1..HEAD",
            "v1.0..v2.0",
        ]
        for ref in valid_ranges:
            _validate_git_ref(ref)  # Should not raise

    def test_invalid_refs_with_shell_metacharacters(self):
        """Refs with shell metacharacters should be rejected."""
        invalid_refs = [
            "main; rm -rf /",
            "branch$(whoami)",
            "branch`id`",
            "branch|cat /etc/passwd",
            "branch & echo pwned",
            "branch\nmalicious",
            "branch'injection",
            'branch"injection',
        ]
        for ref in invalid_refs:
            with pytest.raises(ValueError, match="Invalid git ref"):
                _validate_git_ref(ref)

    def test_empty_ref_rejected(self):
        """Empty refs should be rejected."""
        with pytest.raises(ValueError, match="cannot be empty"):
            _validate_git_ref("")

    def test_get_diff_from_git_range_validates_refs(self, monkeypatch):
        """get_diff_from_git_range should validate refs before execution."""
        # Ensure subprocess.run is never called for invalid refs
        def fail_if_called(*_args, **_kwargs):
            pytest.fail("subprocess.run should not be called for invalid refs")

        monkeypatch.setattr("securevibes.diff.extractor.subprocess.run", fail_if_called)

        with pytest.raises(ValueError, match="Invalid git ref"):
            get_diff_from_git_range(Path("."), "main; rm -rf /", "HEAD")

    def test_get_diff_from_commits_validates_range(self, monkeypatch):
        """get_diff_from_commits should validate the range before execution."""

        def fail_if_called(*_args, **_kwargs):
            pytest.fail("subprocess.run should not be called for invalid refs")

        monkeypatch.setattr("securevibes.diff.extractor.subprocess.run", fail_if_called)

        with pytest.raises(ValueError, match="Invalid git ref"):
            get_diff_from_commits(Path("."), "abc$(id)..def")
