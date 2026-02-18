"""Tests for scanner.progress module."""

from io import StringIO

from rich.console import Console

from securevibes.scanner.progress import ProgressTracker


def _make_tracker(debug: bool = False, single_subagent: str | None = None) -> ProgressTracker:
    """Create a ProgressTracker with a quiet console for testing."""
    console = Console(file=StringIO(), highlight=False, no_color=True)
    return ProgressTracker(console, debug=debug, single_subagent=single_subagent)


class TestAnnouncePhase:
    def test_sets_current_phase(self):
        tracker = _make_tracker()
        tracker.announce_phase("assessment")
        assert tracker.current_phase == "assessment"

    def test_resets_counters(self):
        tracker = _make_tracker()
        tracker.tool_count = 5
        tracker.files_read.add("a.py")
        tracker.files_written.add("b.py")
        tracker.announce_phase("code-review")
        assert tracker.tool_count == 0
        assert len(tracker.files_read) == 0
        assert len(tracker.files_written) == 0

    def test_sets_phase_start_time(self):
        tracker = _make_tracker()
        assert tracker.phase_start_time is None
        tracker.announce_phase("assessment")
        assert tracker.phase_start_time is not None


class TestOnToolStart:
    def test_increments_tool_count(self):
        tracker = _make_tracker()
        tracker.on_tool_start("Read", {"file_path": "a.py"})
        assert tracker.tool_count == 1
        tracker.on_tool_start("Grep", {"pattern": "test"})
        assert tracker.tool_count == 2

    def test_tracks_files_read(self):
        tracker = _make_tracker()
        tracker.on_tool_start("Read", {"file_path": "src/app.py"})
        assert "src/app.py" in tracker.files_read

    def test_tracks_files_read_with_path_key(self):
        tracker = _make_tracker()
        tracker.on_tool_start("Read", {"path": "src/app.py"})
        assert "src/app.py" in tracker.files_read

    def test_tracks_files_written(self):
        tracker = _make_tracker()
        tracker.on_tool_start("Write", {"file_path": "out.json"})
        assert "out.json" in tracker.files_written

    def test_task_tool_pushes_subagent_stack(self):
        tracker = _make_tracker()
        tracker.on_tool_start("Task", {"subagent_type": "code-review", "prompt": "review"})
        assert "code-review" in tracker.subagent_stack

    def test_empty_file_path_not_tracked(self):
        tracker = _make_tracker()
        tracker.on_tool_start("Read", {"file_path": ""})
        assert len(tracker.files_read) == 0


class TestOnToolComplete:
    def test_success_no_output(self):
        tracker = _make_tracker()
        output = tracker.console.file
        tracker.on_tool_complete("Read", success=True)
        assert output.getvalue() == ""

    def test_failure_prints_warning(self):
        tracker = _make_tracker()
        tracker.on_tool_complete("Read", success=False, error_msg="file not found")
        output = tracker.console.file.getvalue()
        assert "Read" in output
        assert "failed" in output


class TestOnSubagentStop:
    def test_pops_subagent_from_stack(self):
        tracker = _make_tracker()
        tracker.subagent_stack.append("code-review")
        tracker.on_subagent_stop("code-review", duration_ms=5000)
        assert "code-review" not in tracker.subagent_stack

    def test_prints_completion_summary(self):
        tracker = _make_tracker()
        tracker.tool_count = 10
        tracker.files_read = {"a.py", "b.py"}
        tracker.on_subagent_stop("assessment", duration_ms=3500)
        output = tracker.console.file.getvalue()
        assert "Complete" in output
        assert "3.5s" in output

    def test_does_not_pop_wrong_agent(self):
        tracker = _make_tracker()
        tracker.subagent_stack.append("assessment")
        tracker.on_subagent_stop("code-review", duration_ms=1000)
        assert tracker.subagent_stack == ["assessment"]

    def test_shows_created_artifact(self):
        tracker = _make_tracker()
        tracker.files_written.add("/repo/SECURITY.md")
        tracker.on_subagent_stop("assessment", duration_ms=1000)
        output = tracker.console.file.getvalue()
        assert "SECURITY.md" in output


class TestOnAssistantText:
    def test_debug_mode_prints_text(self):
        tracker = _make_tracker(debug=True)
        tracker.on_assistant_text("Analyzing code structure")
        output = tracker.console.file.getvalue()
        assert "Analyzing code structure" in output

    def test_non_debug_mode_silent(self):
        tracker = _make_tracker(debug=False)
        tracker.on_assistant_text("Analyzing code structure")
        assert tracker.console.file.getvalue() == ""

    def test_empty_text_ignored_in_debug(self):
        tracker = _make_tracker(debug=True)
        tracker.on_assistant_text("   ")
        assert tracker.console.file.getvalue() == ""


class TestGetSummary:
    def test_returns_expected_keys(self):
        tracker = _make_tracker()
        summary = tracker.get_summary()
        assert set(summary.keys()) == {
            "current_phase",
            "tool_count",
            "files_read",
            "files_written",
            "subagent_depth",
        }

    def test_reflects_current_state(self):
        tracker = _make_tracker()
        tracker.announce_phase("threat-modeling")
        tracker.on_tool_start("Read", {"file_path": "a.py"})
        tracker.on_tool_start("Write", {"file_path": "b.py"})
        summary = tracker.get_summary()
        assert summary["current_phase"] == "threat-modeling"
        assert summary["tool_count"] == 2
        assert summary["files_read"] == 1
        assert summary["files_written"] == 1
        assert summary["subagent_depth"] == 0


class TestSingleSubagentMode:
    def test_overrides_display_name(self):
        tracker = _make_tracker(single_subagent="code-review")
        assert "Sub-Agent 1/1" in tracker.phase_display["code-review"]

    def test_unknown_subagent_uses_raw_name(self):
        tracker = _make_tracker(single_subagent="custom-agent")
        assert "custom-agent" in tracker.phase_display["custom-agent"]
