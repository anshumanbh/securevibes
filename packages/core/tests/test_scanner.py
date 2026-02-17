"""Tests for scanner with real-time progress tracking"""

import os
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from securevibes.scanner.scanner import Scanner
from securevibes.scanner.progress import ProgressTracker
from securevibes.models.result import ScanResult
from securevibes.models.issue import Severity
from rich.console import Console
from io import StringIO


@pytest.fixture
def console():
    """Create a console with string output for testing"""
    return Console(file=StringIO(), force_terminal=True)


@pytest.fixture
def progress_tracker(console):
    """Create a progress tracker instance"""
    return ProgressTracker(console, debug=False)


@pytest.fixture
def debug_progress_tracker(console):
    """Create a progress tracker with debug enabled"""
    return ProgressTracker(console, debug=True)


@pytest.fixture
def scanner():
    """Create a scanner instance"""
    return Scanner(model="sonnet", debug=False)


@pytest.fixture
def test_repo(tmp_path):
    """Create a minimal test repository"""
    (tmp_path / "app.py").write_text(
        """
def hello():
    print("Hello World")
"""
    )
    (tmp_path / "routes.py").write_text(
        """
@app.route('/api')
def api():
    return {'status': 'ok'}
"""
    )
    return tmp_path


class TestScanResultWarnings:
    """Test ScanResult warning behavior."""

    def test_scan_result_warnings_default_empty(self):
        """Warnings should default to an empty list."""
        result = ScanResult(repository_path="/tmp/repo")

        assert result.warnings == []

    def test_scan_result_warnings_stores_values(self):
        """Warnings passed to constructor should be stored."""
        warnings = ["Analysis may be incomplete."]
        result = ScanResult(repository_path="/tmp/repo", warnings=warnings)

        assert result.warnings == warnings

    def test_scan_result_to_dict_includes_warnings_when_non_empty(self):
        """to_dict should include warnings only when present."""
        warnings = ["Missing PR_VULNERABILITIES.json"]
        result = ScanResult(repository_path="/tmp/repo", warnings=warnings)

        data = result.to_dict()

        assert data["warnings"] == warnings

    def test_scan_result_to_dict_omits_warnings_when_empty(self):
        """to_dict should not include warnings when list is empty."""
        result = ScanResult(repository_path="/tmp/repo")

        data = result.to_dict()

        assert "warnings" not in data


class TestProgressTracker:
    """Test ProgressTracker functionality"""

    def test_initialization(self, progress_tracker):
        """Test ProgressTracker initializes correctly"""
        assert progress_tracker.current_phase is None
        assert progress_tracker.tool_count == 0
        assert len(progress_tracker.files_read) == 0
        assert len(progress_tracker.files_written) == 0
        assert len(progress_tracker.subagent_stack) == 0

    def test_announce_phase(self, progress_tracker):
        """Test phase announcement"""
        progress_tracker.announce_phase("assessment")

        assert progress_tracker.current_phase == "assessment"
        assert progress_tracker.phase_start_time is not None
        assert progress_tracker.tool_count == 0  # Reset on new phase

    def test_on_tool_start_read(self, progress_tracker):
        """Test tracking Read tool usage"""
        tool_input = {"file_path": "/path/to/file.py"}

        progress_tracker.on_tool_start("Read", tool_input)

        assert progress_tracker.tool_count == 1
        assert "/path/to/file.py" in progress_tracker.files_read

    def test_on_tool_start_grep(self, progress_tracker):
        """Test tracking Grep tool usage"""
        tool_input = {"pattern": "password|secret"}

        progress_tracker.on_tool_start("Grep", tool_input)

        assert progress_tracker.tool_count == 1

    def test_on_tool_start_write(self, progress_tracker):
        """Test tracking Write tool usage"""
        tool_input = {"file_path": "/path/to/output.json"}

        progress_tracker.on_tool_start("Write", tool_input)

        assert progress_tracker.tool_count == 1
        assert "/path/to/output.json" in progress_tracker.files_written

    def test_on_tool_start_task(self, progress_tracker):
        """Test tracking Task (sub-agent) tool usage"""
        tool_input = {"agent_name": "assessment", "prompt": "Analyze the codebase architecture"}

        # Mock announce_phase to avoid console output
        progress_tracker.announce_phase = lambda x: None

        progress_tracker.on_tool_start("Task", tool_input)

        assert progress_tracker.tool_count == 1
        assert "assessment" in progress_tracker.subagent_stack

    def test_on_tool_complete_success(self, progress_tracker):
        """Test tracking successful tool completion"""
        initial_count = progress_tracker.tool_count
        progress_tracker.on_tool_complete("Read", success=True)
        assert progress_tracker.tool_count == initial_count
        assert progress_tracker.console.file.getvalue() == ""

    def test_on_tool_complete_failure(self, progress_tracker):
        """Test tracking failed tool completion"""
        progress_tracker.on_tool_complete("Read", success=False, error_msg="File not found")
        output = progress_tracker.console.file.getvalue()
        assert "Tool Read failed" in output
        assert "File not found" in output

    def test_on_subagent_stop(self, progress_tracker):
        """Test tracking sub-agent completion"""
        # Set up phase
        progress_tracker.announce_phase("assessment")
        progress_tracker.subagent_stack.append("assessment")
        progress_tracker.tool_count = 50
        progress_tracker.files_read.add("file1.py")
        progress_tracker.files_read.add("file2.py")
        progress_tracker.files_written.add("SECURITY.md")

        # Complete sub-agent
        progress_tracker.on_subagent_stop("assessment", duration_ms=45000)

        # Stack should be popped
        assert "assessment" not in progress_tracker.subagent_stack

    def test_get_summary(self, progress_tracker):
        """Test getting progress summary"""
        progress_tracker.current_phase = "code-review"
        progress_tracker.tool_count = 25
        progress_tracker.files_read.add("file1.py")
        progress_tracker.files_read.add("file2.py")
        progress_tracker.files_written.add("output.json")

        summary = progress_tracker.get_summary()

        assert summary["current_phase"] == "code-review"
        assert summary["tool_count"] == 25
        assert summary["files_read"] == 2
        assert summary["files_written"] == 1
        assert summary["subagent_depth"] == 0

    def test_debug_mode_on_assistant_text(self, debug_progress_tracker):
        """Test agent narration in debug mode"""
        text = "I am analyzing the authentication system for security vulnerabilities"

        debug_progress_tracker.on_assistant_text(text)
        output = debug_progress_tracker.console.file.getvalue()
        assert "I am analyzing the authentication system" in output
        assert "💭" in output

    def test_non_debug_mode_skips_narration(self, progress_tracker):
        """Test agent narration is skipped in non-debug mode"""
        text = "Some agent thinking"

        progress_tracker.on_assistant_text(text)
        assert progress_tracker.console.file.getvalue() == ""

    def test_smart_truncation_in_debug(self, debug_progress_tracker):
        """Test smart truncation of long prompts in debug mode"""
        long_prompt = "A" * 300  # 300 characters
        tool_input = {"agent_name": "test", "prompt": long_prompt}

        # Mock announce_phase to avoid console output
        debug_progress_tracker.announce_phase = lambda x: None

        # Should truncate intelligently (200 chars in debug mode)
        debug_progress_tracker.on_tool_start("Task", tool_input)

        # Verify it didn't crash
        assert debug_progress_tracker.tool_count == 1

    def test_smart_truncation_in_normal(self, progress_tracker):
        """Test smart truncation of long prompts in normal mode"""
        long_prompt = "A" * 150  # 150 characters
        tool_input = {"agent_name": "test", "prompt": long_prompt}

        # Mock announce_phase to avoid console output
        progress_tracker.announce_phase = lambda x: None

        # Should truncate to 100 chars in normal mode
        progress_tracker.on_tool_start("Task", tool_input)

        assert progress_tracker.tool_count == 1

    def test_activity_counter_threshold(self, progress_tracker):
        """Test activity counter shows progress every 20 tools"""
        # Simulate 25 tool executions
        for i in range(25):
            progress_tracker.on_tool_start("Read", {"file_path": f"file{i}.py"})

        # Tool count should reach 25
        assert progress_tracker.tool_count == 25
        # Activity message would appear at tool 20

    def test_phase_display_names(self, progress_tracker):
        """Test phase display names are properly formatted"""
        expected_names = {
            "assessment": "1/4: Architecture Assessment",
            "threat-modeling": "2/4: Threat Modeling (STRIDE Analysis)",
            "code-review": "3/4: Code Review (Security Analysis)",
            "report-generator": "4/4: Report Generation",
        }

        for phase, display_name in expected_names.items():
            assert progress_tracker.phase_display[phase] == display_name


class TestScannerInit:
    """Test Scanner initialization"""

    def test_initialization_defaults(self):
        """Test scanner initializes with defaults"""
        scanner = Scanner()

        assert scanner.model == "sonnet"
        assert scanner.debug is False
        assert scanner.total_cost == 0.0

    def test_initialization_with_model(self):
        """Test scanner initializes with custom model"""
        scanner = Scanner(model="opus")

        assert scanner.model == "opus"

    def test_initialization_with_debug(self):
        """Test scanner initializes with debug mode"""
        scanner = Scanner(debug=True)

        assert scanner.debug is True

    def test_api_key_sets_env_var(self):
        """Test API key is set in environment"""
        # API key is no longer set by the scanner - delegated to claude CLI
        Scanner()


class TestScannerIntegration:
    """Integration tests for Scanner (with mocks)"""

    @pytest.mark.asyncio
    async def test_scan_creates_output_directory(self, scanner, test_repo):
        """Test scan creates .securevibes directory"""
        securevibes_dir = test_repo / ".securevibes"

        # Mock the ClaudeSDKClient to avoid real API calls
        with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
            # Mock the async context manager
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_instance.query = AsyncMock()

            # Create an async generator for receive_messages
            async def async_gen():
                return
                yield  # Makes it a generator

            mock_instance.receive_messages = async_gen

            try:
                await scanner.scan(str(test_repo))
            except RuntimeError:
                # Expected to fail (no results file), but directory should be created
                pass

        assert securevibes_dir.exists()

    @pytest.mark.asyncio
    async def test_scan_invalid_path_raises_error(self, scanner):
        """Test scan raises error for invalid path"""
        with pytest.raises(ValueError, match="does not exist"):
            await scanner.scan("/nonexistent/path")

    @pytest.mark.asyncio
    async def test_scan_tracks_costs(self, scanner, test_repo):
        """Test scan tracks API costs"""
        from claude_agent_sdk.types import ResultMessage

        # Create mock ResultMessage with cost
        mock_result = MagicMock(spec=ResultMessage)
        mock_result.total_cost_usd = 1.23

        with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_instance.query = AsyncMock()

            # Create an async generator that yields the mock result
            async def async_gen():
                yield mock_result

            mock_instance.receive_messages = async_gen

            try:
                await scanner.scan(str(test_repo))
            except RuntimeError:
                # Expected to fail (no results file)
                pass

        # Cost should be tracked
        assert scanner.total_cost == 1.23


class TestScannerResultLoading:
    """Test result loading from generated files"""

    @pytest.mark.asyncio
    async def test_load_from_scan_results_json(self, scanner, test_repo):
        """Test loading results from scan_results.json"""
        securevibes_dir = test_repo / ".securevibes"
        securevibes_dir.mkdir()

        # Create mock scan_results.json
        scan_results = {
            "issues": [
                {
                    "id": "ISSUE-1",
                    "title": "SQL Injection",
                    "description": "SQL injection vulnerability",
                    "severity": "critical",
                    "file_path": "app.py",
                    "line_number": 10,
                    "code_snippet": "query = 'SELECT * FROM users'",
                    "cwe_id": "CWE-89",
                    "recommendation": "Use parameterized queries",
                }
            ]
        }

        import json

        (securevibes_dir / "scan_results.json").write_text(json.dumps(scan_results))

        # Mock scan to load results
        result = scanner._load_scan_results(
            securevibes_dir, test_repo, files_scanned=10, scan_start_time=0
        )

        assert isinstance(result, ScanResult)
        assert len(result.issues) == 1
        assert result.issues[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_load_from_vulnerabilities_json_fallback(self, scanner, test_repo):
        """Test falling back to VULNERABILITIES.json if scan_results.json missing"""
        securevibes_dir = test_repo / ".securevibes"
        securevibes_dir.mkdir()

        # Create mock VULNERABILITIES.json
        vulnerabilities = [
            {
                "threat_id": "THREAT-1",
                "title": "XSS Vulnerability",
                "description": "Cross-site scripting",
                "severity": "high",
                "file_path": "views.py",
                "line_number": 20,
                "code_snippet": "return render(user_input)",
                "cwe_id": "CWE-79",
                "recommendation": "Sanitize input",
            }
        ]

        import json

        (securevibes_dir / "VULNERABILITIES.json").write_text(json.dumps(vulnerabilities))

        # Load results
        result = scanner._load_scan_results(
            securevibes_dir, test_repo, files_scanned=10, scan_start_time=0
        )

        assert isinstance(result, ScanResult)
        assert len(result.issues) == 1
        assert result.issues[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_load_scan_results_surfaces_artifact_regen_warning(
        self, scanner, test_repo, monkeypatch
    ):
        """DAST artifact regeneration warnings should be included in ScanResult.warnings."""
        securevibes_dir = test_repo / ".securevibes"
        securevibes_dir.mkdir()

        import json

        (securevibes_dir / "scan_results.json").write_text(
            json.dumps(
                [
                    {
                        "threat_id": "THREAT-1",
                        "title": "XSS Vulnerability",
                        "description": "Cross-site scripting",
                        "severity": "high",
                        "file_path": "views.py",
                        "line_number": 20,
                        "code_snippet": "return render(user_input)",
                        "cwe_id": "CWE-79",
                        "recommendation": "Sanitize input",
                    }
                ]
            ),
            encoding="utf-8",
        )

        def fake_merge(scan_result, _securevibes_dir):
            scan_result.dast_enabled = True
            return scan_result

        monkeypatch.setattr(scanner, "_merge_dast_results", fake_merge)
        monkeypatch.setattr(
            scanner,
            "_regenerate_artifacts",
            lambda *_args, **_kwargs: "regeneration warning",
        )

        result = scanner._load_scan_results(
            securevibes_dir, test_repo, files_scanned=10, scan_start_time=0
        )

        assert "regeneration warning" in result.warnings

    @pytest.mark.asyncio
    async def test_load_handles_missing_files(self, scanner, test_repo):
        """Test error handling when no results files exist"""
        securevibes_dir = test_repo / ".securevibes"
        securevibes_dir.mkdir()

        # No results files created
        with pytest.raises(RuntimeError, match="failed to generate results"):
            scanner._load_scan_results(
                securevibes_dir, test_repo, files_scanned=10, scan_start_time=0
            )

    @pytest.mark.asyncio
    @patch("securevibes.scanner.scanner.update_scan_state")
    @patch("securevibes.scanner.scanner.get_repo_branch")
    @patch("securevibes.scanner.scanner.get_repo_head_commit")
    async def test_load_updates_scan_state_for_full_scan(
        self, mock_commit, mock_branch, mock_update_state, scanner, test_repo
    ):
        """Test scan state is updated when single_subagent and resume_from are both None"""
        securevibes_dir = test_repo / ".securevibes"
        securevibes_dir.mkdir()

        mock_commit.return_value = "abc123"
        mock_branch.return_value = "main"

        scan_results = {
            "issues": [
                {
                    "threat_id": "TEST-1",
                    "title": "Test Issue",
                    "description": "Test",
                    "severity": "low",
                    "file_path": "test.py",
                    "line_number": 1,
                    "code_snippet": "test",
                    "cwe_id": "CWE-000",
                    "recommendation": "Fix it",
                }
            ]
        }

        import json

        (securevibes_dir / "scan_results.json").write_text(json.dumps(scan_results))

        # Call without single_subagent or resume_from (full scan)
        result = scanner._load_scan_results(
            securevibes_dir, test_repo, files_scanned=10, scan_start_time=0
        )

        assert isinstance(result, ScanResult)
        mock_update_state.assert_called_once()

    @pytest.mark.asyncio
    @patch("securevibes.scanner.scanner.update_scan_state")
    @patch("securevibes.scanner.scanner.get_repo_branch")
    @patch("securevibes.scanner.scanner.get_repo_head_commit")
    async def test_load_skips_scan_state_for_subagent(
        self, mock_commit, mock_branch, mock_update_state, scanner, test_repo
    ):
        """Test scan state is NOT updated when single_subagent is set"""
        securevibes_dir = test_repo / ".securevibes"
        securevibes_dir.mkdir()

        mock_commit.return_value = "abc123"
        mock_branch.return_value = "main"

        scan_results = {"issues": []}

        import json

        (securevibes_dir / "scan_results.json").write_text(json.dumps(scan_results))

        # Call with single_subagent set
        result = scanner._load_scan_results(
            securevibes_dir,
            test_repo,
            files_scanned=10,
            scan_start_time=0,
            single_subagent="assessment",
        )

        assert isinstance(result, ScanResult)
        mock_update_state.assert_not_called()

    @pytest.mark.asyncio
    @patch("securevibes.scanner.scanner.update_scan_state")
    @patch("securevibes.scanner.scanner.get_repo_branch")
    @patch("securevibes.scanner.scanner.get_repo_head_commit")
    async def test_load_skips_scan_state_for_resume(
        self, mock_commit, mock_branch, mock_update_state, scanner, test_repo
    ):
        """Test scan state is NOT updated when resume_from is set"""
        securevibes_dir = test_repo / ".securevibes"
        securevibes_dir.mkdir()

        mock_commit.return_value = "abc123"
        mock_branch.return_value = "main"

        scan_results = {"issues": []}

        import json

        (securevibes_dir / "scan_results.json").write_text(json.dumps(scan_results))

        # Call with resume_from set
        result = scanner._load_scan_results(
            securevibes_dir,
            test_repo,
            files_scanned=10,
            scan_start_time=0,
            resume_from="code-review",
        )

        assert isinstance(result, ScanResult)
        mock_update_state.assert_not_called()

    @pytest.mark.asyncio
    @patch("securevibes.scanner.scanner.update_scan_state")
    @patch("securevibes.scanner.scanner.get_repo_branch")
    @patch("securevibes.scanner.scanner.get_repo_head_commit")
    async def test_load_subagent_code_review_skips_scan_state_update(
        self, mock_commit, mock_branch, mock_update_state, scanner, test_repo
    ):
        """Subagent code-review should not update full-scan state."""
        securevibes_dir = test_repo / ".securevibes"
        securevibes_dir.mkdir()

        mock_commit.return_value = "abc123"
        mock_branch.return_value = "main"

        import json

        (securevibes_dir / "VULNERABILITIES.json").write_text(json.dumps([]))

        result = scanner._load_subagent_results(
            securevibes_dir,
            test_repo,
            files_scanned=10,
            scan_start_time=0,
            subagent="code-review",
        )

        assert isinstance(result, ScanResult)
        mock_update_state.assert_not_called()

    @pytest.mark.asyncio
    @patch("securevibes.scanner.scanner.update_scan_state")
    @patch("securevibes.scanner.scanner.get_repo_branch")
    @patch("securevibes.scanner.scanner.get_repo_head_commit")
    async def test_load_subagent_report_generator_skips_scan_state_update(
        self, mock_commit, mock_branch, mock_update_state, scanner, test_repo
    ):
        """Subagent report-generator should not update full-scan state."""
        securevibes_dir = test_repo / ".securevibes"
        securevibes_dir.mkdir()

        mock_commit.return_value = "abc123"
        mock_branch.return_value = "main"

        import json

        (securevibes_dir / "scan_results.json").write_text(json.dumps({"issues": []}))

        result = scanner._load_subagent_results(
            securevibes_dir,
            test_repo,
            files_scanned=10,
            scan_start_time=0,
            subagent="report-generator",
        )

        assert isinstance(result, ScanResult)
        mock_update_state.assert_not_called()


class TestProgressTrackerEdgeCases:
    """Test edge cases in progress tracking"""

    def test_empty_tool_input(self, progress_tracker):
        """Test handling of empty tool input"""
        progress_tracker.on_tool_start("Read", {})
        assert progress_tracker.tool_count == 1

    def test_missing_file_path(self, progress_tracker):
        """Test handling of missing file path in tool input"""
        progress_tracker.on_tool_start("Read", {"something_else": "value"})
        assert progress_tracker.tool_count == 1

    def test_multiple_phase_announcements(self, progress_tracker):
        """Test multiple phase announcements reset counters"""
        progress_tracker.announce_phase("assessment")
        progress_tracker.tool_count = 50

        progress_tracker.announce_phase("threat-modeling")

        # Tool count should be reset
        assert progress_tracker.tool_count == 0
        assert progress_tracker.current_phase == "threat-modeling"

    def test_subagent_stack_management(self, progress_tracker):
        """Test sub-agent stack is properly managed"""
        # Push multiple agents
        progress_tracker.subagent_stack.append("assessment")
        progress_tracker.subagent_stack.append("threat-modeling")

        # Pop one
        progress_tracker.on_subagent_stop("threat-modeling", 1000)

        assert "assessment" in progress_tracker.subagent_stack
        assert "threat-modeling" not in progress_tracker.subagent_stack

    def test_long_file_paths(self, progress_tracker):
        """Test handling of very long file paths"""
        long_path = "/".join(["very"] * 50) + "/long/path/to/file.py"
        tool_input = {"file_path": long_path}

        progress_tracker.on_tool_start("Read", tool_input)

        assert long_path in progress_tracker.files_read
        assert progress_tracker.tool_count == 1


class TestFullScanAllowedTools:
    """Test that full scan includes Task in allowed_tools for subagent dispatch."""

    @pytest.mark.asyncio
    async def test_full_scan_allows_task_tool(self, test_repo):
        """Full scan must include Task in allowed_tools for subagent dispatch."""
        scanner = Scanner(model="sonnet", debug=False)
        scanner.console = Console(file=StringIO())

        with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_instance.query = AsyncMock()

            async def async_gen():
                return
                yield  # pragma: no cover

            mock_instance.receive_messages = async_gen

            try:
                await scanner.scan(str(test_repo))
            except RuntimeError:
                pass  # Expected — no results file

        options = mock_client.call_args[1]["options"]
        assert (
            "Task" in options.allowed_tools
        ), f"Task tool missing from allowed_tools: {options.allowed_tools}"

    @pytest.mark.asyncio
    async def test_full_scan_has_subagent_hook(self, test_repo):
        """Full scan must wire up SubagentStop hook for subagent lifecycle tracking."""
        scanner = Scanner(model="sonnet", debug=False)
        scanner.console = Console(file=StringIO())

        with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_instance.query = AsyncMock()

            async def async_gen():
                return
                yield  # pragma: no cover

            mock_instance.receive_messages = async_gen

            try:
                await scanner.scan(str(test_repo))
            except RuntimeError:
                pass  # Expected — no results file

        options = mock_client.call_args[1]["options"]
        assert "SubagentStop" in options.hooks, "SubagentStop hook must be configured"
        assert len(options.hooks["SubagentStop"]) > 0

    @pytest.mark.asyncio
    async def test_full_scan_uses_default_permission_and_least_privilege_tools(self, test_repo):
        """Full scan runtime policy should stay explicit and least-privilege."""
        scanner = Scanner(model="sonnet", debug=False)
        scanner.console = Console(file=StringIO())

        with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_instance.query = AsyncMock()

            async def async_gen():
                return
                yield  # pragma: no cover

            mock_instance.receive_messages = async_gen

            try:
                await scanner.scan(str(test_repo))
            except RuntimeError:
                pass  # Expected — no results file

        options = mock_client.call_args[1]["options"]
        assert options.permission_mode == "default"
        assert set(options.allowed_tools) == {
            "Task",
            "Skill",
            "Read",
            "Write",
            "Grep",
            "Glob",
            "LS",
        }

    @pytest.mark.asyncio
    async def test_full_scan_with_dast_includes_bash_tool(self, test_repo):
        """DAST-enabled scans should expose Bash for the DAST sub-agent only."""
        scanner = Scanner(model="sonnet", debug=False)
        scanner.configure_dast(target_url="http://localhost:3000")
        scanner.console = Console(file=StringIO())

        with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_instance.query = AsyncMock()

            async def async_gen():
                return
                yield  # pragma: no cover

            mock_instance.receive_messages = async_gen

            try:
                await scanner.scan(str(test_repo))
            except RuntimeError:
                pass

        options = mock_client.call_args[1]["options"]
        assert "Bash" in options.allowed_tools

    @pytest.mark.asyncio
    async def test_full_scan_prompt_injects_execution_mode_context(self, test_repo):
        """Full scan prompt should include authoritative execution mode context."""
        scanner = Scanner(model="sonnet", debug=False)
        scanner.console = Console(file=StringIO())

        with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_instance.query = AsyncMock()

            async def async_gen():
                return
                yield  # pragma: no cover

            mock_instance.receive_messages = async_gen

            try:
                await scanner.scan(str(test_repo))
            except RuntimeError:
                pass

        prompt = mock_instance.query.call_args.args[0]
        assert "<scan_execution_mode>" in prompt
        assert "run_only_subagent=none" in prompt
        assert "skip_subagents=none" in prompt
        assert "dast_enabled=false" in prompt

    @pytest.mark.asyncio
    async def test_subagent_prompt_injects_run_only_execution_mode_context(self, test_repo):
        """Sub-agent scans should inject run-only execution mode into orchestration prompt."""
        scanner = Scanner(model="sonnet", debug=False)
        scanner.console = Console(file=StringIO())

        with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_instance.query = AsyncMock()

            async def async_gen():
                return
                yield  # pragma: no cover

            mock_instance.receive_messages = async_gen

            try:
                await scanner.scan_subagent(str(test_repo), "assessment", skip_checks=True)
            except RuntimeError:
                pass

        prompt = mock_instance.query.call_args.args[0]
        assert "<scan_execution_mode>" in prompt
        assert "run_only_subagent=assessment" in prompt
        assert "dast_enabled=false" in prompt


class TestScannerExecutionMode:
    """Test explicit execution-mode propagation without environment mutation."""

    @pytest.mark.asyncio
    async def test_scan_does_not_mutate_existing_mode_env_vars(
        self, scanner, test_repo, monkeypatch
    ):
        """Full scan should ignore stale env vars and leave caller env unchanged."""
        monkeypatch.setenv("RUN_ONLY_SUBAGENT", "assessment")
        monkeypatch.setenv("RESUME_FROM_SUBAGENT", "code-review")
        monkeypatch.setenv("SKIP_SUBAGENTS", "assessment")

        with patch.object(
            scanner,
            "_execute_scan",
            new=AsyncMock(return_value=ScanResult(repository_path=str(test_repo), issues=[])),
        ) as mock_execute:
            await scanner.scan(str(test_repo))

        mock_execute.assert_awaited_once()
        assert os.environ.get("RUN_ONLY_SUBAGENT") == "assessment"
        assert os.environ.get("RESUME_FROM_SUBAGENT") == "code-review"
        assert os.environ.get("SKIP_SUBAGENTS") == "assessment"

    @pytest.mark.asyncio
    async def test_scan_subagent_passes_mode_explicitly_without_env_mutation(
        self, scanner, test_repo, monkeypatch
    ):
        """Sub-agent mode should be passed via call args, not env mutation."""
        monkeypatch.setenv("RUN_ONLY_SUBAGENT", "legacy-value")
        monkeypatch.delenv("RESUME_FROM_SUBAGENT", raising=False)
        monkeypatch.delenv("SKIP_SUBAGENTS", raising=False)
        monkeypatch.setenv("DAST_ENABLED", "legacy-dast")

        with patch.object(
            scanner,
            "_execute_scan",
            new=AsyncMock(return_value=ScanResult(repository_path=str(test_repo), issues=[])),
        ) as mock_execute:
            await scanner.scan_subagent(str(test_repo), "assessment", skip_checks=True)

        mock_execute.assert_awaited_once()
        assert mock_execute.await_args.kwargs["single_subagent"] == "assessment"
        assert os.environ.get("RUN_ONLY_SUBAGENT") == "legacy-value"
        assert os.environ.get("DAST_ENABLED") == "legacy-dast"
        assert "RESUME_FROM_SUBAGENT" not in os.environ
        assert "SKIP_SUBAGENTS" not in os.environ

    @pytest.mark.asyncio
    async def test_scan_resume_passes_mode_explicitly_without_env_mutation(
        self, scanner, test_repo, monkeypatch
    ):
        """Resume mode should be passed via call args, not env mutation."""
        monkeypatch.setenv("RUN_ONLY_SUBAGENT", "legacy-value")
        monkeypatch.setenv("RESUME_FROM_SUBAGENT", "legacy-resume")
        monkeypatch.setenv("SKIP_SUBAGENTS", "legacy-skip")

        with patch.object(
            scanner,
            "_execute_scan",
            new=AsyncMock(return_value=ScanResult(repository_path=str(test_repo), issues=[])),
        ) as mock_execute:
            await scanner.scan_resume(str(test_repo), "code-review", skip_checks=True)

        mock_execute.assert_awaited_once()
        assert mock_execute.await_args.kwargs["resume_from"] == "code-review"
        assert os.environ.get("RUN_ONLY_SUBAGENT") == "legacy-value"
        assert os.environ.get("RESUME_FROM_SUBAGENT") == "legacy-resume"
        assert os.environ.get("SKIP_SUBAGENTS") == "legacy-skip"


class TestScannerCostIsolation:
    """Test per-invocation cost isolation on reused Scanner instances."""

    @pytest.mark.asyncio
    async def test_scan_resets_stale_total_cost(self, scanner, test_repo):
        """Full scan should reset stale total_cost before execution starts."""
        scanner.total_cost = 9.99

        async def fake_execute(*args, **kwargs):
            assert scanner.total_cost == 0.0
            return ScanResult(repository_path=str(test_repo), issues=[])

        with patch.object(scanner, "_execute_scan", new=AsyncMock(side_effect=fake_execute)):
            await scanner.scan(str(test_repo))

    @pytest.mark.asyncio
    async def test_scan_subagent_resets_stale_total_cost(self, scanner, test_repo):
        """Sub-agent scan should reset stale total_cost before execution starts."""
        scanner.total_cost = 7.5

        async def fake_execute(*args, **kwargs):
            assert scanner.total_cost == 0.0
            return ScanResult(repository_path=str(test_repo), issues=[])

        with patch.object(scanner, "_execute_scan", new=AsyncMock(side_effect=fake_execute)):
            await scanner.scan_subagent(str(test_repo), "assessment", skip_checks=True)


class TestScannerDastAccountsSync:
    """Test DAST accounts-file sync behavior."""

    @pytest.mark.asyncio
    async def test_scan_syncs_dast_accounts_before_execute_scan(self, scanner, test_repo):
        """DAST accounts sync should create .securevibes even if execute scan is mocked."""
        accounts_file = test_repo / "accounts.json"
        accounts_file.write_text('{"users":[]}', encoding="utf-8")
        scanner.configure_dast(
            target_url="http://localhost:3000",
            timeout=120,
            accounts_path=str(accounts_file),
        )

        securevibes_dir = test_repo / ".securevibes"
        if securevibes_dir.exists():
            pytest.fail(".securevibes should not exist before test setup")

        with patch.object(
            scanner,
            "_execute_scan",
            new=AsyncMock(return_value=ScanResult(repository_path=str(test_repo), issues=[])),
        ):
            await scanner.scan(str(test_repo))

        synced_file = securevibes_dir / "DAST_TEST_ACCOUNTS.json"
        assert synced_file.exists()
        assert synced_file.read_text(encoding="utf-8") == '{"users":[]}'


class TestScannerPathGuards:
    """Test repo boundary protections for scanner-owned writes."""

    def _create_symlink(self, link_path, target_path):
        """Create a directory symlink, skipping test if unsupported."""
        try:
            link_path.symlink_to(target_path, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks are not supported in this environment")

    def test_sync_dast_accounts_rejects_securevibes_symlink_escape(self, scanner, tmp_path):
        """DAST accounts sync should fail when .securevibes escapes repo via symlink."""
        repo = tmp_path / "repo"
        repo.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()

        self._create_symlink(repo / ".securevibes", outside)

        accounts_file = tmp_path / "accounts.json"
        accounts_file.write_text('{"users":[]}', encoding="utf-8")
        scanner.configure_dast(
            target_url="http://localhost:3000",
            timeout=120,
            accounts_path=str(accounts_file),
        )

        with pytest.raises(RuntimeError, match="outside repository root"):
            scanner._sync_dast_accounts_file(repo)

    def test_setup_dast_skills_rejects_symlink_escape(self, scanner, tmp_path):
        """DAST skill sync should fail when .claude/skills escapes repo via symlink."""
        repo = tmp_path / "repo"
        repo.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()

        (repo / ".claude").mkdir()
        self._create_symlink(repo / ".claude" / "skills", outside)

        with pytest.raises(RuntimeError, match="outside repository root"):
            scanner._setup_dast_skills(repo)

    def test_setup_threat_modeling_skills_rejects_symlink_escape(self, scanner, tmp_path):
        """Threat-modeling skill sync should fail when .claude/skills escapes repo via symlink."""
        repo = tmp_path / "repo"
        repo.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()

        (repo / ".claude").mkdir()
        self._create_symlink(repo / ".claude" / "skills", outside)

        with pytest.raises(RuntimeError, match="outside repository root"):
            scanner._setup_threat_modeling_skills(repo)

    def test_setup_threat_modeling_skills_raises_on_copy_failure(self, scanner, tmp_path):
        """Threat-modeling skill sync should fail closed when copy fails."""
        repo = tmp_path / "repo"
        repo.mkdir()

        with patch("shutil.copytree", side_effect=OSError("disk full")):
            with pytest.raises(RuntimeError, match="Failed to sync threat modeling skills"):
                scanner._setup_threat_modeling_skills(repo)


# ---------------------------------------------------------------------------
# Tests for _merge_dast_results (P3.8)
# ---------------------------------------------------------------------------


class TestMergeDastResults:
    """Tests for Scanner._merge_dast_results."""

    def _make_issue(self, issue_id: str, severity: str = "high"):
        from securevibes.models.issue import SecurityIssue, Severity

        return SecurityIssue(
            id=issue_id,
            severity=Severity(severity),
            title=f"Issue {issue_id}",
            description="Test issue",
            file_path="app.py",
            line_number=1,
            code_snippet="x = 1",
        )

    def _make_scan_result(self, issues=None) -> ScanResult:
        return ScanResult(
            repository_path="/tmp/repo",
            issues=issues or [],
        )

    def test_no_dast_file_returns_unchanged(self, scanner, tmp_path):
        """When no DAST_VALIDATION.json exists, scan result is returned unchanged."""
        result = self._make_scan_result([self._make_issue("V001")])
        merged = scanner._merge_dast_results(result, tmp_path)

        assert merged is result
        assert not merged.dast_enabled

    def test_empty_validations_returns_unchanged(self, scanner, tmp_path):
        """When DAST file has no validations array, result is returned unchanged."""
        import json

        dast_file = tmp_path / "DAST_VALIDATION.json"
        dast_file.write_text(
            json.dumps(
                {
                    "dast_scan_metadata": {},
                    "validations": [],
                }
            )
        )

        result = self._make_scan_result([self._make_issue("V001")])
        merged = scanner._merge_dast_results(result, tmp_path)

        assert merged is result

    def test_validated_status_merges_correctly(self, scanner, tmp_path):
        """VALIDATED status should be mapped and metrics updated."""
        import json
        from securevibes.models.issue import ValidationStatus

        dast_file = tmp_path / "DAST_VALIDATION.json"
        dast_file.write_text(
            json.dumps(
                {
                    "dast_scan_metadata": {
                        "total_vulnerabilities_tested": 1,
                        "scan_duration_seconds": 42.0,
                    },
                    "validations": [
                        {
                            "vulnerability_id": "V001",
                            "validation_status": "VALIDATED",
                            "tested_at": "2026-01-01T00:00:00Z",
                            "exploitability_score": 8.5,
                            "evidence": {"request": "GET /admin", "response": "200 OK"},
                        }
                    ],
                }
            )
        )

        result = self._make_scan_result([self._make_issue("V001")])
        merged = scanner._merge_dast_results(result, tmp_path)

        assert merged.dast_enabled is True
        assert merged.dast_validation_rate == 1.0
        assert merged.dast_false_positive_rate == 0.0
        assert merged.dast_scan_time_seconds == 42.0

        issue = merged.issues[0]
        assert issue.validation_status == ValidationStatus.VALIDATED
        assert issue.validated_at == "2026-01-01T00:00:00Z"
        assert issue.exploitability_score == 8.5
        assert issue.dast_evidence == {"request": "GET /admin", "response": "200 OK"}

    def test_legacy_top_level_array_format_merges(self, scanner, tmp_path):
        """Legacy top-level JSON array format should be accepted."""
        import json
        from securevibes.models.issue import ValidationStatus

        dast_file = tmp_path / "DAST_VALIDATION.json"
        dast_file.write_text(
            json.dumps(
                [
                    {
                        "vulnerability_id": "V001",
                        "validation_status": "VALIDATED",
                        "tested_at": "2026-01-01T00:00:00Z",
                    }
                ]
            )
        )

        result = self._make_scan_result([self._make_issue("V001")])
        merged = scanner._merge_dast_results(result, tmp_path)

        assert merged.dast_enabled is True
        assert merged.dast_validation_rate == 1.0
        assert merged.issues[0].validation_status == ValidationStatus.VALIDATED

    def test_unexpected_top_level_type_returns_unchanged(self, scanner, tmp_path):
        """Unexpected top-level JSON type should be treated as malformed and ignored."""
        dast_file = tmp_path / "DAST_VALIDATION.json"
        dast_file.write_text('"malformed"', encoding="utf-8")

        result = self._make_scan_result([self._make_issue("V001")])
        merged = scanner._merge_dast_results(result, tmp_path)

        assert merged is result
        assert not merged.dast_enabled

    def test_non_mapping_validations_are_ignored(self, scanner, tmp_path):
        """Non-object entries in validations should be ignored rather than crashing."""
        import json
        from securevibes.models.issue import ValidationStatus

        dast_file = tmp_path / "DAST_VALIDATION.json"
        dast_file.write_text(
            json.dumps(
                {
                    "dast_scan_metadata": {"total_vulnerabilities_tested": 1},
                    "validations": [
                        "not-an-object",
                        123,
                        {"vulnerability_id": "V001", "validation_status": "FALSE_POSITIVE"},
                    ],
                }
            )
        )

        result = self._make_scan_result([self._make_issue("V001")])
        merged = scanner._merge_dast_results(result, tmp_path)

        assert merged.issues[0].validation_status == ValidationStatus.FALSE_POSITIVE
        assert merged.dast_false_positive_rate == 1.0

    def test_false_positive_status(self, scanner, tmp_path):
        """FALSE_POSITIVE status should be counted correctly."""
        import json
        from securevibes.models.issue import ValidationStatus

        dast_file = tmp_path / "DAST_VALIDATION.json"
        dast_file.write_text(
            json.dumps(
                {
                    "dast_scan_metadata": {"total_vulnerabilities_tested": 1},
                    "validations": [
                        {
                            "vulnerability_id": "V001",
                            "validation_status": "FALSE_POSITIVE",
                            "reason": "Endpoint not reachable",
                        }
                    ],
                }
            )
        )

        result = self._make_scan_result([self._make_issue("V001")])
        merged = scanner._merge_dast_results(result, tmp_path)

        assert merged.dast_enabled is True
        assert merged.dast_false_positive_rate == 1.0
        assert merged.dast_validation_rate == 0.0

        issue = merged.issues[0]
        assert issue.validation_status == ValidationStatus.FALSE_POSITIVE
        assert issue.dast_evidence == {"reason": "Endpoint not reachable"}

    def test_unknown_status_maps_to_unvalidated(self, scanner, tmp_path):
        """Unknown validation_status string should map to UNVALIDATED."""
        import json
        from securevibes.models.issue import ValidationStatus

        dast_file = tmp_path / "DAST_VALIDATION.json"
        dast_file.write_text(
            json.dumps(
                {
                    "dast_scan_metadata": {"total_vulnerabilities_tested": 1},
                    "validations": [
                        {
                            "vulnerability_id": "V001",
                            "validation_status": "BOGUS_STATUS",
                        }
                    ],
                }
            )
        )

        result = self._make_scan_result([self._make_issue("V001")])
        merged = scanner._merge_dast_results(result, tmp_path)

        issue = merged.issues[0]
        assert issue.validation_status == ValidationStatus.UNVALIDATED

    def test_evidence_from_test_steps_and_notes(self, scanner, tmp_path):
        """Evidence should be built from test_steps/reason/notes when evidence field missing."""
        import json

        dast_file = tmp_path / "DAST_VALIDATION.json"
        dast_file.write_text(
            json.dumps(
                {
                    "dast_scan_metadata": {"total_vulnerabilities_tested": 1},
                    "validations": [
                        {
                            "vulnerability_id": "V001",
                            "validation_status": "VALIDATED",
                            "test_steps": ["step1", "step2"],
                            "notes": "Manual verification",
                        }
                    ],
                }
            )
        )

        result = self._make_scan_result([self._make_issue("V001")])
        merged = scanner._merge_dast_results(result, tmp_path)

        issue = merged.issues[0]
        assert issue.dast_evidence["test_steps"] == ["step1", "step2"]
        assert issue.dast_evidence["notes"] == "Manual verification"
        assert "reason" not in issue.dast_evidence

    def test_unmatched_issues_preserved(self, scanner, tmp_path):
        """Issues without matching validation entries should be preserved as-is."""
        import json

        dast_file = tmp_path / "DAST_VALIDATION.json"
        dast_file.write_text(
            json.dumps(
                {
                    "dast_scan_metadata": {"total_vulnerabilities_tested": 1},
                    "validations": [
                        {
                            "vulnerability_id": "V999",
                            "validation_status": "VALIDATED",
                        }
                    ],
                }
            )
        )

        result = self._make_scan_result([self._make_issue("V001")])
        merged = scanner._merge_dast_results(result, tmp_path)

        assert len(merged.issues) == 1
        assert merged.issues[0].validation_status is None

    def test_mixed_statuses_metrics(self, scanner, tmp_path):
        """Multiple issues with mixed statuses should produce correct metrics."""
        import json

        dast_file = tmp_path / "DAST_VALIDATION.json"
        dast_file.write_text(
            json.dumps(
                {
                    "dast_scan_metadata": {"total_vulnerabilities_tested": 3},
                    "validations": [
                        {"vulnerability_id": "V001", "validation_status": "VALIDATED"},
                        {"vulnerability_id": "V002", "validation_status": "FALSE_POSITIVE"},
                        {"vulnerability_id": "V003", "validation_status": "UNVALIDATED"},
                    ],
                }
            )
        )

        issues = [self._make_issue("V001"), self._make_issue("V002"), self._make_issue("V003")]
        result = self._make_scan_result(issues)
        merged = scanner._merge_dast_results(result, tmp_path)

        assert merged.dast_enabled is True
        assert abs(merged.dast_validation_rate - 1 / 3) < 0.01
        assert abs(merged.dast_false_positive_rate - 1 / 3) < 0.01

    def test_json_decode_error_returns_unchanged(self, scanner, tmp_path):
        """Corrupt DAST file should be handled gracefully."""
        dast_file = tmp_path / "DAST_VALIDATION.json"
        dast_file.write_text("not valid json {{{")

        result = self._make_scan_result([self._make_issue("V001")])
        merged = scanner._merge_dast_results(result, tmp_path)

        assert merged is result
        assert not merged.dast_enabled

    def test_os_error_reading_file_returns_unchanged(self, scanner, tmp_path):
        """OSError reading DAST file should be handled gracefully."""
        dast_file = tmp_path / "DAST_VALIDATION.json"
        dast_file.write_text("{}")

        result = self._make_scan_result([self._make_issue("V001")])

        with patch("builtins.open", side_effect=OSError("permission denied")):
            merged = scanner._merge_dast_results(result, tmp_path)

        assert merged is result
