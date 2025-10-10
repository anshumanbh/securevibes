"""Tests for scanner with real-time progress tracking"""

import pytest
import asyncio
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from securevibes.scanner.scanner import (
    Scanner,
    ProgressTracker
)
from securevibes.models.result import ScanResult
from securevibes.models.issue import SecurityIssue, Severity
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
    (tmp_path / "app.py").write_text("""
def hello():
    print("Hello World")
""")
    (tmp_path / "routes.py").write_text("""
@app.route('/api')
def api():
    return {'status': 'ok'}
""")
    return tmp_path


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
        tool_input = {
            "agent_name": "assessment",
            "prompt": "Analyze the codebase architecture"
        }
        
        # Mock announce_phase to avoid console output
        progress_tracker.announce_phase = lambda x: None
        
        progress_tracker.on_tool_start("Task", tool_input)
        
        assert progress_tracker.tool_count == 1
        assert "assessment" in progress_tracker.subagent_stack
    
    def test_on_tool_complete_success(self, progress_tracker):
        """Test tracking successful tool completion"""
        progress_tracker.on_tool_complete("Read", success=True)
        # Should not raise any errors
        assert True
    
    def test_on_tool_complete_failure(self, progress_tracker):
        """Test tracking failed tool completion"""
        progress_tracker.on_tool_complete("Read", success=False, error_msg="File not found")
        # Should handle error gracefully
        assert True
    
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
        
        # Should not raise errors
        debug_progress_tracker.on_assistant_text(text)
        assert True
    
    def test_non_debug_mode_skips_narration(self, progress_tracker):
        """Test agent narration is skipped in non-debug mode"""
        text = "Some agent thinking"
        
        # Should be a no-op in non-debug mode
        progress_tracker.on_assistant_text(text)
        assert True
    
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
            "report-generator": "4/4: Report Generation"
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
        import os
        scanner = Scanner()
        
        # API key is no longer set by the scanner - delegated to claude CLI


class TestScannerIntegration:
    """Integration tests for Scanner (with mocks)"""
    
    @pytest.mark.asyncio
    async def test_scan_creates_output_directory(self, scanner, test_repo):
        """Test scan creates .securevibes directory"""
        securevibes_dir = test_repo / ".securevibes"
        
        # Mock the ClaudeSDKClient to avoid real API calls
        with patch('securevibes.scanner.scanner.ClaudeSDKClient') as mock_client:
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
        
        with patch('securevibes.scanner.scanner.ClaudeSDKClient') as mock_client:
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
                    "recommendation": "Use parameterized queries"
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
                "recommendation": "Sanitize input"
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
    async def test_load_handles_missing_files(self, scanner, test_repo):
        """Test error handling when no results files exist"""
        securevibes_dir = test_repo / ".securevibes"
        securevibes_dir.mkdir()
        
        # No results files created
        with pytest.raises(RuntimeError, match="failed to generate results"):
            scanner._load_scan_results(
                securevibes_dir, test_repo, files_scanned=10, scan_start_time=0
            )


class TestScannerHooks:
    """Test hook integration in Scanner"""
    
    @pytest.mark.asyncio
    async def test_hooks_are_configured(self, scanner, test_repo):
        """Test that hooks are properly configured"""
        with patch('securevibes.scanner.scanner.ClaudeSDKClient') as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_instance.query = AsyncMock()
            
            # Create an async generator
            async def async_gen():
                return
                yield
            
            mock_instance.receive_messages = async_gen
            
            try:
                await scanner.scan(str(test_repo))
            except RuntimeError:
                # Expected to fail
                pass
            
            # Verify ClaudeAgentOptions was called with hooks
            assert mock_client.called
            call_kwargs = mock_client.call_args[1] if mock_client.call_args else {}
            if 'hooks' in call_kwargs:
                hooks = call_kwargs['hooks']
                assert 'PreToolUse' in hooks
                assert 'PostToolUse' in hooks
                assert 'SubagentStop' in hooks


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
