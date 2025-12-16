"""Tests for scanner hooks"""

import pytest
from unittest.mock import Mock
from io import StringIO
from rich.console import Console

from securevibes.scanner.hooks import (
    create_dast_security_hook,
    create_pre_tool_hook,
    create_post_tool_hook,
    create_subagent_hook,
    create_json_validation_hook
)
from securevibes.scanner.scanner import ProgressTracker


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
            "tool_input": {
                "command": "sqlite3 database.db 'SELECT * FROM users'"
            }
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
        
        input_data = {
            "tool_name": "Bash",
            "tool_input": {
                "command": "psql -U admin -d production"
            }
        }
        
        result = await hook(input_data, "tool-123", {})
        
        assert "hookSpecificOutput" in result
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    
    @pytest.mark.asyncio
    async def test_allows_sqlite3_in_other_phases(self, tracker, console):
        """Test that sqlite3 is allowed in non-DAST phases"""
        tracker.current_phase = "code-review"
        hook = create_dast_security_hook(tracker, console, debug=False)
        
        input_data = {
            "tool_name": "Bash",
            "tool_input": {
                "command": "sqlite3 database.db .schema"
            }
        }
        
        result = await hook(input_data, "tool-123", {})
        
        # Should return empty dict (allow)
        assert result == {}
    
    @pytest.mark.asyncio
    async def test_only_filters_bash_commands(self, tracker, console):
        """Test that only Bash commands are filtered"""
        tracker.current_phase = "dast"
        hook = create_dast_security_hook(tracker, console, debug=False)
        
        # Non-Bash tool should not be filtered
        input_data = {
            "tool_name": "Read",
            "tool_input": {
                "file_path": "sqlite3_script.sh"
            }
        }
        
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
            "tool_input": {
                "command": "curl -X POST http://localhost:5000/api/login"
            }
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
        detected_languages = {'python'}
        hook = create_pre_tool_hook(tracker, console, debug=False, detected_languages=detected_languages)
        
        input_data = {
            "tool_name": "Read",
            "tool_input": {
                "file_path": "/project/venv/lib/python3.9/site-packages/django/models.py"
            }
        }
        
        result = await hook(input_data, "tool-123", {})
        
        assert "override_result" in result
        assert "Infrastructure directory" in result["override_result"]["content"]
    
    @pytest.mark.asyncio
    async def test_excludes_node_modules_for_read(self, tracker, console):
        """Test that reads from node_modules are blocked"""
        tracker.current_phase = "assessment"
        detected_languages = {'javascript'}
        hook = create_pre_tool_hook(tracker, console, debug=False, detected_languages=detected_languages)
        
        input_data = {
            "tool_name": "Read",
            "tool_input": {
                "file_path": "/project/node_modules/express/index.js"
            }
        }
        
        result = await hook(input_data, "tool-123", {})
        
        assert "override_result" in result
        assert "Infrastructure directory" in result["override_result"]["content"]
    
    @pytest.mark.asyncio
    async def test_injects_exclude_patterns_for_grep(self, tracker, console):
        """Test that Grep gets exclude patterns injected"""
        tracker.current_phase = "assessment"
        detected_languages = {'python'}
        hook = create_pre_tool_hook(tracker, console, debug=False, detected_languages=detected_languages)
        
        input_data = {
            "tool_name": "Grep",
            "tool_input": {
                "pattern": "password",
                "excludePatterns": []
            }
        }
        
        result = await hook(input_data, "tool-123", {})
        
        # Should inject exclude patterns
        assert len(input_data["tool_input"]["excludePatterns"]) > 0
        assert any("venv" in pattern for pattern in input_data["tool_input"]["excludePatterns"])
        assert result == {}  # No override
    
    @pytest.mark.asyncio
    async def test_injects_exclude_patterns_for_glob(self, tracker, console):
        """Test that Glob gets exclude patterns injected"""
        tracker.current_phase = "assessment"
        detected_languages = {'javascript'}
        hook = create_pre_tool_hook(tracker, console, debug=False, detected_languages=detected_languages)
        
        input_data = {
            "tool_name": "Glob",
            "tool_input": {
                "patterns": ["**/*.js"],
                "excludePatterns": []
            }
        }
        
        result = await hook(input_data, "tool-123", {})
        
        # Should inject exclude patterns
        assert len(input_data["tool_input"]["excludePatterns"]) > 0
        assert any("node_modules" in pattern for pattern in input_data["tool_input"]["excludePatterns"])
    
    @pytest.mark.asyncio
    async def test_blocks_non_artifact_writes_in_dast(self, tracker, console):
        """Test that non-artifact writes are blocked in DAST phase"""
        tracker.current_phase = "dast"
        detected_languages = {'python'}
        hook = create_pre_tool_hook(tracker, console, debug=False, detected_languages=detected_languages)
        
        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/some_file.txt",
                "content": "test data"
            }
        }
        
        result = await hook(input_data, "tool-123", {})
        
        assert "override_result" in result
        assert "DAST phase may only write" in result["override_result"]["content"]
    
    @pytest.mark.asyncio
    async def test_allows_dast_validation_write(self, tracker, console):
        """Test that DAST_VALIDATION.json write is allowed"""
        tracker.current_phase = "dast"
        detected_languages = {'python'}
        hook = create_pre_tool_hook(tracker, console, debug=False, detected_languages=detected_languages)
        
        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/DAST_VALIDATION.json",
                "content": "{}"
            }
        }
        
        result = await hook(input_data, "tool-123", {})
        
        # Should not block (but will call tracker.on_tool_start)
        assert "override_result" not in result
    
    @pytest.mark.asyncio
    async def test_allows_tmp_writes_in_dast(self, tracker, console):
        """Test that /tmp/* writes are allowed in DAST"""
        tracker.current_phase = "dast"
        detected_languages = {'python'}
        hook = create_pre_tool_hook(tracker, console, debug=False, detected_languages=detected_languages)
        
        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/tmp/test_script.py",
                "content": "print('hello')"
            }
        }
        
        result = await hook(input_data, "tool-123", {})
        
        # Should not block
        assert "override_result" not in result
    
    @pytest.mark.asyncio
    async def test_logs_skill_invocations_in_debug(self, tracker, console):
        """Test that Skill invocations are logged in debug mode"""
        tracker.current_phase = "dast"
        detected_languages = {'python'}
        hook = create_pre_tool_hook(tracker, console, debug=True, detected_languages=detected_languages)
        
        input_data = {
            "tool_name": "Skill",
            "tool_input": {
                "skill_name": "authorization-testing",
                "prompt": "Test the API"
            }
        }
        
        result = await hook(input_data, "tool-123", {})
        
        # Should return empty (allow) and log to console
        assert result == {}
        
        # Check console output
        output = console.file.getvalue()
        assert "SKILL INVOKED" in output
        assert "authorization-testing" in output


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
            "tool_response": {"is_error": False, "content": "file content"}
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
            "tool_response": {"is_error": True, "content": "File not found"}
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
            "tool_response": {"is_error": False}
        }
        
        result = await hook(input_data, "tool-123", {})
        
        # Should log to console
        output = console.file.getvalue()
        assert "Read" in output
        assert "/project/app.py" in output
    
    @pytest.mark.asyncio
    async def test_logs_write_operations_in_debug(self, tracker, console):
        """Test that write operations are logged in debug mode"""
        hook = create_post_tool_hook(tracker, console, debug=True)
        
        input_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/project/.securevibes/results.json"},
            "tool_response": {"is_error": False}
        }
        
        result = await hook(input_data, "tool-123", {})
        
        # Should log to console
        output = console.file.getvalue()
        assert "Wrote" in output
        assert "results.json" in output


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
        
        input_data = {
            "agent_name": "assessment",
            "duration_ms": 5000
        }
        
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
        
        input_data = {
            "subagent_type": "threat-modeling",
            "duration_ms": 3000
        }
        
        # Mock the tracker method
        tracker.on_subagent_stop = Mock()
        
        result = await hook(input_data, "tool-123", {})
        
        # Should call tracker
        tracker.on_subagent_stop.assert_called_once_with("threat-modeling", 3000)
    
    @pytest.mark.asyncio
    async def test_handles_missing_agent_name(self, tracker):
        """Test that missing agent_name is handled gracefully"""
        hook = create_subagent_hook(tracker)
        
        input_data = {
            "duration_ms": 1000
        }
        
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
            "severity": "high"
        }
    
    @pytest.mark.asyncio
    async def test_non_write_tool_passes_through(self, console):
        """Non-Write tools should pass through unchanged."""
        hook = create_json_validation_hook(console, debug=False)
        
        input_data = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/VULNERABILITIES.json"}
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
                "content": json.dumps({"some": "data"})
            }
        }
        
        result = await hook(input_data, "tool-123", {})
        
        assert result == {}
    
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
                "content": content
            }
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
                "content": content
            }
        }
        
        result = await hook(input_data, "tool-123", {})
        
        # Should return updatedInput with fixed content
        assert "updatedInput" in result
        fixed_content = result["updatedInput"]["content"]
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
                "content": content
            }
        }
        
        result = await hook(input_data, "tool-123", {})
        
        assert "updatedInput" in result
        fixed_content = result["updatedInput"]["content"]
        assert json.loads(fixed_content) == [vuln]
    
    @pytest.mark.asyncio
    async def test_empty_content_passes_through(self, console):
        """Empty content should pass through."""
        hook = create_json_validation_hook(console, debug=False)
        
        input_data = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/VULNERABILITIES.json",
                "content": ""
            }
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
                "content": content
            }
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
                "content": content
            }
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
                "encoding": "utf-8"
            }
        }
        
        result = await hook(input_data, "tool-123", {})
        
        assert "updatedInput" in result
        assert result["updatedInput"]["file_path"] == "/project/.securevibes/VULNERABILITIES.json"
        assert result["updatedInput"]["encoding"] == "utf-8"
