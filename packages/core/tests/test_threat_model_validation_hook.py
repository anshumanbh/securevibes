"""Tests for THREAT_MODEL.json validation hook."""

from io import StringIO
import json

import pytest
from rich.console import Console

from securevibes.scanner.hooks import create_threat_model_validation_hook


def _threat(tid: str) -> dict:
    return {
        "id": tid,
        "category": "Spoofing",
        "title": "Test threat",
        "description": "Test description",
        "severity": "high",
    }


@pytest.fixture
def console():
    return Console(file=StringIO())


@pytest.mark.asyncio
async def test_non_write_tool_passes_through(console):
    hook = create_threat_model_validation_hook(console, debug=False, require_asi=True)
    result = await hook(
        {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/.securevibes/THREAT_MODEL.json"},
        },
        "tool-123",
        {},
    )
    assert result == {}


@pytest.mark.asyncio
async def test_non_threat_model_file_passes_through(console):
    hook = create_threat_model_validation_hook(console, debug=False, require_asi=True)
    result = await hook(
        {
            "tool_name": "Write",
            "tool_input": {"file_path": "/project/.securevibes/OTHER.json", "content": "[]"},
        },
        "tool-123",
        {},
    )
    assert result == {}


@pytest.mark.asyncio
async def test_non_canonical_threat_model_filename_passes_through(console):
    """Non-canonical THREAT_MODEL artifact names should be ignored."""
    hook = create_threat_model_validation_hook(
        console, debug=False, require_asi=False, max_retries=1
    )
    result = await hook(
        {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/THREAT_MODEL.json.bak",
                "content": "{ invalid json ]]",
            },
        },
        "tool-123",
        {},
    )
    assert result == {}


@pytest.mark.asyncio
async def test_non_canonical_threat_model_path_does_not_consume_retry_budget(console):
    """Ignored non-canonical paths must not affect THREAT_MODEL retry tracking."""
    hook = create_threat_model_validation_hook(
        console, debug=False, require_asi=False, max_retries=1
    )

    ignored_input = {
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/project/.securevibes/THREAT_MODEL.json.bak",
            "content": "{ invalid json ]]",
        },
    }
    canonical_input = {
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/project/.securevibes/THREAT_MODEL.json",
            "content": "{ invalid json ]]",
        },
    }

    ignored_result = await hook(ignored_input, "tool-123", {})
    assert ignored_result == {}

    canonical_first = await hook(canonical_input, "tool-124", {})
    assert "override_result" in canonical_first
    assert canonical_first["override_result"]["is_error"] is True


@pytest.mark.asyncio
async def test_wrapped_threats_get_fixed(console):
    hook = create_threat_model_validation_hook(console, debug=False, require_asi=False)
    content = json.dumps({"threats": [_threat("THREAT-001")]})
    result = await hook(
        {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/project/.securevibes/THREAT_MODEL.json",
                "content": content,
            },
        },
        "tool-123",
        {},
    )

    assert "hookSpecificOutput" in result
    assert result["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    updated_input = result["hookSpecificOutput"]["updatedInput"]
    assert json.loads(updated_input["content"]) == [_threat("THREAT-001")]


@pytest.mark.asyncio
async def test_requires_asi_rejects_first_invalid_write_then_fails(console):
    hook = create_threat_model_validation_hook(
        console, debug=False, require_asi=True, max_retries=1
    )
    content = json.dumps([_threat("THREAT-001")])
    input_data = {
        "tool_name": "Write",
        "tool_input": {"file_path": "/project/.securevibes/THREAT_MODEL.json", "content": content},
    }

    first = await hook(input_data, "tool-1", {})
    assert "override_result" in first
    assert first["override_result"]["is_error"] is True

    with pytest.raises(RuntimeError):
        await hook(input_data, "tool-2", {})


@pytest.mark.asyncio
async def test_malformed_json_rejects(console):
    """Invalid JSON syntax triggers rejection."""
    hook = create_threat_model_validation_hook(
        console, debug=False, require_asi=False, max_retries=1
    )
    input_data = {
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/project/.securevibes/THREAT_MODEL.json",
            "content": "{ invalid json ]]",
        },
    }

    result = await hook(input_data, "tool-1", {})

    assert "override_result" in result
    assert result["override_result"]["is_error"] is True
    assert "Invalid JSON" in result["override_result"]["content"]


@pytest.mark.asyncio
async def test_non_array_content_rejects(console):
    """Single object without array structure triggers rejection."""
    hook = create_threat_model_validation_hook(
        console, debug=False, require_asi=False, max_retries=1
    )
    # A string instead of an array
    input_data = {
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/project/.securevibes/THREAT_MODEL.json",
            "content": '"just a string"',
        },
    }

    result = await hook(input_data, "tool-1", {})

    assert "override_result" in result
    assert result["override_result"]["is_error"] is True
    assert "JSON array" in result["override_result"]["content"]


@pytest.mark.asyncio
async def test_code_fence_wrapped_json_gets_fixed(console):
    """```json\n[...]\n``` gets code fence removed and returns updatedInput."""
    hook = create_threat_model_validation_hook(
        console, debug=False, require_asi=False, max_retries=1
    )
    threats = [_threat(f"THREAT-{i:03d}") for i in range(1, 12)]
    content = f"```json\n{json.dumps(threats)}\n```"

    input_data = {
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/project/.securevibes/THREAT_MODEL.json",
            "content": content,
        },
    }

    result = await hook(input_data, "tool-1", {})

    # Should return hookSpecificOutput with updatedInput (code fence stripped)
    assert "hookSpecificOutput" in result
    assert result["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    fixed_content = result["hookSpecificOutput"]["updatedInput"]["content"]
    assert fixed_content.strip().startswith("[")
    assert "```" not in fixed_content


@pytest.mark.asyncio
async def test_empty_content_passes_through(console):
    """Empty or whitespace-only content passes through unchanged."""
    hook = create_threat_model_validation_hook(
        console, debug=False, require_asi=False, max_retries=1
    )
    input_data = {
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/project/.securevibes/THREAT_MODEL.json",
            "content": "   ",
        },
    }

    result = await hook(input_data, "tool-1", {})

    # Empty/whitespace content passes through (returns empty dict)
    assert result == {}


@pytest.mark.asyncio
async def test_valid_flat_array_passes_through(console):
    """Valid flat array with sufficient threats passes through unchanged."""
    hook = create_threat_model_validation_hook(
        console, debug=False, require_asi=False, max_retries=1
    )
    # Need at least 10 threats to avoid warning, but validation still passes
    threats = [_threat(f"THREAT-{i:03d}") for i in range(1, 12)]
    content = json.dumps(threats)

    input_data = {
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/project/.securevibes/THREAT_MODEL.json",
            "content": content,
        },
    }

    result = await hook(input_data, "tool-1", {})

    # Should pass through unchanged (no modification needed)
    assert result == {}


@pytest.mark.asyncio
async def test_threat_missing_required_fields_rejects(console):
    """Threat missing required fields triggers rejection."""
    hook = create_threat_model_validation_hook(
        console, debug=False, require_asi=False, max_retries=1
    )
    # Missing 'category' and 'severity' fields
    incomplete_threat = {
        "id": "THREAT-001",
        "title": "Test threat",
        "description": "Test description",
    }
    content = json.dumps([incomplete_threat])

    input_data = {
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/project/.securevibes/THREAT_MODEL.json",
            "content": content,
        },
    }

    result = await hook(input_data, "tool-1", {})

    assert "override_result" in result
    assert result["override_result"]["is_error"] is True
    assert "missing required fields" in result["override_result"]["content"]
