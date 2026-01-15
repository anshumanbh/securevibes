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

    assert "updatedInput" in result
    assert json.loads(result["updatedInput"]["content"]) == [_threat("THREAT-001")]


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
