"""Tests for deterministic agentic detection."""

from securevibes.scanner.detection import detect_agentic_patterns


def test_detect_agentic_requires_two_categories(tmp_path):
    (tmp_path / "a.py").write_text("import anthropic\n")

    result = detect_agentic_patterns(tmp_path, [tmp_path / "a.py"])

    assert result.is_agentic is False
    assert "llm_apis" in result.matched_categories


def test_detect_agentic_two_categories_is_true(tmp_path):
    (tmp_path / "a.py").write_text("import anthropic\n")
    (tmp_path / "b.py").write_text("tools = []\n")

    result = detect_agentic_patterns(tmp_path, [tmp_path / "a.py", tmp_path / "b.py"])

    assert result.is_agentic is True
    assert "llm_apis" in result.matched_categories
    assert "tool_execution" in result.matched_categories
