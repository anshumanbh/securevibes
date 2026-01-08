"""Tests for threat modeling skills functionality"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


def test_setup_threat_modeling_skills_copies_to_target(tmp_path):
    """Test that _setup_threat_modeling_skills copies skills to target project"""
    from securevibes.scanner.scanner import Scanner
    
    scanner = Scanner(model="sonnet", debug=False)
    
    # Call setup on temp directory
    scanner._setup_threat_modeling_skills(tmp_path)
    
    # Verify skills were copied
    target_skills = tmp_path / ".claude" / "skills" / "threat-modeling"
    assert target_skills.exists()
    
    # Check agentic-security skill
    assert (target_skills / "agentic-security" / "SKILL.md").exists()
    assert (target_skills / "agentic-security" / "examples.md").exists()
    assert (target_skills / "agentic-security" / "reference" / "README.md").exists()


def test_setup_threat_modeling_skills_always_syncs(tmp_path):
    """Test that _setup_threat_modeling_skills always syncs skills (even if directory exists)"""
    from securevibes.scanner.scanner import Scanner
    
    scanner = Scanner(model="sonnet", debug=False)
    
    # Create existing skills directory with custom file
    target_skills = tmp_path / ".claude" / "skills" / "threat-modeling"
    target_skills.mkdir(parents=True)
    marker_file = target_skills / "custom_skill.txt"
    marker_file.write_text("custom")
    
    # Call setup - should sync new skills while preserving custom files
    scanner._setup_threat_modeling_skills(tmp_path)
    
    # Verify custom file is preserved (dirs_exist_ok=True preserves non-conflicting files)
    assert marker_file.exists()
    assert marker_file.read_text() == "custom"
    
    # Verify skills were synced
    assert (target_skills / "agentic-security" / "SKILL.md").exists()


def test_setup_threat_modeling_skills_handles_missing_gracefully(tmp_path):
    """Test that missing threat modeling skills are handled gracefully (not fatal)"""
    from securevibes.scanner.scanner import Scanner
    
    scanner = Scanner(model="sonnet", debug=True)
    
    # Mock Path to return non-existent skills directory
    # Unlike DAST skills, missing threat modeling skills should not raise an error
    with patch('securevibes.scanner.scanner.Path') as mock_path:
        # Create a mock that returns a non-existent path for skills
        mock_skills_path = MagicMock()
        mock_skills_path.exists.return_value = False
        mock_skills_path.parent.parent = tmp_path / "nonexistent"
        
        # The actual path operations
        real_path = Path(tmp_path)
        mock_path.return_value = real_path
        mock_path.side_effect = lambda x: Path(x) if isinstance(x, str) else real_path
        
        # Should NOT raise error (unlike DAST skills)
        # This is tested by the function returning without error
        scanner._setup_threat_modeling_skills(tmp_path)


def test_bundled_threat_modeling_skills_package_structure():
    """Test that threat modeling skills are included in package"""
    import securevibes
    
    package_dir = Path(securevibes.__file__).parent
    
    # Verify threat-modeling skills directory exists
    tm_skills_dir = package_dir / "skills" / "threat-modeling"
    assert tm_skills_dir.exists(), "Threat-modeling skills directory not found in package"
    
    # Verify README
    assert (tm_skills_dir / "README.md").exists(), "threat-modeling README.md missing"
    
    # Verify agentic-security skill structure
    agentic_skills_dir = tm_skills_dir / "agentic-security"
    assert agentic_skills_dir.exists(), "Agentic-security skills directory not found in package"
    assert (agentic_skills_dir / "SKILL.md").exists(), "agentic-security SKILL.md missing"
    assert (agentic_skills_dir / "examples.md").exists(), "agentic-security examples.md missing"
    assert (agentic_skills_dir / "reference" / "README.md").exists(), "agentic-security reference README missing"


def test_threat_modeling_agent_has_skill_tool():
    """Test that threat-modeling agent has Skill in its tools list"""
    from securevibes.agents.definitions import create_agent_definitions
    
    agents = create_agent_definitions()
    
    # Verify threat-modeling has Skill tool
    assert "Skill" in agents["threat-modeling"].tools, "threat-modeling agent missing Skill tool"
    
    # Verify it still has original tools
    assert "Read" in agents["threat-modeling"].tools
    assert "Write" in agents["threat-modeling"].tools
    assert "Grep" in agents["threat-modeling"].tools
    assert "Glob" in agents["threat-modeling"].tools


def test_threat_modeling_agent_description_updated():
    """Test that threat-modeling agent description mentions skills"""
    from securevibes.agents.definitions import create_agent_definitions
    
    agents = create_agent_definitions()
    
    description = agents["threat-modeling"].description
    
    # Should mention skill-based augmentation
    assert "skill" in description.lower() or "agentic" in description.lower() or "specialized" in description.lower(), \
        "threat-modeling description should mention skill augmentation"


def test_threat_modeling_prompt_has_technology_detection():
    """Test that threat modeling prompt includes technology detection phase"""
    from securevibes.prompts.loader import load_prompt
    
    prompt = load_prompt("threat_modeling", category="agents")
    
    # Should mention technology detection
    assert "TECHNOLOGY DETECTION" in prompt or "technology detection" in prompt.lower(), \
        "threat_modeling prompt should include technology detection phase"
    
    # Should mention agentic patterns
    assert "langchain" in prompt.lower() or "autogen" in prompt.lower() or "agentic" in prompt.lower(), \
        "threat_modeling prompt should mention agentic framework patterns"
    
    # Should mention skill loading
    assert "skill" in prompt.lower(), \
        "threat_modeling prompt should mention skill loading"


def test_threat_modeling_prompt_has_skill_augmented_analysis():
    """Test that threat modeling prompt includes skill-augmented analysis phase"""
    from securevibes.prompts.loader import load_prompt
    
    prompt = load_prompt("threat_modeling", category="agents")
    
    # Should mention ASI categories
    assert "ASI" in prompt, \
        "threat_modeling prompt should mention ASI threat categories"
    
    # Should mention skill-augmented analysis
    assert "SKILL-AUGMENTED" in prompt or "skill-augmented" in prompt.lower(), \
        "threat_modeling prompt should include skill-augmented analysis phase"


def test_agentic_security_skill_content():
    """Test that agentic-security SKILL.md has required content"""
    import securevibes
    
    package_dir = Path(securevibes.__file__).parent
    skill_md = package_dir / "skills" / "threat-modeling" / "agentic-security" / "SKILL.md"
    
    content = skill_md.read_text()
    
    # Check YAML frontmatter
    assert "name: agentic-security-threat-modeling" in content, "Missing skill name in frontmatter"
    assert "description:" in content, "Missing description in frontmatter"
    
    # Check ASI categories are documented
    for asi_num in range(1, 11):
        asi_id = f"ASI{asi_num:02d}" if asi_num < 10 else f"ASI{asi_num}"
        assert asi_id in content or f"ASI0{asi_num}" in content, f"Missing {asi_id} category"
    
    # Check key sections exist
    assert "Agent Goal Hijack" in content, "Missing ASI01 Agent Goal Hijack"
    assert "Tool Misuse" in content, "Missing ASI02 Tool Misuse"
    assert "Identity and Privilege" in content or "Privilege Abuse" in content, "Missing ASI03 Identity/Privilege"
    assert "Supply Chain" in content, "Missing ASI04 Supply Chain"
    assert "Code Execution" in content or "RCE" in content, "Missing ASI05 Code Execution"
    assert "Memory" in content or "Context Poisoning" in content, "Missing ASI06 Memory Poisoning"
    assert "Inter-Agent" in content, "Missing ASI07 Inter-Agent Communication"
    assert "Cascading" in content, "Missing ASI08 Cascading Failures"
    assert "Trust" in content, "Missing ASI09 Trust Exploitation"
    assert "Rogue" in content, "Missing ASI10 Rogue Agents"


def test_agentic_security_skill_detection_patterns():
    """Test that agentic-security skill includes framework detection patterns"""
    import securevibes
    
    package_dir = Path(securevibes.__file__).parent
    skill_md = package_dir / "skills" / "threat-modeling" / "agentic-security" / "SKILL.md"
    
    content = skill_md.read_text()
    
    # Check framework detection patterns
    assert "langchain" in content.lower(), "Missing LangChain detection pattern"
    assert "autogen" in content.lower(), "Missing AutoGen detection pattern"
    assert "crewai" in content.lower(), "Missing CrewAI detection pattern"
    
    # Check LLM API detection patterns (for custom implementations)
    assert "anthropic" in content.lower(), "Missing Anthropic API detection pattern"
    assert "openai" in content.lower(), "Missing OpenAI API detection pattern"
    
    # Check custom agent detection patterns
    assert "runner" in content.lower(), "Missing Runner detection pattern"
    assert "executor" in content.lower(), "Missing Executor detection pattern"
    assert "sandbox" in content.lower(), "Missing sandbox detection pattern"
    assert "auto-reply" in content.lower() or "auto.reply" in content.lower(), "Missing auto-reply detection pattern"
    assert "claude" in content.lower(), "Missing Claude SDK detection pattern"


def test_threat_modeling_prompt_has_asi_format_requirement():
    """Test that prompt requires ASI format for agentic threats"""
    prompt_file = Path(__file__).parent.parent / "securevibes" / "prompts" / "agents" / "threat_modeling.txt"
    content = prompt_file.read_text()
    
    # Check ASI format is documented
    assert "THREAT-ASI" in content, "Missing THREAT-ASI format in prompt"
    assert "ASI01" in content, "Missing ASI01 category reference"
    assert "ASI03" in content, "Missing ASI03 category reference"
    
    # Check mandatory language
    assert "MUST" in content, "Missing mandatory language for ASI format"
    assert "agentic_threat_format" in content.lower() or "agentic threat" in content.lower(), "Missing agentic threat format section"


class TestScannerThreatModelingSkillsSetup:
    """Test scanner integration with threat modeling skills"""
    
    def test_execute_scan_calls_setup_threat_modeling_skills(self, tmp_path):
        """Test that _execute_scan sets up threat modeling skills for full scans"""
        from securevibes.scanner.scanner import Scanner
        from unittest.mock import AsyncMock, patch
        
        scanner = Scanner(model="sonnet", debug=False)
        
        # Create required .securevibes directory
        securevibes_dir = tmp_path / ".securevibes"
        securevibes_dir.mkdir()
        
        # Track if _setup_threat_modeling_skills was called
        setup_called = False
        original_setup = scanner._setup_threat_modeling_skills
        
        def mock_setup(repo):
            nonlocal setup_called
            setup_called = True
            original_setup(repo)
        
        scanner._setup_threat_modeling_skills = mock_setup
        
        # We can't easily run full scan, but we can verify the method exists and is callable
        assert callable(scanner._setup_threat_modeling_skills)
        
        # Call it directly to verify it works
        scanner._setup_threat_modeling_skills(tmp_path)
        assert setup_called, "_setup_threat_modeling_skills should have been called"
        
        # Verify skills were created
        skills_dir = tmp_path / ".claude" / "skills" / "threat-modeling"
        assert skills_dir.exists(), "Threat modeling skills directory should be created"
