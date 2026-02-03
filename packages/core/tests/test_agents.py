"""Tests for agent definitions"""

from securevibes.agents.definitions import create_agent_definitions, SECUREVIBES_AGENTS


class TestAgentDefinitions:
    """Test agent definition creation"""

    def test_create_agents_without_override(self, monkeypatch):
        """Creating agents without override uses defaults"""
        # Clear env vars
        for agent in ["assessment", "threat_modeling", "code_review", "report_generator"]:
            monkeypatch.delenv(f"SECUREVIBES_{agent.upper()}_MODEL", raising=False)

        agents = create_agent_definitions()

        assert agents["assessment"].model == "sonnet"
        assert agents["threat-modeling"].model == "sonnet"
        assert agents["code-review"].model == "sonnet"
        assert agents["report-generator"].model == "sonnet"

    def test_create_agents_with_cli_override(self, monkeypatch):
        """Creating agents with CLI override sets all models"""
        # Clear env vars
        for agent in ["assessment", "threat_modeling", "code_review", "report_generator"]:
            monkeypatch.delenv(f"SECUREVIBES_{agent.upper()}_MODEL", raising=False)

        agents = create_agent_definitions(cli_model="haiku")

        assert agents["assessment"].model == "haiku"
        assert agents["threat-modeling"].model == "haiku"
        assert agents["code-review"].model == "haiku"
        assert agents["report-generator"].model == "haiku"

    def test_create_agents_env_var_overrides_cli(self, monkeypatch):
        """Environment variables override CLI model"""
        # Clear most env vars, set one override
        monkeypatch.delenv("SECUREVIBES_ASSESSMENT_MODEL", raising=False)
        monkeypatch.setenv("SECUREVIBES_CODE_REVIEW_MODEL", "opus")
        monkeypatch.delenv("SECUREVIBES_THREAT_MODELING_MODEL", raising=False)
        monkeypatch.delenv("SECUREVIBES_REPORT_GENERATOR_MODEL", raising=False)

        agents = create_agent_definitions(cli_model="haiku")

        # Most use CLI model
        assert agents["assessment"].model == "haiku"
        assert agents["threat-modeling"].model == "haiku"
        assert agents["report-generator"].model == "haiku"

        # One uses env var override
        assert agents["code-review"].model == "opus"

    def test_default_agents_dict_exists(self):
        """Default SECUREVIBES_AGENTS dict should exist"""
        assert SECUREVIBES_AGENTS is not None
        assert isinstance(SECUREVIBES_AGENTS, dict)
        expected_agents = {
            "assessment",
            "threat-modeling",
            "code-review",
            "pr-code-review",
            "report-generator",
            "dast",
        }
        assert set(SECUREVIBES_AGENTS.keys()) == expected_agents

    def test_agent_definition_structure(self, monkeypatch):
        """Agent definitions should have correct structure"""
        # Clear env vars
        for agent in ["assessment", "threat_modeling", "code_review", "report_generator"]:
            monkeypatch.delenv(f"SECUREVIBES_{agent.upper()}_MODEL", raising=False)

        agents = create_agent_definitions(cli_model="haiku")

        # Check assessment agent
        agent = agents["assessment"]
        assert agent.description is not None
        assert agent.prompt is not None
        assert agent.tools is not None
        assert len(agent.tools) > 0
        assert agent.model == "haiku"

    def test_all_agents_have_required_attributes(self, monkeypatch):
        """All agents should have description, prompt, tools, model"""
        # Clear env vars
        for agent in ["assessment", "threat_modeling", "code_review", "report_generator"]:
            monkeypatch.delenv(f"SECUREVIBES_{agent.upper()}_MODEL", raising=False)

        agents = create_agent_definitions(cli_model="sonnet")

        for agent_name, agent_def in agents.items():
            assert agent_def.description, f"{agent_name} missing description"
            assert agent_def.prompt, f"{agent_name} missing prompt"
            assert agent_def.tools, f"{agent_name} missing tools"
            assert isinstance(agent_def.tools, list), f"{agent_name} tools not a list"
            assert agent_def.model, f"{agent_name} missing model"

    def test_agents_have_expected_tools(self, monkeypatch):
        """Agents should have appropriate tool access"""
        # Clear env vars
        for agent in ["assessment", "threat_modeling", "code_review", "report_generator"]:
            monkeypatch.delenv(f"SECUREVIBES_{agent.upper()}_MODEL", raising=False)

        agents = create_agent_definitions()

        # Assessment needs LS for directory listing
        assert "LS" in agents["assessment"].tools

        # All need Read and Write
        for agent_name in ["assessment", "threat-modeling", "code-review", "report-generator"]:
            assert "Read" in agents[agent_name].tools
            assert "Write" in agents[agent_name].tools

    def test_create_agents_with_multiple_env_overrides(self, monkeypatch):
        """Multiple environment variables should all work"""
        monkeypatch.setenv("SECUREVIBES_ASSESSMENT_MODEL", "haiku")
        monkeypatch.setenv("SECUREVIBES_THREAT_MODELING_MODEL", "haiku")
        monkeypatch.setenv("SECUREVIBES_CODE_REVIEW_MODEL", "opus")
        monkeypatch.setenv("SECUREVIBES_REPORT_GENERATOR_MODEL", "sonnet")

        agents = create_agent_definitions(cli_model="sonnet")

        # Env vars should override CLI model
        assert agents["assessment"].model == "haiku"
        assert agents["threat-modeling"].model == "haiku"
        assert agents["code-review"].model == "opus"
        assert agents["report-generator"].model == "sonnet"

    def test_backward_compatibility_default_dict(self, monkeypatch):
        """SECUREVIBES_AGENTS should work like before (no CLI override)"""
        # Clear env vars
        for agent in ["assessment", "threat_modeling", "code_review", "report_generator"]:
            monkeypatch.delenv(f"SECUREVIBES_{agent.upper()}_MODEL", raising=False)

        # Default dict should use defaults (sonnet)
        assert SECUREVIBES_AGENTS["assessment"].model == "sonnet"
        assert SECUREVIBES_AGENTS["threat-modeling"].model == "sonnet"
        assert SECUREVIBES_AGENTS["code-review"].model == "sonnet"
        assert SECUREVIBES_AGENTS["report-generator"].model == "sonnet"


class TestAgentCreationEdgeCases:
    """Test edge cases in agent creation"""

    def test_create_with_empty_string_cli_model(self, monkeypatch):
        """Empty string CLI model should fall back to defaults"""
        # Clear env vars
        for agent in ["assessment", "threat_modeling", "code_review", "report_generator"]:
            monkeypatch.delenv(f"SECUREVIBES_{agent.upper()}_MODEL", raising=False)

        agents = create_agent_definitions(cli_model="")

        # Should use defaults
        assert agents["assessment"].model == "sonnet"
        assert agents["threat-modeling"].model == "sonnet"

    def test_create_with_none_cli_model(self, monkeypatch):
        """None CLI model should fall back to defaults"""
        # Clear env vars
        for agent in ["assessment", "threat_modeling", "code_review", "report_generator"]:
            monkeypatch.delenv(f"SECUREVIBES_{agent.upper()}_MODEL", raising=False)

        agents = create_agent_definitions(cli_model=None)

        # Should use defaults
        assert agents["assessment"].model == "sonnet"
        assert agents["threat-modeling"].model == "sonnet"

    def test_agent_names_consistency(self):
        """Agent names should be consistent across calls"""
        agents1 = create_agent_definitions()
        agents2 = create_agent_definitions()

        assert set(agents1.keys()) == set(agents2.keys())
        assert "assessment" in agents1
        assert "threat-modeling" in agents1
        assert "code-review" in agents1
        assert "report-generator" in agents1
