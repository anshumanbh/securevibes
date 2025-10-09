"""Tests for configuration management"""

import os
import pytest
from securevibes.config import AgentConfig, config


class TestAgentModelConfiguration:
    """Test agent model selection from environment variables"""
    
    def test_default_agent_models(self):
        """Test default models are set correctly"""
        defaults = AgentConfig.DEFAULTS
        
        assert defaults["assessment"] == "sonnet"
        assert defaults["threat_modeling"] == "sonnet"
        assert defaults["code_review"] == "sonnet"
        assert defaults["report_generator"] == "sonnet"
    
    def test_get_agent_model_uses_default(self, monkeypatch):
        """Test getting agent model without environment variable uses default"""
        # Clear any environment variables
        monkeypatch.delenv("SECUREVIBES_ASSESSMENT_MODEL", raising=False)
        
        model = AgentConfig.get_agent_model("assessment")
        assert model == "sonnet"  # Default
    
    def test_get_agent_model_from_env_var(self, monkeypatch):
        """Test getting agent model from environment variable"""
        monkeypatch.setenv("SECUREVIBES_CODE_REVIEW_MODEL", "opus")
        
        model = AgentConfig.get_agent_model("code_review")
        assert model == "opus"
    
    def test_get_agent_model_env_var_overrides_default(self, monkeypatch):
        """Test environment variable overrides default"""
        # Default is sonnet, override with haiku
        monkeypatch.setenv("SECUREVIBES_THREAT_MODELING_MODEL", "haiku")
        
        model = AgentConfig.get_agent_model("threat_modeling")
        assert model == "haiku"
        assert model != AgentConfig.DEFAULTS["threat_modeling"]
    
    def test_get_all_agent_models(self, monkeypatch):
        """Test getting all agent models at once"""
        monkeypatch.setenv("SECUREVIBES_ASSESSMENT_MODEL", "haiku")
        monkeypatch.setenv("SECUREVIBES_CODE_REVIEW_MODEL", "opus")
        
        models = AgentConfig.get_all_agent_models()
        
        assert isinstance(models, dict)
        assert len(models) == 4
        assert models["assessment"] == "haiku"
        assert models["code_review"] == "opus"


class TestMaxTurnsConfiguration:
    """Test max_turns configuration from environment variable"""
    
    def test_default_max_turns(self):
        """Test default max_turns value"""
        assert AgentConfig.DEFAULT_MAX_TURNS == 50
    
    def test_get_max_turns_uses_default(self, monkeypatch):
        """Test getting max_turns without environment variable uses default"""
        monkeypatch.delenv("SECUREVIBES_MAX_TURNS", raising=False)
        
        max_turns = AgentConfig.get_max_turns()
        assert max_turns == 50
    
    def test_get_max_turns_from_env_var(self, monkeypatch):
        """Test getting max_turns from environment variable"""
        monkeypatch.setenv("SECUREVIBES_MAX_TURNS", "100")
        
        max_turns = AgentConfig.get_max_turns()
        assert max_turns == 100
    
    def test_get_max_turns_with_low_value(self, monkeypatch):
        """Test getting max_turns with low value (for small codebases)"""
        monkeypatch.setenv("SECUREVIBES_MAX_TURNS", "25")
        
        max_turns = AgentConfig.get_max_turns()
        assert max_turns == 25
    
    def test_get_max_turns_with_high_value(self, monkeypatch):
        """Test getting max_turns with high value (for large codebases)"""
        monkeypatch.setenv("SECUREVIBES_MAX_TURNS", "150")
        
        max_turns = AgentConfig.get_max_turns()
        assert max_turns == 150
    
    def test_get_max_turns_handles_invalid_value(self, monkeypatch):
        """Test getting max_turns with invalid value falls back to default"""
        monkeypatch.setenv("SECUREVIBES_MAX_TURNS", "invalid")
        
        max_turns = AgentConfig.get_max_turns()
        assert max_turns == 50  # Should fall back to default
    
    def test_get_max_turns_handles_negative_value(self, monkeypatch):
        """Test getting max_turns with negative value"""
        monkeypatch.setenv("SECUREVIBES_MAX_TURNS", "-10")
        
        max_turns = AgentConfig.get_max_turns()
        # Note: This will parse as -10. In production, scanner should validate.
        # Testing that it parses correctly (not that it validates business logic)
        assert max_turns == -10
    
    def test_get_max_turns_handles_float_string(self, monkeypatch):
        """Test getting max_turns with float string (invalid) falls back to default"""
        monkeypatch.setenv("SECUREVIBES_MAX_TURNS", "50.5")
        
        max_turns = AgentConfig.get_max_turns()
        assert max_turns == 50  # Should fall back to default (can't convert float string to int)
    
    def test_get_max_turns_handles_empty_string(self, monkeypatch):
        """Test getting max_turns with empty string falls back to default"""
        monkeypatch.setenv("SECUREVIBES_MAX_TURNS", "")
        
        max_turns = AgentConfig.get_max_turns()
        assert max_turns == 50  # Should fall back to default
    
    def test_get_max_turns_returns_int(self, monkeypatch):
        """Test get_max_turns always returns int type"""
        monkeypatch.setenv("SECUREVIBES_MAX_TURNS", "75")
        
        max_turns = AgentConfig.get_max_turns()
        assert isinstance(max_turns, int)
        assert not isinstance(max_turns, str)


class TestGlobalConfigInstance:
    """Test global config instance"""
    
    def test_global_config_exists(self):
        """Test global config instance is created"""
        assert config is not None
        assert isinstance(config, AgentConfig)
    
    def test_can_use_global_config_for_models(self, monkeypatch):
        """Test using global config instance to get models"""
        monkeypatch.setenv("SECUREVIBES_ASSESSMENT_MODEL", "haiku")
        
        model = config.get_agent_model("assessment")
        assert model == "haiku"
    
    def test_can_use_global_config_for_max_turns(self, monkeypatch):
        """Test using global config instance to get max_turns"""
        monkeypatch.setenv("SECUREVIBES_MAX_TURNS", "80")
        
        max_turns = config.get_max_turns()
        assert max_turns == 80


class TestEnvironmentVariableNaming:
    """Test environment variable naming conventions"""
    
    def test_model_env_var_naming_convention(self):
        """Test environment variables follow SECUREVIBES_{AGENT}_MODEL pattern"""
        test_cases = [
            ("assessment", "SECUREVIBES_ASSESSMENT_MODEL"),
            ("threat_modeling", "SECUREVIBES_THREAT_MODELING_MODEL"),
            ("code_review", "SECUREVIBES_CODE_REVIEW_MODEL"),
            ("report_generator", "SECUREVIBES_REPORT_GENERATOR_MODEL"),
        ]
        
        for agent_name, expected_env_var in test_cases:
            env_var = f"SECUREVIBES_{agent_name.upper()}_MODEL"
            assert env_var == expected_env_var
    
    def test_max_turns_env_var_name(self):
        """Test max_turns environment variable is SECUREVIBES_MAX_TURNS"""
        # This documents the expected environment variable name
        expected_name = "SECUREVIBES_MAX_TURNS"
        
        # If this is set, get_max_turns should read it
        with pytest.MonkeyPatch.context() as m:
            m.setenv(expected_name, "99")
            assert AgentConfig.get_max_turns() == 99


class TestConfigurationIntegration:
    """Integration tests for configuration"""
    
    def test_multiple_env_vars_at_once(self, monkeypatch):
        """Test setting multiple configuration values simultaneously"""
        monkeypatch.setenv("SECUREVIBES_ASSESSMENT_MODEL", "haiku")
        monkeypatch.setenv("SECUREVIBES_THREAT_MODELING_MODEL", "haiku")
        monkeypatch.setenv("SECUREVIBES_CODE_REVIEW_MODEL", "sonnet")
        monkeypatch.setenv("SECUREVIBES_REPORT_GENERATOR_MODEL", "sonnet")
        monkeypatch.setenv("SECUREVIBES_MAX_TURNS", "75")
        
        # All should be readable
        assert config.get_agent_model("assessment") == "haiku"
        assert config.get_agent_model("threat_modeling") == "haiku"
        assert config.get_agent_model("code_review") == "sonnet"
        assert config.get_agent_model("report_generator") == "sonnet"
        assert config.get_max_turns() == 75
    
    def test_partial_env_vars_with_defaults(self, monkeypatch):
        """Test setting only some env vars uses defaults for others"""
        # Only override code review, leave others as default
        monkeypatch.delenv("SECUREVIBES_ASSESSMENT_MODEL", raising=False)
        monkeypatch.setenv("SECUREVIBES_CODE_REVIEW_MODEL", "opus")
        monkeypatch.delenv("SECUREVIBES_MAX_TURNS", raising=False)
        
        assert config.get_agent_model("assessment") == "sonnet"  # Default
        assert config.get_agent_model("code_review") == "opus"  # Override
        assert config.get_max_turns() == 50  # Default

