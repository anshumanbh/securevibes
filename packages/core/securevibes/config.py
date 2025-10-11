"""Configuration management for SecureVibes"""

import os
from typing import Dict, Optional


class AgentConfig:
    """Configuration for agent model selection and behavior"""
    
    # Default models for each agent (can be overridden via environment variables)
    DEFAULTS = {
        "assessment": "sonnet",          # Fast architecture analysis
        "threat_modeling": "sonnet",     # Fast pattern reconnaissance
        "code_review": "sonnet",        # Deep security validation
        "report_generator": "sonnet"    # Accurate report compilation
    }
    
    # Default max turns for agent queries
    DEFAULT_MAX_TURNS = 50
    
    @classmethod
    def get_agent_model(cls, agent_name: str, cli_override: Optional[str] = None) -> str:
        """
        Get the model to use for a specific agent.
        
        Priority hierarchy (from highest to lowest):
        1. Per-agent environment variable (e.g., SECUREVIBES_ASSESSMENT_MODEL)
        2. CLI model override (from --model flag)
        3. Default from DEFAULTS dict (sonnet)
        
        Environment variables:
            SECUREVIBES_ASSESSMENT_MODEL
            SECUREVIBES_THREAT_MODELING_MODEL
            SECUREVIBES_CODE_REVIEW_MODEL
            SECUREVIBES_REPORT_GENERATOR_MODEL
        
        Args:
            agent_name: Name of the agent (assessment, threat_modeling, code_review, report_generator)
            cli_override: Optional model from CLI --model flag
            
        Returns:
            Model name (e.g., 'sonnet', 'haiku', 'opus')
        
        Examples:
            # With env var (highest priority)
            os.environ['SECUREVIBES_ASSESSMENT_MODEL'] = 'opus'
            get_agent_model('assessment', cli_override='haiku')  # Returns 'opus'
            
            # With CLI override (medium priority)
            get_agent_model('assessment', cli_override='haiku')  # Returns 'haiku'
            
            # Default (lowest priority)
            get_agent_model('assessment')  # Returns 'sonnet'
        """
        # Priority 1: Check per-agent environment variable
        env_var = f"SECUREVIBES_{agent_name.upper()}_MODEL"
        env_value = os.getenv(env_var)
        if env_value:
            return env_value
        
        # Priority 2: Use CLI override if provided
        if cli_override:
            return cli_override
        
        # Priority 3: Fall back to default
        return cls.DEFAULTS.get(agent_name, "sonnet")
    
    @classmethod
    def get_all_agent_models(cls) -> Dict[str, str]:
        """
        Get model configuration for all agents.
        
        Returns:
            Dictionary mapping agent names to their model names
        """
        return {
            agent: cls.get_agent_model(agent)
            for agent in cls.DEFAULTS.keys()
        }
    
    @classmethod
    def get_max_turns(cls) -> int:
        """
        Get the maximum number of turns for agent queries.
        
        Can be overridden via SECUREVIBES_MAX_TURNS environment variable.
        
        Returns:
            Maximum number of turns (default: 50)
        """
        try:
            return int(os.getenv("SECUREVIBES_MAX_TURNS", cls.DEFAULT_MAX_TURNS))
        except ValueError:
            # If invalid value provided, return default
            return cls.DEFAULT_MAX_TURNS


# Global configuration instance
config = AgentConfig()

