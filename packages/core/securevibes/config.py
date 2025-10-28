"""Configuration management for SecureVibes"""

import os
from pathlib import Path
from typing import Dict, Optional, Set


class LanguageConfig:
    """Configuration for supported programming languages"""
    
    # Supported languages and their file extensions
    SUPPORTED_LANGUAGES = {
        'python': ['.py'],
        'javascript': ['.js', '.jsx'],
        'typescript': ['.ts', '.tsx'],
        'go': ['.go'],
        'ruby': ['.rb'],
        'java': ['.java'],
        'php': ['.php'],
        'csharp': ['.cs'],
        'rust': ['.rs'],
        'kotlin': ['.kt'],
        'swift': ['.swift']
    }
    
    @classmethod
    def get_all_extensions(cls) -> Set[str]:
        """Get all supported file extensions"""
        extensions = set()
        for exts in cls.SUPPORTED_LANGUAGES.values():
            extensions.update(exts)
        return extensions
    
    @classmethod
    def detect_languages(cls, repo: Path, sample_size: int = 100) -> Set[str]:
        """
        Detect languages present in repository by sampling files.
        
        Args:
            repo: Repository path
            sample_size: Number of files to sample
            
        Returns:
            Set of detected language names
        """
        languages = set()
        
        # Sample files from repo (limit to avoid performance impact)
        try:
            sample_files = list(repo.glob('**/*'))[:sample_size]
            
            for file in sample_files:
                if not file.is_file():
                    continue
                    
                ext = file.suffix.lower()
                for lang, extensions in cls.SUPPORTED_LANGUAGES.items():
                    if ext in extensions:
                        languages.add(lang)
                        break
        except (OSError, PermissionError):
            pass
        
        return languages


class ScanConfig:
    """Configuration for scan behavior and exclusions"""
    
    # Common infrastructure directories (cross-language)
    EXCLUDED_DIRS_COMMON = {
        '.claude',      # SecureVibes testing infrastructure
        '.git',         # Version control
        'dist',         # Build output
        'build',        # Build output
        '.eggs'         # Python egg files
    }
    
    # Language-specific exclusions
    EXCLUDED_DIRS_PYTHON = {
        'env', 'venv', '.venv',      # Virtual environments
        '__pycache__',                # Python cache
        '.pytest_cache',              # Pytest cache
        '.tox',                       # Tox environments
        '.mypy_cache'                 # MyPy cache
    }
    
    EXCLUDED_DIRS_JS = {
        'node_modules',               # Node.js dependencies
        '.next',                      # Next.js build
        '.nuxt',                      # Nuxt.js build
        'coverage',                   # Test coverage
        '.yarn',                      # Yarn cache
        '.pnp'                        # Yarn PnP
    }
    
    EXCLUDED_DIRS_GO = {
        'vendor',                     # Go vendored dependencies
        'bin'                         # Go binaries
    }
    
    EXCLUDED_DIRS_RUBY = {
        'vendor/bundle',              # Bundled gems
        '.bundle'                     # Bundle config
    }
    
    EXCLUDED_DIRS_JAVA = {
        'target',                     # Maven build
        '.gradle',                    # Gradle cache
        '.mvn'                        # Maven wrapper
    }
    
    EXCLUDED_DIRS_CSHARP = {
        'bin',                        # .NET binaries
        'obj',                        # .NET object files
        'packages'                    # NuGet packages
    }
    
    EXCLUDED_DIRS_RUST = {
        'target',                     # Cargo build
        'Cargo.lock'                  # Lock file (not a dir but excluded)
    }
    
    # DAST security constraints - database CLI tools blocked in DAST phase
    BLOCKED_DB_TOOLS = [
        "sqlite3", "psql", "mysql", "mongosh", "mongo",
        "redis-cli", "mariadb", "cockroach", "influx", "cqlsh"
    ]
    
    @classmethod
    def get_excluded_dirs(cls, languages: Optional[Set[str]] = None) -> Set[str]:
        """
        Get exclusion directories based on detected languages.
        
        Args:
            languages: Set of detected language names (None = include all)
            
        Returns:
            Set of directory names to exclude from scanning
        """
        dirs = cls.EXCLUDED_DIRS_COMMON.copy()
        
        if languages is None:
            # If languages unknown, include all exclusions to be safe
            dirs.update(cls.EXCLUDED_DIRS_PYTHON)
            dirs.update(cls.EXCLUDED_DIRS_JS)
            dirs.update(cls.EXCLUDED_DIRS_GO)
            dirs.update(cls.EXCLUDED_DIRS_RUBY)
            dirs.update(cls.EXCLUDED_DIRS_JAVA)
            dirs.update(cls.EXCLUDED_DIRS_CSHARP)
            dirs.update(cls.EXCLUDED_DIRS_RUST)
        else:
            # Add language-specific exclusions
            if 'python' in languages:
                dirs.update(cls.EXCLUDED_DIRS_PYTHON)
            if 'javascript' in languages or 'typescript' in languages:
                dirs.update(cls.EXCLUDED_DIRS_JS)
            if 'go' in languages:
                dirs.update(cls.EXCLUDED_DIRS_GO)
            if 'ruby' in languages:
                dirs.update(cls.EXCLUDED_DIRS_RUBY)
            if 'java' in languages or 'kotlin' in languages:
                dirs.update(cls.EXCLUDED_DIRS_JAVA)
            if 'csharp' in languages:
                dirs.update(cls.EXCLUDED_DIRS_CSHARP)
            if 'rust' in languages:
                dirs.update(cls.EXCLUDED_DIRS_RUST)
        
        return dirs
    
    @classmethod
    def get_excluded_dirs_for_phase(cls, phase: str, languages: Optional[Set[str]] = None) -> Set[str]:
        """
        Get phase-specific exclusion directories.
        
        DAST phase needs access to .claude/skills/ for loading skills,
        so .claude is removed from exclusions during DAST.
        
        Args:
            phase: Current scan phase (assessment, threat-modeling, code-review, dast)
            languages: Set of detected language names
            
        Returns:
            Set of directory names to exclude for this phase
        """
        dirs = cls.get_excluded_dirs(languages)
        
        # DAST phase needs .claude/skills/ access for skill loading
        if phase == "dast":
            dirs.discard('.claude')
        
        return dirs


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

