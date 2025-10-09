"""Prompt loading utilities for SecureVibes"""
from pathlib import Path
from typing import Dict

PROMPTS_DIR = Path(__file__).parent


def load_prompt(name: str, category: str = "agents") -> str:
    """
    Load a prompt from file.
    
    Args:
        name: Prompt name (e.g., "assessment", "threat_modeling")
        category: Category subdirectory ("agents" or "orchestration")
    
    Returns:
        Prompt text as string
    
    Raises:
        FileNotFoundError: If prompt file doesn't exist
    """
    prompt_file = PROMPTS_DIR / category / f"{name}.txt"
    
    if not prompt_file.exists():
        raise FileNotFoundError(
            f"Prompt file not found: {prompt_file}\n"
            f"Expected location: securevibes/prompts/{category}/{name}.txt"
        )
    
    return prompt_file.read_text(encoding="utf-8")


def load_all_agent_prompts() -> Dict[str, str]:
    """
    Load all agent prompts as a dictionary.
    
    Returns:
        Dictionary mapping agent names to their prompt text
        
    Raises:
        FileNotFoundError: If any prompt file is missing
    """
    try:
        return {
            "assessment": load_prompt("assessment"),
            "threat_modeling": load_prompt("threat_modeling"),
            "code_review": load_prompt("code_review"),
            "report_generator": load_prompt("report_generator"),
        }
    except FileNotFoundError as e:
        raise RuntimeError(
            f"Failed to load SecureVibes prompts: {e}\n"
            f"Ensure securevibes/prompts/ directory is included in package."
        ) from e
