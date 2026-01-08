"""Prompt loading utilities for SecureVibes"""
from pathlib import Path
from typing import Dict, Optional

PROMPTS_DIR = Path(__file__).parent

# Agents that should have shared security rules injected
SECURITY_AGENTS = {"threat_modeling", "code_review"}


def load_shared_rules() -> Optional[str]:
    """
    Load shared security rules from _shared/security_rules.txt.
    
    Returns:
        Shared rules text, or None if file doesn't exist
    """
    shared_file = PROMPTS_DIR / "agents" / "_shared" / "security_rules.txt"
    if shared_file.exists():
        return shared_file.read_text(encoding="utf-8")
    return None


def load_prompt(name: str, category: str = "agents", inject_shared: bool = True) -> str:
    """
    Load a prompt from file, optionally injecting shared rules.
    
    Args:
        name: Prompt name (e.g., "assessment", "threat_modeling")
        category: Category subdirectory ("agents" or "orchestration")
        inject_shared: Whether to inject shared security rules (default True)
    
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
    
    prompt_content = prompt_file.read_text(encoding="utf-8")
    
    # Inject shared rules for security-focused agents
    if inject_shared and category == "agents" and name in SECURITY_AGENTS:
        shared_rules = load_shared_rules()
        if shared_rules:
            # Find the role line (first line) and inject shared rules after it
            lines = prompt_content.split('\n', 1)
            if len(lines) == 2:
                role_line, rest = lines
                prompt_content = f"{role_line}\n\n{shared_rules}\n{rest}"
            else:
                # Just prepend if can't split
                prompt_content = f"{shared_rules}\n\n{prompt_content}"
    
    return prompt_content


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
            "dast": load_prompt("dast"),
        }
    except FileNotFoundError as e:
        raise RuntimeError(
            f"Failed to load SecureVibes prompts: {e}\n"
            f"Ensure securevibes/prompts/ directory is included in package."
        ) from e
