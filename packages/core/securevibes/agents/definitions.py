"""Agent definitions"""

from typing import Dict, Optional
from claude_agent_sdk import AgentDefinition
from securevibes.prompts.loader import load_all_agent_prompts
from securevibes.config import config

# Load all prompts from centralized prompt files
AGENT_PROMPTS = load_all_agent_prompts()


def create_agent_definitions(
    cli_model: Optional[str] = None,
    dast_target_url: Optional[str] = None,
    threat_modeling_context: Optional[str] = None,
) -> Dict[str, AgentDefinition]:
    """
    Create agent definitions with optional CLI model override and DAST target URL.

    This function allows the CLI --model flag to cascade down to all agents
    while still respecting per-agent environment variable overrides.

    Priority hierarchy:
    1. Per-agent env vars (SECUREVIBES_<AGENT>_MODEL) - highest priority
    2. cli_model parameter (from CLI --model flag) - medium priority
    3. Default "sonnet" from config.DEFAULTS - lowest priority

    Args:
        cli_model: Optional model name from CLI --model flag.
                  If provided, becomes the default for all agents unless
                  overridden by per-agent environment variables.
        dast_target_url: Optional target URL for DAST testing. If provided,
                        the {target_url} placeholders in the DAST prompt will
                        be substituted with this value.
        threat_modeling_context: Optional context injected into the threat-modeling
                                agent prompt (after the role line).

    Returns:
        Dictionary mapping agent names to AgentDefinition objects

    Examples:
        # Use CLI model as default for all agents
        agents = create_agent_definitions(cli_model="haiku")

        # Use hardcoded defaults (sonnet)
        agents = create_agent_definitions()

        # Per-agent env var overrides CLI model
        os.environ['SECUREVIBES_CODE_REVIEW_MODEL'] = 'opus'
        agents = create_agent_definitions(cli_model="haiku")
        # Result: assessment/threat-modeling/report-generator use haiku
        #         code-review uses opus

        # With DAST target URL
        agents = create_agent_definitions(dast_target_url="http://localhost:3000")
        # Result: DAST prompt will have {target_url} replaced with the URL
    """
    # Substitute target URL in DAST prompt if provided
    # Using str.replace() instead of .format() because the prompt contains
    # JSON examples with curly braces that would be misinterpreted by .format()
    dast_prompt = AGENT_PROMPTS["dast"]
    if dast_target_url:
        dast_prompt = dast_prompt.replace("{target_url}", dast_target_url)

    threat_modeling_prompt = AGENT_PROMPTS["threat_modeling"]
    if threat_modeling_context:
        # Inject immediately after the role line.
        parts = threat_modeling_prompt.split("\n", 1)
        if len(parts) == 2:
            threat_modeling_prompt = (
                f"{parts[0]}\n\n{threat_modeling_context.strip()}\n\n{parts[1]}"
            )
        else:
            threat_modeling_prompt = (
                f"{threat_modeling_prompt}\n\n{threat_modeling_context.strip()}"
            )

    return {
        "assessment": AgentDefinition(
            description="Analyzes codebase architecture and creates comprehensive security documentation",
            prompt=AGENT_PROMPTS["assessment"],
            tools=["Read", "Grep", "Glob", "LS", "Write"],
            model=config.get_agent_model("assessment", cli_override=cli_model),
        ),
        "threat-modeling": AgentDefinition(
            description="Performs architecture-driven STRIDE threat modeling focused on realistic, high-impact threats, augmented with technology-specific skills for agentic AI, APIs, and other specialized architectures",
            prompt=threat_modeling_prompt,
            tools=["Read", "Grep", "Glob", "Write", "Skill"],
            model=config.get_agent_model("threat_modeling", cli_override=cli_model),
        ),
        "code-review": AgentDefinition(
            description="Applies security thinking methodology to find vulnerabilities with concrete evidence and exploitability analysis",
            prompt=AGENT_PROMPTS["code_review"],
            tools=["Read", "Grep", "Glob", "Write"],
            model=config.get_agent_model("code_review", cli_override=cli_model),
        ),
        "pr-code-review": AgentDefinition(
            description=(
                "Analyzes PR diffs for introduced/enabled/regressed exploit chains "
                "with architecture and threat context"
            ),
            prompt=AGENT_PROMPTS["pr_code_review"],
            tools=["Read", "Grep", "Glob", "Write"],
            model=config.get_agent_model("pr_code_review", cli_override=cli_model),
        ),
        "report-generator": AgentDefinition(
            description="JSON file processor that reformats VULNERABILITIES.json to scan_results.json",
            prompt=AGENT_PROMPTS["report_generator"],
            tools=["Read", "Write"],
            model=config.get_agent_model("report_generator", cli_override=cli_model),
        ),
        "dast": AgentDefinition(
            description="Validates vulnerabilities via HTTP testing ONLY when a matching Agent Skill is available; otherwise reports UNVALIDATED",
            prompt=dast_prompt,
            tools=["Read", "Write", "Skill", "Bash"],
            model=config.get_agent_model("dast", cli_override=cli_model),
        ),
    }


# Backward compatibility: export default instance (no CLI override)
# This ensures existing code that imports SECUREVIBES_AGENTS still works
SECUREVIBES_AGENTS = create_agent_definitions()
