"""Agent definitions"""

from claude_agent_sdk import AgentDefinition
from securevibes.prompts.loader import load_all_agent_prompts
from securevibes.config import config

# Load all prompts from centralized prompt files
AGENT_PROMPTS = load_all_agent_prompts()

SECUREVIBES_AGENTS = {
    "assessment": AgentDefinition(
        description="Analyzes codebase architecture and creates comprehensive security documentation",
        prompt=AGENT_PROMPTS["assessment"],
        tools=["Read", "Grep", "Glob", "LS", "Write"],
        model=config.get_agent_model("assessment")
    ),

    "threat-modeling": AgentDefinition(
        description="Performs architecture-driven STRIDE threat modeling focused on realistic, high-impact threats",
        prompt=AGENT_PROMPTS["threat_modeling"],
        tools=["Read", "Grep", "Glob", "Write"],
        model=config.get_agent_model("threat_modeling")
    ),

    "code-review": AgentDefinition(
        description="Applies security thinking methodology to find vulnerabilities with concrete evidence and exploitability analysis",
        prompt=AGENT_PROMPTS["code_review"],
        tools=["Read", "Grep", "Glob", "Write"],
        model=config.get_agent_model("code_review")
    ),

    "report-generator": AgentDefinition(
        description="JSON file processor that reformats VULNERABILITIES.json to scan_results.json",
        prompt=AGENT_PROMPTS["report_generator"],
        tools=["Read", "Write"],
        model=config.get_agent_model("report_generator")
    )
}
