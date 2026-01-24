# SecureVibes Security Review Skill

## Description
Skill-first distribution of SecureVibes that preserves the CLI subagent workflow and skill bundles.

## When to Use
- Security review of a codebase or PR
- Threat modeling request
- Targeted vulnerability assessment

## Workflow

### Full Security Review (default)
1. **Assessment**: use `prompts/agents/assessment.txt`
2. **Threat Modeling**: use `prompts/agents/threat_modeling.txt`,
   `skills/threat-modeling/agentic-security/`
3. **Code Review**: use `prompts/agents/code_review.txt`
4. **Report Generator**: use `prompts/agents/report_generator.txt` and
   output rules embedded in the prompt
5. **DAST (optional)**: use `prompts/agents/dast.txt` and `skills/dast/` when tool access exists

### Quick Scan
Run the Code Review subagent only.

## Outputs
- `SECURITY.md` (assessment)
- `THREAT_MODEL.json` (threat modeling)
- `VULNERABILITIES.json` (report generator)
- DAST evidence artifacts when applicable

## Source of Truth
The prompt and skill files in this package are direct copies of the SecureVibes CLI assets to
preserve exact behavior and naming.
