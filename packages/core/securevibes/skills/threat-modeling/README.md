# Threat Modeling Skills for SecureVibes

This directory contains Agent Skills for technology-specific threat modeling in SecureVibes.

## Overview

Skills provide specialized threat modeling methodologies that augment the generic STRIDE-based threat modeling with technology-specific threats. Each skill is a self-contained directory with instructions, examples, and reference materials.

## Directory Structure

```
.claude/skills/threat-modeling/
├── README.md                    # This file
└── agentic-security/            # OWASP Top 10 for Agentic Applications 2026
    ├── SKILL.md                 # Core methodology
    ├── examples.md              # Attack scenarios per ASI category
    └── reference/
        └── README.md            # Framework detection patterns
```

## Current Skills

### agentic-security
**Purpose**: Identify agentic AI security threats based on OWASP Top 10 for Agentic Applications 2026. Augments generic STRIDE analysis with agent-specific threat categories (ASI01-ASI10).

**Trigger Patterns**: 
- Agent orchestration frameworks (LangChain, AutoGen, CrewAI, Claude Agent SDK)
- LLM API usage (Anthropic, OpenAI, custom implementations)
- Tool/function definitions for LLMs
- Multi-agent communication patterns
- Memory/context management code
- RAG implementations
- Sandbox/container execution for AI

**Output**: Additional threats with IDs like `THREAT-ASI01-001` mapped to OWASP ASI01-ASI10 categories, including risk assessment fields:
- `existing_controls`: Controls found in codebase
- `control_effectiveness`: none/partial/substantial
- `attack_complexity`, `likelihood`, `impact`, `risk_score`
- `residual_risk`: Risk remaining after existing controls

**Logging**: Skill activation is logged as `🎯 Loading skill: agentic-security-threat-modeling`

## How Skills Augment Threat Modeling

The threat modeling agent follows a two-phase approach:

1. **Generic STRIDE Analysis** (always runs):
   - Analyzes architecture from SECURITY.md
   - Applies STRIDE methodology to all components
   - Generates threats based on data flows and trust boundaries

2. **Skill-Augmented Analysis** (when patterns detected):
   - Detects technology patterns in codebase
   - Loads applicable skills based on detection
   - Generates additional tech-specific threats
   - Merges into final THREAT_MODEL.json

## Adding New Skills

To add a new threat modeling skill:

1. **Create skill directory**:
   ```bash
   mkdir -p skills/threat-modeling/[technology-name]
   ```

2. **Create SKILL.md** with YAML frontmatter:
   ```yaml
   ---
   name: [technology-name]-threat-modeling
   description: Brief description of what this skill identifies and when to use it
   allowed-tools: Read, Grep, Glob, Write
   ---
   
   # [Technology] Threat Modeling Skill
   
   ## Detection Triggers
   ...
   
   ## Threat Categories
   ...
   
   ## Threat Templates
   ...
   ```

3. **Add examples** in `examples.md`:
   - Show real-world attack scenarios
   - Include code patterns that indicate vulnerability
   - Demonstrate threat output format

4. **Add reference materials** (optional) in `reference/`:
   - Framework detection patterns
   - Mapping to security standards (OWASP, CWE, etc.)

## Skill Best Practices

1. **Conciseness**: Keep SKILL.md under 500 lines
2. **Progressive Disclosure**: Link to examples.md rather than embedding
3. **Clear Detection**: Define specific patterns that trigger the skill
4. **Actionable Threats**: Include attack scenarios and mitigations
5. **Standard Mapping**: Map threats to CWE IDs where applicable

## Future Skills (Planned)

- `web-application/` - OWASP Web Top 10 threats
- `api-security/` - OWASP API Top 10 threats
- `llm-security/` - OWASP LLM Top 10 threats
- `mobile-security/` - OWASP Mobile Top 10 threats
- `cloud-native/` - Kubernetes, serverless-specific threats

## Resources

- [OWASP Top 10 for Agentic Applications 2026](../../docs/references/OWASP-Top-10-Agentic-Applications-2026.md)
- [Agent Skills Guide](../../docs/references/AGENT_SKILLS_GUIDE.md)
- [SecureVibes Architecture](../../docs/ARCHITECTURE.md)
