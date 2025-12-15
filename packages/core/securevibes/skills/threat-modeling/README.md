# Threat Modeling Skills for SecureVibes

This directory contains Agent Skills for specialized threat modeling in SecureVibes.

## Overview

Skills provide specialized threat modeling methodologies that the threat modeling agent uses to identify threats specific to particular application types or domains. Each skill is a self-contained directory with instructions, examples, and reference materials.

## Directory Structure

```
skills/threat-modeling/
├── README.md                    # This file
└── agentic-apps/                # Agentic application threat modeling
    ├── SKILL.md                 # Core methodology
    ├── examples.md              # Real-world threat scenarios
    └── reference/               # Deep-dive reference materials
        ├── README.md            # Reference guide
        └── threat_patterns.md   # Detailed attack patterns
```

## Current Skills

### agentic-apps

**Purpose**: Threat model applications that incorporate AI agents, LLMs with tool-calling, autonomous decision-making systems, and multi-agent architectures.

**Trigger**: Use when analyzing applications with LLMs, AI agents, tool-calling (MCP, function calling), autonomous workflows, multi-agent systems, or RAG pipelines.

**Covers**:
- Prompt injection (direct & indirect)
- Tool/action abuse
- Excessive agent autonomy
- Data exfiltration via agents
- Multi-agent attack vectors
- RAG/retrieval attacks
- Model supply chain threats

**Output**: Threat model JSON with agentic-specific fields (agentic_threat_type, trust_boundary_crossed)

## Adding New Skills

To add a new threat modeling skill:

1. **Create skill directory**:
   ```bash
   mkdir -p skills/threat-modeling/[domain]-apps
   ```

2. **Create SKILL.md** with YAML frontmatter:
   ```yaml
   ---
   name: [domain]-threat-modeling
   description: Brief description of what this skill covers and when to use it
   allowed-tools: Read, Grep, Glob, Write
   ---
   
   # [Domain] Threat Modeling Skill
   
   ## Purpose
   ...
   
   ## Threat Categories
   ...
   
   ## Workflow
   ...
   ```

3. **Add examples** in `examples.md`:
   - Real-world threat scenarios
   - Complete threat JSON examples
   - Application architecture diagrams

4. **Add reference materials** (optional) in `reference/`:
   - Detailed attack patterns
   - Mitigation strategies
   - CWE mappings

Skills are model-invoked. Do not hardcode skill names or paths in prompts.

## Skill Best Practices

1. **Specificity**: Focus on threats unique to the domain
2. **Examples**: Provide concrete, actionable threat scenarios
3. **STRIDE Mapping**: Show how domain threats map to STRIDE categories
4. **Mitigations**: Include domain-appropriate security controls
5. **Progressive Disclosure**: Keep SKILL.md lean, put details in reference files

## Future Skills (Planned)

- **mobile-apps**: iOS/Android-specific threat modeling
- **iot-apps**: IoT and embedded system threats
- **blockchain-apps**: Smart contract and DeFi threats
- **cloud-native-apps**: Kubernetes, serverless, microservices threats
- **healthcare-apps**: HIPAA, medical device specific threats

## Resources

- [Agent Skills Guide](../../../docs/references/AGENT_SKILLS_GUIDE.md) - Comprehensive skill development guide
- [STRIDE Methodology](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) - Microsoft STRIDE reference
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling) - OWASP threat modeling resources

