# Agentic Apps Threat Modeling Reference

This directory contains reference materials for threat modeling agentic applications.

## Contents

- **threat_patterns.md**: Detailed threat patterns with attack techniques and detection methods
- **mitigations.md**: Security controls and defensive patterns for agentic systems
- **cwe_mappings.md**: CWE identifiers relevant to agentic applications

## Usage

These files provide deep-dive reference information. The main `SKILL.md` covers the core methodology. Reference these files when:

- You need detailed attack technique descriptions
- You're designing specific mitigations
- You need CWE mappings for compliance/tracking

## Quick Reference

### Agentic Threat Taxonomy

```
Agentic Threats
├── Input-Based Attacks
│   ├── Direct Prompt Injection
│   ├── Indirect Prompt Injection
│   └── Jailbreak Attempts
├── Tool/Action Attacks
│   ├── Tool Invocation Manipulation
│   ├── Parameter Injection
│   └── Tool Chain Exploitation
├── Data Attacks
│   ├── Context Leakage
│   ├── RAG Poisoning
│   └── Action-Based Exfiltration
├── Autonomy Attacks
│   ├── Runaway Loops
│   ├── Self-Modification
│   └── Missing Human Oversight
├── Multi-Agent Attacks
│   ├── Agent Impersonation
│   ├── Cascading Injection
│   └── Orchestration Manipulation
└── Supply Chain Attacks
    ├── Model Compromise
    ├── Plugin/Tool Trojans
    └── Dependency Attacks
```

### Key CWE Mappings

| Threat Type | Primary CWEs |
|-------------|--------------|
| Prompt Injection | CWE-94, CWE-77 |
| Tool Abuse | CWE-78, CWE-89, CWE-285 |
| Data Exfiltration | CWE-200, CWE-522 |
| Excessive Autonomy | CWE-269, CWE-732 |
| RAG Poisoning | CWE-94, CWE-20 |
| Supply Chain | CWE-829, CWE-494 |



