# Threat Modeling Skills for SecureVibes

This directory contains Agent Skills for specialized threat modeling in SecureVibes.

## Overview

Skills provide specialized threat modeling methodologies that the threat modeling agent uses to identify threats specific to particular application types or domains. Each skill is a self-contained directory with instructions, examples, and reference materials.

## Directory Structure

```
skills/threat-modeling/
├── README.md                    # This file
├── agentic-apps/                # AI/LLM application threat modeling
│   ├── SKILL.md
│   ├── examples.md
│   └── reference/
├── web-apps/                    # Traditional web application threats (OWASP Top 10)
│   ├── SKILL.md
│   ├── examples.md
│   └── reference/
├── api-security/                # REST/GraphQL API threats (OWASP API Top 10)
│   ├── SKILL.md
│   ├── examples.md
│   └── reference/
└── microservices/               # Container & distributed system threats
    ├── SKILL.md
    ├── examples.md
    └── reference/
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

**Output**: Threat model JSON with agentic-specific fields (`agentic_threat_type`, `trust_boundary_crossed`)

---

### web-apps

**Purpose**: Threat model traditional web applications using OWASP Top 10 and common web vulnerability patterns.

**Trigger**: Use when analyzing server-rendered web applications, session-based auth, form handling, MVC frameworks (Flask, Django, Express, Rails, Spring, Laravel).

**Covers**:
- Injection attacks (SQL, Command, Template)
- Cross-Site Scripting (XSS) - Reflected, Stored, DOM
- Broken Authentication & Session Management
- Broken Access Control & IDOR
- Security Misconfiguration
- CSRF and Clickjacking
- Insecure Deserialization
- Path Traversal

**Output**: Threat model JSON with web-specific fields (`owasp_category`, `cwe_id`)

---

### api-security

**Purpose**: Threat model REST and GraphQL APIs using OWASP API Security Top 10 (2023).

**Trigger**: Use when analyzing API backends, mobile app backends, SPA backends, microservice endpoints, or third-party API integrations.

**Covers**:
- BOLA (Broken Object Level Authorization)
- Broken Authentication (JWT, API keys)
- BOPLA (Mass Assignment, Excessive Data Exposure)
- Unrestricted Resource Consumption
- BFLA (Broken Function Level Authorization)
- SSRF via API features
- GraphQL-specific attacks (introspection, depth, batching)
- CORS misconfiguration

**Output**: Threat model JSON with API-specific fields (`api_category`, `http_method`, `endpoint`)

---

### microservices

**Purpose**: Threat model distributed microservice architectures, container deployments, and cloud-native applications.

**Trigger**: Use when analyzing Kubernetes deployments, Docker containers, service mesh configurations (Istio, Linkerd), API gateways, or event-driven architectures.

**Covers**:
- Service-to-service authentication (mTLS)
- Container security (root, privileged, escapes)
- Secrets management
- API Gateway vulnerabilities
- Message queue attacks (Kafka, RabbitMQ)
- Service mesh misconfigurations
- CI/CD pipeline security
- RBAC and service accounts

**Output**: Threat model JSON with infrastructure-specific fields (`infrastructure_type`, `affected_resources`)

---

## Skill Selection Guide

| Application Type | Primary Skill | Secondary Skills |
|-----------------|---------------|------------------|
| ChatGPT-like assistant | agentic-apps | api-security |
| Traditional web app | web-apps | - |
| REST API backend | api-security | web-apps |
| GraphQL API | api-security | - |
| Kubernetes microservices | microservices | api-security |
| AI agent with tools | agentic-apps | api-security, microservices |
| Mobile app backend | api-security | - |
| Event-driven system | microservices | api-security |

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
- **healthcare-apps**: HIPAA, medical device specific threats

## Resources

- [Agent Skills Guide](../../../docs/references/AGENT_SKILLS_GUIDE.md) - Comprehensive skill development guide
- [STRIDE Methodology](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) - Microsoft STRIDE reference
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling) - OWASP threat modeling resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Web application security risks
- [OWASP API Security Top 10](https://owasp.org/API-Security/) - API security risks
