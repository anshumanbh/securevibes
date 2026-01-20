# Agentic Security Reference Guide

This document provides reference materials for detecting agentic patterns and mapping threats to OWASP ASI categories.

## Table of Contents
- [Framework Detection Patterns](#framework-detection-patterns)
  - [LangChain](#langchain)
  - [AutoGen](#autogen)
  - [CrewAI](#crewai)
  - [Claude Agent SDK](#claude-agent-sdk)
  - [OpenAI Assistants](#openai-assistants)
  - [Semantic Kernel](#semantic-kernel)
  - [MCP (Model Context Protocol)](#mcp-model-context-protocol)
- [OWASP ASI Category Quick Reference](#owasp-asi-category-quick-reference)
- [Threat ID Convention](#threat-id-convention)
- [Severity Guidelines](#severity-guidelines)
  - [ASI-Specific Severity Defaults](#asi-specific-severity-defaults)
- [Integration with STRIDE](#integration-with-stride)
- [References](#references)

## Framework Detection Patterns

Use these patterns with Grep to detect agentic architectures in codebases.

### LangChain

**Import Patterns**:
```
from langchain
import langchain
from langchain.agents
from langchain.chains
from langchain.memory
from langchain.tools
from langchain.vectorstores
```

**Class/Function Patterns**:
```
LLMChain
AgentExecutor
ConversationBufferMemory
ConversationSummaryMemory
VectorStore
RetrievalQA
@tool
Tool(
initialize_agent
```

**Risk Indicators**:
- `PromptTemplate` with user input → ASI01 (Goal Hijack)
- `Tool(` definitions → ASI02 (Tool Misuse)
- `ConversationBufferMemory` → ASI06 (Memory Poisoning)

### AutoGen

**Import Patterns**:
```
from autogen
import autogen
from autogen.agentchat
```

**Class/Function Patterns**:
```
AssistantAgent
UserProxyAgent
GroupChat
GroupChatManager
initiate_chat
register_function
```

**Risk Indicators**:
- Multiple `AssistantAgent` instances → ASI07 (Inter-Agent Communication)
- `initiate_chat` without auth → ASI07 (Spoofing)
- `register_function` → ASI02 (Tool Misuse)

### CrewAI

**Import Patterns**:
```
from crewai
import crewai
from crewai import Agent, Task, Crew
```

**Class/Function Patterns**:
```
Agent(
Task(
Crew(
allow_delegation
kickoff()
```

**Risk Indicators**:
- `allow_delegation=True` → ASI10 (Rogue Agents)
- Unlimited `Agent(` creation → ASI08 (Cascading Failures)
- No agent monitoring → ASI10 (Rogue Agents)

### Claude Agent SDK

**Import Patterns**:
```
claude_agent_sdk
claude-agent-sdk
from claude_agent_sdk
```

**Class/Function Patterns**:
```
ClaudeAgentOptions
AgentDefinition
ClaudeSDKClient
query(
allowed_tools
setting_sources
```

**Risk Indicators**:
- `allowed_tools` with dangerous tools → ASI02, ASI05
- No `permission_mode` → ASI03 (Privilege Abuse)
- Subagent definitions → ASI07, ASI08

### OpenAI Assistants

**Import Patterns**:
```
openai.beta.assistants
client.beta.assistants
```

**Class/Function Patterns**:
```
assistants.create
threads.create
runs.create
code_interpreter
retrieval
function_calling
```

**Risk Indicators**:
- `code_interpreter` enabled → ASI05 (Code Execution)
- `retrieval` with untrusted files → ASI06 (Context Poisoning)
- `function_calling` → ASI02 (Tool Misuse)

### Semantic Kernel

**Import Patterns**:
```
semantic_kernel
from semantic_kernel
import semantic_kernel
```

**Class/Function Patterns**:
```
Kernel(
@kernel_function
planner
SequentialPlanner
```

**Risk Indicators**:
- `@kernel_function` → ASI02 (Tool Misuse)
- `planner` classes → ASI01 (Goal Hijack), ASI08 (Cascading)

### MCP (Model Context Protocol)

**Import Patterns**:
```
mcp
from mcp
MCPServer
MCPClient
```

**Class/Function Patterns**:
```
@mcp.tool
tool_registration
mcp_config
servers:
```

**Risk Indicators**:
- External MCP servers → ASI04 (Supply Chain)
- Unverified MCP registries → ASI04 (Supply Chain)
- MCP tools with broad access → ASI02 (Tool Misuse)

## OWASP ASI Category Quick Reference

| ASI | Name | STRIDE Mapping | Key CWEs |
|-----|------|----------------|----------|
| ASI01 | Agent Goal Hijack | Tampering | CWE-74, CWE-77 |
| ASI02 | Tool Misuse & Exploitation | Tampering, Info Disclosure | CWE-918, CWE-78, CWE-89 |
| ASI03 | Identity & Privilege Abuse | Elevation of Privilege | CWE-250, CWE-269, CWE-266 |
| ASI04 | Supply Chain Vulnerabilities | Tampering | CWE-829, CWE-494, CWE-1104 |
| ASI05 | Unexpected Code Execution | Tampering | CWE-94, CWE-95, CWE-78 |
| ASI06 | Memory & Context Poisoning | Tampering | CWE-472, CWE-915 |
| ASI07 | Insecure Inter-Agent Comm | Spoofing | CWE-290, CWE-319, CWE-345 |
| ASI08 | Cascading Failures | Denial of Service | CWE-754, CWE-400 |
| ASI09 | Human-Agent Trust Exploitation | Spoofing | CWE-451 |
| ASI10 | Rogue Agents | Repudiation, DoS | CWE-778, CWE-770 |

## Threat ID Convention

Use the format: `THREAT-ASI{XX}-{NNN}`

- `XX`: ASI category number (01-10)
- `NNN`: Sequential number within category

Examples:
- `THREAT-ASI01-001`: First Agent Goal Hijack threat
- `THREAT-ASI02-003`: Third Tool Misuse threat
- `THREAT-ASI10-001`: First Rogue Agent threat

## Severity Guidelines

| Severity | Criteria |
|----------|----------|
| **Critical** | RCE possible, data exfiltration, full system compromise |
| **High** | Privilege escalation, significant data access, tool abuse |
| **Medium** | Information disclosure, partial compromise, DoS |
| **Low** | Minor information leak, limited impact |

### ASI-Specific Severity Defaults

| ASI | Default Severity | Rationale |
|-----|------------------|-----------|
| ASI01 | Critical | Goal hijack can lead to any action |
| ASI02 | High-Critical | Depends on tool capabilities |
| ASI03 | High | Privilege escalation |
| ASI04 | High | Supply chain = broad impact |
| ASI05 | Critical | Code execution = full compromise |
| ASI06 | High | Persistent compromise |
| ASI07 | High | Multi-agent trust breakdown |
| ASI08 | Medium | Availability impact |
| ASI09 | Medium | Trust/social engineering |
| ASI10 | High | Uncontrolled agent behavior |

## Integration with STRIDE

Map ASI categories to STRIDE for consistency with generic threat modeling:

| STRIDE | Related ASI Categories |
|--------|----------------------|
| **Spoofing** | ASI07 (message spoofing), ASI09 (impersonation) |
| **Tampering** | ASI01 (goal tampering), ASI02 (tool tampering), ASI04 (supply chain), ASI05 (code injection), ASI06 (memory tampering) |
| **Repudiation** | ASI10 (rogue agents hiding actions) |
| **Information Disclosure** | ASI02 (data exfil via tools), ASI03 (credential leak), ASI06 (context leak) |
| **Denial of Service** | ASI08 (cascading failures), ASI10 (resource exhaustion) |
| **Elevation of Privilege** | ASI03 (privilege abuse) |

## References

- [OWASP Top 10 for Agentic Applications 2026](../../../../docs/references/OWASP-Top-10-Agentic-Applications-2026.md)
- [OWASP LLM Top 10](https://genai.owasp.org/)
- [CWE Database](https://cwe.mitre.org/)
