---
name: agentic-security-threat-modeling
description: Identify agentic AI security threats based on OWASP Top 10 for Agentic Applications 2026. Use when analyzing AI agents, LLM-powered applications, chatbots, auto-reply systems, tool-using AI, browser automation, sandbox execution, or any application that uses AI/LLM APIs (Anthropic, OpenAI, Claude, GPT) to process user input and take actions.
allowed-tools: Read, Grep, Glob, Write
---

# Agentic Security Threat Modeling Skill

## Purpose
Augment generic STRIDE threat modeling with agentic AI-specific threats from OWASP Top 10 for Agentic Applications 2026. This skill identifies security risks unique to autonomous AI agents, multi-agent systems, and LLM-powered applications.

## When to Use This Skill

**IMPORTANT**: Activate this skill when the codebase contains ANY of these patterns. This includes both standard frameworks AND custom agent implementations.

### Agent Framework Indicators
- `langchain` imports or dependencies
- `autogen` imports or dependencies
- `crewai` imports or dependencies
- `claude_agent_sdk` or `claude-agent-sdk` usage
- `openai.beta.assistants` or OpenAI Assistants API
- `semantic_kernel` imports
- `llama_index` with agent patterns

### LLM/AI API Usage (Custom Implementations)
- `anthropic` or `@anthropic-ai/sdk` imports (Claude API)
- `openai` imports (OpenAI/GPT API)
- `Anthropic(` or `OpenAI(` client instantiation
- `messages.create`, `chat.completions.create` API calls
- Any code calling Claude, GPT, or other LLM APIs

### Custom Agent Patterns (Non-Framework)
- Files or directories named `agent`, `agents`, `runner`, `executor`
- Classes with `Agent`, `Runner`, `Executor`, `Bot`, `Assistant` in name
- Tool execution code (`bash-tools`, `browser-tools`, `tool-use`)
- Sandbox/container execution for AI (`sandbox`, `isolated`, `container`)
- Auto-reply or chatbot systems (`auto-reply`, `reply`, `bot`, `chatbot`)

### Agentic Code Patterns
- Tool/function definitions for LLMs (`@tool`, `tools=[]`, `tools:`, function calling)
- Agent class definitions (`class.*Agent`, `BaseAgent`, `.*Runner`, `.*Executor`)
- Multi-agent communication (`agent.send`, `agent.receive`, inter-agent messaging)
- Memory/context management (`memory`, `context`, `ConversationBuffer`, `session`, `transcript`)
- RAG implementations (`retriever`, `VectorStore`, `embedding`)
- Prompt templates with tool instructions (`system_prompt`, `systemPrompt`)
- Agent orchestration (`AgentExecutor`, `run_agent`, `runAgent`, workflow definitions)
- Browser automation for AI (`playwright`, `puppeteer`, `browser-tool`)

### MCP (Model Context Protocol) Patterns
- MCP server implementations
- Tool registration for MCP
- MCP client connections

## Detection Phase

Before generating threats, scan the codebase for agentic patterns using these searches:

```
1. Search for LLM API usage (CRITICAL - catches custom implementations):
   - Grep for: anthropic|openai|claude|gpt-|llm|completion|chat\.create|messages\.create
   
2. Search for framework imports:
   - Grep for: langchain|autogen|crewai|claude_agent_sdk|openai.*assistant|semantic_kernel
   
3. Search for agent/runner/executor patterns:
   - Grep for: agent|runner|executor|bot|assistant (in file/directory names)
   - Grep for: class.*Agent|class.*Runner|class.*Executor|class.*Bot
   
4. Search for tool execution patterns:
   - Grep for: bash.tool|browser.tool|tool.use|tools\s*[:=]|@tool|function.call
   
5. Search for sandbox/isolation patterns:
   - Grep for: sandbox|container|isolated|docker.*run
   
6. Search for auto-reply/chatbot patterns:
   - Grep for: auto.reply|chatbot|bot.reply|message.handler
   
7. Search for memory/session patterns:
   - Grep for: memory|context|session|transcript|conversation
   
8. Search for MCP patterns:
   - Grep for: mcp|MCPServer|MCPClient|tool_registration
```

**If ANY of these patterns are found, proceed with agentic threat modeling using ASI01-ASI10 categories.**

## OWASP Agentic Security Initiative (ASI) Threat Categories

### ASI01: Agent Goal Hijack

**Description**: Attacks that exploit prompt injection to override, modify, or manipulate the intended goal of an AI Agent, diverting activities toward attacker-specified objectives.

**Code Patterns Indicating Risk**:
- User input directly concatenated into prompts
- No input sanitization before LLM processing
- Missing guardrails against instruction override
- Prompts without clear system/user separation

**Threat Template**:
```json
{
  "id": "THREAT-ASI01-XXX",
  "category": "Tampering",
  "title": "Agent Goal Hijack via [injection point]",
  "description": "Attacker can inject malicious instructions through [input source] to override agent's intended goal and execute unauthorized actions",
  "severity": "critical",
  "affected_components": ["[agent component]", "[input handler]"],
  "attack_scenario": "1. Attacker crafts input containing hidden instructions\n2. Input reaches agent without sanitization\n3. Agent interprets injected content as instructions\n4. Agent executes attacker's goal instead of intended task",
  "vulnerability_types": ["CWE-74", "CWE-77"],
  "mitigation": "Implement input sanitization, use structured prompts with clear boundaries, add output validation, implement goal state monitoring",
  "existing_controls": [],
  "control_effectiveness": "none",
  "attack_complexity": "low",
  "likelihood": "high",
  "impact": "critical",
  "risk_score": "critical",
  "residual_risk": "Without input sanitization or prompt boundaries, full goal hijack is possible"
}
```

### ASI02: Tool Misuse and Exploitation

**Description**: Agents misuse legitimate tools due to prompt injection, misalignment, or unsafe delegation, leading to data exfiltration, tool output manipulation, or workflow hijacking.

**Code Patterns Indicating Risk**:
- Tools with broad permissions (file system, network, database)
- No input validation on tool parameters
- Missing rate limits on tool invocations
- Tools that accept URLs or file paths from user input

**Threat Template**:
```json
{
  "id": "THREAT-ASI02-XXX",
  "category": "Tampering",
  "title": "Tool Misuse via [tool name]",
  "description": "Agent can be manipulated to misuse [tool name] for unauthorized [action type]",
  "severity": "high",
  "affected_components": ["[tool]", "[agent executor]"],
  "attack_scenario": "1. Attacker provides input referencing tool capabilities\n2. Agent invokes tool with attacker-controlled parameters\n3. Tool performs unintended action (data exfil, SSRF, etc.)",
  "vulnerability_types": ["CWE-918", "CWE-78", "CWE-22"],
  "mitigation": "Implement least-privilege tool profiles, add input filtering, require human approval for sensitive actions, sandbox tool execution",
  "existing_controls": [],
  "control_effectiveness": "none",
  "attack_complexity": "medium",
  "likelihood": "high",
  "impact": "high",
  "risk_score": "critical",
  "residual_risk": "Tools with broad permissions can be exploited for data exfiltration or lateral movement"
}
```

### ASI03: Identity and Privilege Abuse

**Description**: Exploits dynamic trust and delegation in agents to escalate access by manipulating delegation chains, role inheritance, or cached credentials.

**Code Patterns Indicating Risk**:
- Agents inheriting user credentials or tokens
- Long-lived tokens passed to agents
- No credential scoping per task
- Shared identity across multiple agents
- Missing delegation chain validation

**Threat Template**:
```json
{
  "id": "THREAT-ASI03-XXX",
  "category": "Elevation of Privilege",
  "title": "Privilege Escalation via [delegation mechanism]",
  "description": "Agent inherits excessive privileges through [mechanism], enabling unauthorized access to [resource]",
  "severity": "high",
  "affected_components": ["[agent]", "[auth component]"],
  "attack_scenario": "1. Agent receives broad credentials for convenience\n2. Attacker exploits agent vulnerability\n3. Attacker gains access to all resources agent can access",
  "vulnerability_types": ["CWE-269", "CWE-250", "CWE-266"],
  "mitigation": "Use per-task identities, implement JIT privileges, segment memory, validate delegation chains",
  "existing_controls": [],
  "control_effectiveness": "none",
  "attack_complexity": "medium",
  "likelihood": "medium",
  "impact": "high",
  "risk_score": "high",
  "residual_risk": "Inherited credentials provide lateral movement opportunities if agent is compromised"
}
```

### ASI04: Agentic Supply Chain Vulnerabilities

**Description**: Vulnerabilities from external components—models, plugins, tools, data sources—that are not adequately vetted or monitored.

**Code Patterns Indicating Risk**:
- Third-party MCP servers or plugins
- Unpinned model versions
- External tool registries
- RAG sources from untrusted origins
- Dynamic plugin loading

**Threat Template**:
```json
{
  "id": "THREAT-ASI04-XXX",
  "category": "Tampering",
  "title": "Supply Chain Compromise via [component]",
  "description": "Malicious or compromised [component type] could inject backdoors or exfiltrate data",
  "severity": "high",
  "affected_components": ["[external component]", "[integration point]"],
  "attack_scenario": "1. Attacker compromises third-party [component]\n2. Agent loads/uses compromised component\n3. Malicious code executes in agent context",
  "vulnerability_types": ["CWE-829", "CWE-494", "CWE-1104"],
  "mitigation": "Vet dependencies, pin versions, verify model provenance, use SBOM/AIBOM, scan for vulnerabilities",
  "existing_controls": [],
  "control_effectiveness": "none",
  "attack_complexity": "high",
  "likelihood": "medium",
  "impact": "high",
  "risk_score": "high",
  "residual_risk": "Third-party components may contain backdoors or vulnerabilities not detected by standard scanning"
}
```

### ASI05: Unexpected Code Execution (RCE)

**Description**: Agent executes code not intended by designers, through prompt injection, tool misuse, or insecure code execution features.

**Code Patterns Indicating Risk**:
- `eval()` or `exec()` on LLM output
- Code interpreter tools
- Shell command execution from agent
- Dynamic code generation without sandboxing

**Threat Template**:
```json
{
  "id": "THREAT-ASI05-XXX",
  "category": "Tampering",
  "title": "Remote Code Execution via [execution path]",
  "description": "Agent can be tricked into executing arbitrary code through [mechanism]",
  "severity": "critical",
  "affected_components": ["[code execution component]"],
  "attack_scenario": "1. Attacker crafts input that generates malicious code\n2. Agent passes generated code to execution engine\n3. Malicious code runs with agent's privileges",
  "vulnerability_types": ["CWE-94", "CWE-95", "CWE-78"],
  "mitigation": "Disable unnecessary code execution, sandbox all generated code, validate code before execution, use allowlists",
  "existing_controls": [],
  "control_effectiveness": "none",
  "attack_complexity": "low",
  "likelihood": "high",
  "impact": "critical",
  "risk_score": "critical",
  "residual_risk": "Code execution without sandboxing allows full system compromise"
}
```

### ASI06: Memory & Context Poisoning

**Description**: Attackers corrupt persistent memory, session context, or RAG knowledge base to influence future agent behavior across sessions.

**Code Patterns Indicating Risk**:
- Persistent conversation memory
- RAG with user-contributed content
- Shared context across users/sessions
- No memory validation or expiration

**Threat Template**:
```json
{
  "id": "THREAT-ASI06-XXX",
  "category": "Tampering",
  "title": "Context Poisoning via [memory component]",
  "description": "Attacker can inject malicious content into [memory type] that persists and influences future agent behavior",
  "severity": "high",
  "affected_components": ["[memory/RAG component]"],
  "attack_scenario": "1. Attacker injects crafted content into agent memory\n2. Malicious content persists across sessions\n3. Future interactions influenced by poisoned context",
  "vulnerability_types": ["CWE-472", "CWE-915"],
  "mitigation": "Validate memory inputs, segment by user/tenant, apply TTLs, monitor for anomalies",
  "existing_controls": [],
  "control_effectiveness": "none",
  "attack_complexity": "medium",
  "likelihood": "medium",
  "impact": "high",
  "risk_score": "high",
  "residual_risk": "Poisoned context can influence agent behavior across multiple sessions and users"
}
```

### ASI07: Insecure Inter-Agent Communication

**Description**: Vulnerabilities when agents exchange messages without proper authentication, encryption, or validation.

**Code Patterns Indicating Risk**:
- Agent-to-agent messaging without auth
- Plaintext inter-agent communication
- No message signing or verification
- Open agent discovery/registration

**Threat Template**:
```json
{
  "id": "THREAT-ASI07-XXX",
  "category": "Spoofing",
  "title": "Inter-Agent Message Injection via [communication channel]",
  "description": "Attacker can inject or spoof messages between agents through [channel]",
  "severity": "high",
  "affected_components": ["[agent A]", "[agent B]", "[communication layer]"],
  "attack_scenario": "1. Attacker intercepts/injects inter-agent messages\n2. Receiving agent trusts spoofed message\n3. Agent performs unauthorized action based on fake request",
  "vulnerability_types": ["CWE-290", "CWE-319", "CWE-345"],
  "mitigation": "Use mTLS for agent communication, sign all messages, validate peer identities, encrypt channels",
  "existing_controls": [],
  "control_effectiveness": "none",
  "attack_complexity": "medium",
  "likelihood": "medium",
  "impact": "high",
  "risk_score": "high",
  "residual_risk": "Spoofed inter-agent messages can trigger unauthorized actions across the agent network"
}
```

### ASI08: Cascading Failures

**Description**: Faults in one agent propagate through interconnected systems, amplifying impact and causing widespread disruption.

**Code Patterns Indicating Risk**:
- Tightly coupled agent dependencies
- No circuit breakers or bulkheads
- Shared resources without isolation
- No retry limits or timeouts

**Threat Template**:
```json
{
  "id": "THREAT-ASI08-XXX",
  "category": "Denial of Service",
  "title": "Cascading Failure via [failure point]",
  "description": "Failure in [component] can cascade to [dependent components], causing system-wide disruption",
  "severity": "medium",
  "affected_components": ["[origin component]", "[dependent components]"],
  "attack_scenario": "1. Attacker triggers failure in [component]\n2. Failure propagates to dependent agents\n3. System-wide outage or degradation occurs",
  "vulnerability_types": ["CWE-754", "CWE-400"],
  "mitigation": "Implement circuit breakers, add bulkheads, validate outputs, apply timeouts and rate limits",
  "existing_controls": [],
  "control_effectiveness": "none",
  "attack_complexity": "medium",
  "likelihood": "medium",
  "impact": "medium",
  "risk_score": "medium",
  "residual_risk": "Tightly coupled agents without circuit breakers can cause system-wide outages"
}
```

### ASI09: Human-Agent Trust Exploitation

**Description**: Attackers leverage trust humans place in AI agents to deceive, manipulate, or social-engineer users.

**Code Patterns Indicating Risk**:
- Agent outputs presented as authoritative
- No source attribution on agent responses
- Agent can impersonate users or systems
- Missing confidence indicators

**Threat Template**:
```json
{
  "id": "THREAT-ASI09-XXX",
  "category": "Spoofing",
  "title": "Trust Exploitation via [agent capability]",
  "description": "Agent can be manipulated to present false information authoritatively, misleading users into [harmful action]",
  "severity": "medium",
  "affected_components": ["[agent]", "[user interface]"],
  "attack_scenario": "1. Attacker manipulates agent output\n2. User trusts agent-presented information\n3. User takes harmful action based on false info",
  "vulnerability_types": ["CWE-451"],
  "mitigation": "Add output attribution, show confidence levels, require human review for high-stakes decisions",
  "existing_controls": [],
  "control_effectiveness": "none",
  "attack_complexity": "low",
  "likelihood": "medium",
  "impact": "medium",
  "risk_score": "medium",
  "residual_risk": "Users may act on false information presented authoritatively by the agent"
}
```

### ASI10: Rogue Agents

**Description**: Agents acting outside intended scope due to compromise, misconfiguration, emergent behavior, or malicious design.

**Code Patterns Indicating Risk**:
- No agent behavior monitoring
- Missing kill switches
- No agent registration/inventory
- Agents can spawn sub-agents without limits

**Threat Template**:
```json
{
  "id": "THREAT-ASI10-XXX",
  "category": "Repudiation",
  "title": "Rogue Agent Behavior in [agent]",
  "description": "[Agent] could act outside intended scope due to [cause], performing unauthorized actions without detection",
  "severity": "high",
  "affected_components": ["[agent]"],
  "attack_scenario": "1. Agent behavior drifts from intended scope\n2. Rogue actions go undetected due to missing monitoring\n3. Agent causes damage before intervention",
  "vulnerability_types": ["CWE-778"],
  "mitigation": "Maintain agent inventory, monitor behavior baselines, implement kill switches, use signed artifacts",
  "existing_controls": [],
  "control_effectiveness": "none",
  "attack_complexity": "medium",
  "likelihood": "medium",
  "impact": "high",
  "risk_score": "high",
  "residual_risk": "Without monitoring and kill switches, rogue agent behavior may go undetected"
}
```

## Output Format

Generate additional threats in the same JSON format as the base threat model:

```json
{
  "id": "THREAT-ASI0X-001",
  "category": "[STRIDE category]",
  "title": "[Specific threat title]",
  "description": "[Detailed description]",
  "severity": "critical|high|medium|low",
  "affected_components": ["component1", "component2"],
  "attack_scenario": "[Step-by-step attack]",
  "vulnerability_types": ["CWE-XXX"],
  "mitigation": "[Specific recommendations]",
  "existing_controls": ["[Controls found in codebase]"],
  "control_effectiveness": "none|partial|substantial",
  "attack_complexity": "low|medium|high",
  "likelihood": "low|medium|high",
  "impact": "low|medium|high|critical",
  "risk_score": "low|medium|high|critical",
  "residual_risk": "[Description of remaining risk after existing controls]"
}
```

**ID Convention**: Use `THREAT-ASI0X-NNN` where X is the ASI category number (1-10).

**Risk Assessment Fields**:
- `existing_controls`: List controls found in the codebase (e.g., sandboxing, rate limiting, input validation)
- `control_effectiveness`: How well existing controls mitigate the threat
- `attack_complexity`: Skill level required to exploit (low = script kiddie, high = expert)
- `likelihood`: Probability of exploitation given controls and complexity
- `impact`: Damage if successfully exploited
- `risk_score`: Calculated from likelihood × impact matrix
- `residual_risk`: What risk remains even with existing controls

## Workflow

1. **Detect Agentic Patterns**: Search codebase for framework imports and agent patterns
2. **Identify Components**: Map detected patterns to specific files and components
3. **Apply ASI Categories**: For each component, evaluate all 10 ASI categories
4. **Generate Threats**: Create threats using templates, customized to specific codebase
5. **Prioritize**: Assign severity based on exploitability and impact
6. **Output**: Add threats to THREAT_MODEL.json alongside STRIDE threats

## Examples

See `examples.md` for comprehensive attack scenarios for each ASI category with real-world code patterns.

## References

- [OWASP Top 10 for Agentic Applications 2026](../../../docs/references/OWASP-Top-10-Agentic-Applications-2026.md)
- [OWASP LLM Top 10](https://genai.owasp.org/)
- [Agent Skills Guide](../../../docs/references/AGENT_SKILLS_GUIDE.md)
