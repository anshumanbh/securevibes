---
name: oauth-abuse-detection
description: Detect AI provider Terms of Service violations related to OAuth token abuse, proxy routing, and client spoofing. Use when scanning repositories that use Claude, OpenAI, or other AI APIs to identify patterns that violate provider ToS - such as using subscription OAuth tokens as API keys through wrapper applications and proxy gateways.
allowed-tools: Read, Grep, Glob, Write
---

# OAuth Abuse Detection Skill

## Purpose

Identify repositories that violate AI provider Terms of Service by:
1. Using Claude Pro/Max OAuth tokens as API keys
2. Routing requests through proxy gateways (OpenRouter, LiteLLM)
3. Spoofing official client identities (X-Client-Name: claude-code)
4. Implementing subscription arbitrage infrastructure

This skill was created in response to the January 2026 crackdown by Anthropic on third-party tools spoofing the Claude Code harness to use subscription pricing for API-like access.

## When to Use This Skill

**IMPORTANT**: Activate this skill when the codebase contains ANY of these patterns.

### AI API Usage Indicators
- `anthropic` or `@anthropic-ai/sdk` imports
- `openai` imports
- `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` environment variables
- `messages.create`, `chat.completions.create` API calls
- Claude, GPT, or other LLM API usage

### OAuth/Token Handling Patterns
- `CLAUDE_CODE_OAUTH_TOKEN` references
- `ANTHROPIC_AUTH_TOKEN` usage
- Token refresh or rotation mechanisms
- `claude setup-token` references

### Proxy/Gateway Indicators
- `ANTHROPIC_BASE_URL` set to non-Anthropic endpoints
- LiteLLM configuration files (`litellm_config.yaml`)
- OpenRouter integration (`openrouter.ai`)
- Proxy server configurations
- Docker Compose with gateway services

### Known Tool Patterns
- clawdbot configuration
- OpenCode-related code
- claude-code-router patterns
- claude-code-proxy patterns

## Detection Phase

Before classifying violations, scan the codebase using these searches:

```
1. Search for OAuth token patterns (CRITICAL):
   - Grep for: CLAUDE_CODE_OAUTH_TOKEN|ANTHROPIC_AUTH_TOKEN|oauth.*token.*anthropic

2. Search for base URL manipulation:
   - Grep for: ANTHROPIC_BASE_URL|api_base.*anthropic|base_url.*anthropic
   - Look for URLs that are NOT https://api.anthropic.com

3. Search for header spoofing:
   - Grep for: X-Client-Name.*claude|User-Agent.*claude-code|client.*identity

4. Search for proxy configurations:
   - Grep for: openrouter\.ai|litellm|localhost:4000|proxy.*anthropic
   - Look for: litellm_config.yaml, docker-compose with gateway services

5. Search for subscription abuse patterns:
   - Grep for: subscription.*oauth|anthropic-oauth|clawdbot|auth.*rotation

6. Search for token extraction:
   - Grep for: setup-token|token.*refresh|oauth.*refresh|token.*extract
```

**If ANY of these patterns are found, proceed with violation classification.**

## Violation Categories

### PV01: OAuth Token as API Key

**Description**: Using a Claude Pro/Max subscription OAuth token in place of a proper Anthropic API key. This violates ToS because OAuth tokens are authorized only for use within official Claude Code tools, not for programmatic API access.

**Code Patterns Indicating Violation**:
- `ANTHROPIC_API_KEY = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")`
- `api_key: ${CLAUDE_CODE_OAUTH_TOKEN}`
- OAuth token assigned to ANTHROPIC_API_KEY
- Token starting with `sk-ant-oauth-` used as API key

**Finding Template**:
```json
{
  "id": "PV01-XXX",
  "category": "tos_violation",
  "title": "OAuth Token Used as API Key",
  "description": "Code uses Claude Code OAuth token as ANTHROPIC_API_KEY, violating Anthropic ToS. OAuth tokens are only authorized for use within official Claude Code CLI or Claude Agent SDK.",
  "severity": "critical",
  "violation_type": "active_violation",
  "affected_files": ["[file path]"],
  "evidence": "[matched pattern]",
  "remediation": "Use a proper Anthropic API key from console.anthropic.com. OAuth tokens should only be used within official Claude Code tools.",
  "references": [
    "https://docs.anthropic.com/en/docs/claude-code",
    "https://github.com/anomalyco/opencode/issues/6930"
  ]
}
```

### PV02: Gateway/Proxy Routing

**Description**: Redirecting Anthropic API requests through third-party gateways (OpenRouter, LiteLLM, custom proxies) to circumvent rate limits or use subscription tokens for API access.

**Code Patterns Indicating Violation**:
- `ANTHROPIC_BASE_URL = "https://openrouter.ai/api"`
- `ANTHROPIC_BASE_URL = "http://localhost:4000"` (LiteLLM)
- `api_base: https://litellm.example.com`
- Any ANTHROPIC_BASE_URL not pointing to api.anthropic.com

**Finding Template**:
```json
{
  "id": "PV02-XXX",
  "category": "tos_violation",
  "title": "Anthropic Requests Routed Through Proxy",
  "description": "ANTHROPIC_BASE_URL is set to [gateway], routing requests through a third-party proxy instead of directly to Anthropic. This may enable ToS violations when combined with OAuth tokens.",
  "severity": "critical",
  "violation_type": "active_violation",
  "affected_files": ["[file path]"],
  "evidence": "[matched pattern]",
  "remediation": "Remove proxy routing. Use api.anthropic.com directly with proper API keys.",
  "references": [
    "https://openrouter.ai/docs/guides/guides/claude-code-integration",
    "https://docs.litellm.ai/docs/tutorials/claude_responses_api"
  ]
}
```

### PV03: Client Identity Spoofing

**Description**: Setting HTTP headers to impersonate the official Claude Code client, tricking Anthropic's API into granting subscription pricing or rate limits.

**Code Patterns Indicating Violation**:
- `headers = {"X-Client-Name": "claude-code"}`
- `headers["User-Agent"] = "claude-code/1.0.0"`
- Any attempt to fake client identity headers

**Finding Template**:
```json
{
  "id": "PV03-XXX",
  "category": "tos_violation",
  "title": "Spoofed Claude Code Client Identity",
  "description": "Code sets headers to impersonate the official Claude Code client. This is used to gain unauthorized access to subscription pricing and rate limits.",
  "severity": "critical",
  "violation_type": "active_violation",
  "affected_files": ["[file path]"],
  "evidence": "[matched pattern]",
  "remediation": "Remove fake client headers. Use your application's actual identity.",
  "references": [
    "https://venturebeat.com/technology/anthropic-cracks-down-on-unauthorized-claude-usage-by-third-party-harnesses"
  ]
}
```

### PV04: Subscription Abuse Infrastructure

**Description**: Configuration or code that enables OAuth subscription routing, profile rotation, or clawdbot-style gateway usage.

**Code Patterns Indicating Violation**:
- `subscription: max` or `subscription: pro` in YAML configs
- `anthropic-oauth` as an auth profile
- `authProfileRotation: true`
- clawdbot gateway configuration

**Finding Template**:
```json
{
  "id": "PV04-XXX",
  "category": "tos_violation",
  "title": "Subscription Abuse Infrastructure",
  "description": "Configuration enables OAuth subscription routing through [tool], which uses Claude Pro/Max subscriptions for API-like access.",
  "severity": "critical",
  "violation_type": "active_violation",
  "affected_files": ["[file path]"],
  "evidence": "[matched pattern]",
  "remediation": "Use proper API keys instead of routing subscription OAuth tokens.",
  "references": [
    "https://github.com/clawdbot/clawdbot"
  ]
}
```

### PV05: Token Extraction/Refresh

**Description**: Code that extracts OAuth tokens from Claude Code or implements token refresh mechanisms for subscription tokens.

**Code Patterns Indicating Violation**:
- References to `claude setup-token`
- OAuth token refresh logic for Anthropic
- Token extraction from Claude CLI

**Finding Template**:
```json
{
  "id": "PV05-XXX",
  "category": "tos_violation",
  "title": "OAuth Token Extraction/Refresh",
  "description": "Code extracts or refreshes OAuth tokens from Claude Code, which may indicate infrastructure for subscription abuse.",
  "severity": "medium",
  "violation_type": "potential_violation",
  "affected_files": ["[file path]"],
  "evidence": "[matched pattern]",
  "remediation": "OAuth tokens from Claude Code should only be used within official Claude Code tools. Review and remove unauthorized token handling.",
  "references": []
}
```

### PV06: Proxy Configuration Without Clear Abuse

**Description**: Gateway or proxy configuration that could potentially be used for ToS violations, but without clear evidence of OAuth token abuse.

**Code Patterns Indicating Potential Violation**:
- LiteLLM config with Anthropic models
- Docker Compose with proxy services
- Gateway setup without OAuth tokens visible

**Finding Template**:
```json
{
  "id": "PV06-XXX",
  "category": "tos_violation",
  "title": "Potential Proxy Infrastructure",
  "description": "Proxy or gateway configuration detected that could enable ToS violations if used with OAuth tokens. Review to ensure proper API key usage.",
  "severity": "medium",
  "violation_type": "potential_violation",
  "affected_files": ["[file path]"],
  "evidence": "[matched pattern]",
  "remediation": "Ensure proxy configuration uses proper Anthropic API keys, not OAuth tokens from Claude Code subscriptions.",
  "references": []
}
```

## Classification Logic

### Active Violation (severity: critical)
Code that is **currently exploiting** OAuth tokens or spoofing client identity:
- PV01: OAuth token used as API key
- PV02: Gateway routing with OAuth
- PV03: Client identity spoofing
- PV04: Subscription abuse infrastructure

### Potential Violation (severity: medium)
Infrastructure that **could enable** violations:
- PV05: Token extraction without clear abuse
- PV06: Proxy configuration without OAuth evidence

### Compliant
Legitimate usage patterns:
- Standard `ANTHROPIC_API_KEY` from console.anthropic.com
- Claude Agent SDK with proper authentication
- No proxy routing or header spoofing

## Output Format

Write findings to `PRIVACY_VIOLATIONS.json` in the `.securevibes/` directory with this structure:

```json
{
  "scan_info": {
    "scanner": "privacy-violation-skill",
    "version": "1.0.0",
    "timestamp": "2026-01-10T12:00:00Z"
  },
  "summary": {
    "total": 5,
    "active_violations": 3,
    "potential_violations": 2
  },
  "findings": [
    {
      "id": "PV01-abc123",
      "category": "tos_violation",
      "title": "OAuth Token Used as API Key",
      "severity": "critical",
      "violation_type": "active_violation",
      "file": "main.py",
      "line": 15,
      "evidence": "ANTHROPIC_API_KEY = os.environ.get(\"CLAUDE_CODE_OAUTH_TOKEN\")",
      "remediation": "Use a proper Anthropic API key from console.anthropic.com"
    }
  ]
}
```

## Known Violating Projects (January 2026)

| Project | Method | Status |
|---------|--------|--------|
| OpenCode | Header spoofing (X-Client-Name) | Blocked by Anthropic |
| clawdbot | OAuth subscription routing | Active |
| claude-code-router | Provider transformers | Active |
| claude-code-proxy | LiteLLM gateway | Active |

## References

- [Anthropic Crackdown - VentureBeat](https://venturebeat.com/technology/anthropic-cracks-down-on-unauthorized-claude-usage-by-third-party-harnesses)
- [OpenCode Issue #6930](https://github.com/anomalyco/opencode/issues/6930)
- [Claude Code Documentation](https://docs.anthropic.com/en/docs/claude-code)
- [Clawdbot GitHub](https://github.com/clawdbot/clawdbot)
