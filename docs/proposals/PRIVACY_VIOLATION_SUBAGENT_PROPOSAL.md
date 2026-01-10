# Privacy Violation Subagent: Technical Proposal

**Author**: Claude (AI-assisted design)
**Date**: January 10, 2026
**Status**: Draft for Review
**Branch**: `claude/privacy-violation-subagent-9aIou`

---

## Executive Summary

This proposal outlines the design for a **Privacy Violation Detection Subagent** that scans repositories for ToS violations related to using Claude CLI OAuth tokens as API keys through wrapper applications and proxy gateways.

The detection targets a specific class of violations that emerged in January 2026: third-party tools (OpenCode, clawdbot, claude-code-router) spoofing the Claude Code harness to use Claude Pro/Max subscription pricing for API-like programmatic access.

---

## Problem Statement

### The Violation Pattern

1. User has Claude Pro/Max subscription ($100-200/month unlimited usage)
2. Third-party app obtains OAuth token via `claude setup-token` or intercepts auth flow
3. App sets environment variables:
   - `ANTHROPIC_API_KEY=<oauth_token>`
   - `ANTHROPIC_AUTH_TOKEN=<oauth_token>`
   - `ANTHROPIC_BASE_URL=https://openrouter.ai/api` (or similar)
4. App spoofs Claude Code headers/client identity
5. Anthropic's API treats requests as legitimate Claude Code usage
6. Result: Enterprise-grade AI at consumer subscription prices

### Why This Matters

- **For Anthropic**: Revenue leakage, inability to diagnose bugs, degraded trust when issues arise
- **For Developers**: Account bans, loss of access, potential legal liability
- **For the Ecosystem**: Creates adversarial relationship between tool builders and AI providers

### Known Violators (January 2026)

| Project | Method | Status |
|---------|--------|--------|
| OpenCode | Header spoofing | Blocked by Anthropic |
| clawdbot | OAuth subscription routing | Active |
| claude-code-router | Provider transformers | Active |
| claude-code-proxy | LiteLLM gateway | Active |

---

## Detection Strategy

### Active Violations (Currently Exploiting)

**Pattern 1: Direct OAuth-as-API Usage**
```python
# Environment variable patterns
ANTHROPIC_API_KEY = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
ANTHROPIC_AUTH_TOKEN = <any_oauth_derived_value>
```

**Pattern 2: Gateway/Proxy Routing**
```python
# Base URL redirects to third-party
ANTHROPIC_BASE_URL = "https://openrouter.ai/api"
ANTHROPIC_BASE_URL = "http://localhost:4000"  # LiteLLM
ANTHROPIC_BASE_URL = "https://litellm.example.com"
```

**Pattern 3: Header Spoofing**
```python
# Fake client identity
headers = {"X-Client-Name": "claude-code"}
headers = {"User-Agent": "claude-code/1.0"}
```

**Pattern 4: Token Extraction/Rotation**
```javascript
// Clawdbot pattern
subscriptions: ["anthropic-oauth", "openai-oauth"]
authProfileRotation: true
```

### Potential Violations (Infrastructure Present)

- LiteLLM proxy configurations without OAuth usage
- OpenRouter integration setup
- Claude Code SDK usage in non-SDK-native contexts
- Token refresh mechanisms for OAuth tokens

---

## Architecture Decision: Standalone Repo vs. Embedded in SecureVibes

### Option A: Embedded in SecureVibes (Like DAST Skills)

```
securevibes/
├── packages/core/securevibes/
│   ├── agents/definitions.py          # Add privacy-violation agent
│   ├── prompts/agents/privacy_violation.txt
│   └── skills/
│       ├── dast/                       # Existing
│       └── privacy-violation/          # New skill category
│           └── oauth-abuse/
│               ├── SKILL.md
│               ├── examples.md
│               └── reference/
```

**Pros:**
- Reuses existing subagent infrastructure
- Single installation for users
- Integrated reporting with other security findings
- Shared test infrastructure

**Cons:**
- Couples to securevibes release cycle
- Adds scope creep to security scanner
- Less reusable by other tools

### Option B: Standalone Repo (Subagent Pattern)

```
anthropic-tos-scanner/
├── packages/core/
│   ├── scanner/
│   │   ├── detector.py           # Core detection logic
│   │   ├── patterns/             # Violation patterns
│   │   └── reporters/            # Output formats
│   ├── skills/
│   │   └── oauth-violation/
│   │       ├── SKILL.md
│   │       └── examples.md
│   └── cli.py                    # Standalone CLI
├── securevibes-integration/
│   └── subagent_adapter.py       # Adapter for securevibes
└── tests/
    └── fixtures/                 # Sample violating repos
```

**Pros:**
- Independent versioning and releases
- Reusable by CI/CD pipelines, GitHub Actions, other tools
- Focused scope = faster iteration
- Potential for Anthropic sponsorship (aligns with their interests)
- Can pivot to broader "AI ToS Compliance" tool

**Cons:**
- Duplicate SDK setup
- Two repos to maintain
- Coordination overhead

### Recommendation: **Hybrid Approach - Standalone with SecureVibes Integration**

**Rationale (thinking as an AI/ML engineer focused on fundability):**

1. **Market Positioning**: A standalone "AI ToS Compliance Scanner" has broader appeal than a securevibes-specific feature. It can:
   - Be used by Anthropic internally
   - Be offered as a GitHub Action
   - Expand to OpenAI, Google, and other AI provider ToS
   - Attract enterprise customers concerned about compliance

2. **Funding Narrative**: "I built a tool that helps AI companies protect their revenue and helps developers stay compliant" is more fundable than "I added a feature to my security scanner."

3. **Technical Separation**: The detection logic (regex, AST analysis, config parsing) is fundamentally different from security vulnerability detection. Mixing them creates architectural debt.

4. **SecureVibes Integration**: Expose as a subagent that securevibes can invoke, similar to how DAST works but at a higher level:

```python
# In securevibes orchestration
SUBAGENT_ORDER = [
    "assessment",
    "threat-modeling",
    "code-review",
    "privacy-violation",  # New: invokes external scanner
    "report-generator",
    "dast"
]
```

---

## Technical Design

### Core Detection Engine

```python
# anthropic_tos_scanner/detector.py

class ViolationDetector:
    """Detects Anthropic ToS violations in repositories."""

    def __init__(self, repo_path: Path):
        self.repo = repo_path
        self.patterns = self._load_patterns()

    def scan(self) -> ScanResult:
        """Full repository scan."""
        findings = []
        findings.extend(self._scan_env_files())
        findings.extend(self._scan_source_code())
        findings.extend(self._scan_config_files())
        findings.extend(self._scan_package_dependencies())
        return ScanResult(findings=findings, repo=self.repo)

    def _scan_env_files(self) -> list[Finding]:
        """Check .env, .env.*, docker-compose for OAuth abuse."""
        patterns = [
            r"ANTHROPIC_API_KEY\s*=\s*.*oauth",
            r"ANTHROPIC_AUTH_TOKEN\s*=",
            r"ANTHROPIC_BASE_URL\s*=\s*(?!https://api\.anthropic\.com)",
            r"CLAUDE_CODE_OAUTH_TOKEN\s*=",
        ]
        # ...

    def _scan_source_code(self) -> list[Finding]:
        """AST analysis for token manipulation."""
        # Python: ast module
        # JavaScript/TypeScript: tree-sitter
        # ...

    def _scan_config_files(self) -> list[Finding]:
        """Check litellm config, openrouter setup, etc."""
        # ...
```

### Skill Definition (For SecureVibes Integration)

```yaml
# skills/privacy-violation/oauth-abuse/SKILL.md
---
name: oauth-abuse-detection
description: Detect Anthropic ToS violations related to OAuth token abuse
allowed-tools: Read, Grep, Glob, Write
---

# OAuth Abuse Detection Skill

## Purpose
Identify repositories that use Claude Pro/Max OAuth tokens as API keys
through wrapper applications, proxy gateways, or header spoofing.

## Detection Methodology

### Phase 1: Dependency Analysis
Search for known violating packages:
- opencode-related dependencies
- clawdbot
- claude-code-router
- litellm with anthropic configuration

### Phase 2: Environment Variable Analysis
Grep for patterns:
- ANTHROPIC_API_KEY with OAuth token references
- ANTHROPIC_BASE_URL pointing to non-Anthropic endpoints
- CLAUDE_CODE_OAUTH_TOKEN usage in non-Claude-Code contexts

### Phase 3: Source Code Analysis
Look for:
- Header spoofing (X-Client-Name, User-Agent manipulation)
- Token extraction from Claude CLI
- OAuth token refresh mechanisms

### Phase 4: Configuration Analysis
Check:
- litellm_config.yaml for Anthropic OAuth routing
- docker-compose.yml for proxy setups
- .claude/ directory misuse

## Classification

### ACTIVE_VIOLATION
Code that currently exploits OAuth tokens as API keys.
Evidence: Direct usage patterns, working gateway configs.

### POTENTIAL_VIOLATION
Infrastructure that could enable violations.
Evidence: Gateway setup without clear OAuth usage, token handling code.

### COMPLIANT
Legitimate Claude Agent SDK usage.
Evidence: Native SDK imports, proper API key usage.
```

### Ralph Wiggum Integration for TDD

```bash
# Development workflow using Ralph Wiggum

/ralph-loop "
Build the Anthropic ToS Violation Scanner.

## Requirements
1. Core detector with pattern matching for:
   - Environment variable abuse
   - Source code token manipulation
   - Config file gateway routing
   - Header spoofing patterns

2. Test suite with fixtures:
   - tests/fixtures/compliant/ - legitimate SDK usage
   - tests/fixtures/active_violation/ - OpenCode-style patterns
   - tests/fixtures/potential_violation/ - gateway configs

3. CLI interface:
   - anthropic-tos-scan <repo_path>
   - --output json|markdown|sarif
   - --severity active|potential|all

4. SecureVibes adapter:
   - Implements SubagentAdapter interface
   - Returns findings in VULNERABILITIES.json format

## TDD Workflow
1. Write failing test for each pattern type
2. Implement detection logic
3. Run pytest
4. If tests fail, debug and fix
5. Refactor for clarity
6. Repeat until all tests pass

## Success Criteria
- All tests passing (pytest -v shows green)
- Coverage > 80%
- Can detect all patterns in fixtures/active_violation/
- Zero false positives on fixtures/compliant/

Output: <promise>COMPLETE</promise>
" --max-iterations 30 --completion-promise "COMPLETE"
```

---

## Test Fixtures Design

### Fixture: Active Violation (OpenCode Pattern)

```python
# tests/fixtures/active_violation/opencode_style/main.py
import os

# VIOLATION: Using OAuth token as API key
ANTHROPIC_API_KEY = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")

# VIOLATION: Routing through OpenRouter
ANTHROPIC_BASE_URL = "https://openrouter.ai/api"

# VIOLATION: Header spoofing
headers = {
    "X-Client-Name": "claude-code",
    "Authorization": f"Bearer {ANTHROPIC_API_KEY}"
}
```

### Fixture: Active Violation (Clawdbot Pattern)

```yaml
# tests/fixtures/active_violation/clawdbot_style/config.yaml
gateway:
  ws: ws://127.0.0.1:18789

providers:
  anthropic:
    type: oauth
    subscription: max  # VIOLATION: Using subscription OAuth

auth:
  rotation: true
  profiles:
    - anthropic-oauth
    - openai-oauth
```

### Fixture: Potential Violation (LiteLLM Setup)

```yaml
# tests/fixtures/potential_violation/litellm_config.yaml
model_list:
  - model_name: claude-opus
    litellm_params:
      model: anthropic/claude-opus-4-5-20251101
      api_base: http://localhost:4000  # POTENTIAL: Local proxy
      # No explicit OAuth abuse, but infrastructure exists
```

### Fixture: Compliant (Native SDK)

```python
# tests/fixtures/compliant/native_sdk/main.py
from claude_agent_sdk import ClaudeAgentOptions, create_agent

# COMPLIANT: Using SDK as intended
options = ClaudeAgentOptions(
    model="opus",
    api_key=os.environ.get("ANTHROPIC_API_KEY")  # Proper API key
)

agent = create_agent(options)
```

---

## Value Proposition & Funding Narrative

### Target Audiences

1. **Anthropic** (Primary)
   - Protects revenue from subscription arbitrage
   - Identifies ecosystem compliance issues
   - Could be integrated into their developer tooling

2. **Enterprise Security Teams**
   - Ensures vendor ToS compliance
   - Reduces legal/contractual risk
   - Audit trail for AI usage

3. **AI Tool Developers**
   - Pre-release compliance checking
   - Avoid accidental ToS violations
   - Build trust with AI providers

### Expansion Roadmap

| Phase | Scope | Timeline |
|-------|-------|----------|
| 1 | Anthropic OAuth abuse detection | MVP |
| 2 | OpenAI ToS compliance (similar patterns) | +1 release |
| 3 | Google AI Studio compliance | +2 releases |
| 4 | Generic "AI Provider Compliance Framework" | Future |

### Funding Angles

1. **Anthropic Partnership**
   - Direct value to their ecosystem health
   - Could sponsor development or acquire
   - Integration with their developer relations

2. **YC/Security VC**
   - "Compliance-as-Code for AI" is a growing market
   - Regulatory pressure increasing on AI usage
   - Enterprise sales motion is clear

3. **Open Source Sustainability**
   - GitHub Sponsors with enterprise tier
   - Consulting/implementation services
   - Custom rule development for enterprises

---

## Implementation Plan

### Phase 1: Foundation (Week 1-2)

- [ ] Create standalone repo `anthropic-tos-scanner`
- [ ] Set up Python package structure with Poetry
- [ ] Implement core pattern matching engine
- [ ] Create test fixtures for all violation types
- [ ] TDD: Write tests before implementation
- [ ] Use Ralph Wiggum loop for iterative development

### Phase 2: Detection Logic (Week 3-4)

- [ ] Environment variable pattern detection
- [ ] Source code AST analysis (Python, JS/TS)
- [ ] Config file parsing (YAML, JSON, TOML)
- [ ] Package dependency analysis
- [ ] Header spoofing detection

### Phase 3: Integration (Week 5-6)

- [ ] CLI interface with multiple output formats
- [ ] SecureVibes subagent adapter
- [ ] GitHub Action for CI/CD
- [ ] SARIF output for GitHub Security tab

### Phase 4: Launch & Outreach (Week 7-8)

- [ ] Documentation and examples
- [ ] Blog post (see proposal below)
- [ ] Reach out to Anthropic DevRel
- [ ] Submit to Hacker News, Reddit
- [ ] Engage with affected communities

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Anthropic changes OAuth mechanism | Patterns become obsolete | Design for extensibility, monitor changes |
| False positives on legitimate SDK use | User frustration | Careful pattern design, whitelist mechanism |
| Adversarial evasion | Violations go undetected | Behavioral analysis, not just static patterns |
| Scope creep | Never ships | Strict MVP focus, use Ralph loop constraints |

---

## Appendix: Design Decisions Log

| Decision | Options Considered | Choice | Rationale |
|----------|-------------------|--------|-----------|
| Repo structure | Monolith / Standalone | Standalone with adapter | Broader market, funding narrative |
| Detection method | Regex / AST / Both | Both | Regex for speed, AST for accuracy |
| Language support | Python-only / Multi | Python + JS/TS | Covers most AI development |
| Output format | Custom / SARIF / Both | SARIF + JSON + MD | GitHub integration, flexibility |
| Dev methodology | Waterfall / TDD+Ralph | TDD + Ralph Wiggum | Iterative refinement, self-correction |

---

## Next Steps

1. Review this proposal
2. Decide on repo name (`anthropic-tos-scanner`? `ai-compliance-scanner`?)
3. Initialize repo with Ralph Wiggum loop
4. Begin Phase 1 implementation
5. Draft blog post in parallel
