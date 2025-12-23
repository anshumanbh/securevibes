# DAST Skills for SecureVibes

This directory contains Agent Skills for Dynamic Application Security Testing (DAST) validation in SecureVibes.

## Overview

Skills provide specialized testing methodologies that the DAST agent uses to validate vulnerabilities discovered during static code analysis. Each skill is a self-contained directory with instructions, examples, and helper scripts.

## Directory Structure

```
.claude/skills/dast/
├── README.md                    # This file
├── authorization-testing/       # Authorization failure validation
│   ├── SKILL.md                 # Core methodology
│   ├── examples.md              # 10+ examples organized by category
│   └── reference/               # Implementation examples
│       ├── README.md            # Reference guide
│       ├── auth_patterns.py     # Reusable authentication functions
│       └── validate_idor.py     # Complete testing script
└── injection-testing/           # Injection vulnerability validation
    ├── SKILL.md                 # Core methodology
    ├── examples.md              # 10+ examples organized by injection type
    └── reference/               # Implementation examples
        ├── README.md            # Reference guide
        ├── injection_payloads.py # Payload generation utilities
        └── validate_injection.py # Complete testing script
```

## Current Skills

### authorization-testing
**Purpose**: Validate authorization failures including IDOR, privilege escalation, and missing access controls through HTTP-based exploitation attempts.

**Trigger**: CWE-639 (IDOR), CWE-269 (Privilege Escalation), CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization), CWE-284 (Access Control), CWE-285 (Improper Authorization), CWE-425 (Forced Browsing)

**Requirements**:
- Target application running and reachable
- Test user accounts (optional but recommended)
- VULNERABILITIES.json with IDOR findings

**Output**: Validation status (VALIDATED/FALSE_POSITIVE/UNVALIDATED) with evidence

### injection-testing
**Purpose**: Validate injection vulnerabilities including SQL, NoSQL, OS Command, LDAP, XPath, SSTI, and XSS by sending crafted payloads and observing application behavior.

**Trigger**: CWE-89 (SQL Injection), CWE-78 (OS Command Injection), CWE-79 (XSS), CWE-90 (LDAP Injection), CWE-917 (Expression Language Injection), CWE-94 (Code Injection), CWE-643 (XPath Injection), CWE-1336 (SSTI)

**Requirements**:
- Target application running and reachable
- Identified injection points (parameters, headers, body fields)
- VULNERABILITIES.json with injection findings

**Output**: Validation status (VALIDATED/FALSE_POSITIVE/PARTIAL/UNVALIDATED) with evidence

## Adding New Skills

To add a new DAST skill:

1. **Create skill directory**:
   ```bash
   mkdir .claude/skills/dast/[vulnerability-type]-testing
   ```

2. **Create SKILL.md** with YAML frontmatter:
   ```yaml
   ---
   name: [vulnerability-type]-testing
   description: Brief description of what this skill validates and when to use it
   allowed-tools: Read, Write, Bash
   ---
   
   # [Vulnerability Type] Testing Skill
   
   ## Purpose
   ...
   
   ## Testing Methodology
   ...
   ```

3. **Add examples** in `examples.md`:
   - Show real-world scenarios
   - Include expected input/output
   - Demonstrate classification logic

4. **Add reference examples** (optional) in `reference/`:
   - Show patterns for auth, requests, and classification
   - Make clear they are examples to adapt, not to run as-is

Skills are model-invoked. Do not hardcode skill names or paths in prompts.

## Skill Best Practices

1. **Conciseness**: Keep SKILL.md under 500 lines
2. **Progressive Disclosure**: Link to examples.md and scripts rather than embedding
3. **Safety First**: Include safety rules and error handling
4. **Evidence Quality**: Redact sensitive data, truncate responses, include hashes
5. **Clear Classification**: Define criteria for VALIDATED/FALSE_POSITIVE/UNVALIDATED

## Testing Skills Independently

Before integrating into SecureVibes, test skills with Claude Code:

```bash
# Start your vulnerable test application
python vulnerable_app.py

# Start Claude Code
claude

# Ask Claude to validate a vulnerability
"Test the /api/users endpoint for IDOR vulnerability. 
User1 ID is 123, User2 ID is 456."
```

Claude should automatically discover and use the appropriate skill.

## Resources

- [Agent Skills Documentation](https://docs.anthropic.com/en/docs/agents-and-tools/agent-skills/overview)
- [Agent Skills Best Practices](https://docs.anthropic.com/en/docs/agents-and-tools/agent-skills/best-practices)
- [SecureVibes DAST Guide](../../docs/DAST_GUIDE.md)
