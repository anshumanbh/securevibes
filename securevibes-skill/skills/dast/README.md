# DAST Skills for SecureVibes

This directory contains Agent Skills for Dynamic Application Security Testing (DAST) validation in SecureVibes.

## Overview

Skills provide specialized testing methodologies that the DAST agent uses to validate vulnerabilities discovered during static code analysis. Each skill is a self-contained directory with instructions, examples, and helper scripts.

## Directory Structure

```
.claude/skills/dast/
├── README.md                    # This file
├── authorization-testing/       # Authorization failure validation
├── command-injection-testing/   # OS command injection validation
├── injection-testing/           # Miscellaneous injection validation
├── nosql-injection-testing/     # NoSQL injection validation
├── sql-injection-testing/       # SQL injection validation
├── xss-testing/                 # Cross-site scripting validation
└── xxe-testing/                 # XML external entity validation
```

Each skill directory contains:
- `SKILL.md` - Core methodology and instructions
- `examples.md` - Real-world examples organized by category
- `reference/` - Implementation examples and helper scripts

## Current Skills

### authorization-testing
**Purpose**: Validate authorization failures including IDOR, privilege escalation, and missing access controls through HTTP-based exploitation attempts.

**Trigger**: CWE-639 (IDOR), CWE-269 (Improper Privilege Management), CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization), CWE-284 (Improper Access Control), CWE-285 (Improper Authorization), CWE-425 (Direct Request / Forced Browsing)

**Requirements**:
- Target application running and reachable
- Test user accounts (optional but recommended)
- VULNERABILITIES.json with IDOR findings

**Output**: Validation status (VALIDATED/FALSE_POSITIVE/UNVALIDATED) with evidence

### sql-injection-testing
**Purpose**: Validate SQL injection vulnerabilities through error-based, union-based, boolean-based, and time-based detection techniques.

**Trigger**: CWE-89 (SQL Injection), CWE-564 (SQL Injection: Hibernate)

**Output**: Validation status with evidence including database type detection and exploitation proof

### nosql-injection-testing
**Purpose**: Validate NoSQL injection vulnerabilities in MongoDB, CouchDB, and other NoSQL databases.

**Trigger**: CWE-943 (NoSQL Injection)

**Output**: Validation status with evidence of query manipulation or data exfiltration

### xss-testing
**Purpose**: Validate Cross-Site Scripting vulnerabilities including reflected, stored, and DOM-based XSS.

**Trigger**: CWE-79 (XSS), CWE-80 through CWE-87 (XSS variants)

**Output**: Validation status with evidence of script execution context

### xxe-testing
**Purpose**: Validate XML External Entity vulnerabilities including file disclosure, SSRF, and denial of service.

**Trigger**: CWE-611 (XXE), CWE-776 (Entity Expansion DoS), CWE-827 (Improper Control of Document Type Definition)

**Output**: Validation status with evidence of entity expansion or external resource access

### command-injection-testing
**Purpose**: Validate OS command injection vulnerabilities through various shell metacharacter and argument injection techniques.

**Trigger**: CWE-78 (OS Command Injection), CWE-77 (Command Injection), CWE-88 (Argument Injection)

**Output**: Validation status with evidence of command execution

### injection-testing
**Purpose**: Validate miscellaneous injection vulnerabilities not covered by dedicated skills (SSTI, LDAP, XPath, XQuery, CRLF/HTTP headers, Expression Language, GraphQL, ORM/HQL, CSV/Formula injection, ReDoS, YAML config, and Shellshock).

**Trigger**: CWE-1336 (SSTI), CWE-90 (LDAP), CWE-643 (XPath), CWE-652 (XQuery), CWE-93/CWE-113 (CRLF/Header Injection), CWE-917 (Expression Language), CWE-94/CWE-95 (Code/Eval Injection), CWE-1333 (ReDoS), CWE-1236 (CSV/Formula)

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
