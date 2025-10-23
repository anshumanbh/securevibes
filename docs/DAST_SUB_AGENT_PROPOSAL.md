# DAST Sub-Agent Integration Proposal for SecureVibes

**Version:** 1.0  
**Date:** 2025-10-23  
**Author:** AI-Assisted Design  
**Status:** Proposal for Review

---

## Executive Summary

This proposal outlines the integration of a Dynamic Application Security Testing (DAST) sub-agent into SecureVibes to validate code review findings through live exploitation attempts, providing proof-of-concept evidence for discovered vulnerabilities.

**Key Features:**
- Validates static analysis findings through dynamic testing
- Provides POC evidence (screenshots, HTTP logs, exploit steps)
- Uses Claude Agent Skills for vulnerability-specific testing logic
- Supports browser-based (Chrome DevTools MCP) and API-based testing
- Optional, non-breaking addition activated via `--dast` CLI flag
- Progressively extensible through skill files (no code changes)

**Business Value:**
- Reduces false positives by confirming exploitability
- Provides actionable evidence for remediation teams
- Prioritizes findings by validated severity
- Saves manual penetration testing time
- Builds institutional knowledge through reusable skills

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Components](#core-components)
3. [Agent Skills Structure](#agent-skills-structure)
4. [CLI Integration](#cli-integration)
5. [MCP Integration](#mcp-integration)
6. [Data Models Enhancement](#data-models-enhancement)
7. [Progressive Skill Addition Strategy](#progressive-skill-addition-strategy)
8. [Error Handling & Edge Cases](#error-handling--edge-cases)
9. [Security & Safety Considerations](#security--safety-considerations)
10. [Testing & Validation](#testing--validation)
11. [Performance Considerations](#performance-considerations)
12. [Cost Estimation](#cost-estimation)
13. [Migration Path](#migration-path)
14. [Documentation Requirements](#documentation-requirements)
15. [Success Metrics](#success-metrics)
16. [Risks & Mitigations](#risks--mitigations)
17. [Future Enhancements](#future-enhancements)
18. [Conclusion](#conclusion)

---

## Architecture Overview

### Current SecureVibes Flow

```
User → CLI → Scanner Orchestrator
                 ├─► Assessment Agent (architecture mapping)
                 ├─► Threat Modeling Agent (STRIDE analysis)
                 ├─► Code Review Agent (vulnerability detection)
                 └─► Report Generator (results formatting)
                      └─► scan_results.json
```

### Proposed Flow with DAST

```
User → CLI (--dast flag + --target-url) → Scanner Orchestrator
                 │
                 ├─► Assessment Agent
                 ├─► Threat Modeling Agent
                 ├─► Code Review Agent
                 │    └─► VULNERABILITIES.json
                 │
                 ├─► DAST Agent (NEW - optional, conditional)
                 │    │
                 │    ├─► Input: VULNERABILITIES.json + target URL
                 │    │
                 │    ├─► Skills: Vulnerability-specific testing logic
                 │    │    ├─► idor-testing/SKILL.md
                 │    │    ├─► sqli-testing/SKILL.md
                 │    │    ├─► xss-testing/SKILL.md
                 │    │    └─► ... (progressively extensible)
                 │    │
                 │    ├─► MCP Integration:
                 │    │    ├─► Chrome DevTools MCP (browser testing)
                 │    │    └─► HTTP MCP (curl-based testing)
                 │    │
                 │    └─► Output: DAST_VALIDATION.json
                 │         ├─► validated: confirmed vulns with POC
                 │         ├─► unvalidated: couldn't be tested
                 │         ├─► false_positives: disproven issues
                 │         └─► screenshots/evidence: proof artifacts
                 │
                 └─► Report Generator (Enhanced)
                      ├─► Merges Code Review + DAST results
                      └─► scan_results.json (with validation_status)
```

### Workflow Sequence

1. **Standard Scan Phases** (unchanged)
   - Assessment → SECURITY.md
   - Threat Modeling → THREAT_MODEL.json
   - Code Review → VULNERABILITIES.json

2. **DAST Phase** (new, conditional on `--dast` flag)
   - Load VULNERABILITIES.json
   - For each vulnerability:
     - Match to appropriate skill
     - Execute exploitation attempt
     - Capture evidence
     - Classify result (VALIDATED/FALSE_POSITIVE/UNVALIDATED)
   - Generate DAST_VALIDATION.json

3. **Report Merging**
   - Combine code review + DAST results
   - Add validation_status to each issue
   - Produce final scan_results.json

---

## Core Components

### 1. DAST Sub-Agent Definition

**File:** `packages/core/securevibes/agents/definitions.py`

**Addition to `create_agent_definitions()`:**

```python
"dast": AgentDefinition(
    description="Validates security vulnerabilities through dynamic testing against running applications. Executes exploitation attempts and captures proof-of-concept evidence.",
    prompt=AGENT_PROMPTS["dast"],
    tools=["Read", "Grep", "Write", "Execute", "Browser"],  # Browser = Chrome DevTools MCP
    model=config.get_agent_model("dast", cli_override=cli_model),
    skills_path=".securevibes/skills/dast"  # Skills directory
)
```

**Key Properties:**
- **Description:** Clear purpose for agent orchestration
- **Tools:** Read/Write for artifacts, Execute for scripts, Browser for MCP
- **Model:** Respects CLI override and environment variables
- **Skills Path:** Directory containing vulnerability-specific skills

---

### 2. DAST Prompt Template

**File:** `packages/core/securevibes/prompts/dast.txt`

```markdown
# DAST Agent: Dynamic Security Validation

You are a security testing expert validating vulnerabilities discovered during static code analysis.

## Context
- Code review has identified potential vulnerabilities in VULNERABILITIES.json
- Target application is running at: {target_url}
- You must validate each finding by attempting exploitation
- Capture proof-of-concept evidence (screenshots, HTTP responses, session data)

## Available Skills
Skills are loaded from .securevibes/skills/dast/ based on vulnerability type:
- idor-testing: Test Insecure Direct Object Reference vulnerabilities
- sqli-testing: Test SQL Injection vulnerabilities  
- xss-testing: Test Cross-Site Scripting vulnerabilities
- auth-bypass-testing: Test authentication bypass issues
- csrf-testing: Test Cross-Site Request Forgery vulnerabilities
- path-traversal-testing: Test path traversal vulnerabilities
- ssrf-testing: Test Server-Side Request Forgery vulnerabilities
- ... (extensible via skill files)

## Workflow

### 1. Load Vulnerabilities
- Read VULNERABILITIES.json from code review phase
- Parse vulnerability details (type, location, CWE, severity)
- Count total vulnerabilities to test

### 2. For Each Vulnerability:

#### a. Determine Testing Approach
- Match vulnerability type/CWE to appropriate skill
- Load skill instructions for that vulnerability class
- If no skill exists, use generic HTTP testing

#### b. Set Up Test Environment
- For browser-based: Use Chrome DevTools MCP
- For API-based: Use curl/HTTP requests
- Establish authenticated session if test accounts provided

#### c. Execute Exploitation Attempt
- Follow skill-specific testing methodology
- Create multiple test cases (user A, user B, admin, etc.)
- Document each step taken
- Respect timeouts (default: 2 minutes per vulnerability)

#### d. Capture Evidence
- Screenshots of successful exploitation
- HTTP request/response pairs
- Session cookies used
- Before/after states
- Error messages or exceptions

#### e. Classify Result
- **VALIDATED**: Successfully exploited, clear POC captured
- **UNVALIDATED**: Couldn't test (endpoint unreachable, missing config)
- **FALSE_POSITIVE**: Testing disproved the vulnerability
- **PARTIAL**: Exploitable but impact differs from code review

### 3. Generate DAST Report
- Create DAST_VALIDATION.json with all results
- Save evidence artifacts to .securevibes/dast_evidence/
- Summary statistics (validation rate, false positive rate)
- Cost and timing information

## Output Format

Create a file `.securevibes/DAST_VALIDATION.json` with this structure:

```json
{
  "dast_scan_metadata": {
    "target_url": "https://example.com",
    "scan_timestamp": "2025-10-23T...",
    "total_vulnerabilities_tested": 15,
    "validated": 8,
    "unvalidated": 3,
    "false_positives": 4,
    "scan_duration_seconds": 420.5
  },
  "validations": [
    {
      "vulnerability_id": "VULN-001",
      "original_severity": "high",
      "validation_status": "VALIDATED",
      "tested_at": "2025-10-23T...",
      "test_steps": [
        "1. Logged in as user1@test.com",
        "2. Accessed /api/users/123 (user1's ID)",
        "3. Modified request to /api/users/456 (user2's ID)",
        "4. Successfully retrieved user2's private data"
      ],
      "evidence": {
        "screenshots": [".securevibes/dast_evidence/vuln-001-1.png"],
        "http_requests": [
          {
            "request": "GET /api/users/456 HTTP/1.1\nCookie: session=...",
            "response": "HTTP/1.1 200 OK\n{\"email\":\"user2@test.com\",\"ssn\":\"[REDACTED]\"}"
          }
        ],
        "session_data": {
          "user1_cookie": "session=abc123...",
          "accessed_user2_data": true
        }
      },
      "impact_confirmed": true,
      "exploitability_score": 9.5,
      "notes": "IDOR confirmed - any authenticated user can access other users' PII"
    }
  ]
}
```

## Testing Modes

### Browser Mode (Chrome DevTools MCP)
- Use for testing web applications with JavaScript
- Capture DOM state and screenshots
- Test XSS, CSRF, client-side issues
- Example: `browser.navigate(url)`, `browser.fill(selector, value)`, `browser.screenshot(path)`

### HTTP Mode (curl/requests)
- Use for API testing
- Test authentication, authorization, injection attacks
- Faster than browser mode
- Example: `curl -X POST {url} -H "Authorization: Bearer {token}" -d {data}`

### Auto Mode (default)
- Decide based on vulnerability type
- Browser for XSS, CSRF, client-side issues
- HTTP for IDOR, SQLi, API issues

## Test Accounts

If provided via --dast-accounts, use this format:

```json
{
  "regular_users": [
    {"email": "user1@test.com", "password": "Pass123!", "user_id": "123"},
    {"email": "user2@test.com", "password": "Pass456!", "user_id": "456"}
  ],
  "admin_users": [
    {"email": "admin@test.com", "password": "Admin789!", "user_id": "999"}
  ],
  "test_data": {
    "document_id_user1": "doc-123",
    "document_id_user2": "doc-456"
  }
}
```

## Safety & Ethics

- ONLY test against --target-url provided by user
- NEVER test production systems without explicit authorization
- STOP immediately if unexpected damage occurs
- DO NOT exfiltrate real user data (capture evidence showing access, don't store actual PII)
- Document all actions for audit trail
- Log all testing activity to .securevibes/dast_audit.log

## Error Handling

- If target unreachable: Mark all as UNVALIDATED, document reason
- If test accounts missing: Test only public endpoints
- If skill not found: Use generic HTTP testing
- If timeout exceeded: Mark as UNVALIDATED with timeout reason
- If unexpected error: Log error, continue with next vulnerability

## Example Success Case

Input vulnerability:
```json
{
  "id": "VULN-001",
  "type": "idor",
  "cwe_id": "CWE-639",
  "severity": "high",
  "title": "IDOR in User Profile API",
  "file_path": "api/users.py",
  "line_number": 42,
  "description": "User ID from URL parameter used directly without authorization check"
}
```

Your validation:
1. Load idor-testing skill
2. Authenticate as user1 (ID: 123)
3. Access /api/users/123 (baseline - should succeed)
4. Access /api/users/456 (user2's ID - should fail but doesn't)
5. Capture response showing user2's data
6. Take screenshots
7. Mark as VALIDATED with evidence

Output:
```json
{
  "vulnerability_id": "VULN-001",
  "validation_status": "VALIDATED",
  "exploitability_score": 9.5,
  "evidence": { ... },
  "notes": "Confirmed IDOR - trivial exploitation"
}
```
```

---

## Agent Skills Structure

Skills follow the [Claude Agent Skills](https://docs.anthropic.com/en/docs/agents-and-tools/agent-skills) format for modular, composable testing logic.

### Skills Directory Structure

```
.securevibes/skills/dast/
├── idor-testing/
│   ├── SKILL.md              # Core testing methodology
│   ├── examples.md           # Example test cases
│   └── scripts/
│       └── validate_idor.py  # Helper validation script
├── sqli-testing/
│   ├── SKILL.md
│   ├── payloads.txt          # SQL injection payloads
│   └── examples.md
├── xss-testing/
│   ├── SKILL.md
│   ├── payloads.txt          # XSS payloads
│   └── examples.md
├── auth-bypass-testing/
│   ├── SKILL.md
│   └── examples.md
├── csrf-testing/
│   ├── SKILL.md
│   └── examples.md
├── path-traversal-testing/
│   ├── SKILL.md
│   └── examples.md
└── ssrf-testing/
    ├── SKILL.md
    └── examples.md
```

### Example Skill: IDOR Testing

**File:** `.securevibes/skills/dast/idor-testing/SKILL.md`

```markdown
---
name: idor-testing
description: Test Insecure Direct Object Reference vulnerabilities by attempting unauthorized access to resources using object ID manipulation. Use when validating IDOR, broken access control, or CWE-639 findings.
allowed-tools: Read, Browser, Execute, Write
---

# IDOR Testing Skill

## Purpose
Validate IDOR vulnerabilities by testing if authenticated users can access resources belonging to other users through direct object reference manipulation.

## Prerequisites
- Target application URL
- At least 2 test user accounts with different privilege levels
- Details of vulnerable endpoint from code review

## Testing Methodology

### Phase 1: Reconnaissance
1. **Identify Object References**
   - From code review: Find endpoints using object IDs (user IDs, document IDs, etc.)
   - Example patterns: `/api/users/{id}`, `/documents/{doc_id}`, `/orders/{order_id}`

2. **Map Access Control**
   - Determine what objects user1 should access
   - Determine what objects user2 should access
   - Identify admin-only resources

### Phase 2: Set Up Test Accounts

**If using Chrome DevTools MCP:**
```python
# Authenticate as user1
browser.navigate(target_url + "/login")
browser.fill("input[name='email']", "user1@test.com")
browser.fill("input[name='password']", "TestPass123!")
browser.click("button[type='submit']")
browser.wait_for_navigation()

# Capture user1 session
user1_cookies = browser.get_cookies()
```

**If using HTTP/curl:**
```bash
# Get user1 session token
curl -X POST {target_url}/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user1@test.com","password":"TestPass123!"}' \
  -c user1_cookies.txt

# Extract token
user1_token=$(grep session user1_cookies.txt | cut -f7)
```

### Phase 3: Execute IDOR Tests

**Test Case Template:**

1. **Establish Baseline (Authorized Access)**
   - User1 accesses their own resource (user1_id)
   - Verify: HTTP 200, data returned correctly
   - Capture: Screenshot/response showing successful legitimate access

2. **Attempt Unauthorized Access**
   - User1 attempts to access user2's resource (user2_id)
   - Keep user1's session/auth token
   - Only change the object ID in URL/request
   
   Example:
   ```
   Authorized:   GET /api/users/123 (user1_id) → 200 OK
   Unauthorized: GET /api/users/456 (user2_id) → Should be 403, test if 200
   ```

3. **Verify Impact**
   - If 200 OK: IDOR confirmed
   - Check response contains sensitive data
   - Document what data was exposed

4. **Test Different HTTP Methods**
   - GET: Read access
   - PUT/PATCH: Modify access
   - DELETE: Delete access
   - POST: Create under wrong owner

### Phase 4: Capture Evidence

**For Browser-Based Testing:**
```python
# Take screenshot before
browser.screenshot(".securevibes/dast_evidence/idor-before.png")

# Execute IDOR
browser.navigate(f"{target_url}/api/users/{user2_id}")

# Take screenshot after
browser.screenshot(".securevibes/dast_evidence/idor-after.png")

# Capture network traffic
network_log = browser.get_network_log()
```

**For API Testing:**
```bash
# Save full request/response
curl -v -X GET {target_url}/api/users/{user2_id} \
  -H "Authorization: Bearer {user1_token}" \
  2>&1 | tee .securevibes/dast_evidence/idor-test-output.txt
```

### Phase 5: Classification

**VALIDATED** if:
- Unauthorized access succeeds (HTTP 200/2xx)
- Response contains other user's data
- Access control is clearly bypassed

**FALSE_POSITIVE** if:
- Proper 403/401 error returned
- Generic data returned (no sensitive info)
- Access control working as expected

**UNVALIDATED** if:
- Endpoint unreachable (404)
- Cannot obtain test accounts
- Application state prevents testing

## Common IDOR Patterns

### Pattern 1: Sequential IDs
```
User A ID: 123 → Can access /users/124, /users/125, etc.
```

### Pattern 2: UUIDs (harder but still testable)
```
User A UUID: abc-def-123
User B UUID: xyz-pqr-789  
Test: Can User A access resource xyz-pqr-789?
```

### Pattern 3: Nested Resources
```
/api/users/123/documents/456
Test: Can user 999 access /api/users/123/documents/456?
```

### Pattern 4: Batch Operations
```
POST /api/users/bulk-update
{"user_ids": [123, 456, 789]}
Test: Can user 123 update users 456 and 789?
```

## Evidence Checklist
- [ ] Screenshot/response showing legitimate access (baseline)
- [ ] Screenshot/response showing unauthorized access succeeding
- [ ] HTTP request headers (showing user1's auth)
- [ ] HTTP response body (showing user2's data)
- [ ] Session cookies used
- [ ] Timestamp of test
- [ ] Exploitability notes

## Example Output

```json
{
  "vulnerability_id": "VULN-IDOR-001",
  "validation_status": "VALIDATED",
  "test_summary": "User1 successfully accessed User2's profile data",
  "test_steps": [
    "1. Logged in as user1@test.com (ID: 123)",
    "2. Verified legitimate access to /api/users/123 → 200 OK",
    "3. Modified request to /api/users/456 (user2's ID)",
    "4. Received 200 OK with user2's email, phone, address"
  ],
  "evidence": {
    "screenshots": ["idor-baseline.png", "idor-exploit.png"],
    "http_logs": ["idor-test-output.txt"],
    "sensitive_data_exposed": ["email", "phone", "address", "ssn"]
  },
  "impact": "Any authenticated user can access PII of all other users",
  "exploitability": "Trivial - only requires changing ID in URL",
  "recommendation": "Implement object-level authorization checks"
}
```

## Timeout Configuration
- Simple IDOR test: 60 seconds
- Complex multi-step: 120 seconds
- If exceeded: Mark as UNVALIDATED with timeout reason

## References
- CWE-639: Authorization Bypass Through User-Controlled Key
- OWASP Top 10: A01:2021 - Broken Access Control
- See `examples.md` for more test cases
```

### Additional Skills to Implement

Following the same structure pattern:

1. **sqli-testing/SKILL.md** - SQL Injection validation
2. **xss-testing/SKILL.md** - Cross-Site Scripting validation
3. **auth-bypass-testing/SKILL.md** - Authentication bypass validation
4. **csrf-testing/SKILL.md** - CSRF token validation
5. **path-traversal-testing/SKILL.md** - Path traversal validation
6. **ssrf-testing/SKILL.md** - Server-Side Request Forgery validation
7. **sensitive-data-exposure-testing/SKILL.md** - Unencrypted data validation

Each follows: reconnaissance → setup → execute → capture → classify.

---

## CLI Integration

### Modified CLI Command

**File:** `packages/core/securevibes/cli/main.py`

**New flags added to `scan` command:**

```python
@cli.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--model', '-m', default='sonnet', help='Claude model to use')
@click.option('--dast', is_flag=True, help='Enable DAST validation phase')
@click.option('--target-url', type=str, help='Target application URL for DAST (required with --dast)')
@click.option('--dast-accounts', type=click.Path(exists=True), help='JSON file with test accounts for DAST')
@click.option('--dast-mode', type=click.Choice(['browser', 'http', 'auto']), default='auto',
              help='DAST testing mode: browser (Chrome DevTools), http (curl), auto (decide per vuln)')
@click.option('--allow-production', is_flag=True, help='Allow DAST testing on production URLs (use with caution)')
@click.option('--dast-timeout', type=int, default=120, help='Timeout per vulnerability test in seconds')
# ... existing options ...
def scan(path: str, model: str, dast: bool, target_url: Optional[str], 
         dast_accounts: Optional[str], dast_mode: str, allow_production: bool,
         dast_timeout: int, ...):
    """
    Scan a repository for security vulnerabilities.
    
    Examples:
    
        # Standard scan (no DAST)
        securevibes scan .
        
        # Scan with DAST validation
        securevibes scan . --dast --target-url http://localhost:3000
        
        # DAST with test accounts
        securevibes scan . --dast --target-url http://localhost:3000 \\
            --dast-accounts test_users.json
        
        # DAST in browser mode only
        securevibes scan . --dast --target-url http://localhost:3000 \\
            --dast-mode browser
        
        # DAST with custom timeout
        securevibes scan . --dast --target-url http://staging.example.com \\
            --dast-timeout 300
    """
    try:
        # Validate DAST requirements
        if dast and not target_url:
            console.print("[red]Error: --target-url required when --dast is enabled[/red]")
            console.print("[dim]Example: securevibes scan . --dast --target-url http://localhost:3000[/dim]")
            sys.exit(1)
        
        # Safety check for production URLs
        if dast and target_url:
            _check_production_url(target_url, allow_production)
        
        # Run standard scan phases
        console.print("[bold cyan]🛡️ SecureVibes Security Scanner[/bold cyan]")
        console.print("[dim]Phase 1-3: Static Analysis[/dim]")
        console.print()
        
        result = asyncio.run(_run_scan(path, model, not no_save, quiet, debug))
        
        # Conditionally run DAST phase
        if dast:
            console.print("\n" + "="*80)
            console.print("[bold cyan]Phase 4: DAST Validation[/bold cyan]")
            console.print("="*80)
            console.print(f"🎯 Target: {target_url}")
            console.print(f"🧪 Mode: {dast_mode}")
            console.print(f"⏱️  Timeout: {dast_timeout}s per vulnerability")
            console.print()
            
            dast_result = asyncio.run(_run_dast_validation(
                path=path,
                target_url=target_url,
                vulnerabilities_file=Path(path) / '.securevibes' / 'VULNERABILITIES.json',
                accounts_file=dast_accounts,
                mode=dast_mode,
                timeout=dast_timeout,
                model=model,
                debug=debug
            ))
            
            # Merge DAST results into scan result
            result = _merge_dast_results(result, dast_result)
            
            # Show DAST summary
            _display_dast_summary(dast_result)
        
        # Output results (existing logic continues)
        # ...
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan cancelled by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]❌ Error:[/bold red] {e}", style="red")
        sys.exit(1)
```

### DAST Validation Function

```python
async def _run_dast_validation(
    path: str,
    target_url: str,
    vulnerabilities_file: Path,
    accounts_file: Optional[str],
    mode: str,
    timeout: int,
    model: str,
    debug: bool
) -> dict:
    """Execute DAST validation phase"""
    
    # Check if target is reachable
    if not _check_target_reachable(target_url):
        console.print(f"[red]❌ Target unreachable: {target_url}[/red]")
        console.print("[dim]Ensure the application is running at the specified URL[/dim]")
        sys.exit(1)
    
    # Load test accounts if provided
    test_accounts = {}
    if accounts_file:
        try:
            with open(accounts_file) as f:
                test_accounts = json.load(f)
            console.print(f"✅ Loaded test accounts from {accounts_file}")
        except Exception as e:
            console.print(f"[yellow]⚠️  Warning: Could not load test accounts: {e}[/yellow]")
            console.print("[dim]Proceeding with unauthenticated testing only[/dim]")
    
    # Verify vulnerabilities file exists
    if not vulnerabilities_file.exists():
        console.print(f"[red]❌ VULNERABILITIES.json not found[/red]")
        console.print("[dim]Run standard scan first to generate vulnerability findings[/dim]")
        sys.exit(1)
    
    # Load vulnerabilities
    with open(vulnerabilities_file) as f:
        vulnerabilities_data = json.load(f)
    
    vuln_count = len(vulnerabilities_data) if isinstance(vulnerabilities_data, list) else \
                 len(vulnerabilities_data.get('vulnerabilities', []))
    
    console.print(f"🔍 Found {vuln_count} vulnerabilities to validate\n")
    
    # Initialize DAST agent
    agents = create_agent_definitions(cli_model=model)
    dast_agent = agents.get("dast")
    
    if not dast_agent:
        console.print("[red]❌ DAST agent not found in definitions[/red]")
        sys.exit(1)
    
    # Prepare DAST prompt
    dast_prompt_template = load_prompt("dast")
    dast_prompt = dast_prompt_template.format(
        target_url=target_url,
        vulnerabilities_file=str(vulnerabilities_file),
        test_accounts=json.dumps(test_accounts, indent=2) if test_accounts else "{}",
        mode=mode,
        timeout=timeout
    )
    
    # Initialize progress tracker
    tracker = ProgressTracker(console, debug=debug)
    
    # Configure hooks (similar to main scanner)
    async def pre_tool_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
        tool_name = input_data.get("tool_name")
        tool_input = input_data.get("tool_input", {})
        tracker.on_tool_start(tool_name, tool_input)
        return {}
    
    async def post_tool_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
        tool_name = input_data.get("tool_name")
        tool_response = input_data.get("tool_response", {})
        is_error = tool_response.get("is_error", False)
        error_msg = tool_response.get("content", "") if is_error else None
        tracker.on_tool_complete(tool_name, not is_error, error_msg)
        return {}
    
    from claude_agent_sdk.types import HookMatcher
    
    # Execute DAST agent with skills
    options = ClaudeAgentOptions(
        agents={"dast": dast_agent},
        cwd=str(Path(path).resolve()),
        max_turns=config.get_max_turns() * 2,  # DAST may need more turns
        permission_mode='bypassPermissions',
        model=model,
        skills_path=Path(path).resolve() / ".securevibes" / "skills" / "dast",
        hooks={
            "PreToolUse": [HookMatcher(hooks=[pre_tool_hook])],
            "PostToolUse": [HookMatcher(hooks=[post_tool_hook])]
        }
    )
    
    tracker.announce_phase("dast")
    
    try:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(dast_prompt)
            
            # Stream messages
            async for message in client.receive_messages():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            tracker.on_assistant_text(block.text)
                
                elif isinstance(message, ResultMessage):
                    console.print("\n✅ DAST validation complete", style="bold green")
                    break
        
    except Exception as e:
        console.print(f"\n[red]❌ DAST validation failed: {e}[/red]")
        raise
    
    # Load DAST results
    dast_results_file = Path(path) / '.securevibes' / 'DAST_VALIDATION.json'
    
    if not dast_results_file.exists():
        console.print(f"[yellow]⚠️  Warning: DAST_VALIDATION.json not created[/yellow]")
        return {
            "dast_scan_metadata": {
                "target_url": target_url,
                "total_vulnerabilities_tested": 0,
                "validated": 0,
                "unvalidated": 0,
                "false_positives": 0
            },
            "validations": []
        }
    
    with open(dast_results_file) as f:
        return json.load(f)
```

### Helper Functions

```python
def _check_production_url(target_url: str, allow_production: bool):
    """Check if URL looks like production and require explicit flag"""
    import re
    
    PRODUCTION_PATTERNS = [
        r'\.com$',
        r'\.org$',
        r'\.net$',
        r'production',
        r'prod\.',
        r'live\.',
        r'www\.',
        r'api\.[a-z]+\.com'
    ]
    
    is_production = any(re.search(pattern, target_url, re.IGNORECASE) 
                       for pattern in PRODUCTION_PATTERNS)
    
    if is_production and not allow_production:
        console.print("[bold red]⚠️  WARNING: Target URL appears to be a production system![/bold red]")
        console.print(f"   {target_url}")
        console.print()
        console.print("[yellow]DAST testing on production requires explicit authorization.[/yellow]")
        console.print("[yellow]If you have authorization, add --allow-production flag.[/yellow]")
        console.print()
        console.print("[dim]Example: securevibes scan . --dast --target-url {url} --allow-production[/dim]")
        sys.exit(1)
    
    if is_production and allow_production:
        console.print("[yellow]⚠️  Production testing enabled with --allow-production[/yellow]")
        console.print("[yellow]   Ensure you have explicit authorization![/yellow]")
        
        confirm = click.confirm("Do you have authorization to test this production system?", default=False)
        if not confirm:
            console.print("[red]DAST cancelled - authorization not confirmed[/red]")
            sys.exit(1)

def _check_target_reachable(target_url: str) -> bool:
    """Check if target application is reachable"""
    import requests
    try:
        response = requests.head(target_url, timeout=5, allow_redirects=True)
        return True
    except requests.RequestException:
        try:
            response = requests.get(target_url, timeout=5, allow_redirects=True)
            return True
        except requests.RequestException:
            return False

def _merge_dast_results(scan_result: ScanResult, dast_result: dict) -> ScanResult:
    """Merge DAST validation results into scan result"""
    
    # Create mapping of vulnerability ID to DAST validation
    validations_map = {
        v["vulnerability_id"]: v 
        for v in dast_result.get("validations", [])
    }
    
    # Update each issue with DAST validation data
    for issue in scan_result.issues:
        validation = validations_map.get(issue.id)
        if validation:
            issue.validation_status = validation["validation_status"]
            issue.dast_evidence = validation.get("evidence")
            issue.exploitability_score = validation.get("exploitability_score")
            issue.validated_at = validation.get("tested_at")
    
    # Update scan result metadata
    metadata = dast_result.get("dast_scan_metadata", {})
    scan_result.dast_enabled = True
    scan_result.dast_validation_rate = (
        metadata.get("validated", 0) / metadata.get("total_vulnerabilities_tested", 1) * 100
    )
    scan_result.dast_false_positive_rate = (
        metadata.get("false_positives", 0) / metadata.get("total_vulnerabilities_tested", 1) * 100
    )
    scan_result.dast_scan_time_seconds = metadata.get("scan_duration_seconds")
    
    return scan_result

def _display_dast_summary(dast_result: dict):
    """Display DAST validation summary"""
    metadata = dast_result.get("dast_scan_metadata", {})
    
    console.print("\n" + "="*80)
    console.print("[bold]DAST Validation Summary[/bold]")
    console.print("="*80)
    
    total = metadata.get("total_vulnerabilities_tested", 0)
    validated = metadata.get("validated", 0)
    false_pos = metadata.get("false_positives", 0)
    unvalidated = metadata.get("unvalidated", 0)
    
    console.print(f"Total tested: {total}")
    console.print(f"✅ Validated: [green]{validated}[/green] ({validated/total*100:.1f}%)" if total > 0 else "✅ Validated: 0")
    console.print(f"❌ False positives: [red]{false_pos}[/red] ({false_pos/total*100:.1f}%)" if total > 0 else "❌ False positives: 0")
    console.print(f"⚠️  Unvalidated: [yellow]{unvalidated}[/yellow] ({unvalidated/total*100:.1f}%)" if total > 0 else "⚠️  Unvalidated: 0")
    
    console.print(f"\n💾 Evidence saved to: [cyan].securevibes/dast_evidence/[/cyan]")
    console.print(f"📄 Full results: [cyan].securevibes/DAST_VALIDATION.json[/cyan]")
```

### Example Usage

```bash
# Standard scan (no DAST)
securevibes scan .

# Scan with DAST validation (auto-mode)
securevibes scan . --dast --target-url http://localhost:3000

# DAST with test accounts
securevibes scan . --dast --target-url http://localhost:3000 --dast-accounts test_users.json

# DAST in browser mode only
securevibes scan . --dast --target-url http://localhost:3000 --dast-mode browser

# DAST with custom timeout
securevibes scan . --dast --target-url http://staging.example.com --dast-timeout 300

# DAST on staging (production-like URL)
securevibes scan . --dast --target-url https://staging.example.com --allow-production

# DAST with specific model
securevibes scan . --model opus --dast --target-url http://localhost:3000
```

### Test Accounts File Format

**File:** `test_users.json`

```json
{
  "regular_users": [
    {
      "email": "user1@test.com",
      "password": "TestPass123!",
      "user_id": "123",
      "role": "user"
    },
    {
      "email": "user2@test.com",
      "password": "TestPass456!",
      "user_id": "456",
      "role": "user"
    }
  ],
  "admin_users": [
    {
      "email": "admin@test.com",
      "password": "AdminPass789!",
      "user_id": "999",
      "role": "admin"
    }
  ],
  "test_data": {
    "document_id_user1": "doc-123",
    "document_id_user2": "doc-456",
    "api_base_url": "/api/v1"
  }
}
```

---

## MCP Integration

### Chrome DevTools MCP Setup

The DAST agent can leverage Chrome DevTools MCP for browser-based testing.

**User Configuration:** `.claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "chrome-devtools": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-chrome-devtools"]
    }
  }
}
```

### MCP Detection in DAST Agent

```python
def browser_mcp_available() -> bool:
    """Check if Chrome DevTools MCP is configured and available"""
    try:
        # Check if MCP server is in config
        config_path = Path.home() / ".claude" / "claude_desktop_config.json"
        if not config_path.exists():
            return False
        
        with open(config_path) as f:
            config = json.load(f)
        
        return "chrome-devtools" in config.get("mcpServers", {})
    except Exception:
        return False
```

### Testing Mode Decision Logic

```python
def determine_testing_mode(vulnerability: dict, requested_mode: str) -> str:
    """Determine whether to use browser or HTTP testing"""
    
    if requested_mode in ["browser", "http"]:
        return requested_mode
    
    # Auto mode: decide based on vulnerability type
    browser_required_types = [
        "xss",
        "csrf",
        "dom-based-xss",
        "clickjacking",
        "client-side-validation-bypass"
    ]
    
    vuln_type = vulnerability.get("type", "").lower()
    
    if any(vtype in vuln_type for vtype in browser_required_types):
        if browser_mcp_available():
            return "browser"
        else:
            console.print(f"[yellow]⚠️  {vulnerability['id']}: Browser mode required but MCP unavailable[/yellow]")
            console.print("[dim]   Install Chrome DevTools MCP or use --dast-mode http[/dim]")
            return "skip"
    
    return "http"
```

### HTTP Fallback Implementation

When browser MCP is unavailable or not needed, use standard HTTP requests:

```python
import requests

def test_via_http(vulnerability: dict, target_url: str, auth_token: str = None):
    """Test vulnerability using HTTP requests"""
    
    headers = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    
    # Example: IDOR testing
    if vulnerability["type"] == "idor":
        # Baseline: authorized access
        authorized_url = f"{target_url}{vulnerability['endpoint']}"
        response_auth = requests.get(authorized_url, headers=headers)
        
        # Test: unauthorized access
        modified_id = _get_different_object_id(vulnerability)
        unauthorized_url = authorized_url.replace(
            str(vulnerability["object_id"]), 
            str(modified_id)
        )
        response_unauth = requests.get(unauthorized_url, headers=headers)
        
        # Analyze results
        if response_unauth.status_code == 200:
            return {
                "status": "VALIDATED",
                "evidence": {
                    "http_requests": [
                        {
                            "request": f"GET {unauthorized_url}",
                            "response": response_unauth.text[:500]
                        }
                    ]
                }
            }
        elif response_unauth.status_code in [401, 403]:
            return {"status": "FALSE_POSITIVE"}
        else:
            return {"status": "UNVALIDATED", "reason": f"Unexpected status {response_unauth.status_code}"}
```

---

## Data Models Enhancement

### Modified SecurityIssue Model

**File:** `packages/core/securevibes/models/issue.py`

```python
@dataclass
class SecurityIssue:
    """Security vulnerability with optional DAST validation"""
    
    # Existing fields
    id: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None
    
    # NEW: DAST validation fields
    validation_status: Optional[str] = None  # VALIDATED, FALSE_POSITIVE, UNVALIDATED, PARTIAL
    dast_evidence: Optional[dict] = None  # Evidence artifacts
    exploitability_score: Optional[float] = None  # 0-10 scale
    validated_at: Optional[str] = None  # ISO timestamp
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        base_dict = {
            "id": self.id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
        }
        
        # Include DAST fields if present
        if self.validation_status:
            base_dict.update({
                "validation_status": self.validation_status,
                "dast_evidence": self.dast_evidence,
                "exploitability_score": self.exploitability_score,
                "validated_at": self.validated_at
            })
        
        return base_dict
    
    @property
    def is_validated(self) -> bool:
        """Check if issue was validated by DAST"""
        return self.validation_status == "VALIDATED"
    
    @property
    def is_false_positive(self) -> bool:
        """Check if issue was disproven by DAST"""
        return self.validation_status == "FALSE_POSITIVE"
```

### Enhanced ScanResult Model

**File:** `packages/core/securevibes/models/result.py`

```python
@dataclass
class ScanResult:
    """Scan results with optional DAST metrics"""
    
    # Existing fields
    repository_path: str
    issues: List[SecurityIssue]
    files_scanned: int
    scan_time_seconds: float
    total_cost_usd: float = 0.0
    
    # NEW: DAST metrics
    dast_enabled: bool = False
    dast_validation_rate: Optional[float] = None  # % of issues validated
    dast_false_positive_rate: Optional[float] = None
    dast_scan_time_seconds: Optional[float] = None
    
    @property
    def validated_issues(self) -> List[SecurityIssue]:
        """Return only DAST-validated issues"""
        return [i for i in self.issues if i.validation_status == "VALIDATED"]
    
    @property
    def false_positives(self) -> List[SecurityIssue]:
        """Return issues disproven by DAST"""
        return [i for i in self.issues if i.validation_status == "FALSE_POSITIVE"]
    
    @property
    def unvalidated_issues(self) -> List[SecurityIssue]:
        """Return issues that couldn't be tested"""
        return [i for i in self.issues if i.validation_status == "UNVALIDATED"]
    
    def to_dict(self) -> dict:
        """Convert to dictionary with DAST fields"""
        result = {
            "repository_path": self.repository_path,
            "files_scanned": self.files_scanned,
            "scan_time_seconds": self.scan_time_seconds,
            "total_cost_usd": self.total_cost_usd,
            "issues": [issue.to_dict() for issue in self.issues],
            "summary": {
                "total": len(self.issues),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            }
        }
        
        # Add DAST metrics if enabled
        if self.dast_enabled:
            result["dast_metrics"] = {
                "enabled": True,
                "validation_rate": self.dast_validation_rate,
                "false_positive_rate": self.dast_false_positive_rate,
                "scan_time_seconds": self.dast_scan_time_seconds,
                "validated_count": len(self.validated_issues),
                "false_positive_count": len(self.false_positives),
                "unvalidated_count": len(self.unvalidated_issues)
            }
        
        return result
```

---

## Progressive Skill Addition Strategy

Skills enable progressive enhancement without modifying core DAST agent code.

### Implementation Phases

#### Phase 1: MVP - Core IDOR Skill (Week 1-2)
**Goal:** Validate feasibility of DAST approach

- Implement `idor-testing/SKILL.md`
- Covers most common web app vulnerability
- Build evidence capture system
- Test with sample vulnerable app

**Success Criteria:**
- IDOR vulnerabilities successfully validated
- Evidence artifacts captured correctly
- Skill triggers appropriately for CWE-639

#### Phase 2: Injection Skills (Week 3-4)
**Goal:** Expand to high-impact vulnerability classes

- `sqli-testing/SKILL.md` - SQL injection validation
- `xss-testing/SKILL.md` - Cross-site scripting validation
- `command-injection-testing/SKILL.md` - OS command injection

**Success Criteria:**
- Injection attacks detected and validated
- Payloads generate appropriate evidence
- No false positives on properly sanitized inputs

#### Phase 3: Authentication & Session Skills (Week 5-6)
**Goal:** Cover authentication vulnerabilities

- `auth-bypass-testing/SKILL.md` - Authentication bypass validation
- `session-fixation-testing/SKILL.md` - Session management issues
- `csrf-testing/SKILL.md` - CSRF token validation

**Success Criteria:**
- Session handling issues validated
- CSRF protections properly tested
- Auth bypass scenarios detected

#### Phase 4: Advanced Web Skills (Week 7-8)
**Goal:** Comprehensive web vulnerability coverage

- `ssrf-testing/SKILL.md` - Server-side request forgery
- `xxe-testing/SKILL.md` - XML external entity
- `path-traversal-testing/SKILL.md` - Directory traversal
- `deserialization-testing/SKILL.md` - Unsafe deserialization

**Success Criteria:**
- Complex attack chains validated
- Multi-step exploits captured
- Evidence clearly demonstrates impact

#### Phase 5: Cloud & API Skills (Week 9-10)
**Goal:** Modern application security

- `s3-misconfiguration-testing/SKILL.md` - Cloud storage issues
- `api-security-testing/SKILL.md` - API-specific vulnerabilities
- `jwt-testing/SKILL.md` - JWT token validation
- `graphql-testing/SKILL.md` - GraphQL security issues

**Success Criteria:**
- Cloud misconfigurations detected
- API security issues validated
- Token vulnerabilities exploited

### Adding New Skills

**Process:**
1. Create skill directory: `.securevibes/skills/dast/{vuln-type}-testing/`
2. Write `SKILL.md` with testing methodology
3. Add examples in `examples.md`
4. Test against sample vulnerable application
5. Document in skill catalog

**No code changes required!** The DAST agent automatically discovers and uses new skills.

---

## Error Handling & Edge Cases

### 1. Target Application Unreachable

**Scenario:** Application not running or URL incorrect

**Handling:**
```python
if not can_reach_target(target_url):
    return {
        "status": "ERROR",
        "reason": "Target application unreachable",
        "dast_scan_metadata": {
            "target_url": target_url,
            "total_vulnerabilities_tested": 0,
            "validated": 0,
            "unvalidated": len(vulnerabilities),
            "false_positives": 0
        },
        "validations": [
            {
                "vulnerability_id": v["id"],
                "validation_status": "UNVALIDATED",
                "reason": "Target unreachable"
            }
            for v in vulnerabilities
        ]
    }
```

**User Guidance:**
```
❌ Target unreachable: http://localhost:3000
   
Ensure the application is running:
- Check if server is started
- Verify port number is correct
- Check firewall rules
```

### 2. Missing Test Accounts

**Scenario:** No test accounts provided or accounts don't work

**Handling:**
```python
if not test_accounts_provided:
    console.print("[yellow]⚠️  No test accounts provided[/yellow]")
    console.print("[dim]   Testing only public/unauthenticated endpoints[/dim]")
    
    # Filter vulnerabilities to only test unauthenticated ones
    testable_vulns = [
        v for v in vulnerabilities 
        if not requires_authentication(v)
    ]
    
    console.print(f"[dim]   {len(testable_vulns)}/{len(vulnerabilities)} vulnerabilities testable without auth[/dim]")
```

**Graceful Degradation:**
- Test public endpoints only
- Mark authenticated endpoints as UNVALIDATED with reason
- Provide guidance on creating test accounts

### 3. Skill Not Found for Vulnerability Type

**Scenario:** Vulnerability type doesn't have a specialized skill

**Handling:**
```python
def get_skill_for_vulnerability(vuln: dict) -> Optional[str]:
    """Map vulnerability to skill, return None if not found"""
    
    cwe_to_skill = {
        "CWE-639": "idor-testing",
        "CWE-89": "sqli-testing",
        "CWE-79": "xss-testing",
        # ... more mappings
    }
    
    skill = cwe_to_skill.get(vuln.get("cwe_id"))
    
    if not skill:
        console.print(f"[dim]   {vuln['id']}: No specialized skill, using generic testing[/dim]")
        return "generic-http-testing"
    
    return skill
```

**Fallback Strategy:**
- Use generic HTTP request testing
- Log warning about missing skill
- Suggest contributing new skill for this vulnerability type

### 4. DAST Timeout Exceeded

**Scenario:** Vulnerability test takes too long

**Handling:**
```python
DAST_PER_VULN_TIMEOUT = {
    "idor": 60,        # 1 minute
    "sqli": 300,       # 5 minutes (blind SQLi can be slow)
    "xss": 90,         # 1.5 minutes
    "default": 120     # 2 minutes
}

async def test_with_timeout(vuln: dict, timeout: int):
    """Test vulnerability with timeout"""
    try:
        return await asyncio.wait_for(
            test_vulnerability(vuln),
            timeout=timeout
        )
    except asyncio.TimeoutError:
        return {
            "vulnerability_id": vuln["id"],
            "validation_status": "UNVALIDATED",
            "reason": f"Testing timeout exceeded ({timeout}s)",
            "notes": "Consider increasing --dast-timeout or testing manually"
        }
```

### 5. Browser MCP Unavailable

**Scenario:** Chrome DevTools MCP not configured but required

**Handling:**
```python
if requires_browser(vuln) and not browser_mcp_available():
    console.print(f"[yellow]⚠️  {vuln['id']}: Requires browser testing but MCP unavailable[/yellow]")
    console.print("[dim]   Install Chrome DevTools MCP:[/dim]")
    console.print("[dim]   npx @modelcontextprotocol/create-app[/dim]")
    
    return {
        "vulnerability_id": vuln["id"],
        "validation_status": "UNVALIDATED",
        "reason": "Chrome DevTools MCP required but not available",
        "recommendation": "Install MCP or use --dast-mode http for API-only testing"
    }
```

### 6. False Negative (Real Vuln Not Exploited)

**Scenario:** DAST fails to exploit a real vulnerability

**Strategy:**
- Mark as `UNVALIDATED` rather than `FALSE_POSITIVE`
- Preserve original code review finding
- Document why testing failed
- Suggest manual verification

```python
if test_failed_but_vuln_likely_real(vuln, test_result):
    return {
        "vulnerability_id": vuln["id"],
        "validation_status": "UNVALIDATED",
        "reason": "Exploitation attempt unsuccessful",
        "notes": "Code review finding preserved - manual verification recommended",
        "automated_test_results": test_result
    }
```

### 7. Application State Issues

**Scenario:** Tests interfere with each other or application state

**Handling:**
- Implement test isolation strategies
- Reset application state between tests (if possible)
- Document state-dependent failures

```python
def cleanup_after_test(vuln: dict):
    """Cleanup actions after testing"""
    # Delete test data created
    # Log out test sessions
    # Reset modified state
    pass
```

---

## Security & Safety Considerations

### 1. Authorization Verification

**Pre-DAST Confirmation:**
```python
def verify_authorization(target_url: str):
    """Require explicit user confirmation for DAST"""
    
    console.print("\n" + "="*80)
    console.print("[bold yellow]⚠️  SECURITY TESTING AUTHORIZATION REQUIRED[/bold yellow]")
    console.print("="*80)
    console.print()
    console.print("DAST will perform security testing against:")
    console.print(f"   🎯 {target_url}")
    console.print()
    console.print("[yellow]You must have explicit authorization to test this application.[/yellow]")
    console.print()
    console.print("Unauthorized security testing may be illegal and could result in:")
    console.print("   • Criminal charges")
    console.print("   • Civil liability")
    console.print("   • Termination of employment")
    console.print("   • Damage to systems or data")
    console.print()
    
    confirm = click.confirm(
        "Do you have explicit written authorization to test this target?",
        default=False
    )
    
    if not confirm:
        console.print("\n[red]❌ DAST testing cancelled - authorization not confirmed[/red]")
        sys.exit(1)
    
    # Log authorization confirmation
    _log_authorization_confirmation(target_url)
```

### 2. Production Environment Protection

**URL Pattern Detection:**
```python
PRODUCTION_INDICATORS = [
    # Domain patterns
    r'\.com$', r'\.org$', r'\.net$',
    
    # Subdomain patterns
    r'^(www|api|app)\.',
    r'production', r'prod\.', r'live\.',
    
    # Cloud provider patterns
    r'\.amazonaws\.com$',
    r'\.azurewebsites\.net$',
    r'\.herokuapp\.com$',
    r'\.vercel\.app$',
    
    # Common production ports
    r':443$', r':80$'
]

def detect_production_environment(target_url: str) -> bool:
    """Detect if URL appears to be production"""
    return any(
        re.search(pattern, target_url, re.IGNORECASE)
        for pattern in PRODUCTION_INDICATORS
    )
```

**Safe Defaults:**
```python
# Localhost/staging patterns (allowed by default)
SAFE_PATTERNS = [
    r'^https?://localhost',
    r'^https?://127\.0\.0\.1',
    r'^https?://0\.0\.0\.0',
    r'staging', r'stage\.', r'dev\.', r'test\.',
    r'\.local$', r'\.test$', r'\.localhost$'
]
```

### 3. Evidence Sanitization

**PII Redaction:**
```python
SENSITIVE_FIELDS = [
    'ssn', 'social_security_number',
    'credit_card', 'card_number', 'cvv',
    'password', 'passwd', 'pwd',
    'token', 'access_token', 'refresh_token',
    'api_key', 'secret', 'private_key',
    'dob', 'date_of_birth',
    'drivers_license', 'passport'
]

def sanitize_evidence(response_data: dict) -> dict:
    """Redact sensitive fields from captured evidence"""
    sanitized = response_data.copy()
    
    def redact_recursive(obj):
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                if any(sensitive in key.lower() for sensitive in SENSITIVE_FIELDS):
                    obj[key] = "[REDACTED]"
                else:
                    redact_recursive(obj[key])
        elif isinstance(obj, list):
            for item in obj:
                redact_recursive(item)
    
    redact_recursive(sanitized)
    return sanitized
```

**Screenshot Privacy:**
```python
def capture_screenshot_with_redaction(page, filename: str):
    """Capture screenshot with sensitive data blurred"""
    
    # Hide sensitive elements before screenshot
    page.evaluate("""
        const sensitiveSelectors = [
            'input[type="password"]',
            '[data-sensitive="true"]',
            '.ssn', '.credit-card'
        ];
        
        sensitiveSelectors.forEach(selector => {
            document.querySelectorAll(selector).forEach(el => {
                el.style.filter = 'blur(10px)';
            });
        });
    """)
    
    page.screenshot(path=filename)
```

### 4. Audit Logging

**Comprehensive Activity Log:**
```python
def log_dast_action(action: str, target: str, result: str, details: dict = None):
    """Audit log for DAST activities"""
    
    audit_entry = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "target": target,
        "result": result,
        "details": details or {},
        "user": os.getenv("USER"),
        "host": socket.gethostname(),
        "cwd": os.getcwd()
    }
    
    audit_file = Path(".securevibes") / "dast_audit.log"
    
    with open(audit_file, 'a') as f:
        f.write(json.dumps(audit_entry) + '\n')
```

**Logged Actions:**
- Authorization confirmations
- Target URL accessed
- Vulnerabilities tested
- Exploitation attempts
- Evidence captured
- Errors encountered

### 5. Rate Limiting

**Prevent DoS-like Behavior:**
```python
class RateLimiter:
    """Rate limit DAST requests to avoid overwhelming target"""
    
    def __init__(self, requests_per_second: int = 5):
        self.requests_per_second = requests_per_second
        self.last_request_time = 0
    
    async def wait(self):
        """Wait if necessary to respect rate limit"""
        now = time.time()
        time_since_last = now - self.last_request_time
        
        if time_since_last < 1.0 / self.requests_per_second:
            await asyncio.sleep(1.0 / self.requests_per_second - time_since_last)
        
        self.last_request_time = time.time()
```

### 6. Destructive Action Prevention

**Read-Only by Default:**
```python
DESTRUCTIVE_METHODS = ["DELETE", "TRUNCATE", "DROP"]
DESTRUCTIVE_ENDPOINTS = ["/admin/delete", "/reset", "/purge"]

def is_destructive_action(method: str, endpoint: str) -> bool:
    """Check if action could be destructive"""
    
    if method.upper() in DESTRUCTIVE_METHODS:
        return True
    
    if any(dangerous in endpoint.lower() for dangerous in DESTRUCTIVE_ENDPOINTS):
        return True
    
    return False

def test_vulnerability_safely(vuln: dict):
    """Test with safety checks"""
    
    if is_destructive_action(vuln.get("method"), vuln.get("endpoint")):
        console.print(f"[yellow]⚠️  {vuln['id']}: Skipping potentially destructive test[/yellow]")
        return {
            "validation_status": "UNVALIDATED",
            "reason": "Destructive action blocked for safety"
        }
    
    # Proceed with testing
    return test_vulnerability(vuln)
```

---

## Testing & Validation

### Unit Tests

**File:** `packages/core/tests/test_dast_agent.py`

```python
import pytest
import asyncio
from pathlib import Path
from securevibes.agents.definitions import create_agent_definitions
from securevibes.cli.main import _run_dast_validation

class TestDASTAgent:
    """Test DAST agent functionality"""
    
    def test_dast_agent_initialization(self):
        """Test DAST agent loads correctly"""
        agents = create_agent_definitions()
        assert "dast" in agents
        assert agents["dast"].description.startswith("Validates security vulnerabilities")
    
    def test_vulnerability_to_skill_mapping(self):
        """Test correct skill selected for vulnerability type"""
        from securevibes.agents.dast import map_vulnerability_to_skill
        
        idor_vuln = {"cwe_id": "CWE-639", "type": "idor"}
        skill = map_vulnerability_to_skill(idor_vuln)
        assert skill == "idor-testing"
        
        sqli_vuln = {"cwe_id": "CWE-89", "type": "sqli"}
        skill = map_vulnerability_to_skill(sqli_vuln)
        assert skill == "sqli-testing"
        
        unknown_vuln = {"cwe_id": "CWE-999", "type": "unknown"}
        skill = map_vulnerability_to_skill(unknown_vuln)
        assert skill == "generic-http-testing"
    
    def test_production_url_detection(self):
        """Test production URL detection"""
        from securevibes.cli.main import detect_production_environment
        
        assert detect_production_environment("https://example.com")
        assert detect_production_environment("https://api.company.com")
        assert detect_production_environment("https://production.app.com")
        
        assert not detect_production_environment("http://localhost:3000")
        assert not detect_production_environment("https://staging.example.com")
        assert not detect_production_environment("http://dev.localhost")
    
    def test_evidence_sanitization(self):
        """Test PII redaction from evidence"""
        from securevibes.cli.main import sanitize_evidence
        
        evidence = {
            "user_data": {
                "name": "John Doe",
                "ssn": "123-45-6789",
                "email": "john@example.com",
                "credit_card": "4111111111111111"
            }
        }
        
        sanitized = sanitize_evidence(evidence)
        
        assert sanitized["user_data"]["name"] == "John Doe"
        assert sanitized["user_data"]["ssn"] == "[REDACTED]"
        assert sanitized["user_data"]["credit_card"] == "[REDACTED]"
        assert sanitized["user_data"]["email"] == "john@example.com"  # Email ok for testing

class TestDASTIntegration:
    """Integration tests with mock vulnerable application"""
    
    @pytest.fixture
    async def mock_vulnerable_app(self):
        """Start mock vulnerable application"""
        from tests.mocks.vulnerable_app import VulnerableApp
        
        app = VulnerableApp()
        await app.start(port=3333)
        yield app
        await app.stop()
    
    @pytest.mark.asyncio
    async def test_dast_with_idor_vulnerability(self, mock_vulnerable_app, tmp_path):
        """Test DAST detects IDOR vulnerability"""
        
        # Create mock VULNERABILITIES.json
        vulns_file = tmp_path / ".securevibes" / "VULNERABILITIES.json"
        vulns_file.parent.mkdir(parents=True)
        vulns_file.write_text(json.dumps([{
            "id": "VULN-001",
            "type": "idor",
            "cwe_id": "CWE-639",
            "severity": "high",
            "title": "IDOR in User API",
            "file_path": "api/users.py",
            "line_number": 42,
            "endpoint": "/api/users/{id}"
        }]))
        
        # Run DAST validation
        result = await _run_dast_validation(
            path=str(tmp_path),
            target_url="http://localhost:3333",
            vulnerabilities_file=vulns_file,
            accounts_file=None,
            mode="http",
            timeout=60,
            model="sonnet",
            debug=True
        )
        
        # Verify IDOR was validated
        assert result["dast_scan_metadata"]["validated"] == 1
        assert result["validations"][0]["validation_status"] == "VALIDATED"
        assert len(result["validations"][0]["evidence"]["http_requests"]) > 0
    
    @pytest.mark.asyncio
    async def test_dast_with_false_positive(self, mock_vulnerable_app, tmp_path):
        """Test DAST correctly identifies false positives"""
        
        # Create vulnerability that doesn't actually exist
        vulns_file = tmp_path / ".securevibes" / "VULNERABILITIES.json"
        vulns_file.parent.mkdir(parents=True)
        vulns_file.write_text(json.dumps([{
            "id": "VULN-002",
            "type": "idor",
            "cwe_id": "CWE-639",
            "severity": "high",
            "title": "False IDOR",
            "file_path": "api/protected.py",
            "line_number": 10,
            "endpoint": "/api/protected/{id}"
        }]))
        
        result = await _run_dast_validation(
            path=str(tmp_path),
            target_url="http://localhost:3333",
            vulnerabilities_file=vulns_file,
            accounts_file=None,
            mode="http",
            timeout=60,
            model="sonnet",
            debug=False
        )
        
        # Verify false positive detected
        assert result["dast_scan_metadata"]["false_positives"] == 1
        assert result["validations"][0]["validation_status"] == "FALSE_POSITIVE"
```

### Integration Tests

**File:** `packages/core/tests/integration/test_full_dast_workflow.py`

```python
import pytest
from pathlib import Path

@pytest.mark.integration
@pytest.mark.asyncio
async def test_complete_scan_with_dast(tmp_path):
    """Test full SecureVibes workflow with DAST"""
    
    # Create sample vulnerable project
    create_sample_project(tmp_path)
    
    # Run complete scan with DAST
    result = await run_full_scan(
        path=tmp_path,
        dast=True,
        target_url="http://localhost:3000"
    )
    
    # Verify all phases completed
    assert (tmp_path / ".securevibes" / "SECURITY.md").exists()
    assert (tmp_path / ".securevibes" / "THREAT_MODEL.json").exists()
    assert (tmp_path / ".securevibes" / "VULNERABILITIES.json").exists()
    assert (tmp_path / ".securevibes" / "DAST_VALIDATION.json").exists()
    assert (tmp_path / ".securevibes" / "scan_results.json").exists()
    
    # Verify DAST results merged into final report
    final_report = json.loads((tmp_path / ".securevibes" / "scan_results.json").read_text())
    assert "dast_metrics" in final_report
    assert any(issue.get("validation_status") for issue in final_report["issues"])

@pytest.mark.integration
def test_cli_dast_flags():
    """Test CLI with DAST flags"""
    from click.testing import CliRunner
    from securevibes.cli.main import cli
    
    runner = CliRunner()
    
    # Test missing target URL
    result = runner.invoke(cli, ['scan', '.', '--dast'])
    assert result.exit_code == 1
    assert "target-url required" in result.output.lower()
    
    # Test with target URL
    result = runner.invoke(cli, [
        'scan', '.', 
        '--dast', 
        '--target-url', 'http://localhost:3000',
        '--no-save'
    ])
    assert result.exit_code in [0, 1, 2]  # May find issues
```

### Manual Testing Checklist

- [ ] DAST activates when --dast flag provided
- [ ] Production URL warning displays correctly
- [ ] Test accounts file loads properly
- [ ] Skills are discovered and loaded
- [ ] Browser MCP integrates correctly
- [ ] HTTP fallback works when MCP unavailable
- [ ] Evidence artifacts saved to correct location
- [ ] DAST_VALIDATION.json has correct format
- [ ] Results merge into scan_results.json
- [ ] Progress tracking displays during DAST
- [ ] Timeouts respected per vulnerability
- [ ] False positives correctly identified
- [ ] Validated findings have evidence
- [ ] Unvalidated findings preserve code review assessment
- [ ] Audit log created with all actions

---

## Performance Considerations

### 1. Parallel Vulnerability Testing

**Concurrent Execution:**
```python
async def test_vulnerabilities_parallel(
    vulnerabilities: List[dict],
    max_concurrent: int = 3
) -> List[dict]:
    """Test multiple vulnerabilities concurrently"""
    
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def test_with_semaphore(vuln):
        async with semaphore:
            console.print(f"[dim]Testing {vuln['id']}...[/dim]")
            result = await test_vulnerability(vuln)
            console.print(f"[dim]✓ {vuln['id']}: {result['validation_status']}[/dim]")
            return result
    
    results = await asyncio.gather(
        *[test_with_semaphore(v) for v in vulnerabilities],
        return_exceptions=True
    )
    
    return results
```

**Benefits:**
- 3x speedup with 3 concurrent tests
- Respects rate limits
- Handles failures gracefully

### 2. Configurable Timeouts

**Per-Vulnerability Type:**
```python
DAST_TIMEOUTS = {
    "idor": 60,              # 1 minute - simple to test
    "sqli": 300,             # 5 minutes - blind SQLi can be slow
    "xss": 90,               # 1.5 minutes
    "ssrf": 180,             # 3 minutes - may need multiple requests
    "auth-bypass": 120,      # 2 minutes
    "default": 120           # 2 minutes
}

def get_timeout_for_vulnerability(vuln: dict) -> int:
    """Get appropriate timeout based on vulnerability type"""
    vuln_type = vuln.get("type", "").lower()
    return DAST_TIMEOUTS.get(vuln_type, DAST_TIMEOUTS["default"])
```

### 3. Browser Instance Pooling

**Reuse Browser Across Tests:**
```python
class BrowserPool:
    """Manage browser instances for DAST"""
    
    def __init__(self, pool_size: int = 2):
        self.pool: List[Browser] = []
        self.pool_size = pool_size
        self.in_use: Set[Browser] = set()
    
    async def acquire(self) -> Browser:
        """Get or create browser instance"""
        if self.pool:
            browser = self.pool.pop()
            self.in_use.add(browser)
            return browser
        
        # Create new browser if under pool size
        if len(self.in_use) < self.pool_size:
            browser = await launch_browser()
            self.in_use.add(browser)
            return browser
        
        # Wait for available browser
        while not self.pool:
            await asyncio.sleep(0.1)
        
        browser = self.pool.pop()
        self.in_use.add(browser)
        return browser
    
    async def release(self, browser: Browser):
        """Return browser to pool"""
        self.in_use.remove(browser)
        
        # Clear cookies/cache
        await browser.clear_context()
        
        if len(self.pool) < self.pool_size:
            self.pool.append(browser)
        else:
            await browser.close()
    
    async def cleanup(self):
        """Close all browsers"""
        for browser in self.pool + list(self.in_use):
            await browser.close()
```

### 4. Caching Authentication Tokens

**Avoid Re-authenticating:**
```python
class AuthCache:
    """Cache authentication tokens for reuse"""
    
    def __init__(self):
        self.tokens: Dict[str, str] = {}  # email -> token
        self.cookies: Dict[str, dict] = {}  # email -> cookies
    
    async def get_token(self, email: str, password: str, target_url: str) -> str:
        """Get cached token or authenticate"""
        
        if email in self.tokens:
            # Verify token still valid
            if await self._token_valid(self.tokens[email], target_url):
                return self.tokens[email]
        
        # Authenticate and cache
        token = await authenticate(email, password, target_url)
        self.tokens[email] = token
        return token
    
    async def _token_valid(self, token: str, target_url: str) -> bool:
        """Check if token is still valid"""
        try:
            response = await http_get(
                f"{target_url}/api/auth/verify",
                headers={"Authorization": f"Bearer {token}"}
            )
            return response.status_code == 200
        except:
            return False
```

### 5. Smart Test Ordering

**Test Simple Vulnerabilities First:**
```python
def prioritize_vulnerabilities(vulnerabilities: List[dict]) -> List[dict]:
    """Order vulnerabilities for efficient testing"""
    
    # Priority: fast tests first, slow tests last
    priority_order = {
        "idor": 1,           # Fast
        "auth-bypass": 2,    # Fast
        "xss": 3,            # Medium
        "csrf": 4,           # Medium
        "sqli": 5,           # Slow (especially blind)
        "ssrf": 6,           # Slow
    }
    
    def get_priority(vuln):
        vuln_type = vuln.get("type", "").lower()
        return priority_order.get(vuln_type, 999)
    
    return sorted(vulnerabilities, key=get_priority)
```

### 6. Evidence Storage Limits

**Prevent Disk Bloat:**
```python
MAX_SCREENSHOT_SIZE_MB = 5
MAX_EVIDENCE_DIR_SIZE_MB = 100

def save_evidence_with_limits(evidence_data: dict, evidence_dir: Path):
    """Save evidence with size limits"""
    
    # Check total evidence directory size
    total_size = sum(f.stat().st_size for f in evidence_dir.rglob('*') if f.is_file())
    total_size_mb = total_size / (1024 * 1024)
    
    if total_size_mb > MAX_EVIDENCE_DIR_SIZE_MB:
        console.print(f"[yellow]⚠️  Evidence directory exceeds {MAX_EVIDENCE_DIR_SIZE_MB}MB[/yellow]")
        console.print("[dim]   Cleaning up old evidence...[/dim]")
        cleanup_old_evidence(evidence_dir)
    
    # Save screenshots with compression
    for screenshot in evidence_data.get("screenshots", []):
        compress_and_save_screenshot(screenshot, MAX_SCREENSHOT_SIZE_MB)
```

---

## Cost Estimation

### Token Usage Analysis

**Standard Scan** (no DAST):
- Assessment: ~50,000 tokens
- Threat Modeling: ~30,000 tokens
- Code Review: ~80,000 tokens
- Report Generator: ~10,000 tokens
- **Total: ~170,000 tokens**
- **Cost: ~$0.85** (with Claude Sonnet @ $5/MTok)

**With DAST** (10 vulnerabilities):
- Standard phases: ~170,000 tokens
- DAST agent initialization: ~5,000 tokens
- Per-vulnerability testing: ~10,000 tokens × 10 = ~100,000 tokens
- DAST report generation: ~5,000 tokens
- **Total: ~280,000 tokens**
- **Cost: ~$1.40** (with Claude Sonnet)

### Per-Vulnerability DAST Cost Breakdown

| Vulnerability Type | Avg Tokens | Cost (Sonnet) | Time |
|-------------------|------------|---------------|------|
| IDOR | 8,000 | $0.04 | 30-60s |
| Auth Bypass | 10,000 | $0.05 | 45-90s |
| XSS | 12,000 | $0.06 | 60-120s |
| CSRF | 11,000 | $0.055 | 60-90s |
| SQLi (simple) | 15,000 | $0.075 | 90-180s |
| SQLi (blind) | 25,000 | $0.125 | 180-300s |
| SSRF | 18,000 | $0.09 | 120-180s |
| XXE | 16,000 | $0.08 | 90-150s |

### Time Estimates

**Without DAST:**
- Small project (<100 files): 5-8 minutes
- Medium project (100-500 files): 10-20 minutes
- Large project (>500 files): 20-40 minutes

**With DAST** (adds):
- 5 vulnerabilities: +3-5 minutes
- 10 vulnerabilities: +5-10 minutes
- 20 vulnerabilities: +10-20 minutes
- 50 vulnerabilities: +25-45 minutes

### Cost Optimization Strategies

1. **Use Haiku for Simple Tests**
   ```python
   # Use faster/cheaper model for simple IDOR tests
   if vuln_type == "idor" and complexity == "simple":
       model = "haiku"  # $0.25/MTok vs $5/MTok
   ```

2. **Parallel Testing**
   - Test 3 vulnerabilities concurrently
   - Reduces wall-clock time by ~60%
   - No token savings but better UX

3. **Smart Filtering**
   ```bash
   # Test only high/critical severity
   securevibes scan . --dast --target-url http://localhost:3000 --severity high
   ```

4. **Quick Mode** (future enhancement)
   ```bash
   # Test only quick-to-validate vulnerabilities
   securevibes scan . --dast --target-url http://localhost:3000 --dast-quick
   ```

---

## Migration Path

### Phase 1: Foundation (Week 1-2)

**Goal:** Core DAST infrastructure

**Tasks:**
1. ✅ Add DAST agent definition to `definitions.py`
2. ✅ Create DAST prompt template `prompts/dast.txt`
3. ✅ Implement CLI flags (`--dast`, `--target-url`, etc.)
4. ✅ Create IDOR testing skill (MVP)
5. ✅ Build evidence capture system
6. ✅ Implement DAST_VALIDATION.json output

**Deliverables:**
- Working DAST agent for IDOR vulnerabilities
- CLI integration functional
- Evidence artifacts saved correctly

**Success Criteria:**
- IDOR vulnerabilities can be validated end-to-end
- Evidence includes screenshots or HTTP logs
- No regressions in standard scanning

---

### Phase 2: Core Skills (Week 3-4)

**Goal:** Expand vulnerability coverage

**Tasks:**
1. ✅ Add SQLi testing skill
2. ✅ Add XSS testing skill
3. ✅ Add auth-bypass testing skill
4. ✅ Implement skill auto-discovery
5. ✅ Add vulnerability-to-skill mapping
6. ✅ Handle missing skills gracefully

**Deliverables:**
- 4 total skills (IDOR, SQLi, XSS, auth-bypass)
- Automatic skill selection based on CWE/type
- Fallback to generic testing

**Success Criteria:**
- 80%+ of common web vulns covered
- Skills trigger correctly for their vulnerability types
- No skill missing errors for covered types

---

### Phase 3: Integration & Polish (Week 5-6)

**Goal:** Production-ready DAST system

**Tasks:**
1. ✅ Integrate Chrome DevTools MCP
2. ✅ Implement HTTP fallback mode
3. ✅ Add production URL detection
4. ✅ Implement authorization checks
5. ✅ Merge DAST results into scan_results.json
6. ✅ Update report generator for validation status
7. ✅ Add progress tracking for DAST phase

**Deliverables:**
- Browser-based testing functional
- Safety checks in place
- Results properly merged
- Rich progress output

**Success Criteria:**
- Both browser and HTTP modes work
- Production testing blocked without flag
- Users see real-time DAST progress

---

### Phase 4: Enhancement & Documentation (Week 7-8)

**Goal:** Complete feature with docs

**Tasks:**
1. ✅ Add remaining skills (CSRF, SSRF, path-traversal)
2. ✅ Implement parallel testing
3. ✅ Add comprehensive error handling
4. ✅ Write user documentation (DAST_GUIDE.md)
5. ✅ Write developer documentation (DAST_SKILLS_DEV.md)
6. ✅ Create example workflow guide
7. ✅ Add integration tests

**Deliverables:**
- 7+ skills covering major vulnerability classes
- Complete documentation suite
- Test coverage >80%
- Example projects and workflows

**Success Criteria:**
- Users can successfully run DAST with docs alone
- Developers can create new skills with guide
- All edge cases handled gracefully

---

### Rollout Strategy

**Week 1-2: Internal Alpha**
- Test on internal projects
- Fix critical bugs
- Gather initial feedback

**Week 3-4: Beta Release**
- Release to select users
- Document common issues
- Iterate on UX

**Week 5-6: Public Release**
- Announce feature in release notes
- Publish blog post with examples
- Monitor for issues

**Week 7-8: Refinement**
- Address user feedback
- Add requested features
- Improve documentation

---

## Documentation Requirements

### 1. User Guide

**File:** `docs/DAST_GUIDE.md`

**Contents:**
- What is DAST validation?
- When should you use DAST?
- Prerequisites (running application, test accounts)
- Step-by-step walkthrough
- Understanding DAST results
- Interpreting validation statuses
- Safety and legal considerations
- Troubleshooting common issues
- FAQ

**Target Audience:** SecureVibes users wanting to validate findings

---

### 2. Developer Guide

**File:** `docs/DAST_SKILLS_DEV.md`

**Contents:**
- Skills architecture overview
- Creating new DAST skills
- Skill file structure requirements
- Testing skill effectiveness
- Contributing skills to SecureVibes
- MCP integration patterns
- Debugging skills

**Target Audience:** Developers extending DAST capabilities

---

### 3. Example Workflow

**File:** `docs/DAST_WORKFLOW_EXAMPLE.md`

**Contents:**
- Complete walkthrough of DAST validation
- Setting up test environment
- Creating test accounts
- Running scan with DAST
- Reviewing validation results
- Acting on validated findings
- Example with screenshots

**Target Audience:** First-time DAST users

---

### 4. Skills Catalog

**File:** `docs/DAST_SKILLS_CATALOG.md`

**Contents:**
- List of all available skills
- Vulnerability types covered by each
- CWE mappings
- Testing methodology summaries
- Prerequisites per skill
- Example outputs

**Target Audience:** Users selecting which skills to use

---

### 5. API Documentation

**File:** Update existing API docs with DAST models

**Contents:**
- SecurityIssue with validation fields
- ScanResult with DAST metrics
- DAST_VALIDATION.json schema
- Test accounts JSON schema

**Target Audience:** API users and integrators

---

## Success Metrics

### Technical Metrics

**Validation Accuracy:**
- **Validation Rate:** % of code review findings confirmed by DAST
  - Target: >60% for MVP, >75% long-term
- **False Positive Rate:** % of findings disproven by DAST
  - Target: 10-20% (expected for static analysis)
- **False Negative Rate:** % of real vulns missed by DAST
  - Target: <10%

**Coverage:**
- **Vulnerability Type Coverage:** % of CWE types with skills
  - Target: 80% of common web vulnerabilities
- **Skill Trigger Rate:** % of vulnerabilities matched to skills
  - Target: >90%

**Performance:**
- **Time Per Vulnerability:** Average DAST testing time
  - Target: <2 minutes average
- **Parallel Efficiency:** Speedup from concurrent testing
  - Target: 2-3x with 3 concurrent tests

**Evidence Quality:**
- **POC Completeness:** % of validations with full evidence
  - Target: >95%
- **Screenshot Capture Rate:** % of browser tests with screenshots
  - Target: >90%

---

### User Metrics

**Adoption:**
- **DAST Usage Rate:** % of scans using --dast flag
  - Target: 20% within 3 months, 40% within 6 months
- **Repeat Usage:** % of users enabling DAST on 2nd scan
  - Target: >70%

**Satisfaction:**
- **User Feedback Score:** Rating of DAST feature
  - Target: >4.0/5.0
- **Documentation Quality:** Users able to use DAST without support
  - Target: >80% self-service success rate

**Time Savings:**
- **Manual Validation Reduction:** Time saved vs. manual pen testing
  - Target: 50-70% time reduction for covered vulnerability types
- **Remediation Prioritization:** Faster decision-making with validation
  - Target: <1 day to prioritize validated findings

---

### Quality Metrics

**Reliability:**
- **DAST Success Rate:** % of DAST runs completing successfully
  - Target: >95%
- **Error Rate:** % of validations ending in errors
  - Target: <5%

**Bug Reports:**
- **Critical Bugs:** Severity 1 issues per month
  - Target: 0 critical bugs after beta
- **User-Reported Issues:** Total issues per month
  - Target: <5 issues/month after release

**Code Quality:**
- **Test Coverage:** % of DAST code covered by tests
  - Target: >80%
- **Documentation Coverage:** % of features documented
  - Target: 100%

---

## Risks & Mitigations

### High Impact Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| **False negatives (real vuln not detected)** | High - Miss real security issues | Medium | Mark as UNVALIDATED rather than FALSE_POSITIVE; preserve code review finding; document testing limitations |
| **Accidental production testing** | Critical - Unauthorized testing, legal issues | Low | Authorization checks; production URL detection; confirmation prompts; audit logging |
| **Data exfiltration/PII exposure** | Critical - Privacy violation, legal issues | Low | Evidence sanitization; screenshot redaction; field filtering; clear documentation |
| **Application damage during testing** | High - Service disruption | Low | Read-only default; destructive action detection; rate limiting; timeout enforcement |

---

### Medium Impact Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| **Long scan times** | Medium - Poor UX, abandonment | High | Parallel testing (3x speedup); configurable timeouts; quick mode option; progress tracking |
| **Missing test accounts** | Medium - Reduced coverage | High | Graceful degradation to public endpoints; clear error messages; account creation guide |
| **Browser MCP unavailable** | Medium - Reduced capability | Medium | HTTP fallback mode; auto-detection; installation guide; skip browser-only tests |
| **Skill maintenance burden** | Medium - Stale skills | Medium | Community contributions; skill template generator; automated skill testing; deprecation warnings |

---

### Low Impact Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| **Evidence storage bloat** | Low - Disk usage | Medium | Configurable size limits; auto-cleanup; compression; retention policies |
| **False positives (disproven finding is real)** | Low - Missed vulnerability | Low | Conservative classification; multiple test attempts; manual verification option |
| **Skill conflicts** | Low - Wrong skill selected | Low | Explicit CWE mapping; priority order; override option; logging |
| **Token cost spikes** | Low - Unexpected costs | Low | Model selection per vuln type; cost estimation before scan; budget alerts |

---

## Future Enhancements

### Short-term (3-6 months)

**1. DAST-Quick Mode**
- Test only high/critical findings
- Skip time-consuming tests
- Fast validation for CI/CD

**2. Interactive Mode**
- Pause for manual verification steps
- User confirms suspicious actions
- Hybrid manual/automated testing

**3. Evidence Replay**
- Re-run exploitation from saved evidence
- Verify fix effectiveness
- Regression testing

**4. Skill Marketplace**
- Community skill repository
- Skill versioning and updates
- Skill ratings and reviews

---

### Mid-term (6-12 months)

**5. ML-Assisted Testing**
- Learn from past validations
- Predict false positive likelihood
- Optimize test ordering

**6. Multi-Target DAST**
- Test staging + production in one run
- Compare validation results
- Detect environment-specific issues

**7. Continuous DAST**
- Integrate with CI/CD pipelines
- Automated regression testing
- Slack/email notifications

**8. DAST Metrics Dashboard**
- Historical validation trends
- Skill effectiveness analytics
- Cost tracking over time

---

### Long-term (12+ months)

**9. Autonomous Exploit Generation**
- AI generates custom exploits
- Adapt to application defenses
- Multi-step attack chains

**10. DAST-as-a-Service**
- Cloud-hosted DAST infrastructure
- Managed test environments
- Scalable parallel testing

**11. Red Team Integration**
- Full attack scenario simulation
- Lateral movement testing
- Post-exploitation analysis

**12. Compliance Mapping**
- Map DAST results to OWASP Top 10
- PCI DSS compliance reporting
- SOC 2 audit evidence

---

## Conclusion

This proposal outlines a comprehensive DAST sub-agent integration for SecureVibes that:

### Key Innovations

1. **Skills-Based Architecture**
   - Progressive capability enhancement without code changes
   - Community-extensible through markdown skill files
   - Modular, maintainable testing logic

2. **Flexible Testing Modes**
   - Browser-based via Chrome DevTools MCP
   - API-based via HTTP/curl
   - Automatic mode selection per vulnerability

3. **Evidence-Driven Validation**
   - POC artifacts for every validated finding
   - Screenshots, HTTP logs, exploit steps
   - Redacted for privacy and compliance

4. **Safety-First Design**
   - Authorization checks before testing
   - Production URL detection and blocking
   - Audit logging for all actions
   - Rate limiting to prevent DoS

5. **Non-Breaking Integration**
   - Optional `--dast` flag
   - Existing scans unchanged
   - Backward compatible data models

### Implementation Strategy

**Phase 1 (Weeks 1-2):** Foundation with IDOR skill (MVP)
**Phase 2 (Weeks 3-4):** Expand to core web vulnerabilities
**Phase 3 (Weeks 5-6):** MCP integration and production polish
**Phase 4 (Weeks 7-8):** Complete documentation and testing

### Expected Impact

- **Reduces false positives** by 10-20% through dynamic validation
- **Saves 50-70% time** on manual vulnerability validation
- **Provides actionable evidence** for remediation teams
- **Enables progressive enhancement** via community-contributed skills

### Recommendation

Begin with **Phase 1** (foundation + IDOR skill) to validate the approach with a working MVP. The skills-based architecture allows incremental capability addition based on user feedback and real-world vulnerability frequency.

The DAST sub-agent aligns with SecureVibes' philosophy of AI-native security testing while maintaining the existing agent orchestration patterns and artifact-based communication flow.

---

**Next Steps:**
1. Review and approve proposal
2. Begin Phase 1 implementation
3. Test IDOR skill with sample vulnerable applications
4. Gather feedback and iterate
5. Proceed with remaining phases based on validation

**Questions or Feedback:** Open for discussion and refinement.
