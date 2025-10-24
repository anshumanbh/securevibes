# DAST Validation Guide

## Overview

SecureVibes DAST (Dynamic Application Security Testing) validates IDOR (Insecure Direct Object Reference) vulnerabilities by sending real HTTP requests to a running application. This moves beyond static analysis to confirm actual exploitability.

**Status**: MVP with IDOR validation (HTTP-only)

---

## Quick Start

### 1. Prerequisites

- Target application running and accessible
- At least 2 test user accounts (for cross-user access testing)
- Authorization to test the target (required!)

**Note:** DAST skills are automatically bundled with SecureVibes and copied to your project's `.claude/skills/dast/` directory during scans. No manual setup required!

### 2. Basic Usage

```bash
# Run SAST + DAST scan on localhost
securevibes scan . --dast --target-url http://localhost:3000

# With custom timeout
securevibes scan . --dast --target-url http://localhost:8080 --dast-timeout 180

# With test accounts for authenticated endpoints
securevibes scan . --dast \
  --target-url http://staging.example.com \
  --dast-accounts test_accounts.json
```

### 3. Example Output

```
🛡️ SecureVibes Security Scanner
AI-Powered Vulnerability Detection

📁 Scanning: /path/to/project
🤖 Model: sonnet
============================================================

━━━ Phase 1/4: Architecture Assessment ━━━
  📖 Reading config.py
  🔍 Searching: authentication
  ...
✅ Phase 1/4: Architecture Assessment Complete

━━━ Phase 5/5: DAST Validation ━━━
  🔍 Loading VULNERABILITIES.json
  🧪 Testing IDOR on /api/users/{id}
  ✅ Validated: user 123 → user 456 (200 OK)
  ...
✅ Phase 5/5: DAST Validation Complete

============================================================
📊 Scan Results:
- 5 vulnerabilities found
- 3 ✅ Validated (confirmed exploitable)
- 1 ❌ False Positive (not exploitable)
- 1 ❓ Unvalidated (could not test)
```

---

## Running DAST Only

After completing a full scan, you can re-run just the DAST validation to save time and API costs:

### Iterative Testing Workflow

1. **Initial Full Scan**: Run complete SAST + DAST
   ```bash
   securevibes scan . --dast --target-url http://localhost:3000
   ```

2. **Review Results**: Check `.securevibes/DAST_VALIDATION.json`
   ```bash
   cat .securevibes/DAST_VALIDATION.json | jq '.validations[] | select(.status == "VALIDATED")'
   ```

3. **Fix Vulnerabilities**: Update code based on findings

4. **Re-test with DAST Only**: Run DAST sub-agent (faster, reuses static analysis)
   ```bash
   securevibes scan . --subagent dast --target-url http://localhost:3000
   ```

5. **Repeat**: Until all issues are validated as fixed

### Sub-Agent Mode

Run only the DAST validation phase:

```bash
# Basic DAST-only scan (uses existing VULNERABILITIES.json)
securevibes scan . --subagent dast --target-url http://localhost:3000

# With test accounts
securevibes scan . --subagent dast \
  --target-url http://localhost:3000 \
  --dast-accounts test_accounts.json

# Force execution without prompts (CI/CD)
securevibes scan . --subagent dast \
  --target-url http://localhost:3000 \
  --force

# Skip artifact validation
securevibes scan . --subagent dast \
  --target-url http://localhost:3000 \
  --skip-checks
```

**Interactive Confirmation:**

```bash
$ securevibes scan . --subagent dast --target-url http://localhost:3000

🔍 Checking prerequisites for 'dast' sub-agent...
✓ Found: .securevibes/VULNERABILITIES.json (modified: 2h ago, 10 issues)

⚠️  Re-running DAST will overwrite existing results.

Options:
  1. Use existing VULNERABILITIES.json and run DAST only [default]
  2. Re-run entire scan (all sub-agents)
  3. Cancel

Choice [1]:
```

**Benefits:**
- ⚡ **Faster**: Skip static analysis (already done)
- 💰 **Cheaper**: Only runs DAST agent (~20% of full scan cost)
- 🔄 **Iterative**: Test → Fix → Re-test cycle
- 🎯 **Focused**: Validate specific fixes

---

## Safety Gates

DAST testing sends **real HTTP requests** to your target. SecureVibes includes multiple safety mechanisms:

### 1. Production URL Detection

Automatically detects production URLs and blocks testing:

```bash
securevibes scan . --dast --target-url https://api.mycompany.com
```

**Output:**
```
⚠️  PRODUCTION URL DETECTED: https://api.mycompany.com

DAST testing sends real HTTP requests to the target.
Testing production systems requires explicit authorization.

To proceed, add --allow-production flag (ensure you have authorization!)
```

**Safe patterns** (auto-allowed):
- `localhost`, `127.0.0.1`, `0.0.0.0`
- `staging`, `dev`, `test`, `qa`
- `.local`, `.test`, `.dev`

**Production indicators** (blocked):
- `.com`, `.net`, `.org`, `.io`
- `production`, `prod`, `api.`, `app.`, `www.`

### 2. Explicit Confirmation

Non-production URLs require user confirmation:

```
⚠️  DAST Validation Enabled
Target: http://staging.example.com

DAST will send HTTP requests to validate IDOR vulnerabilities.
Ensure you have authorization to test this target.

Proceed with DAST validation? [y/N]:
```

### 3. Target Reachability Check

Verifies target is accessible before starting scan:

```
🔍 Checking target reachability: http://localhost:3000
⚠️  Warning: Target http://localhost:3000 is not reachable
DAST validation may fail if target is not running

Continue anyway? [Y/n]:
```

### 4. Bypass Safety (Use with Caution!)

For CI/CD or automated testing:

```bash
# Skip confirmation prompts (still requires --allow-production for prod URLs)
securevibes scan . --dast --target-url http://staging.example.com --allow-production
```

---

## Test Accounts

For testing authenticated endpoints, provide a JSON file with test user credentials:

### Format

```json
{
  "user1": {
    "id": "123",
    "username": "alice@test.com",
    "password": "test-password-1",
    "token": "optional-pre-generated-token",
    "role": "user"
  },
  "user2": {
    "id": "456",
    "username": "bob@test.com",
    "password": "test-password-2",
    "token": "optional-pre-generated-token",
    "role": "user"
  }
}
```

### Usage

```bash
securevibes scan . --dast \
  --target-url http://localhost:3000 \
  --dast-accounts accounts.json
```

**Notes:**
- Minimum 2 accounts required (for cross-user testing)
- If `token` provided, authentication step is skipped
- If `token` missing, DAST agent will attempt login via `/auth/login` or similar endpoints
- Accounts should have **same privilege level** (for horizontal privilege escalation testing)

---

## How DAST Works

### 1. SAST Phase (Phases 1-4)

SecureVibes runs standard static analysis:
- Architecture assessment
- Threat modeling (STRIDE)
- Code review
- Report generation

**Output:** `.securevibes/VULNERABILITIES.json`

### 2. DAST Phase (Phase 5)

If `--dast` enabled, DAST agent:

1. **Loads vulnerabilities**
   - Reads `.securevibes/VULNERABILITIES.json`
   - Filters for IDOR vulnerabilities (CWE-639)

2. **Discovers skills**
   - Loads skills from `.claude/skills/dast/`
   - Currently: `idor-testing` skill

3. **Validates each IDOR**
   - Follows methodology from the `idor-testing` skill
   - Baseline request: User1 → User1's resource (200 OK expected)
   - Test request: User1 → User2's resource (403/401 expected, 200 = vulnerable)

4. **Captures evidence**
   - HTTP responses (8KB limit, SHA-256 hash)
   - Redacts sensitive fields (SSN, passwords, tokens)
   - Records status codes and timestamps

5. **Generates report**
   - Creates `.securevibes/DAST_VALIDATION.json`
   - Merges into `scan_results.json`
   - Marks issues as: VALIDATED, FALSE_POSITIVE, or UNVALIDATED

### Validation Status

| Status | Meaning | Display |
|--------|---------|---------|
| **VALIDATED** | Exploitable - 200 OK received when accessing other user's data | ✅ |
| **FALSE_POSITIVE** | Not exploitable - 403/401 received (access control working) | ❌ |
| **UNVALIDATED** | Could not test - endpoint unreachable, timeout, or error | ❓ |
| **PARTIAL** | Partially validated - mixed results requiring manual review | ⚠️ |

---

## Supported Vulnerabilities

### Current (MVP)

- **IDOR (CWE-639)**: Insecure Direct Object Reference
  - User resource access (`/api/users/{id}`)
  - Document access (`/api/documents/{id}`)
  - Order access (`/api/orders/{id}`)
  - Any endpoint with object ID manipulation

### Planned (Phase 2)

- **SQL Injection (CWE-89)**: Database query injection
- **XSS (CWE-79)**: Cross-site scripting
- **Path Traversal (CWE-22)**: Directory traversal
- **Command Injection (CWE-78)**: OS command execution

---

## Output Format

### Markdown Report

```markdown
# Security Scan Report

**DAST Enabled:** ✓ Yes  
**Validation Rate:** 75.0%  
**DAST Time:** 12.3s  

## Executive Summary

🔴 **5 security vulnerabilities found** - **CRITICAL** - Requires immediate attention

- 🔴 **3 Critical** - Require immediate attention
- 🟠 **2 High** - Should be fixed soon

**DAST Validation Status:**
- ✅ 3 Validated
- ❌ 1 False Positives
- ❓ 1 Unvalidated

## Vulnerability Overview

| # | Severity | Title | Location |
|---|----------|-------|----------|
| 1 | 🔴 CRITICAL ✅ | IDOR on user profile | `api/users.py:45` |
| 2 | 🔴 CRITICAL ❌ | IDOR on documents | `api/docs.py:12` |

## Detailed Findings

### 1. IDOR on user profile [🔴 CRITICAL]

**File:** `api/users.py:45`  
**CWE:** CWE-639  
**Severity:** 🔴 Critical  
**DAST Status:** ✅ **Validated** - Exploitability confirmed  
**Exploitability:** 9.5/10

**Description:**
Endpoint /api/users/{id} allows any user to access another user's data...

**Evidence:** `/tmp/idor_evidence_12345.json`
```

### JSON Report

```json
{
  "repository_path": "/path/to/project",
  "scan_time_seconds": 45.2,
  "files_scanned": 23,
  "total_cost_usd": 0.1234,
  "dast_enabled": true,
  "dast_validation_rate": 75.0,
  "dast_false_positive_rate": 25.0,
  "dast_scan_time_seconds": 12.3,
  "issues": [
    {
      "id": "VULN-001",
      "severity": "critical",
      "title": "IDOR on user profile",
      "description": "...",
      "file_path": "api/users.py",
      "line_number": 45,
      "cwe_id": "CWE-639",
      "validation_status": "VALIDATED",
      "exploitability_score": 9.5,
      "validated_at": "2025-10-23T14:30:00Z",
      "dast_evidence": {
        "baseline_url": "http://localhost:3000/api/users/123",
        "test_url": "http://localhost:3000/api/users/456",
        "baseline_status": 200,
        "test_status": 200,
        "evidence_file": "/tmp/idor_evidence_12345.json"
      }
    }
  ]
}
```

---

## Configuration

### Automatic Skill Setup

DAST skills are bundled with SecureVibes and automatically managed:

- **Installation**: Skills included in package at `securevibes/skills/dast/`
- **Runtime**: Automatically copied to `{project}/.claude/skills/dast/` before DAST execution
- **Cleanup**: Skills remain in project for future scans (or add to `.gitignore`)

**Recommended .gitignore entry:**
```gitignore
# SecureVibes artifacts
.securevibes/
.claude/skills/dast/  # Auto-copied DAST skills
```

**Manual override**: If you want custom skills, create `.claude/skills/dast/` in your project - SecureVibes will use existing skills instead of copying.

### Environment Variables

DAST configuration can be set via environment variables:

```bash
# Enable DAST
export DAST_ENABLED=true

# Target URL
export DAST_TARGET_URL=http://localhost:3000

# Timeout (seconds)
export DAST_TIMEOUT=120

# Test accounts JSON (inline)
export DAST_TEST_ACCOUNTS='{"user1": {...}, "user2": {...}}'
```

**Note:** CLI flags take precedence over environment variables.

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--dast` | Enable DAST validation | `false` |
| `--target-url` | Target URL for testing | Required if `--dast` |
| `--dast-timeout` | Validation timeout (seconds) | `120` |
| `--dast-accounts` | Path to test accounts JSON | None |
| `--allow-production` | Allow production URL testing | `false` |

---

## Troubleshooting

### DAST phase not running

**Symptom:** Scan completes without Phase 5

**Causes:**
1. `--dast` flag not provided
2. `--target-url` missing
3. No IDOR vulnerabilities found in SAST phases
4. Environment variable `DAST_ENABLED` not set to "true"

**Solution:**
```bash
# Ensure both flags present
securevibes scan . --dast --target-url http://localhost:3000
```

### Target unreachable

**Symptom:** "Target http://localhost:3000 is not reachable"

**Causes:**
1. Application not running
2. Wrong port
3. Firewall blocking connection

**Solution:**
```bash
# Verify app is running
curl http://localhost:3000/health

# Check port
netstat -an | grep 3000

# Test with different port
securevibes scan . --dast --target-url http://localhost:8080
```

### All issues unvalidated

**Symptom:** All vulnerabilities marked ❓ UNVALIDATED

**Causes:**
1. Endpoints require authentication but no test accounts provided
2. API routes differ from code analysis (e.g., `/v1/api/users` vs `/api/users`)
3. Target application crashed during testing

**Solution:**
```bash
# Provide test accounts
securevibes scan . --dast \
  --target-url http://localhost:3000 \
  --dast-accounts accounts.json

# Check application logs for errors
tail -f /var/log/app.log

# Increase timeout for slow endpoints
securevibes scan . --dast \
  --target-url http://localhost:3000 \
  --dast-timeout 300
```

### Skills not found

**Symptom:** "Skill 'idor-testing' not found"

**Causes:**
1. `.claude/skills/dast/` directory missing
2. Git submodule not initialized
3. Running scan from wrong directory

**Solution:**
```bash
# Verify skills directory exists
ls -la .claude/skills/dast/

# If missing, ensure you're in repo root
cd /path/to/project
securevibes scan .

# Check SKILL.md exists
cat .claude/skills/dast/idor-testing/SKILL.md
```

### Production URL blocked

**Symptom:** "PRODUCTION URL DETECTED: https://api.mycompany.com"

**Cause:** Safety gate preventing accidental production testing

**Solution:**
```bash
# Option 1: Use staging/dev environment
securevibes scan . --dast --target-url http://staging.mycompany.com

# Option 2: Explicitly allow production (WITH AUTHORIZATION!)
securevibes scan . --dast \
  --target-url https://api.mycompany.com \
  --allow-production
```

---

## Best Practices

### 1. Test Environments First

Always test DAST on non-production environments:

```bash
# ✅ Good
securevibes scan . --dast --target-url http://localhost:3000
securevibes scan . --dast --target-url http://staging.example.com

# ❌ Avoid
securevibes scan . --dast --target-url https://api.production.com
```

### 2. Use Dedicated Test Accounts

Create accounts specifically for security testing:

```json
{
  "user1": {
    "id": "test-user-1",
    "username": "security-test-1@example.com",
    "password": "test-only-password",
    "role": "user"
  },
  "user2": {
    "id": "test-user-2",
    "username": "security-test-2@example.com",
    "password": "test-only-password",
    "role": "user"
  }
}
```

**Never use real user accounts for testing!**

### 3. Review Evidence Files

DAST creates evidence files in `/tmp/idor_evidence_*.json`:

```bash
# View captured evidence
cat /tmp/idor_evidence_12345.json

# Check SHA-256 hashes
jq '.baseline.response_hash' /tmp/idor_evidence_12345.json
```

### 4. CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Start test app
        run: docker-compose up -d test-app
      
      - name: Install SecureVibes
        run: pip install securevibes
      
      - name: Run DAST scan
        run: |
          securevibes scan . \
            --dast \
            --target-url http://localhost:3000 \
            --dast-accounts test/accounts.json \
            --format json \
            --output scan-results.json
      
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: security-scan
          path: scan-results.json
```

### 5. Monitor Scan Costs

DAST adds minimal cost (~$0.01-0.05 per scan):

```bash
# Check total cost
securevibes scan . --dast --target-url http://localhost:3000

# Output includes:
# **Total Cost:** $0.1234
# **DAST Time:** 12.3s
```

---

## Skill Architecture

DAST uses Claude Agent SDK skills for modular, extensible testing:

```
.claude/skills/dast/
├── idor-testing/
│   ├── SKILL.md                 # Methodology-focused skill definition
│   ├── examples.md              # Conceptual test scenarios
│   └── reference/               # Non-runnable examples to adapt
│       └── validate_idor.py
└── (future: sqli-testing, xss-testing, etc.)
```

### Adding Custom Skills

See [AGENT_SKILLS_GUIDE.md](./AGENT_SKILLS_GUIDE.md) for creating custom DAST skills.

---

## FAQ

### Does DAST replace SAST?

No. DAST **complements** SAST:
- **SAST** (Phases 1-4): Finds potential vulnerabilities via code analysis
- **DAST** (Phase 5): Validates which vulnerabilities are actually exploitable

### Is DAST safe?

Yes, with precautions:
- ✅ Only sends read-only HTTP GET requests (MVP)
- ✅ Redacts sensitive data (SSN, passwords, tokens)
- ✅ Production URL blocking
- ✅ User confirmation required
- ❌ **Never test production without authorization**

### How long does DAST take?

- **SAST only**: ~30-60 seconds
- **SAST + DAST**: +10-30 seconds (depends on endpoint response times)

### Can I skip DAST for specific scans?

Yes, DAST is opt-in:

```bash
# SAST only (default)
securevibes scan .

# SAST + DAST
securevibes scan . --dast --target-url http://localhost:3000
```

### Does DAST modify my application?

No. DAST only sends **read-only** HTTP requests. Future skills (SQL injection, XSS) will include additional safety mechanisms.

---

## Support

- **Documentation**: [docs/](../docs/)
- **Issues**: [GitHub Issues](https://github.com/anshumanbh/securevibes/issues)
- **Progress**: [DAST_IMPLEMENTATION_PROGRESS.md](../DAST_IMPLEMENTATION_PROGRESS.md)
