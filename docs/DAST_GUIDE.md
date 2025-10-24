# DAST Validation Guide

## Overview

SecureVibes DAST (Dynamic Application Security Testing) validates vulnerabilities found during the code review phase to confirm actual exploitability.

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

## Logging Behavior

DAST progress logs display only confirmed operations:
- ✅ Read /absolute/path
- ✅ Wrote /absolute/path

Pre‑intent lines (e.g., “Reading …”) are suppressed to reduce noise.

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
- If `token` missing, the agent may attempt a login flow (e.g., POST to `/auth/login`) based on the app
- Accounts should have **same privilege level** (for horizontal privilege escalation testing)
- Do NOT create `DAST_TEST_ACCOUNTS.json` automatically; only provide it explicitly or via `--dast-accounts`

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
   - Determines eligibility based on available skills (model‑invoked)
   - Validates only when a matching skill exists (currently: IDOR); others are marked UNVALIDATED with reason

2. **Discovers skills**
   - Loads skills from `.claude/skills/dast/` (progressive disclosure)
   - Skills are model‑invoked; currently includes `idor-testing`

3. **Validates eligible findings**
   - Follows methodology from the `idor-testing` skill
   - Baseline: User1 → own resource (expect 200)
   - Test: User1 → User2’s resource (expect 401/403; 200 = vulnerable)

4. **Captures evidence**
   - Records minimal, redacted evidence in `.securevibes/DAST_VALIDATION.json`
   - Include small response snippets and SHA‑256 hashes where useful
   - Avoid storing raw PII or full responses

5. **Generates report**
   - Writes `.securevibes/DAST_VALIDATION.json` (only repository file written during DAST)
   - Merges into `scan_results.json`
   - Marks issues as: VALIDATED, FALSE_POSITIVE, or UNVALIDATED

## Skill‑Gated Validation

- DAST validates a vulnerability only when a matching skill is available and loaded from `.claude/skills/dast/`.
- Without a relevant skill, the item is marked `UNVALIDATED` with a clear reason (e.g., "No applicable validation skill").
- This methodology‑first approach focuses on the what (testing logic) rather than prescribing how (hardcoded scripts).

### Validation Status

| Status | Meaning | Display |
|--------|---------|---------|
| **VALIDATED** | Exploitable - 200 OK received when accessing other user's data | ✅ |
| **FALSE_POSITIVE** | Not exploitable - 403/401 received (access control working) | ❌ |
| **UNVALIDATED** | Could not test - endpoint unreachable, timeout, or error | ❓ |
| **PARTIAL** | Partially validated - mixed results requiring manual review | ⚠️ |

---

## Configuration

### Automatic Skill Setup

DAST skills are bundled with SecureVibes and automatically managed:

- **Installation**: Skills included in package at `securevibes/skills/dast/`
- **Runtime**: Automatically copied to `{project}/.claude/skills/dast/` before DAST execution
- **Access**: During the DAST phase, the agent can read `.claude/skills/**` to load SKILLs; other phases treat `.claude/` as infrastructure and skip it
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

## Skill Architecture

DAST uses Claude Agent SDK skills for modular, extensible testing:

```
.claude/skills/dast/
├── idor-testing/
│   ├── SKILL.md                 # Methodology-focused skill definition
│   ├── examples.md              # Conceptual test scenarios
│   └── reference/               # Non-runnable examples to adapt
│       └── ...
└── (future: sqli-testing, xss-testing, etc.)
```

### Adding Custom Skills

See [AGENT_SKILLS_GUIDE.md](./AGENT_SKILLS_GUIDE.md) for creating custom DAST skills.
