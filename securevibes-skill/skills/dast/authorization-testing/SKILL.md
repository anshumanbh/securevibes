---
name: authorization-testing
description: Validate authorization failures including IDOR, privilege escalation, and missing access controls. Test by attempting unauthorized access with lower-privileged credentials. Use when testing CWE-639 (IDOR), CWE-269 (Improper Privilege Management), CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization), CWE-284 (Improper Access Control), CWE-285 (Improper Authorization), or CWE-425 (Direct Request / Forced Browsing) findings.
allowed-tools: Read, Write, Bash
---

# Authorization Testing Skill

## Purpose
Validate authorization failures by attempting actions that should be blocked based on:
- **User identity** (horizontal privilege escalation / IDOR)
- **User role/privilege level** (vertical privilege escalation)
- **Resource ownership** rules
- **Function-level access controls**

## Vulnerability Types Covered

### 1. Insecure Direct Object Reference - IDOR (CWE-639)
Access other users' resources by manipulating object IDs.

**Test Pattern:** Authenticate as User A, access User B's resource (change ID in URL/params)  
**Expected:** 403 Forbidden | **Actual if vulnerable:** 200 OK  
**Example:** `/api/user/456` accessed by user 123

### 2. Vertical Privilege Escalation (CWE-269, CWE-863)
Perform actions requiring higher privileges than possessed.

**Test Pattern:** Authenticate as regular user, attempt admin/privileged action  
**Expected:** 403 Forbidden | **Actual if vulnerable:** 200 OK  
**Examples:**
- Regular user calls `/admin/delete_user`
- User modifies their own role to admin via `/update_role`
- User accesses admin dashboard

### 3. Horizontal Privilege Escalation (CWE-639)
Access peer users' resources at same privilege level.

**Test Pattern:** Authenticate as User A (regular), access/modify User B's data (also regular)  
**Expected:** 403 Forbidden | **Actual if vulnerable:** 200 OK  
**Example:** User 2 modifies User 3's profile

### 4. Missing Authorization (CWE-862)
Actions execute without ANY authorization check.

**Test Pattern:** Authenticate with minimal privileges, attempt protected action  
**Expected:** 403 Forbidden | **Actual if vulnerable:** 200 OK  
**Example:** Unauthenticated or low-privilege access to `/api/admin/users`

### 5. Function-Level Access Control (CWE-285)
Wrong authorization logic applied to functions.

**Test Pattern:** Authenticate as user authorized for function X, attempt function Y (should be blocked)
**Expected:** 403 Forbidden | **Actual if vulnerable:** 200 OK
**Example:** Read-only user performs write operation

### 6. Direct Request / Forced Browsing (CWE-425)
Access restricted functionality by directly requesting URLs, bypassing normal navigation flow.

**Test Pattern:** Request admin/protected URL directly without proper authorization flow
**Expected:** 403 Forbidden or redirect to login | **Actual if vulnerable:** 200 OK
**Examples:**
- Direct access to `/admin/dashboard` without admin session
- Force-browsing to `/api/internal/config` endpoint
- Accessing `/reports/confidential` by guessing URL structure

## Prerequisites
- Target application running and reachable
- Test accounts based on vulnerability type:
  - **IDOR/Horizontal:** 2+ regular users (same role, different accounts)
  - **Vertical Escalation:** 1 regular user + 1 admin user (different roles)
  - **Missing Authorization:** 1 low-privilege or unauthenticated context
- VULNERABILITIES.json with suspected authorization failures

## Testing Methodology

### Phase 1: Understand Authorization Model

Before testing, read the source code to identify:
- **Authentication mechanism** (session cookies, JWT Bearer, API key, OAuth)
- **Authorization checks** (decorators like @admin_required, middleware, guards)
- **Role/permission structure** (user, admin, moderator, etc.)
- **Resource ownership rules** (user_id checks, tenant isolation)
- **Where object identifiers appear** (path params, query params, JSON body)

**Key insight:** Each app implements authorization differently. Read the code first!

### Phase 2: Identify Test Scenarios

Map vulnerabilities to test types:

| CWE | Vulnerability | Test Type | Accounts Needed |
|-----|---------------|-----------|-----------------|
| CWE-639 | IDOR on `/api/user/<id>` | Horizontal | 2 regular users |
| CWE-269 | Missing admin check on `/update_role` | Vertical | 1 regular, 1 admin |
| CWE-862 | No authz on `/admin/dashboard` | Missing | 1 regular user |
| CWE-863 | Flawed check on `/api/profile/<id>/update` | IDOR | 2 regular users |
| CWE-284 | Generic access control bypass | Varies | Based on context |
| CWE-285 | Wrong authz logic on read-only endpoint | Function-level | Read-only + write user |
| CWE-425 | Direct URL access to `/admin/config` | Forced browsing | 1 regular user |

### Phase 3: Prepare Test Accounts

**If .securevibes/DAST_TEST_ACCOUNTS.json exists:**
```json
{
  "accounts": [
    {"username": "user1", "password": "Pass123!", "user_id": "123", "role": "user"},
    {"username": "user2", "password": "Pass456!", "user_id": "456", "role": "user"},
    {"username": "admin", "password": "Admin789!", "user_id": "1", "role": "admin"}
  ]
}
```

Extract credentials for:
- **Horizontal tests:** user1, user2 (both regular role)
- **Vertical tests:** user1 (regular role), admin (admin role)

**If no test accounts:**
- Test only public endpoints
- Mark authenticated paths as UNVALIDATED (insufficient accounts)

### Phase 4: Authenticate Test Users

Read application code to determine auth mechanism, then use authentication helpers from `reference/auth_patterns.py`:

```python
from reference.auth_patterns import session_based_auth, jwt_bearer_auth, api_key_auth

# Session-based (Flask, Express, Django)
session = session_based_auth(target_url, user1_username, user1_password)
response = session.get(f"{target_url}/api/resource")

# JWT Bearer (REST APIs)
headers = jwt_bearer_auth(target_url, user1_username, user1_password)
response = requests.get(f"{target_url}/api/resource", headers=headers)

# API Key
headers = api_key_auth(api_key_for_user1)
response = requests.get(f"{target_url}/api/resource", headers=headers)
```

See `reference/auth_patterns.py` for additional patterns (OAuth2, Basic auth) and customization options.

### Phase 5: Execute Authorization Tests

**Universal Pattern:**
```
1. Authenticate with LOW privilege credentials
2. Baseline: Attempt ALLOWED action → 200 OK (verify auth works)
3. Test: Attempt BLOCKED action → ???
4. Classify:
   - 200 OK: VALIDATED (authorization bypass!)
   - 403/401: FALSE_POSITIVE (authorization working correctly)
   - Other: UNVALIDATED (unclear/error)
```

**Test Variants by Vulnerability Type:**

#### IDOR Test (Horizontal)
```python
# User A accesses User B's resource
auth_as(user_a)  # user_id: 123

# Baseline: own resource
GET /api/user/123 → 200 OK ✓

# Test: other user's resource
GET /api/user/456 → ???
# Expected: 403 Forbidden
# Actual if vulnerable: 200 OK with user 456's data
# Classification: VALIDATED (CWE-639)
```

#### Vertical Privilege Escalation
```python
# Regular user performs admin action
auth_as(regular_user)  # role: user

# Baseline: allowed action
GET /dashboard → 200 OK ✓

# Test: admin action
POST /admin/delete_user {"user_id": 123} → ???
# Expected: 403 Forbidden
# Actual if vulnerable: 200 OK, user deleted
# Classification: VALIDATED (CWE-269)
```

#### Role Self-Modification
```python
# User escalates own role
auth_as(regular_user)  # user_id: 123, role: user

# Baseline: check current role
GET /api/user/123 → {"role": "user"} ✓

# Test: modify own role
POST /update_role {"user_id": 123, "role": "admin"} → ???
# Expected: 403 Forbidden
# Actual if vulnerable: 200 OK, role changed to admin
# Classification: VALIDATED (CWE-269)
```

#### Cross-User Resource Modification
```python
# User A modifies User B's data
auth_as(user_a)  # user_id: 123

# Baseline: modify own profile
POST /api/profile/123/update {"email": "me@example.com"} → 200 OK ✓

# Test: modify other user's profile
POST /api/profile/456/update {"email": "evil@attacker.com"} → ???
# Expected: 403 Forbidden
# Actual if vulnerable: 200 OK, user 456's profile modified
# Classification: VALIDATED (CWE-639)
```

### Phase 6: Capture Evidence

Capture minimal structured evidence with redaction and truncation:

```json
{
  "status": "VALIDATED|FALSE_POSITIVE|PARTIAL|UNVALIDATED",
  "baseline": {
    "url": "http://target.com/api/user/123",
    "method": "GET",
    "status": 200,
    "response_snippet": "{\"id\": 123, \"role\": \"user\"}",
    "response_hash": "sha256:abc123...",
    "truncated": false,
    "original_size_bytes": 58
  },
  "test": {
    "url": "http://target.com/update_role",
    "method": "POST",
    "payload": "{\"user_id\": 123, \"role\": \"admin\"}",
    "status": 200,
    "response_snippet": "{\"success\": true}",
    "response_hash": "sha256:def456...",
    "truncated": false,
    "original_size_bytes": 18
  },
  "evidence": "User 123 escalated own role from 'user' to 'admin'"
}
```

**Evidence Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `response_snippet` | Yes | First 8KB of response body (text only) |
| `response_hash` | Yes | SHA-256 hash of complete response (format: `sha256:...`) |
| `truncated` | Recommended | `true` if response exceeded 8KB limit, `false` otherwise |
| `original_size_bytes` | Recommended | Full response size before truncation |

**Truncation Pattern:**
- Limit response snippets to 8KB (8192 bytes) maximum
- If response exceeds limit, truncate and set `truncated: true`
- Always compute hash of **complete** response (before truncation)
- Include `original_size_bytes` to show actual response size

**Example with Large Response:**
```json
{
  "baseline": {
    "url": "http://target.com/api/users/export",
    "method": "GET",
    "status": 200,
    "response_snippet": "[truncated 8KB of 250KB JSON array...]",
    "response_hash": "sha256:789abc...",
    "truncated": true,
    "original_size_bytes": 256000
  }
}
```

**CRITICAL Redaction Requirements:**

Redact these sensitive field types from response snippets:
- Passwords, API keys, secrets, tokens
- SSN, credit card numbers, CVV codes
- Email addresses (in some contexts)
- Phone numbers, addresses
- Session IDs, JWTs, OAuth tokens
- Any PII or credentials

**Redaction Example:**
```json
// Before redaction
{"user": {"password": "MySecret123", "ssn": "123-45-6789"}}

// After redaction
{"user": {"password": "[REDACTED]", "ssn": "[REDACTED]"}}
```

### Phase 7: Classification Logic

```python
if response.status_code == 200:
    if action_should_be_blocked:
        return "VALIDATED"  # Authorization bypass confirmed!
    else:
        return "FALSE_POSITIVE"  # Action was allowed (not a vulnerability)
elif response.status_code in [401, 403]:
    return "FALSE_POSITIVE"  # Authorization working correctly
elif mixed_results_requiring_manual_review:
    return "PARTIAL"  # Some tests passed, others failed - needs human review
else:
    return "UNVALIDATED"  # Ambiguous result (error, timeout, etc.)
```

**Status Type Definitions:**

| Status | Meaning | When to Use |
|--------|---------|-------------|
| **VALIDATED** | Vulnerability confirmed | 200 OK received when accessing unauthorized resource/action |
| **FALSE_POSITIVE** | Security working correctly | 401/403 received, access properly denied |
| **PARTIAL** | Mixed results | Some operations succeeded, others failed; requires manual review |
| **UNVALIDATED** | Test inconclusive | Error, timeout, or ambiguous response preventing classification |

**PARTIAL Status Criteria:**
- Multiple test variants with inconsistent results (some 200 OK, some 403)
- Partial authorization bypass (e.g., read succeeds but write denied)
- Role-dependent results that don't clearly indicate vulnerability
- Complex multi-step operations with mixed outcomes

**Example PARTIAL Scenario:**
```python
# Testing /api/document/{id} endpoint
GET /api/document/456  → 200 OK (IDOR on read)
PUT /api/document/456  → 403 Forbidden (write protected)
DELETE /api/document/456  → 403 Forbidden (delete protected)

# Classification: PARTIAL
# Reason: Read access bypassed (IDOR), but modification/deletion properly blocked
# Requires manual review to assess actual risk
```

## Output Guidelines

**CRITICAL: Keep responses concise (1-4 sentences)**

**Format for VALIDATED (any authz failure):**
```
Authorization bypass on [endpoint] - [low_priv_user] successfully performed [high_priv_action] (200 OK). [Impact]. Evidence: [file_path]
```

**Format for FALSE_POSITIVE:**
```
Authorization check working on [endpoint] - access properly denied with [status_code]. Evidence: [file_path]
```

**Format for PARTIAL:**
```
Partial authorization bypass on [endpoint] - [operation1] succeeded (200 OK) but [operation2] blocked ([status_code]). Requires manual review. Evidence: [file_path]
```

**Format for UNVALIDATED:**
```
Authorization test incomplete on [endpoint] - [reason]. Evidence: [file_path]
```

**Examples:**

**IDOR (horizontal):**
```
Authorization bypass on /api/user - user 123 accessed user 456's PII (200 OK). Exposed email, phone, address.
```

**Privilege escalation (vertical):**
```
Authorization bypass on /update_role - regular user escalated to admin role (200 OK). Full system compromise possible.
```

**Cross-user modification:**
```
Authorization bypass on /api/profile/1/update - user 2 modified admin profile (200 OK). Account takeover risk.
```

**What NOT to do:**
- ❌ Don't repeat information from the evidence file
- ❌ Don't add CVSS scores unless requested
- ❌ Don't provide recommendations unless requested  
- ❌ Don't write paragraphs of analysis
- ❌ Don't format as "reports" with sections

## CWE Mapping

This skill validates:
- **CWE-639:** IDOR / Authorization Bypass Through User-Controlled Key
- **CWE-269:** Improper Privilege Management
- **CWE-862:** Missing Authorization
- **CWE-863:** Incorrect Authorization Logic
- **CWE-284:** Improper Access Control (parent category)
- **CWE-285:** Improper Authorization
- **CWE-425:** Direct Request / Forced Browsing

## Safety Rules

**Skill Responsibilities:**
- ONLY test against --target-url provided by user
- STOP immediately if unexpected damage occurs
- NO exfiltration of real user data (capture evidence, not actual PII)
- Redact sensitive data from all evidence
- Log all test actions (optional: `.securevibes/dast_audit.log`)

**Scanner Responsibilities (handled at infrastructure level):**
- Production URL detection (blocks testing `.com`, `.net`, `api.`, `www.` domains)
- User confirmation prompts before testing non-production targets
- Target reachability checks before starting tests
- `--allow-production` flag requirement for production testing

**Important:** This skill focuses on testing methodology. Safety gates (production detection, confirmation prompts, reachability checks) are implemented by the SecureVibes scanner, not the skill itself.

## Error Handling
- Target unreachable → Mark all UNVALIDATED
- Test accounts missing → Test only public endpoints, mark others UNVALIDATED
- Authentication fails → UNVALIDATED with reason
- Timeout exceeded → UNVALIDATED with timeout reason
- Unexpected error → Log error, continue with next vulnerability

## Examples

For comprehensive vulnerability-specific examples with code and evidence, see `examples.md`:
- **Horizontal Escalation (IDOR)**: Sequential IDs, UUIDs, nested resources, cross-account modification
- **Vertical Privilege Escalation**: Role self-modification, admin function access
- **Missing Authorization**: Unauthenticated admin endpoints
- **Forced Browsing**: Direct URL access to protected resources
- **Test Result Types**: FALSE_POSITIVE, UNVALIDATED scenarios

### Quick Reference Examples

**IDOR Test (Horizontal)**:
```
User 123 → GET /api/user/456 → 200 OK with user 456's data
Classification: VALIDATED (CWE-639)
```

**Vertical Escalation**:
```
Regular user → POST /update_role {"user_id": self, "role": "admin"} → 200 OK
Classification: VALIDATED (CWE-269)
```

## Reference Implementations

See `reference/` directory for implementation examples:
- **`auth_patterns.py`**: Reusable authentication functions (session, JWT, API key, OAuth2, Basic)
- **`validate_idor.py`**: Complete authorization testing script with redaction and classification
- **`README.md`**: Usage guidance and adaptation notes

These are reference implementations to adapt — not drop-in scripts. Each application requires tailored logic.

### Additional Resources

- [Agent Skills Guide](../../../docs/references/AGENT_SKILLS_GUIDE.md) - Comprehensive skill development guide
- [Claude Agent SDK Guide](../../../docs/references/claude-agent-sdk-guide.md) - Complete SDK documentation
- [DAST Guide](../../../docs/DAST_GUIDE.md) - DAST validation workflow
