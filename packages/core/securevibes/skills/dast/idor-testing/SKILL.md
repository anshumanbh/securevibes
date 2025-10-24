---
name: idor-testing
description: Validate Insecure Direct Object Reference (IDOR) vulnerabilities through HTTP-based exploitation attempts. Use when testing CWE-639 findings or validating access control issues.
allowed-tools: Read, Write, Bash
---

# IDOR Testing Skill

## Purpose
Validate IDOR by attempting unauthorized access to resources using object ID manipulation in HTTP requests. Focus on methodology; adapt steps to the target application.

## Prerequisites
- Target application running and reachable
- At least 2 test users (same role, different accounts) if auth is required
- VULNERABILITIES.json contains suspected IDORs (type "idor" or CWE-639)

## Testing Methodology

### Phase 1: Understand the Application

Before sending requests, read the source code to determine:
- Authentication mechanism (session cookies, JWT Bearer, API key, OAuth)
- Where object identifiers appear (path params, query params, JSON body, GraphQL vars)
- Expected response shapes and authorization checks (middleware/decorators/guards)

Key insight: Each app is different. Read the code first to decide how to authenticate and where to mutate object IDs.

### Phase 2: Prepare Test Accounts
If DAST_TEST_ACCOUNTS.json exists:
- Extract credentials for two distinct regular users (user1, user2)
- Note their identifiers (e.g., user_id) and expected ownership

If no test accounts:
- Test only public endpoints and mark authenticated paths as UNVALIDATED (insufficient accounts)

### Phase 3: Authenticate Test Users (adapt to app)

Session-based auth example:
```python
session = requests.Session()
resp = session.post(f"{target_url}/login", data={"username": user1, "password": pwd1})
```

JWT auth example:
```python
resp = requests.post(f"{target_url}/api/auth/login", json={"username": user1, "password": pwd1})
token = resp.json().get("access_token"); headers = {"Authorization": f"Bearer {token}"}
```

API key example:
```python
headers = {"X-API-Key": api_key_for_user1}
```

Use the application’s actual endpoints, payloads, and headers.

### Phase 4: Execute IDOR Test

**Test Pattern:**
1. Baseline (authorized): With user1’s auth, request user1’s own resource. Expect 200 with user1 data.
2. Test (unauthorized): With the same auth, change only the object identifier to user2’s resource.
3. Classify: 200 (VALIDATED), 401/403 (FALSE_POSITIVE), other/unclear (UNVALIDATED).

### Phase 5: Capture Evidence (concise, redacted)

Capture minimal structured evidence and redact sensitive data. Example:
```json
{
  "status": "VALIDATED|FALSE_POSITIVE|UNVALIDATED",
  "baseline": {"url": "...", "method": "GET", "status": 200, "response_snippet": "...", "response_hash": "sha256:..."},
  "test": {"url": "...", "method": "GET", "status": 200, "response_snippet": "...", "response_hash": "sha256:..."},
  "evidence": "User1 (id 123) accessed User2 (id 456) resource"
}
```
Hash full responses and store only brief redacted snippets.

### Phase 6: Generate DAST_VALIDATION.json

Create `.securevibes/DAST_VALIDATION.json`:
```json
{
  "dast_scan_metadata": {
    "target_url": "$TARGET_URL",
    "scan_timestamp": "$TIMESTAMP",
    "total_vulnerabilities_tested": N,
    "validated": N,
    "unvalidated": N,
    "false_positives": N,
    "scan_duration_seconds": N
  },
  "validations": [
    {
      "vulnerability_id": "VULN-001",
      "validation_status": "VALIDATED",
      "tested_at": "$TIMESTAMP",
      "test_steps": [
        "1. Authenticated as user1 (ID: 123)",
        "2. Verified access to /api/users/123 → 200 OK",
        "3. Modified request to /api/users/456 (user2)",
        "4. Received 200 OK with user2's PII"
      ],
      "evidence": {
        "http_requests": [
          {
            "request": "GET /api/users/456",
            "status": 200,
            "response_snippet": "{\"email\":\"[REDACTED]\"}",
            "response_hash": "sha256:..."
          }
        ]
      },
      "exploitability_score": 9.5,
      "notes": "IDOR confirmed - trivial exploitation"
    }
  ]
}
```

## Output Guidelines

**CRITICAL: Keep responses concise (1-4 sentences)**

Present results as:

**Format for VALIDATED:**
```
IDOR validated on [endpoint] - [resource1_id] successfully accessed [resource2_id] with [status_code]. [Key impact]. Evidence: [file_path]
```

**Format for FALSE_POSITIVE:**
```
IDOR not confirmed on [endpoint] - access properly denied with [status_code]. Evidence: [file_path]
```

**Format for UNVALIDATED:**
```
IDOR test unvalidated on [endpoint] - [reason]. Evidence: [file_path]
```

**Example (VALIDATED):**
```
IDOR validated on /api/users - user 123 accessed user 456's data (200 OK). Exposed PII including SSN. Evidence: /tmp/idor_evidence.json
```

**What NOT to do:**
- ❌ Don't repeat information from the evidence file
- ❌ Don't add CVSS scores unless requested
- ❌ Don't provide recommendations unless requested
- ❌ Don't write paragraphs of analysis
- ❌ Don't format as "reports" with sections

## Safety Rules
- ONLY test against --target-url provided by user
- NEVER test production without explicit authorization
- STOP if unexpected damage occurs
- NO exfiltration of real user data (capture evidence, not actual PII)
- Log all actions to .securevibes/dast_audit.log (optional)

## Error Handling
- Target unreachable → All UNVALIDATED
- Test accounts missing → Test public endpoints only
- Timeout exceeded → UNVALIDATED with timeout reason
- Unexpected error → Log, continue with next vulnerability

## Examples
See examples.md for:
- Sequential ID IDOR (123 → 456)
- UUID IDOR (abc-def-123 → xyz-pqr-789)
- Nested resource IDOR (/users/123/documents/456)

## Reference Implementations (read-only)
See `reference/` for example patterns (session cookies, JWT, API key). These are examples to read and adapt — do not run them verbatim.
