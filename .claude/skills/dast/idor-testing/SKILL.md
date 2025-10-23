---
name: idor-testing
description: Validate Insecure Direct Object Reference (IDOR) vulnerabilities through HTTP-based exploitation attempts. Use when testing CWE-639 findings or validating access control issues.
allowed-tools: Read, Write, Bash
---

# IDOR Testing Skill

## Purpose
Test IDOR vulnerabilities by attempting unauthorized access to resources using object ID manipulation via HTTP requests.

## Prerequisites
- Target application running and reachable
- At least 2 test user accounts (different privilege levels)
- VULNERABILITIES.json with IDOR findings (CWE-639)

## Testing Methodology

### Phase 1: Load Vulnerability Details
1. Read VULNERABILITIES.json
2. Filter for IDOR vulnerabilities (CWE-639, "idor" type)
3. Extract: endpoint, method, object_id_parameter, file_path

### Phase 2: Prepare Test Accounts
If test accounts provided (via DAST_TEST_ACCOUNTS.json):
- Authenticate as user1 (regular user)
- Authenticate as user2 (different user, same privilege)
- Extract session tokens/cookies

If no test accounts:
- Test only public/unauthenticated endpoints
- Mark authenticated endpoints as UNVALIDATED

### Phase 3: Execute IDOR Tests

**Test Pattern:**
1. **Baseline (Authorized Access)**
   - User1 accesses their own resource (user1_id)
   - Record: HTTP method, URL, status code, response snippet
   - Expected: 200 OK with user1's data

2. **Test (Unauthorized Access)**
   - User1 attempts to access user2's resource (user2_id)
   - Keep user1's session/auth token
   - Change only the object ID in URL/request
   - Record: HTTP method, URL, status code, response snippet
   - Expected: 403/401 (properly secured) OR 200 (IDOR confirmed)

3. **Classification**
   - **VALIDATED**: 200 OK received with user2's data
   - **FALSE_POSITIVE**: 403/401 received (access control working)
   - **UNVALIDATED**: Endpoint unreachable, timeout, or cannot test

### Phase 4: Capture Evidence

For each test, run `scripts/validate_idor.py`:
```bash
python scripts/validate_idor.py \
  --endpoint "$ENDPOINT" \
  --method "$METHOD" \
  --user1-token "$USER1_TOKEN" \
  --user1-id "$USER1_ID" \
  --user2-id "$USER2_ID" \
  --output evidence.json
```

**Script returns:**
```json
{
  "status": "VALIDATED|FALSE_POSITIVE|UNVALIDATED",
  "baseline": {
    "url": "https://target.com/api/users/123",
    "status": 200,
    "response_snippet": "{\"id\":123,\"email\":\"[REDACTED]\"}",
    "response_hash": "sha256:abc..."
  },
  "test": {
    "url": "https://target.com/api/users/456",
    "status": 200,
    "response_snippet": "{\"id\":456,\"email\":\"[REDACTED]\"}",
    "response_hash": "sha256:def..."
  },
  "evidence": "User1 successfully accessed User2's data"
}
```

### Phase 5: Generate DAST_VALIDATION.json

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
