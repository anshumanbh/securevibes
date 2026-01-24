---
name: nosql-injection-testing
description: Validate NoSQL injection vulnerabilities across MongoDB, Cassandra, CouchDB, Redis, and other NoSQL databases. Test operator injection, JavaScript injection, and query manipulation patterns. Use when testing CWE-943 (Improper Neutralization of Special Elements in Data Query Logic) and related NoSQL injection classes.
allowed-tools: Read, Write, Bash
---

# NoSQL Injection Testing Skill

## Purpose
Validate NoSQL injection vulnerabilities by injecting special operators, JavaScript code, or malformed queries into user-controlled inputs and observing:
- **Authentication bypass** via operator injection (`$ne`, `$gt`, `$regex`)
- **Data exfiltration** via query manipulation
- **JavaScript execution** in databases supporting server-side JS (`$where`, `mapReduce`)
- **Boolean-based inference** by comparing response differences
- **Time-based inference** via heavy operations or sleep-like constructs

## Vulnerability Types Covered

### 1. Operator Injection (CWE-943)
Inject MongoDB query operators to manipulate query logic.

**Detection Methods:**
- `{"$ne": ""}` — not equal empty, bypasses equality checks
- `{"$gt": ""}` — greater than empty, returns all matching documents
- `{"$regex": ".*"}` — regex wildcard match
- `{"$or": [...]}` — logical OR injection

**Example Attack:**
```json
// Normal: {"username": "admin", "password": "secret"}
// Attack: {"username": "admin", "password": {"$ne": ""}}
// Effect: Returns admin user regardless of password
```

### 2. JavaScript Injection (CWE-943)
Inject JavaScript in databases supporting server-side execution.

**Detection Methods:**
- `$where` clause injection: `{"$where": "this.password.length > 0"}`
- `mapReduce` function injection
- `$function` aggregation operator (MongoDB 4.4+)

**Example Attack:**
```json
// Payload: {"$where": "sleep(5000) || true"}
// Effect: 5-second delay if JS execution enabled
```

### 3. Array/Object Injection (CWE-943)
Exploit type confusion when arrays or objects are passed where strings expected.

**Detection Methods:**
- `username[$ne]=` via query string (Express.js extended query parser)
- Array index manipulation: `items[0]=malicious`

### 4. Aggregation Pipeline Injection (CWE-943)
Inject into MongoDB aggregation pipelines.

**Detection Methods:**
- `$lookup` injection for cross-collection access
- `$out` or `$merge` for write operations
- `$group` manipulation for data extraction

## Database-Specific Notes

| Database | Operator Injection | JS Injection | Boolean-Based | Time-Based |
|----------|-------------------|--------------|---------------|------------|
| MongoDB | ✓ (`$ne`, `$gt`, `$regex`, `$or`) | ✓ (`$where`, `mapReduce`) | ✓ | ✓ (via `$where` sleep or heavy ops) |
| CouchDB | ✓ (view manipulation) | ✓ (design doc JS) | ✓ | Limited |
| Cassandra | Limited (CQL injection) | No | ✓ | Limited |
| Redis | Command injection patterns | Lua script injection | ✓ | ✓ (`DEBUG SLEEP`) |
| Elasticsearch | ✓ (query DSL manipulation) | ✓ (scripting if enabled) | ✓ | ✓ (script-based) |
| DynamoDB | Condition expression injection | No | ✓ | No |

## Prerequisites
- Target reachable; NoSQL-backed functionality identified (API endpoints, forms, JSON bodies)
- Know (or infer) database type to select appropriate payloads
- If authentication required: test accounts available or mark paths UNVALIDATED
- VULNERABILITIES.json with suspected NoSQLi findings if provided

## Testing Methodology

### Phase 1: Identify Injection Points
- JSON POST bodies (most common for NoSQL APIs)
- URL query parameters (especially with extended query parsers)
- HTTP headers (authorization tokens, custom headers)
- Path parameters

**Key Insight:** NoSQL APIs typically accept JSON; look for object/array inputs where operators can be injected.

### Phase 2: Establish Baseline
- Send a normal request; record status, content, and response time
- Note authentication/authorization behavior
- Identify error message patterns

### Phase 3: Execute NoSQL Injection Tests

**Operator Injection (Authentication Bypass):**
```python
# Baseline
baseline = post("/login", json={"username": "admin", "password": "wrong"})
# Expected: 401 Unauthorized

# Test with $ne operator
test = post("/login", json={"username": "admin", "password": {"$ne": ""}})
# If 200 OK: VALIDATED - operator injection bypassed auth
```

**Operator Injection (Data Extraction):**
```python
# Baseline
baseline = get("/api/users?role=user")
# Expected: Returns only users with role="user"

# Test with $gt operator
test = get("/api/users?role[$gt]=")
# If returns more users: VALIDATED - operator injection expanded query
```

**Boolean-Based Inference:**
```python
# True condition
true_resp = post("/api/search", json={"name": {"$regex": "^a"}})
# False condition
false_resp = post("/api/search", json={"name": {"$regex": "^zzzzz"}})
# Compare response lengths/content
if len(true_resp.text) != len(false_resp.text):
    status = "VALIDATED"
```

**JavaScript Injection (if enabled):**
```python
# Time-based test
baseline_time = measure(post("/api/query", json={"filter": "normal"}))
test_time = measure(post("/api/query", json={"$where": "sleep(5000) || true"}))
if test_time > baseline_time + 4.5:
    status = "VALIDATED"
```

### Phase 4: Classification Logic

| Status | Meaning |
|--------|---------|
| **VALIDATED** | Clear NoSQLi indicators (auth bypass, data leak, JS execution, boolean/time diff) |
| **FALSE_POSITIVE** | No indicators; operators rejected or sanitized |
| **PARTIAL** | Weak signals (small differences, inconsistent results) |
| **UNVALIDATED** | Blocked, error, or insufficient evidence |

### Phase 5: Capture Evidence
Capture minimal structured evidence (redact PII/secrets, truncate to 8KB, hash full response):
- `status`, `injection_type`, `cwe`
- Baseline request (url/method/status/body hash)
- Test request (url/method/status/body hash)
- Payload used
- Authentication bypass details if applicable

### Phase 6: Safety Rules
- Detection-only payloads; **never** destructive operations (`$out`, `db.dropDatabase()`)
- Avoid data exfiltration; use boolean/time-based confirmation
- Do not execute arbitrary JS that modifies data
- Respect rate limits
- Redact credentials, tokens, and personal data in evidence

## Output Guidelines
- Keep responses concise (1-4 sentences)
- Include endpoint, payload, detection method, and impact

**Validated examples:**
```
NoSQL injection on /login - $ne operator bypassed password check (CWE-943). Admin access without credentials.
MongoDB $where injection on /api/search - sleep(5000) caused 5.1s delay (CWE-943). Server-side JS execution confirmed.
Operator injection on /api/users - $gt operator returned all users instead of filtered set (CWE-943).
```

**Unvalidated example:**
```
NoSQL injection test incomplete on /api/data - operators rejected with 400 Bad Request. Evidence: path/to/evidence.json
```

## CWE Mapping

**Primary CWE (DAST-testable):**
- **CWE-943:** Improper Neutralization of Special Elements in Data Query Logic
  - This is THE designated CWE for NoSQL injection
  - Alternate terms: "NoSQL Injection", "NoSQLi"
  - Covers: MongoDB, Cassandra, CouchDB, Redis, Elasticsearch, DynamoDB, and other NoSQL databases

**Parent/Related CWEs (context):**
- **CWE-74:** Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') — parent class
- **CWE-20:** Improper Input Validation — related root cause
- **CWE-116:** Improper Encoding or Escaping of Output — related mitigation failure

**Sibling CWEs under CWE-943 (for reference):**
- CWE-89: SQL Injection (separate skill)
- CWE-90: LDAP Injection
- CWE-643: XPath Injection
- CWE-652: XQuery Injection

**Related Attack Pattern:**
- **CAPEC-676:** NoSQL Injection

**Note:** Unlike SQL injection (CWE-89), NoSQL injection does not have a dedicated base-level CWE. CWE-943 at the class level is the correct mapping for NoSQL injection vulnerabilities per MITRE guidance.

## Notable CVEs (examples)
- **CVE-2024-50672 (eLearning Platform):** NoSQL injection via Mongoose find function allowing password resets.
- **CVE-2021-20736 (Rocket.Chat):** NoSQL injection in team collaboration product.
- **CVE-2021-22911 (Rocket.Chat):** Blind NoSQL injection allowing admin account takeover.
- **CVE-2020-35666 (PaaS Platform):** NoSQL injection using MongoDB operator.
- **CVE-2019-2389 (MongoDB):** Information disclosure via aggregation pipeline.
- **CVE-2017-18381 (KeystoneJS):** NoSQL injection in password reset functionality.

## Safety Reminders
- ONLY test against user-approved targets; stop if production protections trigger
- Do not log or store sensitive data; redact in evidence
- Prefer parameterized queries and input validation in mitigations
- Disable server-side JavaScript execution in production MongoDB (`--noscripting`)

## Reference Implementations
- See `reference/nosql_payloads.py` for NoSQLi payloads by database type
- See `reference/validate_nosqli.py` for NoSQLi-focused validation flow
- See `examples.md` for concrete NoSQLi scenarios and evidence formats

### Additional Resources
- [OWASP NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
- [PortSwigger NoSQL Injection](https://portswigger.net/web-security/nosql-injection)
- [CAPEC-676: NoSQL Injection](https://capec.mitre.org/data/definitions/676.html)
- [HackTricks NoSQL Injection](https://book.hacktricks.xyz/pentesting-web/nosql-injection)
