---
name: web-apps-threat-modeling
description: Threat model web applications using OWASP Top 10 and common web vulnerability patterns. Use when analyzing traditional web applications with HTML/JS frontends, server-side rendering, session management, form handling, or database-backed CRUD operations. Covers injection, authentication, XSS, CSRF, access control, and security misconfigurations.
allowed-tools: Read, Grep, Glob, Write
---

# Web Application Threat Modeling Skill

## Purpose

Apply comprehensive threat modeling to traditional web applications, covering the OWASP Top 10 and common web security patterns. This skill focuses on server-rendered applications, session-based authentication, form handling, and database interactions.

## When to Use This Skill

Use this skill when the target application includes ANY of:
- Server-side web frameworks (Flask, Django, Express, Rails, Spring, Laravel)
- HTML form handling and user input processing
- Session-based authentication (cookies, server sessions)
- Database-backed CRUD operations
- Server-side template rendering
- Traditional MVC/MVT architecture

## Web Application Threat Categories

### 1. INJECTION (A03:2021)

Attackers send malicious data that is interpreted as commands or queries.

**SQL Injection**
- User input concatenated into SQL queries
- ORM misuse allowing raw SQL execution
- Second-order injection via stored data

**Command Injection**
- User input passed to system commands
- Unsanitized file paths in shell operations
- Template injection in server-side rendering

**LDAP/XPath/NoSQL Injection**
- Query languages vulnerable to injection
- Document database query manipulation

**Indicators to Look For:**
- String concatenation in database queries
- `os.system()`, `subprocess`, `exec()` with user input
- Template engines with `|safe` or autoescape disabled
- Raw SQL queries instead of parameterized statements

### 2. BROKEN AUTHENTICATION (A07:2021)

Authentication mechanisms that can be bypassed or exploited.

**Session Management Flaws**
- Predictable session IDs
- Session fixation vulnerabilities
- Missing session timeout/invalidation
- Session tokens in URLs

**Credential Weaknesses**
- Weak password policies
- Missing brute-force protection
- Credential stuffing vulnerabilities
- Insecure password storage (MD5, SHA1, no salt)

**Authentication Bypass**
- Missing authentication on endpoints
- Broken "remember me" functionality
- Insecure password reset flows

**Indicators to Look For:**
- Custom session management instead of framework defaults
- `@login_required` missing on protected routes
- Password hashing without bcrypt/argon2/scrypt
- No rate limiting on login endpoints

### 3. CROSS-SITE SCRIPTING - XSS (A03:2021)

Attackers inject client-side scripts into web pages viewed by others.

**Reflected XSS**
- User input immediately reflected in response
- Search results, error messages with user input
- URL parameters rendered without encoding

**Stored XSS**
- User content stored and displayed to others
- Comments, profiles, messages with HTML/JS
- Database content rendered without sanitization

**DOM-based XSS**
- JavaScript manipulating DOM with untrusted data
- `innerHTML`, `document.write()` with user input
- URL fragment (#) data used unsafely

**Indicators to Look For:**
- `|safe` filter in Jinja2/Django templates
- `dangerouslySetInnerHTML` in React
- Missing Content-Security-Policy headers
- User input in HTML attributes without encoding

### 4. BROKEN ACCESS CONTROL (A01:2021)

Users acting outside their intended permissions.

**Horizontal Privilege Escalation**
- Accessing other users' data by changing IDs
- IDOR (Insecure Direct Object Reference)
- Missing ownership checks on resources

**Vertical Privilege Escalation**
- Regular users accessing admin functionality
- Role checks missing on sensitive endpoints
- Client-side only access control

**Path Traversal**
- `../` sequences in file paths
- Accessing files outside intended directories
- Arbitrary file read/write

**Indicators to Look For:**
- User IDs in URLs without ownership verification
- `@admin_required` decorator missing
- Client-side role checks without server validation
- File operations with user-controlled paths

### 5. SECURITY MISCONFIGURATION (A05:2021)

Insecure default configurations or missing security hardening.

**Debug Mode in Production**
- Detailed error messages with stack traces
- Debug endpoints exposed
- Development settings in production

**Default Credentials**
- Default admin passwords unchanged
- Default API keys or secrets
- Sample/test accounts in production

**Missing Security Headers**
- No Content-Security-Policy
- Missing X-Frame-Options (clickjacking)
- Absent X-Content-Type-Options

**Indicators to Look For:**
- `DEBUG = True` in production config
- Hardcoded secrets in source code
- Missing helmet/security middleware
- Verbose error pages enabled

### 6. CRYPTOGRAPHIC FAILURES (A02:2021)

Weak or missing encryption of sensitive data.

**Data in Transit**
- HTTP instead of HTTPS
- Weak TLS configurations
- Mixed content issues

**Data at Rest**
- Plaintext passwords in database
- Unencrypted sensitive data storage
- Weak encryption algorithms (DES, RC4)

**Key Management**
- Hardcoded encryption keys
- Keys stored with encrypted data
- Weak key derivation functions

**Indicators to Look For:**
- `http://` URLs in code
- MD5/SHA1 for password hashing
- Encryption keys in source code
- `SECRET_KEY` with weak/default values

### 7. CROSS-SITE REQUEST FORGERY - CSRF (A01:2021)

Attackers trick users into performing unintended actions.

**Missing CSRF Tokens**
- State-changing requests without CSRF protection
- CSRF tokens not validated server-side
- Token reuse across sessions

**CSRF Bypass**
- GET requests for state changes
- JSON-based CSRF attacks
- Subdomain token leakage

**Indicators to Look For:**
- POST/PUT/DELETE without `@csrf_protect`
- Missing `csrf_token` in forms
- AJAX requests without CSRF headers
- State changes via GET requests

### 8. INSECURE DESERIALIZATION (A08:2021)

Untrusted data used to abuse application logic or execute code.

**Object Injection**
- Pickle/Marshal with untrusted data
- YAML.load without safe_load
- JSON with type confusion

**Magic Method Exploitation**
- `__reduce__` in Python pickle
- `__wakeup` in PHP unserialize
- Gadget chains in Java serialization

**Indicators to Look For:**
- `pickle.loads()` with user data
- `yaml.load()` instead of `yaml.safe_load()`
- Cookie-based object serialization
- Session data in client-side storage

### 9. VULNERABLE COMPONENTS (A06:2021)

Using components with known security vulnerabilities.

**Outdated Dependencies**
- Old framework versions with CVEs
- Unpatched libraries
- Abandoned packages

**Dependency Confusion**
- Private package name conflicts
- Typosquatting attacks
- Malicious package injection

**Indicators to Look For:**
- Old versions in requirements.txt/package.json
- Known CVEs in dependency versions
- No lockfile (requirements.txt without versions)
- Importing from untrusted sources

### 10. LOGGING & MONITORING FAILURES (A09:2021)

Insufficient logging to detect attacks or breaches.

**Missing Audit Logs**
- Authentication events not logged
- Access control failures not recorded
- No alerting on suspicious activity

**Sensitive Data in Logs**
- Passwords logged in plaintext
- Session tokens in log files
- PII exposed in error logs

**Indicators to Look For:**
- No logging of login attempts
- `print()` statements instead of proper logging
- Sensitive data in exception messages
- No centralized log aggregation

## Mapping to STRIDE

| STRIDE Category | Web Application Manifestation |
|-----------------|------------------------------|
| **Spoofing** | Session hijacking, credential theft, CSRF |
| **Tampering** | SQL injection, parameter manipulation, XSS |
| **Repudiation** | Missing audit logs, unsigned transactions |
| **Info Disclosure** | Error messages, directory listing, IDOR |
| **Denial of Service** | Resource exhaustion, ReDoS, file upload bombs |
| **Elevation of Privilege** | Broken access control, privilege escalation |

## Threat Identification Workflow

### Phase 1: Identify Entry Points
1. Map all routes/endpoints in the application
2. Identify form inputs and query parameters
3. Document file upload functionality
4. List authentication/authorization points

### Phase 2: Analyze Data Flows
1. Trace user input through the application
2. Identify database query construction
3. Map session/cookie handling
4. Document output encoding points

### Phase 3: Apply OWASP Top 10
For each entry point and data flow:
- Check against all 10 categories above
- Consider attack chains (XSS → session hijack)
- Assess likelihood and impact

## Output Format

Generate threats with web-specific fields:

```json
{
  "id": "THREAT-XXX",
  "category": "Tampering",
  "title": "SQL Injection in User Search",
  "description": "User search endpoint concatenates input into SQL query",
  "severity": "critical",
  "affected_components": ["search_controller.py", "user_model.py"],
  "attack_scenario": "Attacker submits ' OR 1=1-- in search field",
  "owasp_category": "A03:2021 Injection",
  "cwe_id": "CWE-89",
  "vulnerability_types": ["CWE-89", "CWE-20"],
  "mitigation": "Use parameterized queries via ORM"
}
```

## Examples

### SQL Injection
```
Entry: GET /search?q=<user_input>
Code: cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{q}%'")
Threat: SQL injection allows data exfiltration or modification
Severity: Critical
```

### XSS in Comments
```
Entry: POST /comments with body field
Storage: Comment saved to database
Display: {{ comment.body | safe }} in template
Threat: Stored XSS executes in all viewers' browsers
Severity: High
```

### Broken Access Control
```
Entry: GET /api/orders/{order_id}
Code: Order.query.get(order_id) - no user check
Threat: Any user can view any order by changing ID
Severity: High
```

## Safety Notes

When threat modeling web applications:
- Focus on OWASP Top 10 as baseline coverage
- Consider business logic flaws beyond technical vulns
- Check framework-specific security features
- Verify security headers and CSP configuration

