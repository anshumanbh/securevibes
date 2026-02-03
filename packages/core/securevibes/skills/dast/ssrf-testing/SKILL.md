---
name: ssrf-testing
description: Validate Server-Side Request Forgery (SSRF) vulnerabilities by testing if user-controlled URLs can reach internal services, cloud metadata endpoints, or alternative protocols. Use when testing CWE-918 (SSRF), CWE-441 (Unintended Proxy), CWE-611 (XXE leading to SSRF), or findings involving URL fetching, webhooks, file imports, image/PDF/SVG processing, or XML parsing with external entities.
---

# SSRF Testing Skill

## Purpose
Validate SSRF vulnerabilities by sending crafted URLs to user-controlled input points and observing:
- **Internal service access** (localhost, internal IPs, cloud metadata)
- **Protocol smuggling** (file://, gopher://, dict://)
- **Filter bypass success** (IP encoding, DNS rebinding, redirects)
- **Out-of-band callbacks** (OOB detection for blind SSRF)

## Vulnerability Types Covered

### 1. Basic SSRF (CWE-918)
Force server to make requests to attacker-controlled or internal destinations.

**Test Pattern:** Supply internal URL in user-controlled parameter  
**Expected if secure:** Request blocked or validated  
**Actual if vulnerable:** Server fetches internal resource and returns/processes content

### 2. Blind SSRF (CWE-918)
Server makes request but response is not returned to attacker.

**Test Pattern:** Supply OOB callback URL (Burp Collaborator, interact.sh)  
**Expected if secure:** No callback received  
**Actual if vulnerable:** HTTP/DNS callback received at attacker server

### 3. Cloud Metadata SSRF (CWE-918)
Access cloud provider metadata endpoints to steal credentials.

**Test Pattern:** Request `http://169.254.169.254/latest/meta-data/` (AWS) or equivalent  
**Expected if secure:** Request blocked  
**Actual if vulnerable:** IAM credentials, instance metadata exposed

**Cloud Providers:**
- AWS (169.254.169.254) - IMDSv1 & IMDSv2
- GCP (metadata.google.internal) - requires `Metadata-Flavor: Google` header
- Azure (169.254.169.254) - requires `Metadata: true` header
- DigitalOcean, Alibaba (100.100.100.200), Oracle (192.0.0.192), Hetzner

### 4. Protocol Smuggling (CWE-918)
Use alternative URL schemes to access local files or internal services.

**Protocols:**
- `file://` - Local file read
- `gopher://` - Raw TCP (Redis, Memcached, SMTP exploitation)
- `dict://` - Dictionary protocol (service detection)
- `ftp://`, `sftp://`, `tftp://` - File transfer protocols
- `ldap://` - Directory access
- `php://` - PHP stream wrappers (php://filter, php://input)
- `data://` - Data URI scheme
- `jar://` - Java archive scheme
- `netdoc://` - Java netdoc wrapper

### 5. Internal Port Scanning (CWE-918)
Enumerate internal services via response timing or error differences.

**Test Pattern:** Request internal IPs on various ports  
**Expected if secure:** All requests blocked equally  
**Actual if vulnerable:** Different responses for open vs closed ports

### 6. SSRF via XXE (CWE-611 → CWE-918)
XML External Entity injection leading to SSRF.

**Test Pattern:** Inject XXE payload with external entity pointing to internal URL  
**Expected if secure:** XXE disabled or external entities blocked  
**Actual if vulnerable:** Internal content returned in XML response

See [examples.md](examples.md#xxe-based-ssrf) for payloads.

### 7. SSRF via PDF/HTML Rendering (CWE-918)
HTML-to-PDF converters (wkhtmltopdf, Puppeteer, Chrome headless) fetch embedded resources.

**Test Pattern:** Inject HTML with internal resource references (iframe, img, link, script tags)  
See [examples.md](examples.md#pdfhtml-renderer-ssrf) and [ssrf_payloads.py](references/ssrf_payloads.py) for payloads.

### 8. SSRF via SVG/Image Processing (CWE-918)
Image processors that handle SVG or fetch external images.

**Test Pattern:** Upload SVG with external references  
See [examples.md](examples.md#svgimage-processing-ssrf) for payloads.

### 9. Partial URL SSRF (Path Injection)
Application constructs URL from user input (path/host injection).

**Test Pattern:** Inject path traversal or host override  
See [examples.md](examples.md#advanced-bypass-examples) for techniques.

## Prerequisites
- Target application running and reachable
- Identified SSRF injection points (URL parameters, webhooks, file imports)
- OOB callback server for blind SSRF (optional but recommended)
- VULNERABILITIES.json with suspected SSRF findings

## Testing Methodology

### Phase 1: Identify Injection Points

Before testing, analyze vulnerability report and source code for:
- **URL parameters:** `?url=`, `?path=`, `?src=`, `?dest=`, `?redirect=`, `?uri=`
- **Webhook configurations:** Callback URL fields
- **File import features:** "Import from URL" functionality
- **Image/avatar fetchers:** Profile picture from URL
- **PDF generators:** HTML-to-PDF with embedded resources
- **API integrations:** OAuth callbacks, external API endpoints

**Key insight:** Any user-controlled input that causes server-side HTTP requests is a potential SSRF vector.

### Phase 2: Establish Baseline

Send a request to an external domain you control or an OOB service to confirm URL fetching is enabled. See [validate_ssrf.py](references/validate_ssrf.py) for implementation.

### Phase 3: Test Internal Access

#### Localhost Access

Test standard localhost references and bypass variants. See [ssrf_payloads.py](references/ssrf_payloads.py) `get_localhost_payloads()` for complete list including decimal/hex/octal encodings and [examples.md](examples.md#basic-ssrf---localhost-access) for testing patterns.

#### Cloud Metadata Access

Test cloud provider metadata endpoints. See [ssrf_payloads.py](references/ssrf_payloads.py) `get_cloud_metadata_payloads()` for complete provider-specific URLs and required headers. See [examples.md](examples.md#cloud-metadata-ssrf) for testing patterns.

### Phase 4: Test Filter Bypasses

#### IP Encoding Bypasses

Test decimal, hex, octal, IPv6-mapped encodings. See [ssrf_payloads.py](references/ssrf_payloads.py) `get_ip_encoding_payloads()` for encoding functions.

#### URL Parser Confusion

Exploit parser differences using @, #, \ characters. See [ssrf_payloads.py](references/ssrf_payloads.py) `get_url_parser_confusion_payloads()`.

#### DNS Rebinding

Use DNS services that alternate responses (1u.ms, rebind.network). See [ssrf_payloads.py](references/ssrf_payloads.py) `get_dns_rebinding_payloads()`.

#### Redirect-Based Bypass

Use 307/308 redirect services. See [ssrf_payloads.py](references/ssrf_payloads.py) `get_redirect_payloads()`.

#### Unicode/Punycode Bypass

Test unicode normalization and punycode. See [ssrf_payloads.py](references/ssrf_payloads.py) for patterns.

#### CRLF Injection in URL

Inject headers via CRLF sequences. See [ssrf_payloads.py](references/ssrf_payloads.py) for patterns.

#### JAR Scheme Bypass (Java)

Test JAR scheme for Java apps. See [ssrf_payloads.py](references/ssrf_payloads.py) `get_protocol_payloads()`.

### Phase 5: Test Protocol Handlers

Test alternative URL schemes (file://, gopher://, dict://, php://, ldap://, etc.). See [ssrf_payloads.py](references/ssrf_payloads.py) `get_protocol_payloads()` and [examples.md](examples.md#protocol-smuggling) for complete list and patterns.

### Phase 5b: Test XXE-based SSRF

If application processes XML, test XXE leading to SSRF. See [ssrf_payloads.py](references/ssrf_payloads.py) `get_xxe_payloads()` for examples.

### Phase 5c: Test HTML/PDF Injection SSRF

If application generates PDFs from HTML, inject tags that fetch resources. See [ssrf_payloads.py](references/ssrf_payloads.py) `get_html_injection_payloads()`.

### Phase 6: Blind SSRF Detection

Use OOB callback service (Burp Collaborator, interact.sh) to detect blind SSRF. See [examples.md](examples.md#blind-ssrf) and [validate_ssrf.py](references/validate_ssrf.py) for implementation.

### Phase 7: Classification Logic

Classify responses based on internal content indicators, timing differences, and OOB callbacks. See [validate_ssrf.py](references/validate_ssrf.py) for complete classification function with indicators for:
- Linux/Windows system files
- AWS/GCP/Azure metadata
- Internal services (Redis, Memcached, etc.)
- Docker/K8s environments

**Status Definitions:**

| Status | Meaning | Criteria |
|--------|---------|----------|
| **VALIDATED** | SSRF confirmed | Internal content returned, cloud metadata exposed, or OOB callback received |
| **FALSE_POSITIVE** | Not vulnerable | All internal requests blocked, no bypass succeeded |
| **PARTIAL** | Possible SSRF | Response differs for internal URLs but no clear content leak; requires manual review |
| **UNVALIDATED** | Test inconclusive | Error, timeout, or ambiguous response |

## Evidence Capture

Capture baseline, test payload, response data, and classification. See [examples.md](examples.md#test-result-types) for evidence structure.

**CRITICAL Redaction Requirements:**
- AWS AccessKeyId, SecretAccessKey, Token
- GCP/Azure access tokens
- Any credentials or secrets in metadata responses
- Internal IP addresses (if sensitive)
- Private SSH keys

## Output Guidelines

**CRITICAL: Keep responses concise (1-4 sentences)**

**Format for VALIDATED:**
```
SSRF on [endpoint] - server fetched [internal_resource] returning [data_type]. [Impact]. Evidence: [file_path]
```

**Format for FALSE_POSITIVE:**
```
SSRF check on [endpoint] - internal requests properly blocked ([status_code]/[error]). Evidence: [file_path]
```

**Format for PARTIAL:**
```
Possible SSRF on [endpoint] - response differs for internal URL but no content leak confirmed. Requires manual review. Evidence: [file_path]
```

**Format for UNVALIDATED:**
```
SSRF test incomplete on [endpoint] - [reason]. Evidence: [file_path]
```

**Examples:**

**Cloud Metadata SSRF:**
```
SSRF on /api/fetch - server accessed AWS metadata (169.254.169.254) exposing IAM credentials. Full AWS account compromise possible. Evidence: .securevibes/ssrf_evidence_001.json
```

**Localhost Access:**
```
SSRF on /webhook/test - server fetched http://127.0.0.1:6379 (Redis) returning version info. Internal service enumeration confirmed. Evidence: .securevibes/ssrf_evidence_002.json
```

**Protocol Smuggling:**
```
SSRF on /api/import - file:// protocol accepted, returned /etc/passwd contents. Local file read vulnerability. Evidence: .securevibes/ssrf_evidence_003.json
```

**Blind SSRF:**
```
Blind SSRF on /pdf/generate - OOB callback received at interact.sh from target server. Server makes external requests. Evidence: .securevibes/ssrf_evidence_004.json
```

**What NOT to do:**
- ❌ Don't repeat full payload lists in output
- ❌ Don't include raw credential values (always redact)
- ❌ Don't write multi-paragraph analysis
- ❌ Don't provide remediation unless requested

## CWE Mapping

This skill validates:
- **CWE-918:** Server-Side Request Forgery (SSRF)
- **CWE-441:** Unintended Proxy or Intermediary
- **CWE-611:** Improper Restriction of XML External Entity Reference (XXE → SSRF)
- **CWE-829:** Inclusion of Functionality from Untrusted Control Sphere (via PDF/HTML rendering)

## Safety Rules

**Skill Responsibilities:**
- ONLY test against --target-url provided by user
- NEVER exfiltrate actual cloud credentials (capture evidence of exposure, redact values)
- STOP if destructive action detected (e.g., gopher:// to Redis FLUSHALL)
- Redact all sensitive data in evidence files
- Use benign payloads (INFO, GET) not destructive ones (DELETE, FLUSHALL)

**Scanner Responsibilities (handled at infrastructure level):**
- Production URL detection
- User confirmation prompts
- Target reachability checks

## Error Handling
- Target unreachable → Mark UNVALIDATED
- Timeout on internal request → Note in evidence, may indicate filtering
- Connection refused → May indicate port scanning capability (PARTIAL)
- OOB service unavailable → Test non-blind methods only, note limitation

## Examples

For comprehensive examples with payloads and evidence, see `examples.md`:
- **Basic SSRF**: Localhost and internal IP access
- **Cloud Metadata**: AWS, GCP, Azure, DigitalOcean, Alibaba, Oracle
- **Filter Bypasses**: IP encoding, DNS rebinding, redirects, URL parser confusion
- **Protocol Smuggling**: file://, gopher://, dict://, ldap://
- **Blind SSRF**: OOB detection techniques

## Reference Implementations

See `references/` directory for implementation examples:
- **`ssrf_payloads.py`**: Payload generator functions for all bypass techniques
- **`validate_ssrf.py`**: Complete SSRF testing script with classification
- **`README.md`**: Usage guidance and adaptation notes

### Additional Resources

- [PayloadsAllTheThings SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [OWASP SSRF Prevention Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [HackTricks SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)

