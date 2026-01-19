# XSS Testing Reference

Reference implementations for Cross-Site Scripting (XSS) testing.

## Contents

- `xss_payloads.py` - XSS payload generators organized by context
- `validate_xss.py` - XSS validation workflow script

## Usage

### Payload Generation

```python
from xss_payloads import (
    html_body_payloads,
    attribute_payloads,
    javascript_payloads,
    uri_scheme_payloads,
    filter_bypass_payloads,
    dom_based_payloads
)

# Get payloads for HTML body context
for payload in html_body_payloads():
    print(payload)

# Get payloads for attribute context
for payload in attribute_payloads(quote_char='"'):
    print(payload)

# Get payloads for JavaScript string context
for payload in javascript_payloads(quote_char="'"):
    print(payload)
```

### Validation

```python
from validate_xss import XSSValidator

validator = XSSValidator(base_url="http://target.com")
results = validator.validate_endpoint(
    endpoint="/search",
    param="q",
    method="GET"
)

for result in results:
    print(f"{result['status']}: {result['evidence']}")
```

## Context-Specific Testing

| Context | Payload Module | Detection Method |
|---------|----------------|------------------|
| HTML Body | `html_body_payloads()` | Check for unencoded `<script>`, `onerror=`, etc. |
| HTML Attribute | `attribute_payloads()` | Check for event handler injection |
| JavaScript | `javascript_payloads()` | Check for string breakout |
| URI (href/src) | `uri_scheme_payloads()` | Check for `javascript:` in attributes |
| DOM-Based | `dom_based_payloads()` | Check DOM state after client-side rendering |

## CWE Coverage

These reference implementations help detect:
- **CWE-79:** Cross-site Scripting (all types)
- **CWE-80:** Basic XSS
- **CWE-81:** XSS in Error Messages
- **CWE-83:** XSS in Attributes
- **CWE-84:** XSS via URI Schemes
- **CWE-85:** Doubled Character XSS
- **CWE-86:** Invalid Character XSS
- **CWE-87:** Alternate XSS Syntax

## Safety Notes

- Use benign payloads (`alert(1)`, `console.log`) for detection
- Clean up stored XSS test data after validation
- Test in staging/isolated environments when possible
- Never inject payloads that could affect real users
