# Injection Testing Reference (Miscellaneous)

Reference implementations for miscellaneous injection testing.

**Note:** This covers injection types NOT handled by dedicated skills:
- SQL Injection → use `sql-injection-testing`
- NoSQL Injection → use `nosql-injection-testing`
- XSS → use `xss-testing`
- XXE → use `xxe-testing`
- Command Injection → use `command-injection-testing`

## Contents

- `injection_payloads.py` - Payload generators for various injection types
- `validate_injection.py` - Injection validation workflow script

## Usage

### Payload Generation

```python
from injection_payloads import (
    ssti_payloads,
    ldap_payloads,
    xpath_payloads,
    crlf_payloads,
    el_payloads,
    graphql_payloads,
    csv_formula_payloads,
    redos_payloads
)

# Get SSTI detection payloads
for payload in ssti_payloads():
    print(payload)

# Get LDAP injection payloads
for payload in ldap_payloads():
    print(payload)

# Get CRLF injection payloads
for payload in crlf_payloads():
    print(payload)
```

### Validation

```python
from validate_injection import InjectionValidator

validator = InjectionValidator(base_url="http://target.com")

# Test SSTI
result = validator.validate_ssti("/greet", "name")
print(result.to_dict())

# Test LDAP injection
result = validator.validate_ldap("/search", "user")
print(result.to_dict())

# Test CRLF injection
result = validator.validate_crlf("/redirect", "url")
print(result.to_dict())
```

## Injection Types Covered

| Type | Payload Module | Detection Method |
|------|----------------|------------------|
| SSTI | `ssti_payloads()` | Math evaluation (49 from 7*7) |
| LDAP | `ldap_payloads()` | Content length change with wildcard |
| XPath | `xpath_payloads()` | Boolean-based / error-based |
| CRLF | `crlf_payloads()` | Header injection detection |
| EL/OGNL | `el_payloads()` | Math evaluation |
| GraphQL | `graphql_payloads()` | Introspection / schema exposure |
| CSV Formula | `csv_formula_payloads()` | Formula in export |
| ReDoS | `redos_payloads()` | Response time increase |

## CWE Coverage

- **CWE-1336:** Server-Side Template Injection (SSTI)
- **CWE-90:** LDAP Injection
- **CWE-643:** XPath Injection
- **CWE-652:** XQuery Injection
- **CWE-93:** CRLF Injection
- **CWE-113:** HTTP Response Splitting
- **CWE-917:** Expression Language Injection
- **CWE-1333:** ReDoS
- **CWE-1236:** CSV/Formula Injection

## Safety Notes

- Use detection-only payloads (math eval, timing, markers)
- NEVER execute destructive commands via SSTI/EL
- Do not exfiltrate real data
- CSV formula testing only in isolated environments
- Respect rate limits
