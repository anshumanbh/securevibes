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
    xquery_payloads,
    crlf_payloads,
    email_header_payloads,
    el_payloads,
    javascript_eval_payloads,
    graphql_payloads,
    csv_formula_payloads,
    redos_payloads,
    orm_hql_payloads,
    yaml_config_payloads,
    shellshock_payloads,
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

# Test XQuery injection
result = validator.validate_xquery("/user", "name")
print(result.to_dict())

# Test JavaScript eval injection
result = validator.validate_js_eval("/calc", "expr")
print(result.to_dict())
```

## Injection Types Covered

| Type | Payload Module | Detection Method |
|------|----------------|------------------|
| SSTI | `ssti_payloads()` | Math evaluation (49 from 7*7) |
| LDAP | `ldap_payloads()` | Content length change with wildcard |
| XPath | `xpath_payloads()` | Boolean-based / error-based |
| XQuery | `xquery_payloads()` | Boolean-based / error-based |
| CRLF | `crlf_payloads()` | Header injection detection |
| Email Header | `email_header_payloads()` | BCC/CC header injection |
| EL/OGNL | `el_payloads()` | Math evaluation |
| JS Eval | `javascript_eval_payloads()` | Math evaluation |
| GraphQL | `graphql_payloads()` | Introspection / schema exposure |
| CSV Formula | `csv_formula_payloads()` | Formula in export |
| ReDoS | `redos_payloads()` | Response time increase |
| ORM/HQL | `orm_hql_payloads()` | Boolean-based / syntax errors |
| YAML/Config | `yaml_config_payloads()` | Anchor/merge key abuse |
| Shellshock | `shellshock_payloads()` | Header-based env var injection |

## CWE Coverage

- **CWE-1336:** Server-Side Template Injection (SSTI)
- **CWE-90:** LDAP Injection
- **CWE-643:** XPath Injection
- **CWE-652:** XQuery Injection
- **CWE-93:** CRLF Injection
- **CWE-113:** HTTP Response Splitting
- **CWE-644:** HTTP Header Injection (Scripting Syntax)
- **CWE-917:** Expression Language Injection
- **CWE-1333:** ReDoS
- **CWE-1236:** CSV/Formula Injection
- **CWE-94:** Code Injection
- **CWE-95:** Eval Injection
- **CWE-200:** Exposure of Sensitive Information (GraphQL introspection)
- **CWE-502:** Deserialization of Untrusted Data (YAML)
- **CWE-78:** OS Command Injection (Shellshock)
- **CWE-89:** SQL Injection (ORM/HQL/GraphQL sinks)
- **CWE-943:** Improper Neutralization in Data Query Logic

## Safety Notes

- Use detection-only payloads (math eval, timing, markers)
- NEVER execute destructive commands via SSTI/EL
- Do not exfiltrate real data
- CSV formula testing only in isolated environments
- Respect rate limits
