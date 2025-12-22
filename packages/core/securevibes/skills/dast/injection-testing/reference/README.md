# Injection Testing Reference Implementations

This directory contains reference implementations for injection vulnerability testing. These are **examples to adapt**, not drop-in scripts that run across all applications.

## Files

### injection_payloads.py

Payload generation utilities organized by injection type:

- `get_sqli_payloads(detection, db_type)` - SQL injection payloads (time/error/boolean)
- `get_cmdi_payloads(os_type, detection)` - OS command injection payloads
- `get_xss_payloads(context)` - XSS payloads for different contexts
- `get_nosql_payloads(db_type)` - NoSQL injection payloads (MongoDB operators)
- `get_ssti_payloads(engine)` - Template injection payloads
- `get_ldap_payloads()` - LDAP injection payloads
- `get_xpath_payloads()` - XPath injection payloads
- `get_el_payloads()` - Expression Language injection payloads

**Usage:**
```python
from injection_payloads import get_sqli_payloads

# Get MySQL time-based payloads
payloads = get_sqli_payloads(detection="time", db_type="mysql")
for p in payloads:
    print(f"Payload: {p['payload']}, Expected delay: {p['delay']}s")
```

### validate_injection.py

Complete injection testing script with:

- Time-based SQL injection detection
- Error-based SQL injection detection
- Reflected XSS detection
- OS command injection detection
- SSTI detection
- Response truncation and hashing
- Sensitive data redaction

**Usage:**
```bash
python validate_injection.py \
    --url "http://target.com/api/search" \
    --param "q" \
    --value "test" \
    --types "sqli_time,sqli_error,xss" \
    --output results.json
```

## Adaptation Notes

### 1. Authentication

Add authentication headers as needed:

```bash
python validate_injection.py \
    --url "http://target.com/api/search" \
    --param "q" \
    --value "test" \
    --header "Authorization: Bearer eyJhbG..." \
    --header "Cookie: session=abc123" \
    --output results.json
```

### 2. POST Requests

The reference script uses GET requests. For POST testing, modify `validate_injection.py`:

```python
# Instead of:
test_resp = requests.get(test_url, headers=headers, timeout=timeout)

# Use:
test_resp = requests.post(
    url,
    json={"param": payload},  # or data= for form data
    headers=headers,
    timeout=timeout
)
```

### 3. Custom Payloads

Extend `injection_payloads.py` with application-specific payloads:

```python
def get_custom_payloads():
    return [
        {"payload": "custom_payload_here", "type": "custom"},
    ]
```

### 4. Response Analysis

Adjust detection patterns for your application:

```python
# Add application-specific error patterns
SQL_ERROR_PATTERNS.extend([
    r"custom_error_pattern",
    r"your_framework_error",
])
```

## Safety Reminders

1. **Only test authorized targets** - Never run against production without permission
2. **Use detection-only payloads** - No destructive operations (DROP, DELETE, rm -rf)
3. **Respect rate limits** - Add delays between requests if needed
4. **Log all actions** - Keep audit trail of test requests

## Dependencies

```bash
pip install requests
```

## Related Resources

- [SKILL.md](../SKILL.md) - Full testing methodology
- [examples.md](../examples.md) - Comprehensive injection examples
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
