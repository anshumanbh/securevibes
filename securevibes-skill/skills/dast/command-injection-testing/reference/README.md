# Command Injection Testing Reference

Reference implementations for OS Command Injection testing.

## Contents

- `cmdi_payloads.py` - Command injection payload generators by platform and detection type
- `validate_cmdi.py` - Command injection validation workflow script

## Usage

### Payload Generation

```python
from cmdi_payloads import (
    direct_payloads,
    time_based_payloads,
    oob_payloads,
    argument_payloads,
    filter_bypass_payloads
)

# Get direct injection payloads for Linux
for payload in direct_payloads(platform="linux"):
    print(payload)

# Get time-based payloads with 5 second delay
for payload in time_based_payloads(delay=5, platform="linux"):
    print(payload)

# Get OOB payloads with callback URL
for payload in oob_payloads(callback_url="http://attacker.com"):
    print(payload)
```

### Validation

```python
from validate_cmdi import CommandInjectionValidator

validator = CommandInjectionValidator(base_url="http://target.com")
results = validator.validate_endpoint(
    endpoint="/ping",
    param="host",
    method="GET"
)

for result in results:
    print(f"{result['status']}: {result['evidence']}")
```

## Detection Types

| Detection Type | Payload Module | Detection Method |
|----------------|----------------|------------------|
| Direct | `direct_payloads()` | Check for command output in response |
| Time-Based | `time_based_payloads()` | Measure response time increase |
| Out-of-Band | `oob_payloads()` | Monitor callback server for DNS/HTTP |
| Argument | `argument_payloads()` | Check for help output or behavior change |

## CWE Coverage

These reference implementations help detect:
- **CWE-78:** Improper Neutralization of Special Elements used in an OS Command
- **CWE-77:** Improper Neutralization of Special Elements used in a Command
- **CWE-88:** Improper Neutralization of Argument Delimiters in a Command

## Safety Notes

- Use benign commands only (`id`, `whoami`, `hostname`, `sleep`, `ping`)
- NEVER use destructive commands (`rm`, `del`, `format`, `shutdown`)
- OOB callbacks only to domains you control
- Keep sleep durations minimal (5 seconds max)
- Stop immediately if unexpected server behavior detected
