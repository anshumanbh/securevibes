# Security Scan Report

**Repository:** `/Users/anshumanbhartiya/repos/securevibes`  
**Scan Date:** 2025-10-09 17:48:59  
**Files Scanned:** 2915  
**Scan Duration:** 1134.94s (~18m 55s)  
**Total Cost:** $2.1379  

---

## Executive Summary

🔴 **19 security vulnerabilities found** - **CRITICAL** - Requires immediate attention

- 🔴 **2 Critical** - Require immediate attention
- 🟠 **6 High** - Should be fixed soon
- 🟡 **8 Medium** - Address when possible
- 🟢 **3 Low** - Minor issues

---

## Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 Critical | 2 | 11% |
| 🟠 High | 6 | 32% |
| 🟡 Medium | 8 | 42% |
| 🟢 Low | 3 | 16% |

---

## Vulnerability Overview

| # | Severity | Title | Location |
|---|----------|-------|----------|
| 1 | 🔴 CRITICAL | Arbitrary Filesystem Access via bypassPermissions Mode | `packages/core/securevibes/scanner/scanner.py:294` |
| 2 | 🟠 HIGH | Malicious Prompt Injection via Unverified Prompt Files | `packages/core/securevibes/prompts/loader.py:30` |
| 3 | 🟠 HIGH | API Key Exposure via Environment Variables | `packages/core/securevibes/scanner/scanner.py:308` |
| 4 | 🟠 HIGH | Cost Overrun via Unbounded Repository Scanning | `packages/core/securevibes/scanner/scanner.py:250` |
| 5 | 🔴 CRITICAL | Supply Chain Attack via Unpinned claude-agent-sdk Dependency | `packages/core/pyproject.toml:29` |
| 6 | 🟠 HIGH | Secrets Exposure in Code Snippets within Scan Results | `packages/core/securevibes/models/issue.py:27` |
| 7 | 🟡 MEDIUM | No Audit Trail for Security Scan Operations | `packages/core/securevibes/scanner/scanner.py:225` |
| 8 | 🟡 MEDIUM | XSS Injection Risk in Agent-Generated Markdown Output | `packages/core/securevibes/reporters/markdown_reporter.py:25` |
| 9 | 🟢 LOW | Absolute Path Disclosure in Debug Mode and Error Messages | `packages/core/securevibes/scanner/scanner.py:80` |
| 10 | 🟠 HIGH | Arbitrary Code Execution via Write Tool File Extension Abuse | `packages/core/securevibes/scanner/scanner.py:242` |
| 11 | 🟢 LOW | Race Condition in Concurrent File Writes to .securevibes/ | `packages/core/securevibes/scanner/scanner.py:242` |
| 12 | 🟡 MEDIUM | No Integrity Verification for Scan Results | `packages/core/securevibes/reporters/json_reporter.py:24` |
| 13 | 🟠 HIGH | Symlink Attack Enabling Privilege Escalation via .securevibe... | `packages/core/securevibes/scanner/scanner.py:240` |
| 14 | 🟡 MEDIUM | Scan Results Stored Without Encryption at Rest | `packages/core/securevibes/reporters/json_reporter.py:24` |
| 15 | 🟡 MEDIUM | Configuration Injection via Unvalidated Environment Variable... | `packages/core/securevibes/config.py:67` |
| 16 | 🟡 MEDIUM | Memory Exhaustion via Large Code Snippets in Vulnerability R... | `packages/core/securevibes/scanner/scanner.py:368` |
| 17 | 🟡 MEDIUM | Resource Exhaustion via Uncontrolled Glob Pattern Execution | `packages/core/securevibes/scanner/scanner.py:250` |
| 18 | 🟢 LOW | Information Disclosure via Verbose Error Messages | `packages/core/securevibes/cli/main.py:159` |
| 19 | 🟡 MEDIUM | Python Import Hijacking Risk via .securevibes/ Package Struc... | `packages/core/securevibes/scanner/scanner.py:242` |

---

## Detailed Findings

### 1. Arbitrary Filesystem Access via bypassPermissions Mode [🔴 CRITICAL]

**File:** `packages/core/securevibes/scanner/scanner.py:294`  
**CWE:** CWE-22  
**Severity:** 🔴 Critical

**Description:**

The Scanner class configures ClaudeSDKClient with permission_mode='bypassPermissions', granting unrestricted filesystem access to all AI agents. No validation restricts file reads/writes to the repository directory. Agents can access any file readable by the user process, including SSH keys, credentials, browser data, and system files. This enables prompt injection attacks where malicious instructions in code comments or repository files could direct agents to exfiltrate sensitive data.

**Code Snippet:**

```python
options = ClaudeAgentOptions(
    agents=SECUREVIBES_AGENTS,
    cwd=str(repo),
    max_turns=config.get_max_turns(),
    permission_mode='bypassPermissions',
    model=self.model,
    hooks={...}
)
```

**Recommendation:**

1. Change permission_mode to 'default' or 'acceptEdits' to require user confirmation. 2. Implement filesystem jail by validating all file paths in pre_tool_hook to ensure they are within the repository boundary using os.path.realpath() and checking the resolved path starts with the repo path. 3. Add SECUREVIBES_RESTRICT_FILESYSTEM environment variable to enforce strict mode. 4. Implement path validation in the hook that rejects absolute paths outside the repository: if not realpath(file_path).startswith(realpath(repo)): raise PermissionError()

---

### 2. Malicious Prompt Injection via Unverified Prompt Files [🟠 HIGH]

**File:** `packages/core/securevibes/prompts/loader.py:30`  
**CWE:** CWE-494  
**Severity:** 🟠 High

**Description:**

Agent prompts are loaded from the filesystem without any integrity verification (signatures, checksums, or hashes). The load_prompt() function in prompts/loader.py reads prompt files directly using read_text() with no validation. If an attacker compromises the package installation directory or performs a supply chain attack on PyPI, they can modify prompt files to inject malicious instructions that exfiltrate data, bypass security checks, or manipulate scan results. The prompts directory has no write protection or integrity monitoring.

**Code Snippet:**

```python
return prompt_file.read_text(encoding="utf-8")
```

**Recommendation:**

1. Implement cryptographic signing of prompt files during package build. 2. Add runtime integrity verification: compute SHA-256 hashes of all prompt files and compare against a manifest file signed with the package maintainer's private key. 3. Store prompt hashes in a secure manifest: prompts_manifest.json with structure {"assessment.txt": "sha256:..."}. 4. Add verification before loading: if hashlib.sha256(prompt_file.read_bytes()).hexdigest() != expected_hash: raise SecurityError("Prompt integrity verification failed"). 5. Add --verify-prompts CLI flag for manual integrity checks. 6. Set restrictive file permissions (0444) on prompt files during installation.

---

### 3. API Key Exposure via Environment Variables [🟠 HIGH]

**File:** `packages/core/securevibes/scanner/scanner.py:308`  
**CWE:** CWE-522  
**Severity:** 🟠 High

**Description:**

The application relies on ANTHROPIC_API_KEY stored in environment variables with no additional protection. Environment variables are accessible to all processes running as the same user, visible in process listings (/proc/PID/environ on Linux), and may leak through error messages, debug logs, or crash dumps. No code exists to protect the API key in memory or implement secure credential storage. The key is passed directly to ClaudeSDKClient without encryption or obfuscation.

**Code Snippet:**

```python
async with ClaudeSDKClient(options=options) as client:
    await client.query(orchestration_prompt)
```

**Recommendation:**

1. Integrate with OS credential managers: macOS Keychain (keyring.get_password('securevibes', 'anthropic_api_key')), Windows Credential Manager, Linux Secret Service. 2. Add keyring as a dependency and use it as the primary credential source, falling back to environment variables only with a warning. 3. Implement API key encryption at rest using cryptography.fernet with a user-provided passphrase. 4. Add warning when API key is sourced from environment: console.print('[yellow]Warning: API key from environment variable. Consider using keyring for better security[/yellow]'). 5. Implement secure memory handling: overwrite API key in memory after use. 6. Add --setup-keyring command to securely store credentials.

---

### 4. Cost Overrun via Unbounded Repository Scanning [🟠 HIGH]

**File:** `packages/core/securevibes/scanner/scanner.py:250`  
**CWE:** CWE-400  
**Severity:** 🟠 High

**Description:**

The Scanner class performs no pre-scan validation of repository size or file count. The scan() method at line 250 counts files using glob() but only for reporting - it does not enforce any limits. An attacker or careless user could scan massive repositories (e.g., scanning filesystem root '/', monorepos with millions of files, directories including node_modules) causing excessive API costs and long execution times. No timeout mechanism exists beyond max_turns configuration.

**Code Snippet:**

```python
files_scanned = len(list(repo.glob('**/*.py'))) + len(list(repo.glob('**/*.ts'))) + \
               len(list(repo.glob('**/*.js'))) + len(list(repo.glob('**/*.tsx'))) + \
               len(list(repo.glob('**/*.jsx')))
```

**Recommendation:**

1. Implement pre-scan size validation before line 250: if files_scanned > 10000: console.print('[red]Error: Repository too large[/red]'); raise ValueError(). 2. Add --max-files CLI option with default of 10,000 files. 3. Implement cost estimation: estimated_cost = (files_scanned * avg_tokens_per_file * model_cost_per_token); if estimated_cost > threshold: prompt for confirmation. 4. Add default exclusions for common bloat directories: exclude patterns ['**/node_modules/**', '**/.git/**', '**/venv/**', '**/__pycache__/**', '**/dist/**', '**/build/**']. 5. Implement scan timeout: add asyncio.wait_for() wrapper around the scan with configurable timeout via SECUREVIBES_MAX_SCAN_TIME. 6. Add --dry-run flag to estimate cost without running scan.

---

### 5. Supply Chain Attack via Unpinned claude-agent-sdk Dependency [🔴 CRITICAL]

**File:** `packages/core/pyproject.toml:29`  
**CWE:** CWE-1357  
**Severity:** 🔴 Critical

**Description:**

The pyproject.toml specifies claude-agent-sdk>=0.1.0 using a minimum version constraint rather than exact pinning. This allows automatic installation of any future version >= 0.1.0, including potentially compromised versions. Since claude-agent-sdk controls all AI agent orchestration, tool execution, and API communication, a compromised version could inject backdoors, exfiltrate code, modify scan results, or execute arbitrary code. No dependency integrity verification (hash checking) is implemented.

**Code Snippet:**

```
dependencies = [
    "claude-agent-sdk>=0.1.0",
    "anyio>=4.0.0",
    "python-dotenv>=1.0.0",
    "click>=8.0.0",
    "rich>=13.0.0",
]
```

**Recommendation:**

1. Pin exact dependency versions in production deployments: change 'claude-agent-sdk>=0.1.0' to 'claude-agent-sdk==0.1.0'. 2. Generate requirements.txt with pip freeze and use pip install --require-hashes for hash verification. 3. Implement automated dependency scanning in CI/CD: add pip-audit or safety checks. 4. Create a lockfile mechanism: use poetry.lock or pip-tools to ensure reproducible builds. 5. Add pre-install verification: check that installed claude-agent-sdk matches expected hash before import. 6. Document recommended installation: 'pip install securevibes==X.Y.Z --require-hashes -r requirements-hashes.txt'. 7. Monitor Anthropic security advisories for claude-agent-sdk updates.

---

### 6. Secrets Exposure in Code Snippets within Scan Results [🟠 HIGH]

**File:** `packages/core/securevibes/models/issue.py:27`  
**CWE:** CWE-312  
**Severity:** 🟠 High

**Description:**

The Code Review Agent includes raw code snippets in VULNERABILITIES.json without redaction or secrets detection. The SecurityIssue model stores code_snippet as plain text with no sanitization. If vulnerable code contains hardcoded secrets (API keys, passwords, database credentials), these are captured verbatim in scan results. The scan_results.json and VULNERABILITIES.json files are stored unencrypted in .securevibes/ directory and may be committed to Git, shared via email, or uploaded to issue trackers, leaking credentials.

**Code Snippet:**

```python
@dataclass
class SecurityIssue:
    ...
    code_snippet: str
    ...
    def to_dict(self) -> dict:
        return {
            ...
            "code_snippet": self.code_snippet,
            ...
        }
```

**Recommendation:**

1. Implement secrets detection before storing code snippets: use regex patterns to detect common secret formats (API keys: [A-Za-z0-9]{32,}, JWT tokens, AWS keys, etc.). 2. Add redaction function: def redact_secrets(code: str) -> str: return re.sub(r'(api[_-]?key|password|secret|token)\s*=\s*["\'][^"\'
]+["\']', r'\1="[REDACTED]"', code, flags=re.IGNORECASE). 3. Integrate detect-secrets library: from detect_secrets import SecretsCollection; scan code snippets before storage. 4. Add --redact-secrets CLI flag (default enabled). 5. Display warning when secrets detected: 'WARNING: Potential credentials found in scan results at line X'. 6. Add pre-commit hook to prevent committing .securevibes/ directory: add '.securevibes/' to .gitignore template. 7. Implement configurable redaction patterns via SECUREVIBES_SECRET_PATTERNS environment variable.

---

### 7. No Audit Trail for Security Scan Operations [🟡 MEDIUM]

**File:** `packages/core/securevibes/scanner/scanner.py:225`  
**CWE:** CWE-778  
**Severity:** 🟡 Medium

**Description:**

The Scanner class provides no audit logging of scan operations. No record is maintained of who performed scans, when, on which repositories, what files were accessed, or what vulnerabilities were found. The console output displayed by ProgressTracker is ephemeral and not persisted. No log files are created. This prevents forensic investigation after security incidents, makes it impossible to track scan history, and fails compliance requirements (SOC 2, ISO 27001) for security tool usage auditing.

**Code Snippet:**

```python
async def scan(self, repo_path: str) -> ScanResult:
    ...
    scan_start_time = time.time()
    ...
    # No audit logging code exists
```

**Recommendation:**

1. Implement audit logging module: create securevibes/audit.py with structured logging. 2. Log scan events to ~/.securevibes/audit.log with format: {"timestamp": "ISO8601", "user": os.getlogin(), "action": "scan_start", "repository": repo_path, "model": self.model}. 3. Add audit events for: scan_start, scan_complete, file_read (in pre_tool_hook), vulnerability_found, scan_error. 4. Implement secure append-only log file with proper permissions (0600). 5. Add --audit-mode CLI flag that requires log review before showing results. 6. Implement SIEM integration: add --syslog or --cloudwatch-logs options for enterprise environments. 7. Include audit trail in scan_results.json: add 'audit_trail' field with list of significant events. 8. Add audit log rotation to prevent disk exhaustion.

---

### 8. XSS Injection Risk in Agent-Generated Markdown Output [🟡 MEDIUM]

**File:** `packages/core/securevibes/reporters/markdown_reporter.py:25`  
**CWE:** CWE-79  
**Severity:** 🟡 Medium

**Description:**

Agents write SECURITY.md and generate markdown reports that may be rendered in web interfaces (GitHub, GitLab, documentation sites, internal dashboards). The MarkdownReporter and agent prompts do not sanitize or HTML-escape content. An attacker who compromises agent prompts could inject XSS payloads in vulnerability descriptions, threat titles, or architecture documentation. When rendered in a web context, these payloads could execute JavaScript, steal session cookies, or perform actions on behalf of viewers.

**Code Snippet:**

```python
output_file.write_text(markdown)
```

**Recommendation:**

1. Implement output sanitization for all user-facing text: import html; sanitized = html.escape(user_content). 2. Escape HTML in all markdown output: threat titles, descriptions, code snippets, file paths. 3. Add markdown sanitization library: use bleach.clean() to allow only safe markdown tags. 4. Implement Content Security Policy recommendation in documentation: warn users that scan results should be rendered with CSP headers. 5. Add JSON schema validation with regex patterns to reject content containing <script>, javascript:, or other suspicious patterns. 6. Escape code snippets in markdown code blocks properly: wrap in triple backticks with language identifier. 7. Add --sanitize-output CLI flag (default enabled) to HTML-escape all agent-generated content.

---

### 9. Absolute Path Disclosure in Debug Mode and Error Messages [🟢 LOW]

**File:** `packages/core/securevibes/scanner/scanner.py:80`  
**CWE:** CWE-209  
**Severity:** 🟢 Low

**Description:**

The ProgressTracker displays absolute file paths when debug mode is enabled. Error messages throughout the codebase expose absolute paths in exceptions (FileNotFoundError, PermissionError). These paths reveal internal system structure including usernames, project names, directory layouts, and technology stack. Debug output is displayed to console and may be captured in CI/CD logs, shared in support tickets, or logged to centralized systems, aiding reconnaissance for attackers.

**Code Snippet:**

```python
if file_path:
    self.files_read.add(file_path)
    filename = Path(file_path).name
    self.console.print(f"  📖 Reading {filename}", style="dim")
```

**Recommendation:**

1. Sanitize file paths in debug output: replace absolute paths with relative paths from repository root. 2. Implement path transformation: def sanitize_path(path: str, repo_root: str) -> str: return os.path.relpath(path, repo_root) if path.startswith(repo_root) else Path(path).name. 3. Add path sanitization to ProgressTracker: use sanitized paths in all console.print() calls. 4. Implement error message sanitization: catch exceptions and re-raise with sanitized messages. 5. Add --redact-paths CLI flag to anonymize all file paths in output. 6. Replace user home directory with ~/ in displayed paths: path.replace(os.path.expanduser('~'), '~'). 7. Add warning when --debug is enabled: 'Warning: Debug mode may expose system paths'. 8. Configure CI/CD systems to filter sensitive path patterns from logs.

---

### 10. Arbitrary Code Execution via Write Tool File Extension Abuse [🟠 HIGH]

**File:** `packages/core/securevibes/scanner/scanner.py:242`  
**CWE:** CWE-94  
**Severity:** 🟠 High

**Description:**

Agents use the Write tool to create files in .securevibes/ directory without file extension validation. While the prompts instruct agents to write .json and .md files, no code enforcement prevents writing arbitrary file types. A compromised agent could write executable files (.py, .sh, .exe), Python modules with __init__.py, or other dangerous file types. If users or automated systems execute these files, arbitrary code execution occurs. The agents have no restrictions on file content or permissions.

**Code Snippet:**

```python
securevibes_dir.mkdir(exist_ok=True)
```

**Recommendation:**

1. Implement file extension whitelist validation in pre_tool_hook: ALLOWED_EXTENSIONS = {'.json', '.md', '.txt'}; if Path(file_path).suffix not in ALLOWED_EXTENSIONS: raise PermissionError(). 2. Add file content validation: scan written files for dangerous patterns (eval, exec, __import__, subprocess). 3. Set restrictive file permissions on all created files: os.chmod(file_path, 0o644) to prevent execution. 4. Explicitly reject __init__.py: if Path(file_path).name == '__init__.py': raise PermissionError('Cannot write __init__.py'). 5. Add Content Security Policy validation before writing files: detect suspicious code patterns using AST parsing for .py files. 6. Implement post-scan verification: scan .securevibes/ for unexpected file types and warn user. 7. Add .securevibes/ to .gitignore template generated during scan.

---

### 11. Race Condition in Concurrent File Writes to .securevibes/ [🟢 LOW]

**File:** `packages/core/securevibes/scanner/scanner.py:242`  
**CWE:** CWE-362  
**Severity:** 🟢 Low

**Description:**

Multiple concurrent scans of the same repository can write to the same .securevibes/ directory simultaneously. The Scanner creates files without file locking, atomic writes, or concurrency control. Agents use the Write tool which performs direct file writes without synchronization. In CI/CD pipelines with parallel jobs or when multiple developers scan simultaneously, this causes race conditions leading to corrupted JSON files, interleaved data, or lost scan results.

**Code Snippet:**

```python
securevibes_dir.mkdir(exist_ok=True)
```

**Recommendation:**

1. Implement file locking: import fcntl; with open(file, 'w') as f: fcntl.flock(f.fileno(), fcntl.LOCK_EX); f.write(data); fcntl.flock(f.fileno(), fcntl.LOCK_UN). 2. Use unique output directories per scan: securevibes_dir = repo / f'.securevibes-{uuid.uuid4().hex[:8]}'. 3. Implement atomic file writes: write to temporary file, then os.rename() to final location. 4. Add PID-based locking: create .securevibes/.lock file containing process PID; check lock before scanning. 5. Add --output-dir CLI flag to specify custom output location for concurrent scans. 6. Detect concurrent scans: check for .securevibes/.lock and warn: 'WARNING: Another scan in progress'. 7. Implement scan queue with mutex for CI/CD environments. 8. Add timestamp-based output directories: .securevibes-{timestamp}/.

---

### 12. No Integrity Verification for Scan Results [🟡 MEDIUM]

**File:** `packages/core/securevibes/reporters/json_reporter.py:24`  
**CWE:** CWE-345  
**Severity:** 🟡 Medium

**Description:**

Scan result files (scan_results.json, VULNERABILITIES.json, THREAT_MODEL.json) have no cryptographic signatures, checksums, or integrity verification. After agents generate these files, they can be modified by attackers without detection. A malicious insider or attacker with filesystem access could edit scan results to remove vulnerabilities, add false positives, or alter severity levels. No tamper detection mechanism exists, making scan results unreliable for compliance or security audits.

**Code Snippet:**

```python
with open(output_file, 'w') as f:
    json.dump(result.to_dict(), f, indent=2)
```

**Recommendation:**

1. Implement HMAC-SHA256 signatures for all output files: import hmac, hashlib; signature = hmac.new(api_key.encode(), file_content.encode(), hashlib.sha256).hexdigest(). 2. Add 'signature' field to scan_results.json: compute signature over canonical JSON representation (sorted keys, no whitespace). 3. Store signature in separate .securevibes/scan_results.json.sig file. 4. Implement verification command: 'securevibes verify scan_results.json' that recomputes signature and compares. 5. Sign using API key or session token as HMAC secret. 6. Add signature verification to report command before loading results. 7. Include timestamp in signed data to prevent replay attacks. 8. Add --require-signature flag that aborts if signature verification fails. 9. Log signature verification results to audit log.

---

### 13. Symlink Attack Enabling Privilege Escalation via .securevibes/ [🟠 HIGH]

**File:** `packages/core/securevibes/scanner/scanner.py:240`  
**CWE:** CWE-59  
**Severity:** 🟠 High

**Description:**

The Scanner creates and writes to .securevibes/ directory without symlink validation. If an attacker creates .securevibes/ as a symlink pointing to a sensitive location (e.g., ~/.ssh/, /etc/, ~/.bashrc), agents writing files will follow the symlink and overwrite the target. This enables privilege escalation: .securevibes/SECURITY.md → ~/.ssh/authorized_keys would allow the attacker to inject their SSH key. The Write tool in claude-agent-sdk may not check for symlinks before writing.

**Code Snippet:**

```python
securevibes_dir = repo / SECUREVIBES_DIR
try:
    securevibes_dir.mkdir(exist_ok=True)
```

**Recommendation:**

1. Implement symlink detection before creating directory: if securevibes_dir.is_symlink(): raise SecurityError('Output directory is a symlink'). 2. Use os.path.realpath() to resolve symlinks and verify resolved path is within repository: if not realpath(securevibes_dir).startswith(realpath(repo)): raise SecurityError(). 3. Create directory with O_NOFOLLOW semantics: use os.mkdir() with manual check instead of Path.mkdir(). 4. Validate all file paths before writing in pre_tool_hook: ensure no component of the path is a symlink. 5. Add --no-follow-symlinks flag (enabled by default). 6. Implement TOCTOU protection: verify path after directory creation. 7. Set securevibes_dir permissions to 0755 and validate after creation. 8. Use temporary directory with restricted permissions, then atomic move to final location.

---

### 14. Scan Results Stored Without Encryption at Rest [🟡 MEDIUM]

**File:** `packages/core/securevibes/reporters/json_reporter.py:24`  
**CWE:** CWE-311  
**Severity:** 🟡 Medium

**Description:**

All scan output files (SECURITY.md, THREAT_MODEL.json, VULNERABILITIES.json, scan_results.json) are stored in plaintext with no encryption. These files contain sensitive security information including vulnerability details, proof-of-concept exploits, system architecture, and potentially code snippets with secrets. If the repository is stored on unencrypted disk, backed up to cloud storage, or synced via Dropbox/OneDrive, vulnerability data is exposed. Disk theft or unauthorized filesystem access leaks complete security assessment results.

**Code Snippet:**

```python
with open(output_file, 'w') as f:
    json.dump(result.to_dict(), f, indent=2)
```

**Recommendation:**

1. Implement AES-256-GCM encryption for scan output files: from cryptography.fernet import Fernet; cipher = Fernet(key); encrypted = cipher.encrypt(json_bytes). 2. Derive encryption key from API key or user-provided passphrase using PBKDF2: key = PBKDF2(password, salt, iterations=100000). 3. Add --encrypt CLI flag: 'securevibes scan --encrypt' prompts for passphrase. 4. Store encrypted files with .enc extension: scan_results.json.enc. 5. Implement key management: store encryption key in OS keyring, never in plaintext. 6. Add automatic decryption in report command with passphrase prompt. 7. Set SECUREVIBES_ENCRYPT_OUTPUT=true environment variable for always-on encryption. 8. Implement file shredding for temporary plaintext artifacts: use os.remove() followed by overwriting file location. 9. Add --ephemeral flag to store results in memory only without persisting to disk.

---

### 15. Configuration Injection via Unvalidated Environment Variables [🟡 MEDIUM]

**File:** `packages/core/securevibes/config.py:67`  
**CWE:** CWE-15  
**Severity:** 🟡 Medium

**Description:**

Agent configuration is controlled by environment variables (SECUREVIBES_ASSESSMENT_MODEL, SECUREVIBES_MAX_TURNS, etc.) with minimal validation. The AgentConfig.get_max_turns() attempts integer conversion but silently falls back to defaults on invalid input. An attacker controlling the environment (compromised CI/CD, malicious shell script) can inject invalid configurations to cause denial of service (max_turns=0), bypass security (set invalid model causing failures), or manipulate scan behavior. No validation ensures model names are valid or max_turns is within reasonable bounds.

**Code Snippet:**

```python
try:
    return int(os.getenv("SECUREVIBES_MAX_TURNS", cls.DEFAULT_MAX_TURNS))
except ValueError:
    # If invalid value provided, return default
    return cls.DEFAULT_MAX_TURNS
```

**Recommendation:**

1. Implement strict configuration validation with value ranges: if not 1 <= max_turns <= 200: raise ValueError('max_turns must be between 1 and 200'). 2. Whitelist allowed model names: VALID_MODELS = {'sonnet', 'haiku', 'opus', 'claude-3-5-sonnet-20241022'}; if model not in VALID_MODELS: raise ValueError(). 3. Add configuration verification mode: 'securevibes config --verify' that validates and displays all settings. 4. Log configuration source and values to audit log: log.info(f'Using max_turns={max_turns} from {source}'). 5. Add warnings for non-default configurations: if max_turns != DEFAULT: console.print('[yellow]Warning: Using custom max_turns[/yellow]'). 6. Implement configuration immutability: require --force-config flag to override defaults. 7. Add --config-file option to load validated configuration from signed JSON file instead of environment variables. 8. Validate all environment variables at startup before any scanning occurs.

---

### 16. Memory Exhaustion via Large Code Snippets in Vulnerability Reports [🟡 MEDIUM]

**File:** `packages/core/securevibes/scanner/scanner.py:368`  
**CWE:** CWE-400  
**Severity:** 🟡 Medium

**Description:**

The Code Review Agent includes code snippets in VULNERABILITIES.json with no size limits. If a vulnerability is found in a file with very long lines (minified JavaScript, base64-encoded data, single-line JSON), the entire line may be included as code_snippet. When loading scan results, the entire JSON file is read into memory without streaming. Large vulnerability reports (50MB+ JSON files with many massive code snippets) can cause memory exhaustion on systems with limited RAM, crashing the CLI or consuming excessive resources.

**Code Snippet:**

```python
with open(results_file) as f:
    results_data = json.load(f)
```

**Recommendation:**

1. Implement code snippet truncation: MAX_SNIPPET_LENGTH = 500; code_snippet = code[:MAX_SNIPPET_LENGTH] + '...' if len(code) > MAX_SNIPPET_LENGTH else code. 2. Add validation in SecurityIssue constructor: if len(code_snippet) > 1000: raise ValueError('Code snippet too large'). 3. Implement streaming JSON parser for large files: use ijson library for incremental parsing. 4. Add file size check before loading: if results_file.stat().st_size > 10_000_000: console.print('[yellow]Warning: Large result file[/yellow]'). 5. Implement lazy loading: load issues on-demand rather than all at once. 6. Add --no-snippets CLI flag to exclude code snippets from output. 7. Compress large scan results: use gzip to compress .securevibes/*.json files automatically. 8. Add memory monitoring: if psutil.virtual_memory().percent > 80: abort loading.

---

### 17. Resource Exhaustion via Uncontrolled Glob Pattern Execution [🟡 MEDIUM]

**File:** `packages/core/securevibes/scanner/scanner.py:250`  
**CWE:** CWE-400  
**Severity:** 🟡 Medium

**Description:**

Agents can execute the Glob tool with arbitrary patterns. While patterns are restricted to the repository by the cwd parameter, agents could still execute expensive glob patterns like '**/*' that recursively match millions of files in large monorepos. The glob operations at scanner.py lines 250-252 demonstrate this - they use '**/*.py', '**/*.ts', etc. without result limits. A malicious or misconfigured agent could cause CPU and memory exhaustion by executing many broad glob patterns, hanging the scan.

**Code Snippet:**

```python
files_scanned = len(list(repo.glob('**/*.py'))) + len(list(repo.glob('**/*.ts'))) + \
               len(list(repo.glob('**/*.js'))) + len(list(repo.glob('**/*.tsx'))) + \
               len(list(repo.glob('**/*.jsx')))
```

**Recommendation:**

1. Implement maximum result limit for Glob tool: add validation in pre_tool_hook that raises error if glob would return more than 10,000 results. 2. Add timeout for glob operations: use asyncio.wait_for() with 30 second timeout around glob executions. 3. Implement pattern validation: reject overly broad patterns like '**/*' or patterns with excessive wildcards. 4. Use iterator-based approach instead of list(): replace len(list(repo.glob())) with sum(1 for _ in repo.glob()) to avoid loading all paths in memory. 5. Add resource monitoring: track total glob operations per scan and abort if exceeds threshold (e.g., 1000 glob calls). 6. Implement glob result streaming: process results incrementally rather than collecting all paths. 7. Add --max-glob-results CLI option with default of 10,000. 8. Cache glob results to avoid repeated expensive operations.

---

### 18. Information Disclosure via Verbose Error Messages [🟢 LOW]

**File:** `packages/core/securevibes/cli/main.py:159`  
**CWE:** CWE-209  
**Severity:** 🟢 Low

**Description:**

Exception handling throughout the codebase displays detailed error messages containing absolute file paths, system information, and internal state. The CLI displays raw exception messages without sanitization. PermissionError, FileNotFoundError, and other exceptions reveal directory structure, usernames in paths, and implementation details. These error messages may be captured in CI/CD logs, monitoring systems, or shared in support tickets, aiding attacker reconnaissance.

**Code Snippet:**

```python
except Exception as e:
    console.print(f"\n[bold red]❌ Error:[/bold red] {e}", style="red")
```

**Recommendation:**

1. Implement custom exception classes with sanitized messages: class ScanError(Exception): def __str__(self): return self.user_friendly_message. 2. Sanitize error messages before display: remove absolute paths, replace with relative paths or generic descriptions. 3. Add error message mapping: map technical exceptions to user-friendly messages. 4. Log detailed errors to secure location: write full exception and stack trace to ~/.securevibes/errors.log with restricted permissions. 5. Add --sanitize-errors CLI flag (default enabled) to remove sensitive information from error messages. 6. Show detailed errors only in --debug mode: if not debug: show_generic_error() else: show_full_exception(). 7. Implement error categorization: categorize errors as 'permission', 'not_found', 'invalid_input' and show appropriate generic messages. 8. Add error reporting API: allow users to submit sanitized error reports for debugging.

---

### 19. Python Import Hijacking Risk via .securevibes/ Package Structure [🟡 MEDIUM]

**File:** `packages/core/securevibes/scanner/scanner.py:242`  
**CWE:** CWE-427  
**Severity:** 🟡 Medium

**Description:**

If an attacker creates malicious files in .securevibes/ directory (e.g., __init__.py, common module names like utils.py, config.py), and the repository is imported as a Python package, these files may be executed. While SecureVibes doesn't explicitly create __init__.py, nothing prevents its creation. If a user's Python application imports from the scanned repository, Python's import system may load .securevibes/__init__.py automatically, executing attacker code. This is especially dangerous in automated testing or deployment pipelines.

**Code Snippet:**

```python
securevibes_dir.mkdir(exist_ok=True)
```

**Recommendation:**

1. Never write __init__.py to .securevibes/: add explicit check in pre_tool_hook: if Path(file_path).name == '__init__.py': raise PermissionError('Cannot create __init__.py in scan output'). 2. Add .securevibes/ to .gitignore automatically: create/append to .gitignore during scan initialization. 3. Create .securevibes/.nopackage marker file to signal this is not a Python package. 4. Document the import hijacking risk in README with warning about .securevibes/ location. 5. Set directory permissions to prevent execution: os.chmod(securevibes_dir, 0o755) and all files to 0o644. 6. Implement post-scan verification: check for unexpected .py files in .securevibes/ and warn user. 7. Consider alternative output location: use ~/.securevibes/{repo_hash}/ instead of repo/.securevibes/. 8. Add PYTHONDONTWRITEBYTECODE=1 to prevent .pyc compilation in .securevibes/.

---

*Generated by SecureVibes Security Scanner*  
*Report generated at: 2025-10-09 17:48:59*