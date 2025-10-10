# Security Scan Report

**Repository:** `/Users/anshumanbhartiya/repos/securevibes`  
**Scan Date:** 2025-10-10 13:18:18  
**Files Scanned:** 2915  
**Scan Duration:** 908.02s (~15m 8s)  
**Total Cost:** $1.8811  

---

## Executive Summary

🔴 **18 security vulnerabilities found** - **CRITICAL** - Requires immediate attention

- 🔴 **1 Critical** - Require immediate attention
- 🟠 **5 High** - Should be fixed soon
- 🟡 **7 Medium** - Address when possible
- 🟢 **5 Low** - Minor issues

---

## Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 Critical | 1 | 6% |
| 🟠 High | 5 | 28% |
| 🟡 Medium | 7 | 39% |
| 🟢 Low | 5 | 28% |

---

## Vulnerability Overview

| # | Severity | Title | Location |
|---|----------|-------|----------|
| 1 | 🔴 CRITICAL | AI Agents Running with bypassPermissions Grants Unrestricted... | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:294` |
| 2 | 🟠 HIGH | Symlink Following in .securevibes Directory Creation Enables... | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:242` |
| 3 | 🟠 HIGH | Source Code and Absolute File Paths Transmitted to External ... | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:308` |
| 4 | 🟠 HIGH | ANTHROPIC_API_KEY Exposure Through Environment Variable Inhe... | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:308` |
| 5 | 🟡 MEDIUM | Scan Results Containing Vulnerability Details Stored in Plai... | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:360` |
| 6 | 🟡 MEDIUM | No Integrity Validation of AI-Generated Artifacts Between Ph... | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:360` |
| 7 | 🟡 MEDIUM | No Audit Logging of Scan Execution and File Access Operation... | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:225` |
| 8 | 🟡 MEDIUM | No Rate Limiting or Cost Controls on API Usage | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:293` |
| 9 | 🟠 HIGH | Supply Chain Attack via Malicious Dependencies | `/Users/anshumanbhartiya/repos/securevibes/packages/core/pyproject.toml:28` |
| 10 | 🟠 HIGH | AI Prompt Injection via Malicious Repository Content | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/agents/definitions.py:14` |
| 11 | 🟢 LOW | Verbose Error Messages Leaking System Information | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/cli/main.py:158` |
| 12 | 🟡 MEDIUM | Path Traversal Risk in User-Provided Output Paths | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/cli/main.py:103` |
| 13 | 🟢 LOW | Malformed JSON Artifacts Causing Scan Failures | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:368` |
| 14 | 🟢 LOW | Race Condition in Concurrent .securevibes Directory Access | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:242` |
| 15 | 🟢 LOW | Environment Variable Injection via SECUREVIBES_* Configurati... | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/config.py:66` |
| 16 | 🟡 MEDIUM | No Digital Signatures on Scan Reports Enabling Report Forger... | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/reporters/markdown_reporter.py:21` |
| 17 | 🟢 LOW | Recursive Directory Traversal Causing Resource Exhaustion | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:250` |
| 18 | 🟡 MEDIUM | Agent Prompt Files Modifiable Allowing Custom Agent Behavior... | `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/prompts/loader.py:30` |

---

## Detailed Findings

### 1. AI Agents Running with bypassPermissions Grants Unrestricted Filesystem Access [🔴 CRITICAL]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:294`  
**CWE:** CWE-250  
**Severity:** 🔴 Critical

**Description:**

The Scanner class configures ClaudeSDKClient with permission_mode='bypassPermissions' at line 294, granting all AI agents unrestricted Read/Write access to the filesystem without user prompts. This bypasses normal permission checks and allows agents to read sensitive files (SSH keys, credentials, environment files) and write to arbitrary locations. Since agents process untrusted input from scanned repositories, a malicious repository could exploit this through prompt injection to exfiltrate data or modify system files.

**Code Snippet:**

```python
options = ClaudeAgentOptions(
    agents=SECUREVIBES_AGENTS,
    cwd=str(repo),
    max_turns=config.get_max_turns(),
    permission_mode='bypassPermissions',
    model=self.model,
```

**Recommendation:**

1. Replace `bypassPermissions` with `interactivePermissions` or `passthrough` mode to require user consent for file operations.
2. Implement strict working directory restrictions using chroot or sandboxing.
3. Add file path allowlisting to only permit access to the target repository directory.
4. Implement file type validation to prevent reading sensitive file types (.pem, .key, .ssh, .aws, etc.).
5. Add audit logging for all file operations performed by agents.

---

### 2. Symlink Following in .securevibes Directory Creation Enables File Overwrite [🟠 HIGH]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:242`  
**CWE:** CWE-59  
**Severity:** 🟠 High

**Description:**

The scanner creates the .securevibes/ directory using securevibes_dir.mkdir(exist_ok=True) at line 242 without validating that the path is not a symbolic link. An attacker who creates .securevibes/ as a symlink to a sensitive location (e.g., ~/.ssh/, /etc/) can cause the scanner to follow the symlink and overwrite critical files with scan artifacts. Combined with bypassPermissions mode, this enables arbitrary file write attacks.

**Code Snippet:**

```python
securevibes_dir = repo / SECUREVIBES_DIR
try:
    securevibes_dir.mkdir(exist_ok=True)
except (OSError, PermissionError) as e:
    raise RuntimeError(f"Failed to create output directory {securevibes_dir}: {e}")
```

**Recommendation:**

1. Check if .securevibes/ is a symlink before writing using `Path.is_symlink()`.
2. Use `os.open()` with `O_NOFOLLOW` flag for file creation.
3. Validate that the created directory is within the expected repository path.
4. Add user confirmation if .securevibes/ already exists as a symlink.
5. Use Path.resolve(strict=True) to detect symlink traversal attempts.

---

### 3. Source Code and Absolute File Paths Transmitted to External Anthropic API [🟠 HIGH]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:308`  
**CWE:** CWE-200  
**Severity:** 🟠 High

**Description:**

By design, the entire scanned repository's source code is transmitted to Anthropic's Claude API (api.anthropic.com) for analysis via the ClaudeSDKClient. Additionally, absolute file paths containing usernames and directory structures are sent via tool execution results. This creates a mandatory third-party data exposure risk where proprietary code, trade secrets, or sensitive business logic is transmitted outside the organization.

**Code Snippet:**

```python
async with ClaudeSDKClient(options=options) as client:
    await client.query(orchestration_prompt)
    
    # Stream messages for real-time progress
    async for message in client.receive_messages():
```

**Recommendation:**

1. Implement file filtering to exclude sensitive patterns (.env, secrets.json, credentials).
2. Add --local-only mode that uses local LLMs if available.
3. Provide clear warnings before scanning with examples of what will be transmitted.
4. Strip absolute paths to relative paths before sending to API.
5. Add configuration to exclude specific directories/files from scanning.
6. Implement data minimization by sending only relevant code snippets rather than entire files.

---

### 4. ANTHROPIC_API_KEY Exposure Through Environment Variable Inheritance [🟠 HIGH]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:308`  
**CWE:** CWE-522  
**Severity:** 🟠 High

**Description:**

The ANTHROPIC_API_KEY is accessed by claude-agent-sdk without secure credential storage. Environment variables are visible to all processes running as the same user via 'ps aux e', /proc/PID/environ, and in core dumps. The API key persists in plaintext in process memory throughout scan execution with no memory protection (mlock) or OS keyring integration.

**Code Snippet:**

```python
async with ClaudeSDKClient(options=options) as client:
```

**Recommendation:**

1. Support OS keyring integration (keyring library) for secure credential storage.
2. Implement secure memory handling (mlock) for sensitive data.
3. Recommend Claude CLI session authentication over API key.
4. Add automatic redaction of API keys in error messages and logs.
5. Document secure setup procedures including restrictive file permissions on .env files.
6. Implement API key rotation reminders after scans.

---

### 5. Scan Results Containing Vulnerability Details Stored in Plaintext [🟡 MEDIUM]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:360`  
**CWE:** CWE-532  
**Severity:** 🟡 Medium

**Description:**

The .securevibes/ directory contains detailed vulnerability information including exact file paths, line numbers, code snippets, and exploitation details, all stored in plaintext JSON and Markdown files (scan_results.json, VULNERABILITIES.json, THREAT_MODEL.json, SECURITY.md). These files are readable by any user with filesystem access and could be accidentally committed to version control.

**Code Snippet:**

```python
results_file = securevibes_dir / SCAN_RESULTS_FILE
vulnerabilities_file = securevibes_dir / VULNERABILITIES_FILE

if results_file.exists():
    try:
        with open(results_file) as f:
            results_data = json.load(f)
```

**Recommendation:**

1. Implement encryption for scan result files using user's SSH key or system keychain.
2. Add stronger warnings when .securevibes/ is not in .gitignore.
3. Implement automatic sanitization of code snippets (remove literals, tokens).
4. Add --ephemeral mode that doesn't save results to disk.
5. Set restrictive file permissions (chmod 600) on all artifact files.
6. Add git pre-commit hook template to prevent committing .securevibes/.

---

### 6. No Integrity Validation of AI-Generated Artifacts Between Phases [🟡 MEDIUM]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:360`  
**CWE:** CWE-345  
**Severity:** 🟡 Medium

**Description:**

The four-phase scanning process relies on agents reading artifacts created by previous phases (SECURITY.md -> THREAT_MODEL.json -> VULNERABILITIES.json -> scan_results.json), but there's no integrity validation, digital signatures, or tamper detection. An attacker with filesystem access could modify intermediate artifacts to inject false vulnerabilities, hide real ones, or manipulate the threat model to mislead subsequent analysis phases.

**Code Snippet:**

```python
results_file = securevibes_dir / SCAN_RESULTS_FILE
vulnerabilities_file = securevibes_dir / VULNERABILITIES_FILE

if results_file.exists():
    try:
        with open(results_file) as f:
            results_data = json.load(f)
```

**Recommendation:**

1. Implement `HMAC` or digital signatures for all artifact files.
2. Validate artifact integrity before each phase reads previous phase's output.
3. Store checksums in metadata file and verify before processing.
4. Add file locking during scan execution to prevent external modifications.
5. Log file modification timestamps and warn if artifacts are modified during scan.
6. Implement atomic writes to prevent partial file corruption.

---

### 7. No Audit Logging of Scan Execution and File Access Operations [🟡 MEDIUM]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:225`  
**CWE:** CWE-778  
**Severity:** 🟡 Medium

**Description:**

SecureVibes has no audit logging mechanism to record who ran scans, what repositories were scanned, which files were accessed by AI agents, or what actions were performed. In shared environments or CI/CD systems, there's no accountability or forensic capability if scans are abused for unauthorized reconnaissance, data exfiltration, or excessive API usage causing cost overruns.

**Code Snippet:**

```python
async def scan(self, repo_path: str) -> ScanResult:
    """Run complete security scan with real-time progress streaming."""
    repo = Path(repo_path).resolve()
    if not repo.exists():
        raise ValueError(f"Repository path does not exist: {repo_path}")
```

**Recommendation:**

1. Implement audit log file (`.securevibes/audit.log`) recording timestamps, usernames, PIDs, commands.
2. Log all file read/write operations performed by agents.
3. Record API costs per scan for accountability.
4. Add tamper-proof logging using append-only mode or remote syslog.
5. Include git commit hash of scanned repository in logs for traceability.
6. Provide admin mode that enables centralized logging to `SIEM` systems.

---

### 8. No Rate Limiting or Cost Controls on API Usage [🟡 MEDIUM]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:293`  
**CWE:** CWE-770  
**Severity:** 🟡 Medium

**Description:**

The scanner has no built-in rate limiting, cost caps, or circuit breakers to prevent excessive API usage. A large repository scan could trigger thousands of API calls costing hundreds of dollars. Configuration allows max_turns up to any value via SECUREVIBES_MAX_TURNS environment variable, and malicious users could set it arbitrarily high.

**Code Snippet:**

```python
options = ClaudeAgentOptions(
    agents=SECUREVIBES_AGENTS,
    cwd=str(repo),
    max_turns=config.get_max_turns(),
    permission_mode='bypassPermissions',
```

**Recommendation:**

1. Implement --max-cost flag to abort scan when cost threshold is reached.
2. Add repository size checks and warn before scanning repos with >1000 files.
3. Implement exponential backoff on API errors to prevent retry storms.
4. Add scan resume capability to recover from interruptions.
5. Show cost estimates before starting scan based on repository size.
6. Implement per-user/per-day scan quotas in shared environments.
7. Add circuit breaker pattern to stop scan if error rate exceeds threshold.

---

### 9. Supply Chain Attack via Malicious Dependencies [🟠 HIGH]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/pyproject.toml:28`  
**CWE:** CWE-1357  
**Severity:** 🟠 High

**Description:**

The project uses minimum version constraints (>=) in pyproject.toml without pinning exact versions or verifying package integrity through checksums. The critical claude-agent-sdk dependency is closed-source from Anthropic. Transitive dependencies are uncontrolled, and there's no automated dependency scanning or SBOM generation. An attacker who compromises a dependency on PyPI could inject malicious code executed during scanning.

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

1. Pin exact dependency versions in requirements.txt with hash verification.
2. Implement pip-audit or Dependabot in CI/CD to detect known vulnerabilities.
3. Generate and publish Software Bill of Materials (`SBOM`).
4. Add subresource integrity checks for critical dependencies.
5. Document the trust assumption around claude-agent-sdk.
6. Use pip --require-hashes for production installations.
7. Implement dependency vendoring for critical deployments.

---

### 10. AI Prompt Injection via Malicious Repository Content [🟠 HIGH]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/agents/definitions.py:14`  
**CWE:** CWE-74  
**Severity:** 🟠 High

**Description:**

AI agents receive untrusted input from repository files (README.md, code comments, configuration files, docstrings) without validation or sanitization. Maliciously crafted repository content could contain prompt injection payloads designed to manipulate agent behavior: ignoring real vulnerabilities, fabricating false vulnerabilities, exfiltrating data via Write tool, or bypassing security analysis logic. Combined with bypassPermissions, this amplifies impact.

**Code Snippet:**

```python
"assessment": AgentDefinition(
    description="Analyzes codebase architecture and creates comprehensive security documentation",
    prompt=AGENT_PROMPTS["assessment"],
    tools=["Read", "Grep", "Glob", "LS", "Write"],
    model=config.get_agent_model("assessment")
),
```

**Recommendation:**

1. Implement input sanitization for all content read from repositories.
2. Add prompt injection detection using known pattern matching.
3. Use separate system prompts that are immutable and clearly distinguish instructions from data.
4. Implement output validation to detect anomalous agent behavior.
5. Add human-in-the-loop review for high-severity findings.
6. Sandbox agent execution with strict output whitelisting.
7. Use XML tags or structured formats to separate instructions from user data.

---

### 11. Verbose Error Messages Leaking System Information [🟢 LOW]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/cli/main.py:158`  
**CWE:** CWE-209  
**Severity:** 🟢 Low

**Description:**

The CLI and scanner produce detailed error messages and stack traces that may leak sensitive system information like absolute file paths, usernames, environment variable names, Python installation paths, and internal component structure. These error messages are displayed in console output and could appear in CI/CD logs, screenshots, or support tickets.

**Code Snippet:**

```python
except Exception as e:
    console.print(f"\n[bold red]❌ Error:[/bold red] {e}", style="red")
    if not quiet:
        console.print("\n[dim]Run with --help for usage information[/dim]")
    sys.exit(1)
```

**Recommendation:**

1. Implement generic error messages for users ('Scan failed. Check logs for details').
2. Write detailed errors to `.securevibes/error.log` instead of console.
3. Strip absolute paths in error messages, show relative paths only.
4. Sanitize exception messages to remove sensitive information.
5. Limit stack trace depth in production mode.
6. Add --safe-mode flag that suppresses all detailed diagnostics.

---

### 12. Path Traversal Risk in User-Provided Output Paths [🟡 MEDIUM]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/cli/main.py:103`  
**CWE:** CWE-22  
**Severity:** 🟡 Medium

**Description:**

The CLI accepts user-provided output paths via --output flag without sufficient validation against path traversal attacks. While Python's Path handling provides some protection, an attacker could potentially use sequences like '../../../etc/cron.d/malicious' to write scan output to locations outside the repository directory.

**Code Snippet:**

```python
output_path = Path(output)
if not output_path.is_absolute():
    output_path = Path(path) / '.securevibes' / output

try:
    # Ensure parent directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    MarkdownReporter.save(result, output_path)
```

**Recommendation:**

1. Implement strict path validation using `os.path.realpath()` and `os.path.commonpath()`.
2. Restrict --output to only write within repository directory or explicit safe locations.
3. Add confirmation prompt when output path is outside repository.
4. Validate that parent directory exists and is writable before attempting write.
5. Use allowlist of permitted output directories.
6. Implement chroot-like restrictions for output operations.

---

### 13. Malformed JSON Artifacts Causing Scan Failures [🟢 LOW]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:368`  
**CWE:** CWE-755  
**Severity:** 🟢 Low

**Description:**

The scanner relies on valid JSON artifacts being created by each agent phase, but there's insufficient error handling for malformed or incomplete JSON. If an agent produces invalid JSON due to truncation, character encoding issues, or AI hallucination, subsequent phases will fail. The validators module exists but isn't actively used during scanning to verify artifact integrity.

**Code Snippet:**

```python
try:
    with open(results_file) as f:
        results_data = json.load(f)
    
    issues_data = results_data.get("issues") or results_data.get("vulnerabilities")
```

**Recommendation:**

1. Actively use validators.py to validate artifacts after each phase completes.
2. Implement graceful degradation to use partial results if validation fails.
3. Add schema validation using `JSON` Schema for all artifact types.
4. Implement atomic file writes with temp files and rename.
5. Add artifact size limits and truncation detection.
6. Create checkpoint/resume capability so scans can recover from failures.
7. Better error messages indicating which phase and artifact failed validation.

---

### 14. Race Condition in Concurrent .securevibes Directory Access [🟢 LOW]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:242`  
**CWE:** CWE-362  
**Severity:** 🟢 Low

**Description:**

The scanner creates .securevibes/ with mkdir(exist_ok=True) and writes multiple artifact files sequentially, but doesn't implement file locking or atomic operations. If multiple scan instances run concurrently on the same repository (e.g., in parallel CI/CD pipelines), they could race to create and modify the same files, resulting in corrupted artifacts, mixed results, or incomplete data.

**Code Snippet:**

```python
securevibes_dir = repo / SECUREVIBES_DIR
try:
    securevibes_dir.mkdir(exist_ok=True)
except (OSError, PermissionError) as e:
    raise RuntimeError(f"Failed to create output directory {securevibes_dir}: {e}")
```

**Recommendation:**

1. Implement file locking using fcntl or filelock library.
2. Create .securevibes.lock file at scan start and remove at completion.
3. Generate unique scan IDs and write to .securevibes/scan-{id}/ subdirectories.
4. Add detection for concurrent scans and fail-fast with clear error.
5. Implement atomic file writes using temp files and atomic rename.
6. Add --scan-id parameter for explicit multi-scan coordination.

---

### 15. Environment Variable Injection via SECUREVIBES_* Configuration [🟢 LOW]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/config.py:66`  
**CWE:** CWE-15  
**Severity:** 🟢 Low

**Description:**

The configuration system reads multiple environment variables (SECUREVIBES_*_MODEL, SECUREVIBES_MAX_TURNS) without strict validation or sanitization. In shared hosting environments or containers with untrusted input, an attacker could inject malicious values through environment variable manipulation. While the current implementation validates ValueError, it doesn't cap max_turns at reasonable limits.

**Code Snippet:**

```python
try:
    return int(os.getenv("SECUREVIBES_MAX_TURNS", cls.DEFAULT_MAX_TURNS))
except ValueError:
    # If invalid value provided, return default
    return cls.DEFAULT_MAX_TURNS
```

**Recommendation:**

1. Implement strict validation for all configuration values.
2. Use allowlists for model names (sonnet, haiku, opus only).
3. Cap `SECUREVIBES_MAX_TURNS` at reasonable maximum (e.g., 100).
4. Add configuration file (.securevibes.yaml) with precedence over environment variables.
5. Log warnings when environment variables override defaults.
6. Document security implications of configuration in multi-tenant environments.
7. Implement configuration validation at startup before any operations.

---

### 16. No Digital Signatures on Scan Reports Enabling Report Forgery [🟡 MEDIUM]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/reporters/markdown_reporter.py:21`  
**CWE:** CWE-345  
**Severity:** 🟡 Medium

**Description:**

Scan reports generated by securevibes have no digital signatures, checksums, or authentication mechanisms to prove authenticity or prevent tampering. An attacker could modify scan_report.md or scan_results.json to hide vulnerabilities, add false findings, or forge reports entirely. In compliance scenarios or security audits, forged reports could be used to misrepresent the security posture of a codebase.

**Code Snippet:**

```python
output_file = Path(output_path)
output_file.parent.mkdir(parents=True, exist_ok=True)

markdown = MarkdownReporter.generate(result)
output_file.write_text(markdown)
```

**Recommendation:**

1. Implement GPG signatures on all scan reports using user's signing key.
2. Add checksums file (`.securevibes/checksums.txt`) with `SHA256` hashes of all artifacts.
3. Include scan metadata with timestamp and cryptographic proof.
4. Add --verify command to validate report authenticity.
5. Store tamper-evident logs on external append-only storage.
6. Include git commit hash of scanned repository in signed metadata.
7. Provide report verification UI showing signature status.

---

### 17. Recursive Directory Traversal Causing Resource Exhaustion [🟢 LOW]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py:250`  
**CWE:** CWE-674  
**Severity:** 🟢 Low

**Description:**

The scanner recursively searches for files using Path.glob('**/*.py') and similar patterns without depth limits or cycle detection. Malicious repositories could contain deeply nested directory structures (1000+ levels) or symbolic link loops that cause the scanner to exhaust stack space, memory, or file descriptors. The file counting uses glob operations on entire directory trees.

**Code Snippet:**

```python
files_scanned = len(list(repo.glob('**/*.py'))) + len(list(repo.glob('**/*.ts'))) + \
               len(list(repo.glob('**/*.js'))) + len(list(repo.glob('**/*.tsx'))) + \
               len(list(repo.glob('**/*.jsx')))
```

**Recommendation:**

1. Implement maximum directory depth limits (e.g., 20 levels).
2. Follow symlinks only once and detect cycles.
3. Add timeout limits on glob operations.
4. Implement file count limits (refuse to scan repos with >10000 files).
5. Use iterative algorithms instead of recursive for directory traversal.
6. Add --max-depth parameter for user-controlled limits.
7. Precheck repository structure before starting expensive AI operations.

---

### 18. Agent Prompt Files Modifiable Allowing Custom Agent Behavior Injection [🟡 MEDIUM]

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/prompts/loader.py:30`  
**CWE:** CWE-494  
**Severity:** 🟡 Medium

**Description:**

Agent prompts are loaded from files in the prompts/ directory, and there's no integrity verification of these files. An attacker with write access to the installation directory could modify agent prompt files to inject malicious instructions, change agent behavior, or create backdoors. In development environments or shared Python installations, this creates an avenue for persistent compromise where modified prompts execute on every scan.

**Code Snippet:**

```python
return prompt_file.read_text(encoding="utf-8")
```

**Recommendation:**

1. Implement checksum verification for all prompt files on load.
2. Store checksums in code or signed manifest file.
3. Add integrity check during package installation.
4. Sign prompt files with developer key and verify signature.
5. Make prompt directory read-only during installation.
6. Log warnings if prompt files are modified after installation.
7. Add --verify-installation command to check integrity.
8. Consider embedding prompts as Python strings instead of external files.

---

*Generated by SecureVibes Security Scanner*  
*Report generated at: 2025-10-10 13:18:18*