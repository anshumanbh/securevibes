# Security Scan Report

**Repository:** `/Users/anshumanbhartiya/repos/securevibes`  
**Scan Date:** 2025-10-10 16:29:43  
**Files Scanned:** 2898  
**Scan Duration:** 1790.39s (~29m 50s)  
**Total Cost:** $3.4408  

---

## Executive Summary

🔴 **17 security vulnerabilities found** - **CRITICAL** - Requires immediate attention

- 🔴 **2 Critical** - Require immediate attention
- 🟠 **6 High** - Should be fixed soon
- 🟡 **9 Medium** - Address when possible

---

## Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 Critical | 2 | 12% |
| 🟠 High | 6 | 35% |
| 🟡 Medium | 9 | 53% |

---

## Vulnerability Overview

| # | Severity | Title | Location |
|---|----------|-------|----------|
| 1 | 🔴 CRITICAL | World-Readable .securevibes Directory Exposes Vulnerability ... | `packages/core/securevibes/scanner/scanner.py:242` |
| 2 | 🟠 HIGH | Unrestricted Agent Write Access Enables Path Traversal | `packages/core/securevibes/scanner/scanner.py:298` |
| 3 | 🟠 HIGH | Malicious JSON Injection via Unsanitized Agent Output | `packages/core/securevibes/scanner/scanner.py:373` |
| 4 | 🟠 HIGH | Vulnerability Reports Not Actively Protected from Git Commit... | `packages/core/securevibes/scanner/scanner.py:242` |
| 5 | 🟡 MEDIUM | Race Condition in Concurrent Scans Writing to Same Directory | `packages/core/securevibes/reporters/json_reporter.py:24` |
| 6 | 🟡 MEDIUM | Unvalidated Environment Variable Configuration Injection | `packages/core/securevibes/config.py:92` |
| 7 | 🟡 MEDIUM | Unpinned Package Dependencies Enable Supply Chain Attacks | `packages/core/pyproject.toml:29` |
| 8 | 🟠 HIGH | Unprotected Prompt Files Enable Persistent Backdoor Injectio... | `packages/core/securevibes/prompts/loader.py:30` |
| 9 | 🟡 MEDIUM | Markdown Injection Leading to XSS in Report Viewers | `packages/core/securevibes/reporters/markdown_reporter.py:181` |
| 10 | 🟡 MEDIUM | Unbounded File Read Operations Enable Memory Exhaustion | `packages/core/securevibes/scanner/scanner.py:250` |
| 11 | 🟡 MEDIUM | Symlink Traversal Enabling Infinite Loops | `packages/core/securevibes/scanner/scanner.py:250` |
| 12 | 🟡 MEDIUM | No Persistent Audit Trail for Agent Operations | `packages/core/securevibes/scanner/scanner.py:72` |
| 13 | 🟡 MEDIUM | Sensitive Data Leakage via Verbose Error Messages | `packages/core/securevibes/cli/main.py:159` |
| 14 | 🟡 MEDIUM | No Verification of Report Authenticity or Origin | `packages/core/securevibes/cli/main.py:282` |
| 15 | 🟠 HIGH | API Key Exposure via Environment Variables Without Protectio... | `packages/core/securevibes/config.py:57` |
| 16 | 🔴 CRITICAL | Source Code Exfiltration to Anthropic API Without Consent | `packages/core/securevibes/scanner/scanner.py:298` |
| 17 | 🟠 HIGH | Unbounded Agent Execution Enables Cost Exhaustion | `packages/core/securevibes/scanner/scanner.py:297` |

---

## Detailed Findings

### 1. World-Readable .securevibes Directory Exposes Vulnerability Reports [🔴 CRITICAL]

**File:** `packages/core/securevibes/scanner/scanner.py:242`  
**CWE:** CWE-732  
**Severity:** 🔴 Critical

**Description:**

The .securevibes/ directory is created using mkdir(exist_ok=True) which inherits default umask permissions (typically 0755 on Unix). No explicit permission restrictions are applied. This results in world-readable files containing complete vulnerability reports including exact file paths, line numbers, code snippets, and exploitation details. On multi-user systems or CI/CD environments, any local user can read these files before vulnerabilities are patched.

**Code Snippet:**

```python
securevibes_dir.mkdir(exist_ok=True)
```

**Recommendation:**

Implement restrictive permissions immediately after directory creation: os.chmod(securevibes_dir, 0o700). Additionally apply secure permissions to all files written: output_file.touch(mode=0o600) before writing content.

---

### 2. Unrestricted Agent Write Access Enables Path Traversal [🟠 HIGH]

**File:** `packages/core/securevibes/scanner/scanner.py:298`  
**CWE:** CWE-22  
**Severity:** 🟠 High

**Description:**

Agents operate with permission_mode='bypassPermissions' allowing unrestricted file system access. The Write tool has no path validation preventing traversal outside .securevibes/. While agents are instructed via prompts to write only to .securevibes/, there is no technical enforcement. A malicious or confused agent could write to ../../etc/ or ~/.ssh/ if the process has permissions.

**Code Snippet:**

```python
permission_mode='bypassPermissions',
```

**Recommendation:**

1. Implement path validation in Write tool wrapper to reject paths outside repo/.securevibes/.
2. Use `Path.resolve()` to detect traversal attempts.
3. Change permission_mode to `requirePermissions` with explicit whitelist.
4. Add write operation logging for audit trail.

---

### 3. Malicious JSON Injection via Unsanitized Agent Output [🟠 HIGH]

**File:** `packages/core/securevibes/scanner/scanner.py:373`  
**CWE:** CWE-502  
**Severity:** 🟠 High

**Description:**

Agents write JSON files using Write tool with no output sanitization or schema validation. The system trusts agent-generated JSON to be well-formed. When files are loaded via json.load() in scanner.py lines 373 and 424, malicious content in fields like 'code_snippet', 'description', or 'recommendation' could exploit vulnerabilities in terminal rendering (Rich library), markdown viewers, or downstream processing.

**Code Snippet:**

```python
results_data = json.load(f)
```

**Recommendation:**

1. Implement strict `JSON` schema validation before loading agent-generated files.
2. Sanitize string fields to remove `ANSI` codes and terminal escape sequences.
3. Validate field types, lengths, and allowed characters.
4. Add --no-color flag to disable `ANSI` rendering.
5. Implement content length limits for all string fields.

---

### 4. Vulnerability Reports Not Actively Protected from Git Commits [🟠 HIGH]

**File:** `packages/core/securevibes/scanner/scanner.py:242`  
**CWE:** CWE-200  
**Severity:** 🟠 High

**Description:**

While .securevibes/ is in .gitignore (line 68), the system provides no active protection against accidental commits. Developers may use 'git add -f' to force-add, or repositories may have non-standard .gitignore configurations. No warning is displayed after scan completion, and there's no check to detect if .securevibes/ is already tracked in version control.

**Code Snippet:**

```python
securevibes_dir.mkdir(exist_ok=True)
```

**Recommendation:**

1. Display warning after scan: '`WARNING`: .securevibes/ contains sensitive vulnerability data. Ensure it is not committed to version control.'
2. Check if .git exists and if .securevibes/ is tracked via git ls-files --error-unmatch.
3. Provide --check-git flag.
4. Generate Git pre-commit hook template.

---

### 5. Race Condition in Concurrent Scans Writing to Same Directory [🟡 MEDIUM]

**File:** `packages/core/securevibes/reporters/json_reporter.py:24`  
**CWE:** CWE-362  
**Severity:** 🟡 Medium

**Description:**

Multiple scans can run simultaneously against the same repository, all writing to .securevibes/. No file locking mechanism exists. Files are written using write_text() and open() which are not atomic operations. Concurrent writes to scan_results.json or VULNERABILITIES.json will result in corrupted JSON, data loss, or interleaved content.

**Code Snippet:**

```python
with open(output_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
```

**Recommendation:**

1. Implement file locking using `fcntl.flock()` before writes.
2. Use unique output directories per scan: .securevibes/scan-<timestamp>/.
3. Implement atomic write pattern: write to temp file, then rename.
4. Add scan_id to detect mixed results.
5. Check for active scans before starting.

---

### 6. Unvalidated Environment Variable Configuration Injection [🟡 MEDIUM]

**File:** `packages/core/securevibes/config.py:92`  
**CWE:** CWE-20  
**Severity:** 🟡 Medium

**Description:**

config.py reads SECUREVIBES_MAX_TURNS environment variable without upper bound validation. While invalid non-numeric values fall back to defaults, valid integers like 999999 are accepted. This allows bypass of DoS protection intended by the max_turns limit. An attacker who can set environment variables could set arbitrarily high values to cause excessive API costs and execution time.

**Code Snippet:**

```python
return int(os.getenv("SECUREVIBES_MAX_TURNS", cls.DEFAULT_MAX_TURNS))
```

**Recommendation:**

1. Enforce maximum reasonable value (e.g., max 200 turns).
2. Log warning when non-default configurations are used.
3. Validate all environment variables against acceptable ranges.
4. Add --verify-config flag to display configuration before scan.
5. Implement configuration validation at startup.

---

### 7. Unpinned Package Dependencies Enable Supply Chain Attacks [🟡 MEDIUM]

**File:** `packages/core/pyproject.toml:29`  
**CWE:** CWE-494  
**Severity:** 🟡 Medium

**Description:**

pyproject.toml uses >= version constraints without upper bounds (claude-agent-sdk>=0.1.0, anyio>=4.0.0, click>=8.0.0, rich>=13.0.0). This allows automatic installation of any newer versions during pip install. If a dependency is compromised or contains vulnerabilities in future versions, users will automatically receive the vulnerable code. No checksum verification or SBOM exists.

**Code Snippet:**

```
claude-agent-sdk>=0.1.0
```

**Recommendation:**

1. Pin exact versions: claude-agent-sdk==0.1.
2. Generate requirements.txt with hashes: pip install --require-hashes.
3. Implement dependency verification.
4. Use dependabot for security updates.
5. Run pip-audit to scan for known vulnerabilities.
6. Generate `SBOM` using CycloneDX.

---

### 8. Unprotected Prompt Files Enable Persistent Backdoor Injection [🟠 HIGH]

**File:** `packages/core/securevibes/prompts/loader.py:30`  
**CWE:** CWE-494  
**Severity:** 🟠 High

**Description:**

Agent prompts are loaded from prompts/agents/*.txt files via load_prompt() with no integrity verification. These plaintext files have no checksums or signatures. An attacker who gains write access to the installation directory could modify prompt files to inject malicious instructions that persist across all future scans. Modified prompts could exfiltrate data, skip security checks, or write malicious output.

**Code Snippet:**

```python
return prompt_file.read_text(encoding="utf-8")
```

**Recommendation:**

1. Implement SHA-256 checksums of official prompts and validate on load.
2. Sign prompt files with cryptographic signatures.
3. Make prompts read-only (chmod 0444).
4. Implement prompt version tracking.
5. Add --verify-prompts flag.
6. Log warning if prompts modified since installation.

---

### 9. Markdown Injection Leading to XSS in Report Viewers [🟡 MEDIUM]

**File:** `packages/core/securevibes/reporters/markdown_reporter.py:181`  
**CWE:** CWE-79  
**Severity:** 🟡 Medium

**Description:**

MarkdownReporter embeds agent-generated content into markdown reports without sufficient sanitization. While pipe characters are escaped (line 150), HTML tags and JavaScript protocols are not filtered. Field 'code_snippet', 'description', and 'recommendation' contain user-controlled content that could include malicious payloads like <img src=x onerror=alert()> or javascript: URLs that execute when viewed in markdown renderers supporting HTML.

**Code Snippet:**

```python
lines.append(issue.description)
```

**Recommendation:**

1. Escape `HTML` entities: < → &lt;, > → &gt;.
2. Strip or escape javascript: protocol URLs.
3. Remove `HTML` tags from all text fields.
4. Use plaintext code blocks without syntax highlighting for untrusted content.
5. Add --safe-markdown flag for maximum sanitization.

---

### 10. Unbounded File Read Operations Enable Memory Exhaustion [🟡 MEDIUM]

**File:** `packages/core/securevibes/scanner/scanner.py:250`  
**CWE:** CWE-400  
**Severity:** 🟡 Medium

**Description:**

Agents can read files of any size through the Read tool with no size validation. The scanner counts files (lines 250-252) but doesn't check file sizes. Large files are loaded entirely into memory for processing and API transmission. Multiple large file reads could exhaust system memory causing crashes or OS out-of-memory kills. Malicious repositories could contain artificially large files to cause DoS.

**Code Snippet:**

```python
files_scanned = len(list(repo.glob('**/*.py'))) + len(list(repo.glob('**/*.ts'))) + \
                       len(list(repo.glob('**/*.jsx')))
```

**Recommendation:**

1. Implement file size limits (e.g., reject files >1MB).
2. Add pre-scan validation of file sizes.
3. Implement streaming reads for large files.
4. Add memory usage monitoring.
5. Skip binary files and non-code files.
6. Add --max-file-size configuration option.

---

### 11. Symlink Traversal Enabling Infinite Loops [🟡 MEDIUM]

**File:** `packages/core/securevibes/scanner/scanner.py:250`  
**CWE:** CWE-59  
**Severity:** 🟡 Medium

**Description:**

File enumeration uses Path.glob() (lines 250-252) with no symlink cycle detection. Agents use Glob tool for file discovery without protection against circular symbolic links. A malicious repository with symlinks creating loops (e.g., src/ → ../src/) would cause infinite file discovery, consuming API tokens and disk I/O repeatedly analyzing the same files until manual intervention.

**Code Snippet:**

```python
files_scanned = len(list(repo.glob('**/*.py')))
```

**Recommendation:**

1. Implement symlink cycle detection using inode tracking.
2. Use `Path.resolve()` to canonicalize paths before processing.
3. Add --no-follow-symlinks flag.
4. Limit directory traversal depth (max 20 levels).
5. Implement visited-file tracking with bloom filter.
6. Add traversal timeout (max 5 minutes).

---

### 12. No Persistent Audit Trail for Agent Operations [🟡 MEDIUM]

**File:** `packages/core/securevibes/scanner/scanner.py:72`  
**CWE:** CWE-778  
**Severity:** 🟡 Medium

**Description:**

ProgressTracker displays real-time tool usage to console but generates no persistent audit log. Console output is ephemeral and easily lost. If agents perform malicious actions (reading sensitive files, writing to unexpected locations), no forensic evidence exists after execution. Debug output goes to console only, providing no immutable audit trail for incident response or compliance verification.

**Code Snippet:**

```python
def on_tool_start(self, tool_name: str, tool_input: dict):
        """Called when a tool execution begins"""
        self.tool_count += 1
        self.last_update = datetime.now()
```

**Recommendation:**

1. Implement structured logging to `.securevibes/audit.log` with append-only permissions.
2. Log every tool execution with timestamp, tool name, parameters, and results.
3. Include cryptographic hashing of events for tamper detection.
4. Add --audit flag for detailed logging.
5. Integrate with syslog for centralized logging.

---

### 13. Sensitive Data Leakage via Verbose Error Messages [🟡 MEDIUM]

**File:** `packages/core/securevibes/cli/main.py:159`  
**CWE:** CWE-209  
**Severity:** 🟡 Medium

**Description:**

Error handling prints detailed error messages including file paths, line numbers, and internal state to console. Debug mode (--debug) exposes agent narration and tool inputs. Error messages in scanner.py (lines 341-343), cli/main.py (lines 158-162), and throughout expose file system structure. If output is logged to files or CI/CD systems, sensitive information could leak including codebase structure and API responses.

**Code Snippet:**

```python
console.print(f"\n[bold red]❌ Error:[/bold red] {e}", style="red")
```

**Recommendation:**

1. Implement structured error messages with sensitive data redaction.
2. Replace absolute paths with relative paths in output.
3. Add --safe-output mode.
4. Redact API keys and tokens from error messages.
5. Implement different verbosity levels.
6. Add warning when debug mode enabled.

---

### 14. No Verification of Report Authenticity or Origin [🟡 MEDIUM]

**File:** `packages/core/securevibes/cli/main.py:282`  
**CWE:** CWE-345  
**Severity:** 🟡 Medium

**Description:**

The 'securevibes report' command loads scan_results.json without verifying authenticity. No digital signatures, timestamps, or provenance tracking exist. A malicious actor could craft fake reports showing clean security scans and place them in .securevibes/. These forged reports would display as legitimate, potentially allowing vulnerable code to bypass security gates in deployment pipelines.

**Code Snippet:**

```python
data = JSONReporter.load(report_path)
```

**Recommendation:**

1. Implement `HMAC` or digital signatures for all reports.
2. Include signature in report metadata with timestamp and scanner version.
3. Add --verify flag to validate signatures.
4. Embed scanner fingerprint in reports.
5. Add chain-of-custody tracking.
6. Display visual indicators for unverified reports.

---

### 15. API Key Exposure via Environment Variables Without Protection [🟠 HIGH]

**File:** `packages/core/securevibes/config.py:57`  
**CWE:** CWE-522  
**Severity:** 🟠 High

**Description:**

ANTHROPIC_API_KEY is expected to be stored in plaintext environment variables without validation. Environment variables are visible to all processes under the same user via /proc/<pid>/environ on Linux. Shell history may persist keys in plaintext. The config.py module reads environment variables without any key validation, rotation mechanism, or secure storage integration. If leaked, attackers gain full API access.

**Code Snippet:**

```python
env_value = os.getenv(env_var)
```

**Recommendation:**

1. Integrate with system secrets managers (Keychain, Windows Credential Manager, Secret Service).
2. Implement API key validation at initialization.
3. Clear `ANTHROPIC_API_KEY` from environment after reading.
4. Add key rotation reminders.
5. Log API key usage anomalies.
6. Support session-based authentication.

---

### 16. Source Code Exfiltration to Anthropic API Without Consent [🔴 CRITICAL]

**File:** `packages/core/securevibes/scanner/scanner.py:298`  
**CWE:** CWE-359  
**Severity:** 🔴 Critical

**Description:**

All source code accessed by agents is transmitted to Anthropic's API in plaintext over HTTPS. Scanner operates with bypassPermissions mode (line 298) allowing unrestricted file access. No opt-out mechanism, file exclusion patterns, or user consent prompt exists before transmitting potentially sensitive source code, credentials, or trade secrets to third-party cloud service. Users cannot control what data is sent or verify deletion.

**Code Snippet:**

```python
permission_mode='bypassPermissions',
```

**Recommendation:**

1. Implement .gitignore-style file exclusion patterns.
2. Add explicit user consent prompt before first scan.
3. Provide --exclude flag for sensitive file patterns.
4. Add --local-only mode using local LLMs.
5. Implement automatic secret detection and redaction using detect-secrets.
6. Display warning about data transmission.

---

### 17. Unbounded Agent Execution Enables Cost Exhaustion [🟠 HIGH]

**File:** `packages/core/securevibes/scanner/scanner.py:297`  
**CWE:** CWE-770  
**Severity:** 🟠 High

**Description:**

Scanner has no cost ceiling enforcement or circuit breaker. Config allows max_turns=50 per agent but this is not globally enforced across all agents. The system displays costs (lines 329-335) but requires manual intervention to abort. With 4 agents each executing up to 50 turns with high token usage, a malicious repository with complex structure could accumulate hundreds of dollars in API charges before detection.

**Code Snippet:**

```python
max_turns=config.get_max_turns(),
```

**Recommendation:**

1. Implement absolute cost ceiling with automatic abortion.
2. Add file count and size limits (refuse to scan >10,000 files).
3. Implement rate limiting on tool executions.
4. Add cost estimation before scan based on repo size.
5. Provide --max-cost flag.
6. Add cost alerts at 25%, 50%, 75% thresholds.

---

*Generated by SecureVibes Security Scanner*  
*Report generated at: 2025-10-10 16:29:43*