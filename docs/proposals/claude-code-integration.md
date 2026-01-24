# SecureVibes Claude Code Integration Spec

**Status:** Proposal  
**Author:** SecureVibes Team  
**Created:** 2026-01-24  
**Version:** 1.0.0

---

## Table of Contents

1. [Overview and Motivation](#1-overview-and-motivation)
2. [User Stories and Use Cases](#2-user-stories-and-use-cases)
3. [Proposed Architecture](#3-proposed-architecture)
4. [CLI Commands](#4-cli-commands)
5. [MCP (Model Context Protocol) Integration](#5-mcp-model-context-protocol-integration)
6. [Integration Points with Existing CLI](#6-integration-points-with-existing-cli)
7. [Authentication Flow](#7-authentication-flow)
8. [Output Format](#8-output-format)
9. [Implementation Roadmap](#9-implementation-roadmap)
10. [Future Enhancements](#10-future-enhancements)

---

## 1. Overview and Motivation

### 1.1 Background

Claude Code is Anthropic's official CLI for Claude, providing developers with an AI-powered coding assistant directly in their terminal. With the growing ecosystem of Claude Code plugins (e.g., Greptile for code review), there's an opportunity to bring **security-focused analysis** directly into the developer workflow.

### 1.2 Problem Statement

Currently, developers using SecureVibes need to:
1. Exit their Claude Code session
2. Run `securevibes scan` separately
3. Parse results manually or switch contexts
4. Manually apply fixes or ask Claude about remediation

This context-switching breaks developer flow and slows down the secure development lifecycle.

### 1.3 Proposed Solution

Create a **SecureVibes Claude Code integration** that enables:
- **Inline security scanning** without leaving Claude Code
- **Contextual fix suggestions** leveraging Claude's understanding of the codebase
- **Seamless findings management** within the conversation
- **MCP tools** for programmatic access by Claude

### 1.4 Goals

| Goal | Description |
|------|-------------|
| **Zero context switch** | Security scanning without leaving Claude Code |
| **Conversational fixes** | "Fix this SQL injection" → Claude applies the fix |
| **Progressive disclosure** | Scan → Review → Fix workflow |
| **MCP-first architecture** | Enable Claude to invoke security tools autonomously |

### 1.5 Non-Goals (v1)

- Real-time continuous monitoring (future)
- IDE plugin (VS Code, JetBrains)
- GitHub App/Action integration (separate project)
- DAST integration (requires additional setup)

---

## 2. User Stories and Use Cases

### 2.1 User Stories

#### US-1: Quick Security Check
> **As a developer**, I want to run a quick security scan on my current directory while in Claude Code, so that I can catch vulnerabilities before committing.

**Acceptance Criteria:**
- [ ] Run scan with single command
- [ ] See summary in <30 seconds for small projects
- [ ] Critical/high findings highlighted

#### US-2: PR Security Review
> **As a developer**, I want to scan a specific PR for security issues, so that I can catch vulnerabilities before merge.

**Acceptance Criteria:**
- [ ] Scan only changed files in PR
- [ ] Show diff-aware findings
- [ ] Exit code for CI integration

#### US-3: Contextual Fix Suggestions
> **As a developer**, I want Claude to suggest fixes for identified vulnerabilities using its understanding of my codebase.

**Acceptance Criteria:**
- [ ] Reference specific finding by ID
- [ ] Claude generates context-aware fix
- [ ] Option to apply fix automatically

#### US-4: Findings Triage
> **As a developer**, I want to view, filter, and manage findings from previous scans without re-running the scan.

**Acceptance Criteria:**
- [ ] List cached findings
- [ ] Filter by severity, file, CWE
- [ ] Mark as false positive (persisted)

#### US-5: Autonomous Security Analysis
> **As a Claude Code user**, I want Claude to automatically check for security issues when I ask it to review my code.

**Acceptance Criteria:**
- [ ] MCP tools available to Claude
- [ ] Claude invokes scan when relevant
- [ ] Findings integrated into conversation

### 2.2 Use Case Flows

#### UC-1: Interactive Scan Flow
```
Developer                          Claude Code
    |                                   |
    |--- "scan this for security" ---->|
    |                                   |
    |<-- "Running securevibes..." -----|
    |                                   |
    |<-- "Found 3 issues: ..." --------|
    |                                   |
    |--- "fix the SQL injection" ----->|
    |                                   |
    |<-- [Applies fix to code] --------|
```

#### UC-2: MCP Autonomous Flow
```
Developer                          Claude (via MCP)
    |                                   |
    |--- "review this PR" ------------>|
    |                                   |
    |        [Claude invokes securevibes_scan]
    |        [Claude invokes securevibes_findings]
    |                                   |
    |<-- "I found 2 security issues..." |
```

---

## 3. Proposed Architecture

### 3.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Claude Code                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐    ┌──────────────────────────────────┐  │
│  │   CLI Commands   │    │      MCP Server (optional)        │  │
│  │                  │    │                                    │  │
│  │  securevibes     │    │  securevibes_scan                 │  │
│  │  ├── scan        │    │  securevibes_findings             │  │
│  │  ├── findings    │    │  securevibes_fix                  │  │
│  │  └── fix         │    │  securevibes_explain              │  │
│  │                  │    │                                    │  │
│  └────────┬─────────┘    └───────────────┬──────────────────┘  │
│           │                               │                      │
│           └──────────────┬───────────────┘                      │
│                          ▼                                       │
│            ┌─────────────────────────┐                          │
│            │  SecureVibes Core SDK   │                          │
│            │  (packages/core)        │                          │
│            └────────────┬────────────┘                          │
│                         │                                        │
│                         ▼                                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Artifact Cache                         │   │
│  │  .securevibes/                                            │   │
│  │  ├── scan_results.json    (cached scan)                   │   │
│  │  ├── VULNERABILITIES.json (detailed findings)             │   │
│  │  └── .config.json         (auth, preferences)             │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Component Responsibilities

| Component | Responsibility |
|-----------|----------------|
| **CLI Commands** | Human-friendly interface for manual invocation |
| **MCP Server** | Machine-friendly interface for Claude to invoke |
| **Core SDK** | Shared scanning logic (reuses existing `securevibes` package) |
| **Artifact Cache** | Persisted findings, auth tokens, configuration |

### 3.3 Package Structure

```
packages/
├── core/                    # Existing SecureVibes core
│   └── securevibes/
│       ├── scanner/
│       ├── agents/
│       └── ...
│
└── claude-code/             # NEW: Claude Code integration
    ├── pyproject.toml
    └── securevibes_claude/
        ├── __init__.py
        ├── cli/
        │   ├── __init__.py
        │   └── commands.py      # CLI command implementations
        ├── mcp/
        │   ├── __init__.py
        │   ├── server.py        # MCP server implementation
        │   └── tools.py         # MCP tool definitions
        ├── cache/
        │   ├── __init__.py
        │   └── findings.py      # Findings cache management
        └── auth/
            ├── __init__.py
            └── provider.py      # Auth token management
```

---

## 4. CLI Commands

### 4.1 Command Reference

#### `securevibes scan [PATH]`

Scan a directory or specific files for security vulnerabilities.

```bash
# Scan current directory
securevibes scan .

# Scan specific path
securevibes scan /path/to/project

# Scan with options
securevibes scan . --severity high --format json

# Scan specific PR (requires git context)
securevibes scan --pr 123

# Scan only changed files
securevibes scan --diff HEAD~1

# Quick scan (assessment + code-review only, skip threat modeling)
securevibes scan . --quick
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--severity` | Minimum severity to report | `low` |
| `--format` | Output format: `table`, `json`, `markdown` | `table` |
| `--pr <number>` | Scan specific PR (requires GitHub context) | - |
| `--diff <ref>` | Scan only changed files since ref | - |
| `--quick` | Fast scan (skip threat modeling) | `false` |
| `--no-cache` | Force fresh scan, ignore cache | `false` |
| `--model` | Claude model for analysis | `sonnet` |

**Output (table format):**

```
🛡️  SecureVibes Security Scan

📁 Scanned: 42 files
⏱️  Time: 23.4s
💰 Cost: $0.0234

┌─────────┬──────────┬────────────────────────────────┬──────────────────────┐
│ ID      │ Severity │ Title                          │ Location             │
├─────────┼──────────┼────────────────────────────────┼──────────────────────┤
│ SV-001  │ CRITICAL │ SQL Injection in user query    │ app/db.py:42         │
│ SV-002  │ HIGH     │ Hardcoded API credentials      │ config/settings.py:8 │
│ SV-003  │ MEDIUM   │ Missing rate limiting          │ api/views.py:156     │
└─────────┴──────────┴────────────────────────────────┴──────────────────────┘

Run 'securevibes findings SV-001' for details
Run 'securevibes fix SV-001' for remediation
```

#### `securevibes findings [FINDING_ID]`

List or inspect security findings.

```bash
# List all findings from last scan
securevibes findings

# Show details for specific finding
securevibes findings SV-001

# Filter findings
securevibes findings --severity critical
securevibes findings --file "app/db.py"
securevibes findings --cwe CWE-89

# Output as JSON (for piping to other tools)
securevibes findings --format json
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--severity` | Filter by severity | - |
| `--file` | Filter by file path | - |
| `--cwe` | Filter by CWE ID | - |
| `--format` | Output format: `table`, `json`, `markdown` | `table` |
| `--status` | Filter by status: `open`, `fixed`, `fp` | `open` |

**Output (detail view):**

```
🔍 Finding SV-001: SQL Injection in user query

┌────────────────┬────────────────────────────────────────────────┐
│ Severity       │ 🔴 CRITICAL                                    │
│ CWE            │ CWE-89: SQL Injection                          │
│ File           │ app/db.py                                      │
│ Line           │ 42                                             │
│ Threat ID      │ THREAT-003                                     │
│ Status         │ Open                                           │
└────────────────┴────────────────────────────────────────────────┘

📝 Description:
User input from request.args['user_id'] is directly concatenated into
a SQL query without sanitization, allowing arbitrary SQL execution.

💻 Vulnerable Code:
    41 │ def get_user(user_id):
    42 │     cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    43 │     return cursor.fetchone()

🎯 Evidence:
Data flows from request.args['user_id'] (line 38) directly to
cursor.execute() (line 42) without parameterization or validation.

💡 Recommendation:
Use parameterized queries:
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

Run 'securevibes fix SV-001' to generate a fix
```

#### `securevibes fix <FINDING_ID>`

Get or apply a fix for a specific finding.

```bash
# Show fix suggestion
securevibes fix SV-001

# Apply fix automatically (creates backup)
securevibes fix SV-001 --apply

# Show fix as diff
securevibes fix SV-001 --diff

# Generate fix for all critical findings
securevibes fix --all --severity critical
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--apply` | Apply fix to file (creates .bak) | `false` |
| `--diff` | Show fix as unified diff | `false` |
| `--all` | Generate fixes for all findings | `false` |
| `--severity` | With `--all`, filter by severity | - |
| `--no-backup` | Don't create backup when applying | `false` |

**Output (suggestion):**

```
🔧 Fix for SV-001: SQL Injection in user query

📄 File: app/db.py

📍 Before (lines 41-43):
    def get_user(user_id):
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        return cursor.fetchone()

✅ After:
    def get_user(user_id):
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cursor.fetchone()

💬 Explanation:
The fix uses parameterized queries instead of string formatting.
This prevents SQL injection by separating the query structure from
the data, ensuring user input cannot modify the query logic.

Run 'securevibes fix SV-001 --apply' to apply this fix
```

#### `securevibes status`

Show current scan status and configuration.

```bash
securevibes status
```

**Output:**

```
🛡️  SecureVibes Status

Authentication: ✅ Authenticated (session)
Last Scan:      2026-01-24 09:15:23 (42 files, 3 findings)
Cache:          .securevibes/ (valid)
Model:          claude-sonnet-4-20250514
API Key:        ✅ Set (ANTHROPIC_API_KEY)

Open Findings:
  🔴 Critical: 1
  🟠 High:     1
  🟡 Medium:   1
  🟢 Low:      0
```

---

## 5. MCP (Model Context Protocol) Integration

### 5.1 Overview

The MCP integration allows Claude to invoke SecureVibes tools directly during conversation, enabling autonomous security analysis.

### 5.2 MCP Server Configuration

**Installation:**

```bash
# Install with MCP support
pip install securevibes[mcp]

# Or from source
pip install -e packages/claude-code[mcp]
```

**Claude Code configuration (`~/.claude/mcp.json`):**

```json
{
  "mcpServers": {
    "securevibes": {
      "command": "securevibes-mcp",
      "args": ["serve"],
      "env": {
        "ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"
      }
    }
  }
}
```

### 5.3 MCP Tool Definitions

#### Tool: `securevibes_scan`

Scan a directory for security vulnerabilities.

```json
{
  "name": "securevibes_scan",
  "description": "Scan code for security vulnerabilities using AI-powered analysis. Returns identified threats and vulnerabilities with severity ratings.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "path": {
        "type": "string",
        "description": "Path to scan (relative or absolute). Defaults to current directory.",
        "default": "."
      },
      "severity": {
        "type": "string",
        "enum": ["critical", "high", "medium", "low"],
        "description": "Minimum severity to report",
        "default": "low"
      },
      "quick": {
        "type": "boolean",
        "description": "Fast scan (skip threat modeling)",
        "default": false
      },
      "files": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Specific files to scan (optional)"
      }
    },
    "required": []
  }
}
```

**Example invocation by Claude:**

```json
{
  "name": "securevibes_scan",
  "arguments": {
    "path": "./src",
    "severity": "high"
  }
}
```

**Response:**

```json
{
  "scan_id": "scan_20260124_091523",
  "status": "completed",
  "summary": {
    "files_scanned": 42,
    "scan_time_seconds": 23.4,
    "total_findings": 3,
    "by_severity": {
      "critical": 1,
      "high": 1,
      "medium": 1,
      "low": 0
    }
  },
  "findings": [
    {
      "id": "SV-001",
      "severity": "critical",
      "title": "SQL Injection in user query",
      "file_path": "app/db.py",
      "line_number": 42,
      "cwe_id": "CWE-89",
      "description": "User input directly concatenated into SQL query"
    }
  ]
}
```

#### Tool: `securevibes_findings`

Retrieve and filter findings from the most recent scan.

```json
{
  "name": "securevibes_findings",
  "description": "Get detailed information about security findings. Can filter by severity, file, or CWE.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "finding_id": {
        "type": "string",
        "description": "Specific finding ID (e.g., 'SV-001') for detailed view"
      },
      "severity": {
        "type": "string",
        "enum": ["critical", "high", "medium", "low"],
        "description": "Filter by minimum severity"
      },
      "file": {
        "type": "string",
        "description": "Filter by file path pattern"
      },
      "cwe": {
        "type": "string",
        "description": "Filter by CWE ID (e.g., 'CWE-89')"
      }
    },
    "required": []
  }
}
```

**Example invocation:**

```json
{
  "name": "securevibes_findings",
  "arguments": {
    "finding_id": "SV-001"
  }
}
```

**Response:**

```json
{
  "finding": {
    "id": "SV-001",
    "threat_id": "THREAT-003",
    "severity": "critical",
    "title": "SQL Injection in user query",
    "description": "User input from request.args['user_id'] is directly concatenated into a SQL query without sanitization.",
    "file_path": "app/db.py",
    "line_number": 42,
    "code_snippet": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
    "cwe_id": "CWE-89",
    "evidence": "Data flows from request.args['user_id'] (line 38) directly to cursor.execute() (line 42)",
    "recommendation": "Use parameterized queries: cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
    "status": "open"
  }
}
```

#### Tool: `securevibes_fix`

Generate or apply a fix for a security finding.

```json
{
  "name": "securevibes_fix",
  "description": "Generate a security fix for a specific vulnerability. Can return the fix as a suggestion or apply it directly.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "finding_id": {
        "type": "string",
        "description": "Finding ID to fix (e.g., 'SV-001')"
      },
      "apply": {
        "type": "boolean",
        "description": "Apply the fix to the file (creates backup)",
        "default": false
      }
    },
    "required": ["finding_id"]
  }
}
```

**Response:**

```json
{
  "finding_id": "SV-001",
  "file_path": "app/db.py",
  "fix": {
    "before": {
      "start_line": 41,
      "end_line": 43,
      "code": "def get_user(user_id):\n    cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n    return cursor.fetchone()"
    },
    "after": {
      "code": "def get_user(user_id):\n    cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n    return cursor.fetchone()"
    },
    "explanation": "Use parameterized queries to prevent SQL injection by separating query structure from data."
  },
  "applied": false
}
```

#### Tool: `securevibes_explain`

Get a detailed explanation of a security vulnerability type.

```json
{
  "name": "securevibes_explain",
  "description": "Get educational information about a vulnerability type, CWE, or security concept.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "topic": {
        "type": "string",
        "description": "Topic to explain (CWE ID, vulnerability type, or concept)"
      }
    },
    "required": ["topic"]
  }
}
```

### 5.4 MCP Usage Examples

**Example 1: Claude initiates security review**

```
User: "Review this code for security issues"

Claude: [Thinking: I should scan the code for security vulnerabilities]
        [Calls securevibes_scan with path="."]

Claude: "I found 3 security issues in your codebase:

        1. **CRITICAL** - SQL Injection in `app/db.py:42`
           User input is directly concatenated into SQL queries.
        
        2. **HIGH** - Hardcoded credentials in `config/settings.py:8`
           API keys are committed to source code.
        
        3. **MEDIUM** - Missing rate limiting in `api/views.py:156`
           The login endpoint has no rate limiting.
        
        Would you like me to fix any of these?"
```

**Example 2: Claude provides contextual fix**

```
User: "Fix the SQL injection issue"

Claude: [Calls securevibes_fix with finding_id="SV-001"]
        [Reads the response with before/after code]

Claude: "I'll fix the SQL injection in `app/db.py`. Here's what I'm changing:

        **Before:**
        ```python
        cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")
        ```
        
        **After:**
        ```python
        cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))
        ```
        
        This uses parameterized queries to prevent SQL injection.
        Should I apply this fix?"
```

---

## 6. Integration Points with Existing CLI

### 6.1 Core SDK Reuse

The Claude Code integration reuses the existing `securevibes` core package:

```python
# packages/claude-code/securevibes_claude/scanner.py

from securevibes.scanner.scanner import Scanner
from securevibes.models.result import ScanResult

class ClaudeCodeScanner:
    """Wrapper around core Scanner for Claude Code integration."""
    
    def __init__(self, model: str = "sonnet"):
        self.scanner = Scanner(model=model)
    
    async def scan(self, path: str, quick: bool = False) -> ScanResult:
        """Run security scan using core SDK."""
        if quick:
            # Skip threat modeling for faster results
            return await self.scanner.scan_subagent(path, "code-review")
        return await self.scanner.scan(path)
    
    def get_findings(self, scan_id: str = None) -> list:
        """Load findings from cache."""
        # Read from .securevibes/VULNERABILITIES.json
        ...
```

### 6.2 Shared Artifacts

Both the standalone CLI and Claude Code integration use the same artifact cache:

```
.securevibes/
├── SECURITY.md            # Architecture assessment
├── THREAT_MODEL.json      # Threat modeling results
├── VULNERABILITIES.json   # Confirmed vulnerabilities (findings source)
├── scan_results.json      # Complete scan results
└── .config.json           # Integration-specific config
```

### 6.3 Model Configuration

The Claude Code integration respects existing environment variables:

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | API key for Claude |
| `SECUREVIBES_MODEL` | Default model for all agents |
| `SECUREVIBES_CODE_REVIEW_MODEL` | Model for code review agent |
| `SECUREVIBES_MAX_TURNS` | Max turns per agent |

---

## 7. Authentication Flow

### 7.1 Authentication Methods

The integration supports multiple authentication methods:

#### Method 1: API Key (Recommended for CI/automation)

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
securevibes scan .
```

#### Method 2: Session Auth (Recommended for interactive use)

```bash
# Uses Claude CLI session (from `claude /login`)
securevibes auth login

# Status
securevibes auth status
```

#### Method 3: OAuth (Future - for web dashboard)

```bash
securevibes auth login --oauth
# Opens browser for OAuth flow
```

### 7.2 Auth Implementation

```python
# packages/claude-code/securevibes_claude/auth/provider.py

class AuthProvider:
    """Unified authentication provider."""
    
    def get_api_key(self) -> str:
        """Get API key from environment or session."""
        # 1. Check environment variable
        if key := os.environ.get("ANTHROPIC_API_KEY"):
            return key
        
        # 2. Check Claude CLI session
        if key := self._get_session_key():
            return key
        
        # 3. Check stored credentials
        if key := self._get_stored_key():
            return key
        
        raise AuthError("No authentication found. Run 'securevibes auth login'")
    
    def _get_session_key(self) -> Optional[str]:
        """Read API key from Claude CLI session."""
        session_path = Path.home() / ".claude" / "session.json"
        if session_path.exists():
            session = json.loads(session_path.read_text())
            return session.get("api_key")
        return None
```

### 7.3 Credential Storage

```json
// ~/.securevibes/credentials.json
{
  "api_key": "sk-ant-...",  // Encrypted at rest
  "created_at": "2026-01-24T09:15:23Z",
  "method": "api_key"
}
```

---

## 8. Output Format

### 8.1 JSON Schema for Findings

All tools return findings in a consistent JSON format:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "SecureVibes Finding",
  "type": "object",
  "properties": {
    "id": {
      "type": "string",
      "description": "Unique finding identifier (e.g., 'SV-001')",
      "pattern": "^SV-\\d{3}$"
    },
    "threat_id": {
      "type": "string",
      "description": "Related threat from threat model"
    },
    "severity": {
      "type": "string",
      "enum": ["critical", "high", "medium", "low", "info"]
    },
    "title": {
      "type": "string",
      "description": "Short title of the vulnerability"
    },
    "description": {
      "type": "string",
      "description": "Detailed description of the issue"
    },
    "file_path": {
      "type": "string",
      "description": "Path to affected file"
    },
    "line_number": {
      "type": "integer",
      "description": "Line number of vulnerable code"
    },
    "code_snippet": {
      "type": "string",
      "description": "Relevant code snippet"
    },
    "cwe_id": {
      "type": "string",
      "description": "CWE identifier (e.g., 'CWE-89')"
    },
    "evidence": {
      "type": "string",
      "description": "Evidence supporting the finding"
    },
    "recommendation": {
      "type": "string",
      "description": "How to fix the issue"
    },
    "status": {
      "type": "string",
      "enum": ["open", "fixed", "false_positive", "accepted_risk"],
      "default": "open"
    }
  },
  "required": ["id", "severity", "title", "file_path", "line_number"]
}
```

### 8.2 Scan Summary Format

```json
{
  "scan_id": "scan_20260124_091523",
  "repository_path": "/path/to/project",
  "scan_timestamp": "2026-01-24T09:15:23Z",
  "status": "completed",
  "summary": {
    "files_scanned": 42,
    "scan_time_seconds": 23.4,
    "total_cost_usd": 0.0234,
    "total_findings": 3,
    "by_severity": {
      "critical": 1,
      "high": 1,
      "medium": 1,
      "low": 0
    }
  },
  "findings": [/* array of Finding objects */]
}
```

### 8.3 Human-Readable Formats

**Table format** (default for CLI):
- Colorized severity indicators
- Truncated descriptions
- Interactive prompts

**Markdown format** (for reports):
- Full details
- Code blocks with syntax highlighting
- Severity badges

---

## 9. Implementation Roadmap

### 9.1 Phase 1: CLI Integration (Week 1-2)

| Task | Description | Status |
|------|-------------|--------|
| Setup package | Create `packages/claude-code` structure | ⬜ |
| Core wrapper | Wrap existing Scanner for CLI | ⬜ |
| `scan` command | Implement basic scan with output | ⬜ |
| `findings` command | List and detail findings | ⬜ |
| `fix` command | Generate fix suggestions | ⬜ |
| Cache management | Persist findings between runs | ⬜ |
| Tests | Unit and integration tests | ⬜ |

### 9.2 Phase 2: MCP Server (Week 3-4)

| Task | Description | Status |
|------|-------------|--------|
| MCP server setup | Implement FastMCP server | ⬜ |
| `securevibes_scan` tool | Implement scan tool | ⬜ |
| `securevibes_findings` tool | Implement findings tool | ⬜ |
| `securevibes_fix` tool | Implement fix tool | ⬜ |
| Documentation | MCP setup guide | ⬜ |
| Integration tests | Test with Claude Code | ⬜ |

### 9.3 Phase 3: Polish & Release (Week 5-6)

| Task | Description | Status |
|------|-------------|--------|
| Auth flow | API key + session auth | ⬜ |
| Error handling | Graceful failures | ⬜ |
| Progress indicators | Real-time progress | ⬜ |
| PyPI package | Publish to PyPI | ⬜ |
| Documentation | README, examples | ⬜ |
| Announcement | Blog post, socials | ⬜ |

---

## 10. Future Enhancements

### 10.1 Near-term (v1.1)

| Feature | Description |
|---------|-------------|
| **PR scanning** | Scan only changed files in a PR |
| **Diff-aware** | Highlight findings in changed code |
| **Fix apply** | Auto-apply fixes with backup |
| **DAST integration** | Dynamic testing via MCP |

### 10.2 Medium-term (v1.5)

| Feature | Description |
|---------|-------------|
| **VS Code extension** | Native IDE integration |
| **GitHub Action** | CI/CD integration |
| **Slack/Discord bot** | Chat-based security scanning |
| **Dashboard** | Web UI for findings management |

### 10.3 Long-term (v2.0)

| Feature | Description |
|---------|-------------|
| **Continuous monitoring** | Watch mode for live scanning |
| **Custom rules** | User-defined security rules |
| **Team collaboration** | Shared findings, assignments |
| **Compliance mapping** | OWASP, PCI-DSS, SOC2 |
| **AI training** | Learn from false positive feedback |

### 10.4 Technical Debt Considerations

- Keep MCP server stateless when possible
- Cache invalidation strategy for findings
- Rate limiting for API usage
- Graceful degradation when Claude API unavailable

---

## Appendix A: Comparison with Greptile

| Feature | Greptile | SecureVibes |
|---------|----------|-------------|
| **Focus** | Code review | Security vulnerabilities |
| **Analysis depth** | Surface-level | Deep multi-agent |
| **Threat modeling** | ❌ | ✅ STRIDE methodology |
| **CWE mapping** | ❌ | ✅ Full CWE coverage |
| **DAST support** | ❌ | ✅ Dynamic testing |
| **Fix generation** | Basic | Context-aware |
| **MCP support** | ✅ | ✅ (this spec) |

---

## Appendix B: Security Considerations

### B.1 Secret Handling

- API keys never logged or displayed
- Credentials encrypted at rest
- Session tokens expire after 24 hours

### B.2 Code Access

- Scan only reads code, never executes
- Fix apply creates backup before modification
- No network access during scan (except Claude API)

### B.3 Finding Privacy

- Findings stored locally in `.securevibes/`
- No telemetry without explicit opt-in
- Cloud sync optional (future feature)

---

## Appendix C: Related Documents

- [SecureVibes Architecture](../ARCHITECTURE.md)
- [DAST Guide](../DAST_GUIDE.md)
- [MCP Specification](https://modelcontextprotocol.io/docs)
- [Claude Code Documentation](https://docs.anthropic.com/claude-code)

---

*This spec is a living document. Please submit feedback via GitHub issues or discussions.*
