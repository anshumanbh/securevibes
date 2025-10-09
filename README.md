# 🛡️ SecureVibes

**AI-Native Security Scanner for Vibecoded Applications**

SecureVibes uses **Claude's multi-agent architecture** to autonomously find security vulnerabilities in your codebase. Four specialized AI agents work together to deliver comprehensive, context-aware security analysis with concrete evidence.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.3.2-green.svg)](https://github.com/anshumanbh/securevibes/releases)
[![Tests](https://img.shields.io/badge/tests-74%20passed-success.svg)](https://github.com/anshumanbh/securevibes)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

---

## ✨ Features

### True Agent Architecture
- **🤖 Autonomous Orchestration**: Claude intelligently coordinates agents
- **📐 Assessment Agent**: Maps your codebase architecture
- **🎯 Threat Modeling Agent**: Architecture-driven STRIDE threat analysis
- **🔍 Code Review Agent**: Security thinking methodology to find vulnerabilities
- **📊 Report Generator**: Compiles comprehensive scan results

### Results Include
- ✅ Exact file paths and line numbers
- ✅ Vulnerable code snippets
- ✅ CWE IDs for tracking
- ✅ Remediation recommendations
- ✅ Evidence of exploitability

---

## 🚀 Quick Start

```bash
# Install
pip install securevibes

# Set API key (get yours from https://console.anthropic.com/)
export CLAUDE_API_KEY="your-api-key-here"

# Scan your project
securevibes scan .

# View results
securevibes report
```

---

## 📊 Example Output

```bash
$ securevibes scan /Users/xyz/repos/test

🛡️ SecureVibes Security Scanner
AI-Powered Vulnerability Detection

📁 Scanning: /Users/xyz/repos/test
🤖 Model: sonnet
============================================================

✅ Phase 1/4: Architecture Assessment Complete
   Created: SECURITY.md

━━━ Phase 2/4: Threat Modeling (STRIDE Analysis) ━━━

━━━ Phase 2/4: Threat Modeling (STRIDE Analysis) ━━━

✅ Phase 2/4: Threat Modeling (STRIDE Analysis) Complete
   Created: THREAT_MODEL.json

━━━ Phase 3/4: Code Review (Security Analysis) ━━━

━━━ Phase 3/4: Code Review (Security Analysis) ━━━

✅ Phase 3/4: Code Review (Security Analysis) Complete
   Created: VULNERABILITIES.json

━━━ Phase 4/4: Report Generation ━━━

✅ Phase 4/4: Report Generation Complete
   Created: scan_results.json

================================================================================

================================================================================
📊 Scan Results
================================================================================

  📁 Files scanned:   1953
  ⏱️  Scan time:       1053.66s
  💰 Total cost:      $2.2732
  🐛 Issues found:    28
     🔴 Critical:     5
     🟠 High:         10
     🟡 Medium:       10
     🟢 Low:          3


                                            🔍 Detected Vulnerabilities
╭─────┬────────────┬────────────────────────────────────────────────────┬─────────────────────────────────────────╮
│ #   │ Severity   │ Issue                                              │ Location                                │
├─────┼────────────┼────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ 1   │ CRITICAL   │ Unauthorized Blog Post Creation via Unauthenticate │ server/routes.ts:538                    │
├─────┼────────────┼────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ 2   │ HIGH       │ Course Data Manipulation via Unprotected Seed Endp │ server/routes.ts:732                    │
├─────┼────────────┼────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ 3   │ CRITICAL   │ Stripe Webhook Signature Bypass Allows Payment Man │ server/routes.ts:426                    │
├─────┼────────────┼────────────────────────────────────────────────────┼─────────────────────────────────────────┤
│ 4   │ HIGH       │ Race Condition in Course Seat Reservation Allows O │ server/routes.ts:218                    │
├─────┼────────────┼────────────────────────────────────────────────────┼─────────────────────────────────────────┤
....
💾 Full report: .securevibes/scan_results.json
```

---

## 🎯 Usage

### Basic Commands

```bash
# Full security scan
securevibes scan .

# View results
securevibes report

# Individual phases (optional)
securevibes assess .        # Phase 1: Architecture mapping
securevibes threat-model .  # Phase 2: STRIDE analysis
securevibes review .        # Phase 3: Vulnerability validation
```

### Common Options

```bash
# Export results as JSON
securevibes scan . --format json --output results.json

# Filter by severity
securevibes scan . --severity high

# Use different model
securevibes scan . --model claude-3-5-haiku-20241022

# Quiet mode
securevibes scan . --quiet
```

---

## 🐍 Python API

For programmatic access:

```python
import asyncio
from securevibes import SecurityScanner

async def main():
    scanner = SecurityScanner(
        api_key="your-api-key",  # or use CLAUDE_API_KEY env var
        model="claude-3-5-sonnet-20241022"
    )
    
    result = await scanner.scan("/path/to/repo")
    
    print(f"Found {len(result.issues)} vulnerabilities")
    print(f"Critical: {result.critical_count}")
    print(f"High: {result.high_count}")
    
    for issue in result.issues:
        print(f"\n[{issue.severity.value.upper()}] {issue.title}")
        print(f"  File: {issue.file_path}:{issue.line_number}")
        print(f"  CWE: {issue.cwe_id}")
        print(f"  Fix: {issue.recommendation}")

asyncio.run(main())
```

---

## ⚙️ Configuration

### Required Environment Variables

```bash
# Claude API Key (required for all operations)
export CLAUDE_API_KEY='your-api-key-here'
```

Get your API key from: https://console.anthropic.com/

### Optional Configuration

SecureVibes can be customized via environment variables:

#### 🤖 Agent Models
Customize which Claude model each agent uses (default: `sonnet`):

```bash
# Assessment Agent - Architecture documentation
export SECUREVIBES_ASSESSMENT_MODEL="sonnet"

# Threat Modeling Agent - STRIDE analysis  
export SECUREVIBES_THREAT_MODELING_MODEL="sonnet"

# Code Review Agent - Security analysis
export SECUREVIBES_CODE_REVIEW_MODEL="opus"  # Use opus for maximum accuracy

# Report Generator - JSON formatting
export SECUREVIBES_REPORT_GENERATOR_MODEL="sonnet"
```

**Available models:** `haiku` (fast/cheap), `sonnet` (balanced), `opus` (thorough/expensive)

#### 🔄 Max Reasoning Turns
Control how deeply agents analyze your code (default: `50`):

```bash
# Adjust based on codebase size and complexity
export SECUREVIBES_MAX_TURNS=75   # Large/complex codebases
export SECUREVIBES_MAX_TURNS=30   # Small projects (faster, cheaper)
export SECUREVIBES_MAX_TURNS=100  # Maximum depth (use with caution)
```

**Note:** Higher values = deeper analysis but higher cost and longer scan time.

#### 🎯 Quick Configuration Examples

**Optimize for Speed & Cost:**
```bash
export CLAUDE_API_KEY='your-key'
export SECUREVIBES_ASSESSMENT_MODEL="haiku"
export SECUREVIBES_THREAT_MODELING_MODEL="haiku"
export SECUREVIBES_CODE_REVIEW_MODEL="sonnet"
export SECUREVIBES_MAX_TURNS=30
securevibes scan .
```

**Optimize for Accuracy (Recommended):**
```bash
export CLAUDE_API_KEY='your-key'
export SECUREVIBES_CODE_REVIEW_MODEL="opus"
export SECUREVIBES_THREAT_MODELING_MODEL="sonnet"
export SECUREVIBES_MAX_TURNS=75
securevibes scan .
```

---

## 🏗️ How It Works

SecureVibes uses a **multi-agent architecture** where Claude autonomously orchestrates 4 specialized agents:

1. **Assessment Agent** → Analyzes architecture → `SECURITY.md`
2. **Threat Modeling Agent** → Applies STRIDE → `THREAT_MODEL.json`
3. **Code Review Agent** → Validates vulnerabilities → `VULNERABILITIES.json`
4. **Report Generator** → Compiles results → `scan_results.json`

**Key Benefits:**
- ✅ Claude intelligently adapts to your codebase
- ✅ Agents build on each other's findings
- ✅ Security thinking methodology (not just pattern matching)
- ✅ Concrete evidence with file paths and line numbers

For detailed architecture, agent descriptions, and data flow, see [ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## 🔒 Privacy & Security

### Data Handling

**What SecureVibes Sends to Anthropic:**
- Your source code files
- Relative file paths within scanned repository

**What SecureVibes Does NOT Send:**
- Absolute paths containing usernames
- Environment variables or secrets
- Git history or metadata
- Files outside scanned directory

**Your API Key:** Stored locally, only used for Anthropic authentication

### Important Notes

⚠️ SecureVibes sends your code to Anthropic's Claude API for analysis.

Before scanning:
1. Review [Anthropic's Privacy Policy](https://www.anthropic.com/legal/privacy)
2. Don't scan proprietary code unless you've reviewed data handling
3. Consider scanning only public portions of sensitive codebases

---

## 📚 Documentation

- **[Architecture Guide](docs/ARCHITECTURE.md)** - Multi-agent system design and workflow
- **[Claude SDK Guide](docs/references/claude-agent-sdk-guide.md)** - Claude Agent SDK reference

---

## 🤝 Contributing

Contributions are welcome! We appreciate bug reports, feature requests, and code contributions.

---

## 👤 Author

Built by [@anshumanbh](https://github.com/anshumanbh)

🌟 Star the repo to follow along!

---

## 🙏 Acknowledgments

- Powered by [Claude](https://www.anthropic.com/claude) by Anthropic
- Built with [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk-python)
- Inspired by traditional SAST tools but reimagined with AI

---
