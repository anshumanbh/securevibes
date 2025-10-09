# 🛡️ SecureVibes

**AI-Native Security Scanner for Vibecoded Applications**

SecureVibes uses **Claude's multi-agent architecture** to autonomously find security vulnerabilities in your codebase. Four specialized AI agents work together to deliver comprehensive, context-aware security analysis with concrete evidence.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.1.1-green.svg)](https://pypi.org/project/securevibes/)

---

## 🚀 Quick Start

```bash
# Install
pip install securevibes

# Configure API key
export CLAUDE_API_KEY="your-api-key-here"

# Scan your project
securevibes scan .

# View results
securevibes report
```

Get your Claude API key from: https://console.anthropic.com/

---

## ✨ What You Get

- ✅ **Exact file paths and line numbers** for every vulnerability
- ✅ **CWE IDs** for industry-standard tracking
- ✅ **Concrete code snippets** showing the vulnerable code
- ✅ **Remediation recommendations** with actionable fixes
- ✅ **Exploitability analysis** with realistic attack scenarios

---

## 🤖 Multi-Agent Architecture

SecureVibes orchestrates 4 specialized Claude agents:

1. **Assessment Agent** - Maps codebase architecture and technology stack
2. **Threat Modeling Agent** - Applies STRIDE methodology for realistic threats
3. **Code Review Agent** - Uses security thinking framework to find vulnerabilities
4. **Report Generator** - Compiles findings into actionable reports

**Key Difference:** Unlike traditional pattern-matching tools, SecureVibes agents *understand* your code's context, architecture, and business logic to find novel vulnerabilities that static analysis misses.

---

## 📊 Example Scan

```bash
$ securevibes scan .

🛡️ SecureVibes Security Scanner
📁 Scanning: /Users/xyz/repos/my-project
🤖 Model: sonnet
============================================================

✅ Phase 1/4: Architecture Assessment Complete
✅ Phase 2/4: Threat Modeling (STRIDE Analysis) Complete
✅ Phase 3/4: Code Review (Security Analysis) Complete
✅ Phase 4/4: Report Generation Complete

================================================================================
📊 Scan Results
================================================================================

  📁 Files scanned:   1953
  ⏱️  Scan time:       1053.66s
  💰 Total cost:      $2.27
  🐛 Issues found:    28
     🔴 Critical:     5
     🟠 High:         10
     🟡 Medium:       10
     🟢 Low:          3
```

---

## 🎯 Common Use Cases

```bash
# Export JSON for CI/CD pipeline
securevibes scan . --format json --output security-report.json

# Focus on critical/high severity
securevibes scan . --severity high

# Fast scan with cheaper model
securevibes scan . --model haiku

# Quiet mode for automation
securevibes scan . --quiet
```

---

## ⚙️ Configuration

Control agent models and analysis depth via environment variables:

```bash
# Required
export CLAUDE_API_KEY='your-api-key'

# Optional: Customize agent models (default: sonnet)
export SECUREVIBES_CODE_REVIEW_MODEL="opus"  # Max accuracy
export SECUREVIBES_THREAT_MODELING_MODEL="sonnet"

# Optional: Control analysis depth (default: 50)
export SECUREVIBES_MAX_TURNS=75  # Deeper analysis
```

**Models:** `haiku` (fast/cheap) | `sonnet` (balanced) | `opus` (thorough/expensive)

---

## 🐍 Python API

```python
import asyncio
from securevibes import SecurityScanner

async def main():
    scanner = SecurityScanner(
        api_key="your-api-key",
        model="claude-3-5-sonnet-20241022"
    )
    
    result = await scanner.scan("/path/to/repo")
    print(f"Found {len(result.issues)} vulnerabilities")

asyncio.run(main())
```

---

## 🔒 Privacy & Security

**What SecureVibes sends to Anthropic:**
- Your source code files
- Relative file paths within the scanned repository

**What SecureVibes does NOT send:**
- Absolute paths or usernames
- Environment variables or secrets
- Git history or metadata

⚠️ **Important:** SecureVibes sends your code to Anthropic's Claude API for analysis. Review [Anthropic's Privacy Policy](https://www.anthropic.com/legal/privacy) before scanning proprietary code.

---

## 📚 Full Documentation

This is a quick reference for PyPI users. For comprehensive documentation, visit:

**📖 [Full Documentation on GitHub](https://github.com/anshumanbh/securevibes)**

Including:
- 🏗️ [Architecture Deep Dive](https://github.com/anshumanbh/securevibes/blob/main/docs/ARCHITECTURE.md)
- 🔧 [Advanced Configuration](https://github.com/anshumanbh/securevibes#%EF%B8%8F-configuration)
- 🧪 [Example Scans & Results](https://github.com/anshumanbh/securevibes#-example-output)
- 🤝 [Contributing Guide](https://github.com/anshumanbh/securevibes#-contributing)

---

## 👤 Author & Support

Built by [@anshumanbh](https://github.com/anshumanbh)

- 🐛 **Bug Reports:** [GitHub Issues](https://github.com/anshumanbh/securevibes/issues)
- 💡 **Feature Requests:** [GitHub Discussions](https://github.com/anshumanbh/securevibes/discussions)
- 🌟 **Star the repo** to follow development!

---

## 🙏 Acknowledgments

- Powered by [Claude](https://www.anthropic.com/claude) by Anthropic
- Built with [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk-python)
- Inspired by traditional SAST tools, reimagined with AI

---

**License:** AGPL-3.0 | **Requires:** Python 3.10+
