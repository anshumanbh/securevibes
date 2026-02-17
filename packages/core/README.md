# 🛡️ SecureVibes

<div align="center">

### 🌐 [securevibes.ai](https://securevibes.ai) — Website, docs & blog

</div>

**AI‑Native Security for Vibecoded Apps**

SecureVibes uses Claude’s multi‑agent architecture to find security issues with concrete evidence. Agents coordinate to map your architecture, model threats, review code, and generate a clear report. An optional DAST phase validates exploitability via HTTP testing using auto‑discovered skills.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

---

## 🚀 Quick Start

```bash
# Install for the latest release on PyPi (might not have all the latest changes in the code)
pip install securevibes

# NOTE: the package uploaded on PyPi might not have all the latest changes. 
# I will try to release a new version of the package whenever there are significant changes/developments
# If you would rather use the version with the latest changes, you can do the following:

# Install for the latest version (might be buggy)
git clone https://github.com/anshumanbh/securevibes.git
cd securevibes
virtualenv env
. env/bin/activate
pip install -e packages/core

# Authenticate (choose one method)
# Method 1: Session-based (recommended)
# You could use your Claude subscription here, if you don't want to pay per API requests
claude  # Run interactive CLI, then type: /login

# Method 2: API key
export ANTHROPIC_API_KEY="your-api-key-here"

# Scan your project
securevibes scan /path/to/code --debug

# The most important part
# Sit back and relax. Please be patient as the scans might take some time, depending upon the model being used.
```

Get your API key from: https://console.anthropic.com/

---

## 🔐 Runtime Safety Model

SecureVibes currently runs scan orchestration with Claude SDK `permission_mode="bypassPermissions"`.
Runtime safety depends on explicit tool surfaces and scanner hooks (for example, PR review repo-boundary guardrails and DAST database CLI blocking).

Operational guidance:
- Run scans only on trusted repositories.
- Prefer isolated CI runners/containers for scans.
- Avoid running scans with access to production credentials or sensitive networks.

---

## 🤖 Agents

- Assessment → `SECURITY.md`
- Threat Modeling (STRIDE + technology-specific skills) → `THREAT_MODEL.json`
- Code Review → `VULNERABILITIES.json`
- Report Generator → `scan_results.json`
- DAST (optional) → `DAST_VALIDATION.json` (validates via HTTP when --target-url provided)

## 🤖 Agentic Detection

SecureVibes automatically detects agentic applications (LLM APIs, agent frameworks, tool execution) and requires OWASP ASI threats in threat models. Override with `--agentic` or `--no-agentic`.

## 🌍 Supported Languages

**11 Languages:** Python, JavaScript, TypeScript, Go, Ruby, Java, PHP, C#, Rust, Kotlin, Swift

**Smart Features:**
- Auto-detects languages in your project
- Language-aware exclusions (Python: `venv/`, JS: `node_modules/`, Go: `vendor/`)
- Handles mixed-language codebases intelligently

For detailed language support and exclusion rules, see the [full documentation](https://github.com/anshumanbh/securevibes#-supported-languages).

---

## 🎯 Common Commands

```bash
# Default: creates .securevibes/scan_report.md (markdown format)
securevibes scan .

# Export JSON for CI/CD pipeline
securevibes scan . --format json --output security-report.json

# Custom markdown report (saved to .securevibes/custom_report.md)
securevibes scan . --format markdown --output custom_report.md

# Terminal table output (no file saved)
securevibes scan . --format table

# Focus on critical/high severity
securevibes scan . --severity high

# Fast scan with cheaper model
securevibes scan . --model haiku

# Quiet mode for automation
securevibes scan . --quiet

# Run individual sub-agents
securevibes scan . --subagent assessment
securevibes scan . --subagent code-review
securevibes scan . --subagent report-generator

# DAST (optional): skill‑gated dynamic validation
securevibes scan . --subagent dast --target-url http://localhost:3000
  # Validates only when a matching skill is available (e.g., IDOR)
  # Writes .securevibes/DAST_VALIDATION.json; no ad‑hoc files in repo

# Agentic detection override
securevibes scan . --agentic      # Force ASI threat requirement
securevibes scan . --no-agentic   # ASI threats optional

# Works with any supported language:
securevibes scan /path/to/go-app        # Go project
securevibes scan /path/to/ruby-app      # Ruby project
securevibes scan /path/to/mixed-stack   # Multi-language project

# PR review (requires prior scan artifacts in .securevibes/)
securevibes pr-review . --base main --head feature-branch
securevibes pr-review . --range abc123~1..abc123
securevibes pr-review . --diff changes.patch

# Commit tracking (requires baseline scan and scan_state.json)
securevibes pr-review . --since-last-scan
securevibes pr-review . --since 2026-02-01
securevibes pr-review . --last 10

# Update base artifacts from PR findings
securevibes pr-review . --range abc123~1..abc123 --update-artifacts

# Clean transient PR artifacts before reruns
securevibes pr-review . --range abc123~1..abc123 --clean-pr-artifacts

# PR review output formats (default: markdown)
securevibes pr-review . --base main --head feature-branch --format markdown
securevibes pr-review . --base main --head feature-branch --format json --output pr_review.json
securevibes pr-review . --base main --head feature-branch --format table

# PR review severity threshold
securevibes pr-review . --base main --head feature-branch --severity high

# Catchup: pull latest + review since last full scan
securevibes catchup . --branch main
```

`securevibes catchup` requires a clean working tree (commit, stash, or discard local changes first).

PR review runtime controls:

```bash
# Timeout per PR review attempt in seconds (default: 240)
export SECUREVIBES_PR_REVIEW_TIMEOUT_SECONDS=300

# Number of PR review attempts before giving up (default: 4)
export SECUREVIBES_PR_REVIEW_ATTEMPTS=5
```

PR review fails closed if diff context would be truncated
(more than 16 prioritized files or any hunk over 200 lines).
Split large reviews with smaller `--range`, `--last`, or `--since` windows.

PR review artifacts (written to `.securevibes/`):
- `DIFF_CONTEXT.json` (parsed diff summary)
- `PR_VULNERABILITIES.json` (raw findings)
- `pr_review_report.md` (default markdown report)
- `scan_state.json` (commit tracking for pr-review/catchup)

---

## ⚙️ Configuration

### Models

SecureVibes uses a **three-tier priority system** for model selection:

**Priority Hierarchy:**
1. 🥇 **Per-agent environment variables** (highest)
2. 🥈 **CLI `--model` flag** (applies to all agents)
3. 🥉 **Default "sonnet"** (fallback)

**Examples:**

```bash
# All agents use haiku
securevibes scan . --model haiku

# All use haiku, except code-review uses opus
export SECUREVIBES_CODE_REVIEW_MODEL=opus
securevibes scan . --model haiku

# Fine-grained control per agent
export SECUREVIBES_ASSESSMENT_MODEL=haiku
export SECUREVIBES_CODE_REVIEW_MODEL=opus
securevibes scan .  # Others use default (sonnet)
```

Models: `haiku` (fast/cheap), `sonnet` (balanced), `opus` (thorough/expensive)

### Per‑Agent Overrides
Override specific agent models via environment variables:

```bash
# Authenticate first (see Quick Start above)

# Override specific agent models (overrides CLI --model flag)
export SECUREVIBES_CODE_REVIEW_MODEL="opus"  # Max accuracy
export SECUREVIBES_THREAT_MODELING_MODEL="sonnet"
export SECUREVIBES_PR_CODE_REVIEW_MODEL="sonnet"

# Control analysis depth (default: 50)
export SECUREVIBES_MAX_TURNS=75  # Deeper analysis
```

---

## 🐍 Python API (minimal)

```python
import asyncio
from securevibes import Scanner

async def main():
    # Auth via Claude Agent SDK:
    # - ANTHROPIC_API_KEY or
    # - Session token from `claude` CLI (/login)
    scanner = Scanner(
        model="sonnet",  # Use shorthand: sonnet, haiku, opus
        debug=True  # Show agent narration for verbose output
    )
    
    result = await scanner.scan("/path/to/repo")
    print(f"Found {len(result.issues)} vulnerabilities")
    print(f"Cost: ${result.total_cost_usd:.4f}")

asyncio.run(main())
```

---

## 📚 Full Documentation

This is a quick reference for PyPI users. For comprehensive documentation, visit:

**🌐 [securevibes.ai](https://securevibes.ai)** — Full website with docs & blog

Including:
- 📖 [How It Works](https://securevibes.ai/how-it-works)
- ✨ [Features](https://securevibes.ai/features)
- 📝 [Blog](https://securevibes.ai/blog)

---

## 👤 Author

Built by [@anshumanbh](https://github.com/anshumanbh)

🌐 [securevibes.ai](https://securevibes.ai) — Website, docs & blog

🌟 **Star the repo** to follow development!

---

## 🙏 Acknowledgments

- Powered by [Claude](https://www.anthropic.com/claude) by Anthropic
- Built with [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk-python)
- Inspired by traditional SAST tools, reimagined with AI

---

**License:** AGPL-3.0 | **Requires:** Python 3.10+
