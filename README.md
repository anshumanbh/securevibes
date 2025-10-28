# 🛡️ SecureVibes

**AI-Native Security System for Vibecoded Applications**

SecureVibes uses **Claude's multi-agent architecture** to autonomously find security vulnerabilities in your codebase. Five specialized AI agents (4 required + 1 optional DAST) work together to deliver comprehensive, context-aware security analysis with concrete evidence.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

---

## ✨ Features

### True Agent Architecture
- **🤖 Autonomous Orchestration**: Claude intelligently coordinates agents
- **📐 Assessment Agent**: Maps your codebase architecture
- **🎯 Threat Modeling Agent**: Architecture-driven STRIDE threat analysis
- **🔍 Code Review Agent**: Security thinking methodology to find vulnerabilities
- **🧪 DAST Agent**: Dynamic testing with auto-bundled skills
- **📊 Report Generator**: Compiles comprehensive scan results

### Multi-Language Support
- **11 Languages**: Python, JavaScript, TypeScript, Go, Ruby, Java, PHP, C#, Rust, Kotlin, Swift
- **Smart Detection**: Automatically detects languages in your project
- **Language-Aware Exclusions**: Python projects exclude `venv/`, JS projects exclude `node_modules/`, Go projects exclude `vendor/`
- **Mixed Projects**: Handles polyglot codebases intelligently

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
export ANTHROPIC_API_KEY="your-api-key-here"  # Get from https://console.anthropic.com/

# Scan your project
securevibes scan /path/to/code --debug

# The most important part
# Sit back and relax. Please be patient as the scans might take some time, depending upon the model being used.
```

---

## 🎯 Usage

### Basic Commands

```bash
# Full security scan
securevibes scan .

# View results
securevibes report
```

### Common Options

```bash
# Default: creates .securevibes/scan_report.md (markdown format)
securevibes scan .

# Export results as JSON
securevibes scan . --format json --output results.json

# Custom markdown report (saved to .securevibes/custom_report.md)
securevibes scan . --format markdown --output custom_report.md

# Terminal table output (no file saved)
securevibes scan . --format table

# Filter by severity
securevibes scan . --severity high

# Use different model
securevibes scan . --model haiku

# Verbose debug output (shows agent narration)
securevibes scan . --debug

# Quiet mode
securevibes scan . --quiet
```

### Running Individual Sub-Agents

SecureVibes breaks down security scanning into 5 sub-agents. You can run them individually to save time and API costs:

```bash
# Run specific sub-agent only
securevibes scan . --subagent assessment
securevibes scan . --subagent threat-modeling
securevibes scan . --subagent code-review
securevibes scan . --subagent report-generator
securevibes scan . --subagent dast --target-url http://localhost:3000

# Resume from specific sub-agent onwards
securevibes scan . --resume-from code-review
securevibes scan . --resume-from dast --dast --target-url http://localhost:3000

# Force execution without prompts (CI/CD mode)
securevibes scan . --subagent dast --target-url http://localhost:3000 --force

# Skip artifact validation checks
securevibes scan . --subagent code-review --skip-checks
```

**Sub-Agent Dependencies:**
- `assessment` → Creates `SECURITY.md`
- `threat-modeling` → Needs `SECURITY.md` → Creates `THREAT_MODEL.json`
- `code-review` → Needs `THREAT_MODEL.json` → Creates `VULNERABILITIES.json`
- `report-generator` → Needs `VULNERABILITIES.json` → Creates `scan_results.json`
- `dast` → Needs `VULNERABILITIES.json` → Creates `DAST_VALIDATION.json`

**Interactive Workflow:**

When running a sub-agent, SecureVibes checks for existing artifacts:

```bash
$ securevibes scan . --subagent dast --target-url http://localhost:3000

🔍 Checking prerequisites for 'dast' sub-agent...
✓ Found: .securevibes/VULNERABILITIES.json (modified: 2h ago, 10 issues)

⚠️  Re-running DAST will overwrite existing results.

Options:
  1. Use existing VULNERABILITIES.json and run DAST only [default]
  2. Re-run entire scan (all sub-agents)
  3. Cancel

Choice [1]:
```

**Example output:**
```bash
$ securevibes scan . --debug

🛡️ SecureVibes Security Scanner
AI-Powered Vulnerability Detection (Streaming Mode)

📁 Scanning: /Users/user/repos/myapp
🤖 Model: sonnet
============================================================
  💭 Starting Phase 1: Assessment
  🤖 Starting assessment: Perform comprehensive security assessment...

━━━ Phase 1/4: Architecture Assessment ━━━

  📖 Reading package.json
  📖 Reading index.ts
  📖 Reading routes.ts
  📖 Reading schema.ts
  🔍 Searching: API_KEY|SECRET|PASSWORD|TOKEN
  📖 Reading FirecrawlService.ts
  🔍 Searching: passport|session|auth|login
  🔍 Searching: cors|helmet|sanitize|validate
  💾 Writing SECURITY.md
  💭 Assessment complete

━━━ Phase 2/4: Threat Modeling (STRIDE Analysis) ━━━

  📖 Reading SECURITY.md
  📖 Reading routes.ts
  🔍 Searching: STRIPE_SECRET_KEY|DATABASE_URL
  💾 Writing THREAT_MODEL.json
  💭 Threat modeling complete - 28 threats identified

━━━ Phase 3/4: Code Review (Security Analysis) ━━━

  📖 Reading THREAT_MODEL.json
  📖 Reading routes.ts
  🔍 Searching: rate.limit|rateLimit
  🔍 Searching: csrf|CSRF
  📖 Reading BlogPost.tsx
  🔍 Searching: dangerouslySetInnerHTML
  💾 Writing VULNERABILITIES.json
  💭 Code review complete - 21 vulnerabilities validated

━━━ Phase 4/4: Report Generation ━━━

  📖 Reading VULNERABILITIES.json
  💾 Writing scan_results.json
  💭 Report generation complete
  💰 Cost update: $2.16

================================================================================
📊 Scan Results
================================================================================

  📁 Files scanned:   2053
  ⏱️  Scan time:       987.93s (~16.5 min)
  💰 Total cost:      $2.16
  🐛 Issues found:    21
     🔴 Critical:     3
     🟠 High:         5
     🟡 Medium:       11
     🟢 Low:          2

                        🔍 Detected Vulnerabilities
╭────┬──────────┬──────────────────────────────────┬────────────────────╮
│ #  │ Severity │ Issue                            │ Location           │
├────┼──────────┼──────────────────────────────────┼────────────────────┤
│ 1  │ CRITICAL │ Unauthenticated Blog Access      │ server/routes.ts   │
│ 2  │ HIGH     │ No Rate Limiting                 │ server/index.ts    │
│ 3  │ CRITICAL │ Stripe Webhook Bypass            │ server/routes.ts   │
│ 4  │ CRITICAL │ Plaintext Password Storage       │ shared/schema.ts   │
│ 5  │ HIGH     │ Stored XSS via Blog Content      │ BlogPost.tsx       │
╰────┴──────────┴──────────────────────────────────┴────────────────────╯
... and 16 more issues

📄 Markdown report: .securevibes/scan_report.md
💾 JSON results: .securevibes/scan_results.json
```

**Learn more:** [Streaming Mode Documentation →](docs/STREAMING_MODE.md)

---

## 🌍 Supported Languages

SecureVibes automatically detects and scans code in **11 programming languages**:

| Language | Extensions | Auto-Excluded Directories |
|----------|-----------|---------------------------|
| Python | `.py`, `.pyw` | `venv/`, `env/`, `.venv/`, `__pycache__/`, `.pytest_cache/`, `.tox/`, `.eggs/`, `*.egg-info/` |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | `node_modules/`, `.npm/`, `.yarn/` |
| TypeScript | `.ts`, `.tsx` | `node_modules/`, `.npm/`, `.yarn/`, `dist/`, `build/` |
| Go | `.go` | `vendor/`, `bin/`, `pkg/` |
| Ruby | `.rb`, `.rake` | `vendor/`, `.bundle/`, `tmp/` |
| Java | `.java` | `target/`, `build/`, `.gradle/`, `.m2/` |
| PHP | `.php` | `vendor/`, `.composer/` |
| C# | `.cs` | `bin/`, `obj/`, `packages/` |
| Rust | `.rs` | `target/` |
| Kotlin | `.kt`, `.kts` | `build/`, `.gradle/` |
| Swift | `.swift` | `.build/`, `.swiftpm/`, `Packages/` |

**Smart Exclusions:**
- Only language-relevant directories are excluded (e.g., Python-only projects won't exclude `node_modules/`)
- Common directories like `.git/`, `.svn/`, `.hg/` are always excluded
- DAST phase can access `.claude/skills/` for dynamic testing capabilities

**Mixed-Language Projects:**
SecureVibes detects all languages present and applies combined exclusion rules. For example, a Python + TypeScript project will exclude both `venv/` and `node_modules/`.

---

## 🐍 Python API

### Classic Scanner

For programmatic access:

```python
import asyncio
from securevibes import Scanner

async def main():
    # Authentication is automatically handled by Claude Agent SDK via:
    # - ANTHROPIC_API_KEY environment variable, or
    # - Session token from `claude` CLI (run: claude, then /login)
    scanner = Scanner(
        model="sonnet"  # Use shorthand: sonnet, haiku, opus
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

### Streaming Scanner (Real-Time Progress)

For long-running scans with real-time progress:

```python
import asyncio
from securevibes import Scanner

async def main():
    # Authentication is automatically handled by Claude Agent SDK via:
    # - ANTHROPIC_API_KEY environment variable, or
    # - Session token from `claude` CLI (run: claude, then /login)
    scanner = Scanner(
        model="sonnet",  # Use shorthand: sonnet, haiku, opus
        debug=True  # Show agent narration for verbose output
    )
    
    # Scan with live progress updates to stdout
    result = await scanner.scan("/path/to/large/repo")
    
    # Same result format as classic scanner
    print(f"\n{'='*60}")
    print(f"Scan complete!")
    print(f"Found {len(result.issues)} vulnerabilities")
    print(f"Cost: ${result.total_cost_usd:.4f}")

asyncio.run(main())
```

---

## ⚙️ Configuration

### Authentication

SecureVibes uses the Claude CLI for AI analysis. Authenticate using any of these methods:

**Method 1: Session-based authentication (recommended)**
```bash
claude
# In interactive mode, type: /login
# Follow the prompts to authenticate
```

**Method 2: API Key**
```bash
export ANTHROPIC_API_KEY='your-api-key-here'
```
Get your API key from: https://console.anthropic.com/


### Model Selection

SecureVibes provides flexible model selection with a **three-tier priority system**:

**Priority Hierarchy:**
1. 🥇 **Per-agent environment variables** (highest priority)
2. 🥈 **CLI `--model` flag** (applies to all agents)
3. 🥉 **Default "sonnet"** (fallback)

**Examples:**

```bash
# All agents use haiku (CLI flag)
securevibes scan . --model haiku

# All use haiku, except code-review uses opus (env var overrides CLI)
export SECUREVIBES_CODE_REVIEW_MODEL=opus
securevibes scan . --model haiku

# Fine-grained control per agent
export SECUREVIBES_ASSESSMENT_MODEL=haiku        # Fast
export SECUREVIBES_CODE_REVIEW_MODEL=opus        # Most thorough
securevibes scan .  # Other agents use default (sonnet)
```

**Available models:** `haiku` (fast/cheap), `sonnet` (balanced), `opus` (thorough/expensive)

---

### Optional Configuration

SecureVibes can be customized via environment variables:

#### 🤖 Per-Agent Model Override
Override the model for specific agents (overrides CLI `--model` flag):

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
# Ensure you're authenticated first (see Authentication section)
export SECUREVIBES_ASSESSMENT_MODEL="haiku"
export SECUREVIBES_THREAT_MODELING_MODEL="haiku"
export SECUREVIBES_CODE_REVIEW_MODEL="sonnet"
export SECUREVIBES_MAX_TURNS=30
securevibes scan .
```

**Optimize for Accuracy (Recommended):**
```bash
# Ensure you're authenticated first (see Authentication section)
export SECUREVIBES_CODE_REVIEW_MODEL="opus"
export SECUREVIBES_THREAT_MODELING_MODEL="sonnet"
export SECUREVIBES_MAX_TURNS=75
securevibes scan .
```

---

## 🏗️ How It Works

SecureVibes uses a **multi-agent architecture** where Claude autonomously orchestrates 5 specialized agents (4 required + 1 optional DAST):

1. **Assessment Agent** → Analyzes architecture → `SECURITY.md`
2. **Threat Modeling Agent** → Applies STRIDE → `THREAT_MODEL.json`
3. **Code Review Agent** → Validates vulnerabilities → `VULNERABILITIES.json`
4. **Report Generator** → Compiles results → `scan_results.json`
5. **DAST Agent (Optional)** → Dynamic validation via HTTP → `DAST_VALIDATION.json` (requires `--target-url`)

**Key Benefits:**
- ✅ Claude intelligently adapts to your codebase
- ✅ Agents build on each other's findings
- ✅ Security thinking methodology (not just pattern matching)
- ✅ Concrete evidence with file paths and line numbers
- ✅ Optional dynamic validation for exploitability confirmation

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
- **[Streaming Mode Guide](docs/STREAMING_MODE.md)** - Real-time progress tracking (recommended for large repos)
- **[Maintenance Guide](docs/MAINTENANCE.md)** - Keep codebase clean, tested, and pruned
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
