# Comprehensive Guide to Creating and Using Claude Agent Skills

## Table of Contents
1. [Introduction](#introduction)
2. [What Are Agent Skills?](#what-are-agent-skills)
3. [Architecture and Technical Foundation](#architecture-and-technical-foundation)
4. [Skill Structure and Components](#skill-structure-and-components)
5. [Creating Your First Skill](#creating-your-first-skill)
6. [Best Practices for Skill Development](#best-practices-for-skill-development)
7. [Using Skills with Claude Agent SDK](#using-skills-with-claude-agent-sdk)
8. [Testing and Iteration](#testing-and-iteration)
9. [Real-World Examples](#real-world-examples)
10. [Troubleshooting and Common Pitfalls](#troubleshooting-and-common-pitfalls)
11. [Advanced Topics](#advanced-topics)

---

## Introduction

Agent Skills are reusable, filesystem-based resources that provide Claude with domain-specific expertise: workflows, context, and best practices that transform general-purpose agents into specialists. Unlike prompts (conversation-level instructions for one-off tasks), Skills load on-demand and eliminate the need to repeatedly provide the same guidance across multiple conversations.

Skills are **model-invoked**—Claude autonomously decides when to use them based on context, without requiring explicit user commands.

**Key benefits**:
- **Specialize Claude**: Tailor capabilities for domain-specific tasks
- **Reduce repetition**: Create once, use automatically
- **Compose capabilities**: Combine Skills to build complex workflows

This guide provides a comprehensive blueprint for creating, deploying, and using Agent Skills across Claude's products. It synthesizes official documentation from [Anthropic's engineering blog](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills) and the [Claude Platform documentation](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview).

> **Last Updated**: December 2025 (aligned with official documentation from October 2025)

---

## What Are Agent Skills?

### Core Characteristics

**Composable**: Skills work together automatically. Claude can combine multiple skills to accomplish complex tasks without manual orchestration.

**Portable**: The same skill format works across:
- Claude apps on claude.ai (Pro, Max, Team, Enterprise users)
- Claude Code CLI
- Claude API (via Messages API with beta headers and `/v1/skills` endpoint)
- Claude Agent SDK (Python and TypeScript)

**Efficient**: Only minimal required information loads when relevant, using a progressive disclosure pattern to manage context windows effectively.

**Powerful**: Skills can include executable code (Python, Bash, JavaScript) for reliable, deterministic task execution.

### Model-Invoked vs. User-Invoked

**Skills are model-invoked**: Claude decides when to activate them based on the task and skill description. This differs from:
- **Slash commands**: Require explicit user invocation (e.g., `/review-code`)
- **Tools/Functions**: Explicitly defined in API calls

### When to Use Skills

Skills are ideal for:
- Specialized domain knowledge (e.g., security scanning, financial analysis)
- Complex workflows requiring multiple steps
- Document generation and manipulation
- Code generation following specific patterns
- Data processing with consistent rules
- Tasks requiring organization-specific guidelines

### Pre-built Agent Skills

Anthropic provides pre-built Agent Skills for common document tasks:

| Skill | Description | Available On |
|-------|-------------|--------------|
| **PowerPoint (pptx)** | Create presentations, edit slides, analyze content | claude.ai, API |
| **Excel (xlsx)** | Create spreadsheets, analyze data, generate charts | claude.ai, API |
| **Word (docx)** | Create documents, edit content, format text | claude.ai, API |
| **PDF (pdf)** | Generate formatted PDF documents and reports | claude.ai, API |

These Skills are available immediately without any setup. Claude automatically uses them when relevant to your request.

### Where Skills Work

Skills are available across Claude's products with different configuration requirements:

| Platform | Pre-built Skills | Custom Skills | Configuration |
|----------|-----------------|---------------|---------------|
| **claude.ai** | Yes | Upload via Settings > Features | Automatic |
| **Claude API** | Yes (via beta headers) | Upload via `/v1/skills` endpoint | Requires beta headers |
| **Claude Code CLI** | No | Auto-discovered from filesystem | Automatic |
| **Claude Agent SDK** | No | Filesystem-based | Requires `setting_sources` config |

#### API Beta Headers

Using Skills via the Claude API requires three beta headers:

```python
headers = {
    "anthropic-beta": "code-execution-2025-08-25,skills-2025-10-02,files-api-2025-04-14"
}
```

- `code-execution-2025-08-25` - Skills run in the code execution container
- `skills-2025-10-02` - Enables Skills functionality
- `files-api-2025-04-14` - Required for uploading/downloading files to/from the container

### Runtime Environment Constraints

The runtime environment available to your skill depends on where you use it:

| Platform | Network Access | Package Installation |
|----------|---------------|---------------------|
| **claude.ai** | Varies (user/admin settings) | Yes (npm, PyPI, GitHub) |
| **Claude API** | **No network access** | **No runtime install** (pre-installed packages only) |
| **Claude Code** | Full network access | Local only (global install discouraged) |

**Important API Limitation**: Skills on the Claude API cannot make external API calls or access the internet. Only pre-installed packages are available.

### Cross-Surface Availability

> **Warning**: Custom Skills do NOT sync across surfaces.

Skills uploaded to one surface are not automatically available on others:
- Skills uploaded to claude.ai must be separately uploaded to the API
- Skills uploaded via the API are not available on claude.ai
- Claude Code Skills are filesystem-based and separate from both

You must manage and upload Skills separately for each surface where you want to use them.

### Sharing Scope

Skills have different sharing models depending on where you use them:

| Platform | Sharing Scope |
|----------|--------------|
| **claude.ai** | Individual user only (each team member uploads separately) |
| **Claude API** | Workspace-wide (all workspace members can access) |
| **Claude Code** | Personal (`~/.claude/skills/`) or project-based (`.claude/skills/`) |

> **Note**: claude.ai does not currently support centralized admin management or org-wide distribution of custom Skills.

---

## Security Considerations

> **Important**: We strongly recommend using Skills only from trusted sources: those you created yourself or obtained from Anthropic.

Skills provide Claude with new capabilities through instructions and code. While this makes them powerful, it also means a malicious Skill can direct Claude to invoke tools or execute code in ways that don't match the Skill's stated purpose.

**Key security considerations**:

- **Audit thoroughly**: Review all files bundled in the Skill: SKILL.md, scripts, images, and other resources. Look for unusual patterns like unexpected network calls, file access patterns, or operations that don't match the Skill's stated purpose
- **External sources are risky**: Skills that fetch data from external URLs pose particular risk, as fetched content may contain malicious instructions. Even trustworthy Skills can be compromised if their external dependencies change over time
- **Tool misuse**: Malicious Skills can invoke tools (file operations, bash commands, code execution) in harmful ways
- **Data exposure**: Skills with access to sensitive data could be designed to leak information to external systems
- **Treat like installing software**: Only use Skills from trusted sources. Be especially careful when integrating Skills into production systems with access to sensitive data or critical operations

---

## Architecture and Technical Foundation

### Progressive Disclosure Pattern

Skills implement a three-tier context management system:

```
┌─────────────────────────────────────────────────┐
│ Tier 1: Metadata (Always Loaded)               │
│ - Name                                          │
│ - Description                                   │
│ - Stored in system prompt                       │
└─────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────┐
│ Tier 2: SKILL.md (Loaded When Triggered)       │
│ - Core instructions                             │
│ - Workflow steps                                │
│ - References to additional files                │
└─────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────┐
│ Tier 3: Supporting Files (Loaded On-Demand)    │
│ - reference.md                                  │
│ - examples.md                                   │
│ - Scripts (Python, Bash, etc.)                  │
│ - Templates and resources                       │
└─────────────────────────────────────────────────┘
```

**Key Insight**: This architecture enables "effectively unbounded" context without overwhelming the model's window. Claude only loads what's needed for the current task.

### Context Window Management

Typical token usage progression:
1. **Initial load**: System prompt + skill metadata + user message
2. **Skill activation**: Claude invokes tool to read SKILL.md
3. **Progressive expansion**: Claude selects additional files based on requirements

### Code Execution Integration

Skills can include executable scripts that Claude invokes as tools. This provides:
- **Deterministic execution**: More reliable than token generation for operations like sorting, parsing, or calculations
- **Efficiency**: Operations run "without loading either the script or data into context"
- **Error handling**: Scripts can validate inputs and catch errors before destructive changes

---

## Skill Structure and Components

### Directory Structure

```
skill-name/
├── SKILL.md              # Required: Core instructions with YAML frontmatter
├── reference.md          # Optional: Detailed reference documentation
├── examples.md           # Optional: Example inputs/outputs
├── scripts/              # Optional: Executable code
│   ├── validate.py
│   ├── process.sh
│   └── utils.js
├── resources/            # Optional: Templates and data files
│   ├── template.json
│   └── schema.yaml
└── LICENSE.txt           # Optional: License information
```

### SKILL.md Format

Every skill **must** contain a `SKILL.md` file with YAML frontmatter:

```yaml
---
name: skill-name
description: What this does and when to use it
allowed-tools: Read, Grep, Glob  # Optional: Tool restrictions
---

# Skill Instructions

## Purpose
Brief explanation of what this skill does and when Claude should use it.

## Usage
Step-by-step instructions for Claude to follow.

## Examples
Concrete examples of inputs and expected outputs.

## Additional Resources
- See `reference.md` for detailed API documentation
- See `examples/` for more examples
```

### YAML Frontmatter Requirements

**name** (required):
- Maximum 64 characters
- Lowercase letters, numbers, and hyphens only
- Cannot contain XML tags
- Cannot contain reserved words: "anthropic", "claude"
- Use gerund form (verb + -ing): `processing-pdfs`, `analyzing-spreadsheets`
- Avoid vague names like `helper`, `utils`, `tool`

**description** (required):
- Must be non-empty
- Maximum 1024 characters
- Cannot contain XML tags
- Specify **what** the skill does and **when** to use it
- Write in third person (not "I can help you..." or "You can use this...")
- Include specific trigger terms users might mention
- Example: "Extract text and tables from PDFs, fill forms, merge documents. Use when working with PDF files or document extraction."

**allowed-tools** (optional):
- Comma-separated list of tools Claude can use when this skill is active
- Enables read-only skills or limits scope
- Example: `Read, Grep, Glob` (no file modification)
- Example: `Read, Write, Edit, Bash` (full access)
- **Note**: This field is only respected in Claude Code CLI; it is ignored by the Agent SDK

### Skill Types by Location

**1. Personal Skills** (`~/.claude/skills/`):
- Available across all your projects
- Not shared with team
- Good for personal workflows and preferences

**2. Project Skills** (`.claude/skills/`):
- Shared with team via git
- Project-specific patterns and guidelines
- Version controlled with codebase

**3. Plugin Skills**:
- Bundled with installed plugins
- Distributed via marketplace
- Automatically available when plugin is installed

---

## Creating Your First Skill

### Step-by-Step Guide

#### Step 1: Define the Purpose

Ask yourself:
- What specific task does this skill perform?
- When should Claude use this skill?
- What are the trigger words or scenarios?
- What value does it provide over Claude's default capabilities?

#### Step 2: Choose the Skill Location

```bash
# Personal skill (all projects)
mkdir -p ~/.claude/skills/my-skill

# Project skill (shared with team)
mkdir -p .claude/skills/my-skill
```

#### Step 3: Create the SKILL.md File

```markdown
---
name: api-endpoint-generator
description: Generate RESTful API endpoints following our team's architecture patterns. Use when creating new API routes, controllers, or modifying backend API structure.
allowed-tools: Read, Write, Edit, Glob, Grep
---

# API Endpoint Generator

## Purpose
This skill helps generate consistent RESTful API endpoints following our team's architecture patterns, including controllers, routes, middleware, and tests.

## Architecture Pattern
We use a layered architecture:
- **Routes**: Define HTTP methods and paths
- **Controllers**: Handle request/response logic
- **Services**: Contain business logic
- **Models**: Define data structures

## Workflow
1. Identify the resource name (e.g., "user", "product")
2. Create the model schema
3. Generate the service layer with CRUD operations
4. Create the controller with request validation
5. Define routes with appropriate middleware
6. Generate corresponding tests

## File Structure
```
backend/
├── models/
│   └── {resource}.py
├── services/
│   └── {resource}_service.py
├── controllers/
│   └── {resource}_controller.py
├── routes/
│   └── {resource}_routes.py
└── tests/
    └── test_{resource}.py
```

## Examples
See `examples.md` for complete endpoint generation examples.

## Validation
Before finalizing:
- Run `scripts/validate_endpoint.py` to check consistency
- Ensure all CRUD operations have corresponding tests
- Verify middleware is properly applied
```

#### Step 4: Add Supporting Files (Optional)

Create `examples.md`:

```markdown
# API Endpoint Generator Examples

## Example 1: User Management Endpoint

**Input**: "Create a user management endpoint with authentication"

**Output**:
- `models/user.py`: User model with fields (id, email, password, created_at)
- `services/user_service.py`: CRUD operations with password hashing
- `controllers/user_controller.py`: Request handlers with validation
- `routes/user_routes.py`: Routes with JWT middleware
- `tests/test_user.py`: Full test coverage

## Example 2: Product Catalog Endpoint

**Input**: "Generate product endpoint with categories"

**Output**: (similar structure with category relationship)
```

Create validation script `scripts/validate_endpoint.py`:

```python
#!/usr/bin/env python3
"""
Validate that a generated API endpoint follows team patterns.
"""
import sys
import os
from pathlib import Path

def validate_endpoint(resource_name):
    """Check that all required files exist and follow patterns."""
    required_files = [
        f"backend/models/{resource_name}.py",
        f"backend/services/{resource_name}_service.py",
        f"backend/controllers/{resource_name}_controller.py",
        f"backend/routes/{resource_name}_routes.py",
        f"backend/tests/test_{resource_name}.py"
    ]

    errors = []
    for file_path in required_files:
        if not Path(file_path).exists():
            errors.append(f"Missing required file: {file_path}")

    if errors:
        print("Validation failed:")
        for error in errors:
            print(f"  - {error}")
        return False

    print(f"Validation passed for {resource_name} endpoint!")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: validate_endpoint.py <resource_name>")
        sys.exit(1)

    resource = sys.argv[1]
    success = validate_endpoint(resource)
    sys.exit(0 if success else 1)
```

#### Step 5: Test the Skill

Use Claude Code to test:

```bash
# Start Claude Code
claude

# Ask Claude to use your skill
"Create a new product API endpoint with inventory tracking"
```

Claude should automatically detect and activate your skill based on the description and trigger terms.

---

## Best Practices for Skill Development

### 1. Conciseness is Critical

**Target**: Keep SKILL.md under 500 lines.

**Rationale**: Every line consumes tokens. Only include context Claude doesn't already have.

**Challenge each piece**: "Does this information justify its token cost?"

**Use progressive disclosure**: Move detailed reference material to separate files that Claude loads only when needed.

### 2. Set Appropriate Degrees of Freedom

Match the level of specificity to the task's fragility and variability:

| Freedom Level | When to Use | Example |
|---------------|-------------|---------|
| **High** (text instructions) | Multiple valid approaches exist; decisions depend on context | "Follow our code review guidelines" |
| **Medium** (pseudocode with parameters) | Preferred pattern exists; some variation acceptable | "Use this template: `function {name}({params}) { ... }`" |
| **Low** (specific scripts) | Fragile operations; consistency critical | "Run `scripts/deploy.sh --env production`" |

**Analogy**: Think of Claude as a robot exploring a path:
- **Narrow bridge with cliffs on both sides**: There's only one safe way forward. Provide specific guardrails and exact instructions (low freedom). Example: database migrations that must run in exact sequence.
- **Open field with no hazards**: Many paths lead to success. Give general direction and trust Claude to find the best route (high freedom). Example: code reviews where context determines the best approach.

### 3. Write Effective Descriptions

**Bad**: "Helps with API development"

**Good**: "Generate RESTful API endpoints following our team's architecture patterns. Use when creating new API routes, controllers, or modifying backend API structure."

**Description Formula**:
```
[What it does] + [When to use it] + [Trigger terms]
```

**Examples**:

```yaml
description: Extract text and tables from PDFs, fill forms, merge documents. Use when working with PDF files or document extraction.

description: Run security scans using OWASP ZAP and Nuclei. Use when testing web applications for vulnerabilities or performing penetration tests.

description: Generate React components following our design system with TypeScript, Tailwind CSS, and accessibility best practices. Use when creating new UI components.
```

### 4. Use Consistent Terminology

**Bad**: Mixing terms
- "API endpoint" → "URL" → "route" → "path"

**Good**: Choose one term
- Always use "API endpoint" throughout the skill

This reduces confusion and improves Claude's understanding.

### 5. Provide Concrete Examples

**Bad**: Abstract descriptions
```markdown
## Output Format
Generate code following best practices.
```

**Good**: Input/output pairs
```markdown
## Examples

**Input**: "Create user login endpoint"

**Output**:
```python
# routes/auth_routes.py
from flask import Blueprint, request, jsonify
from controllers.auth_controller import AuthController

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    return AuthController.login(request)
```
```

### 6. Implement Validation and Feedback Loops

For complex operations, follow "validate → fix → repeat" patterns:

```markdown
## Workflow

1. Generate the code structure
2. Run `scripts/validate.py` to check for issues
3. Fix any errors identified
4. Re-run validation
5. Proceed only when validation passes
```

**Validation script example**:
```python
def validate_code_structure(files):
    """Validate that generated code follows patterns."""
    issues = []

    # Check imports
    if not has_proper_imports(files):
        issues.append("Missing required imports")

    # Check type hints
    if not has_type_hints(files):
        issues.append("Missing type hints")

    # Check tests
    if not has_test_coverage(files):
        issues.append("Insufficient test coverage")

    return issues
```

### 7. Structure Long Files

For reference files exceeding 100 lines, include a table of contents:

```markdown
# API Reference

## Table of Contents
1. [Authentication](#authentication)
2. [User Endpoints](#user-endpoints)
3. [Product Endpoints](#product-endpoints)
4. [Error Handling](#error-handling)

## Authentication
...

## User Endpoints
...
```

**Rationale**: Claude may only partially read long files. A ToC ensures visibility of all available sections.

### 8. Avoid Time-Sensitive Information

**Bad**:
```markdown
As of 2024, use React 18 hooks.
```

**Good**:
```markdown
Use React hooks for state management.

## Old Patterns (Deprecated)
- Class components with `this.state`
- HOCs for state sharing
```

### 9. One-Level Deep References

**Bad**: Nested references
```
SKILL.md → reference.md → api_details.md → examples.md
```

**Good**: Flat structure
```
SKILL.md → reference.md
         → examples.md
         → api_details.md
```

**Rationale**: Claude may only partially read files that reference other files.

### 10. Make Script Execution Intent Clear

**For execution**:
```markdown
Run the validation script:
```bash
python scripts/validate.py --input generated_code/
```
```

**For reference**:
```markdown
See `scripts/analyze.py` for the algorithm used to parse code structure.
```

### 11. Test Across Models

Skills act as additions to models, so effectiveness depends on the underlying model. Verify skills work with all models you plan to use:

| Model | Use Case | Testing Considerations |
|-------|----------|----------------------|
| **Claude Haiku** | Fast, economical tasks | Does the Skill provide enough guidance? |
| **Claude Sonnet** | Balanced performance | Is the Skill clear and efficient? |
| **Claude Opus** | Complex reasoning | Does the Skill avoid over-explaining? |

What works perfectly for Opus might need more detail for Haiku. If you plan to use your Skill across multiple models, aim for instructions that work well with all of them.

---

## Using Skills with Claude Agent SDK

### Important: Platform Distinctions

Skills work across multiple platforms with **different configuration requirements**:

| Platform | Custom Skills | Pre-built Skills | Configuration |
|----------|--------------|-----------------|---------------|
| **Claude Code CLI** | Auto-discovered | No | Automatic from `.claude/skills/` and `~/.claude/skills/` |
| **Claude Messages API** | Via `/v1/skills` endpoint | Yes (via beta headers) | Requires beta headers |
| **Python Agent SDK** | Filesystem-based | No | **MUST set `setting_sources=["user", "project"]`** |
| **TypeScript Agent SDK** | Filesystem-based | No | **MUST set `settingSources: ['user', 'project']`** |

This section focuses on the **Python and TypeScript Agent SDKs**.

> **Note**: Unlike subagents (which can be defined programmatically), Skills must be created as filesystem artifacts. The SDK does not provide a programmatic API for registering Skills.

### Critical Configuration Requirements

⚠️ **THE MOST COMMON ISSUE**: The Agent SDK does **NOT** load filesystem settings by default.

**You MUST explicitly configure two things:**

1. ✅ Enable settings sources via `setting_sources=["project"]` and/or `setting_sources=["user"]`
2. ✅ Include `"Skill"` in `allowed_tools`

**Without these, your skills will NOT load**, even if they exist in the correct directories.

### Python Agent SDK Configuration

#### Minimal Working Example

```python
import asyncio
from claude_agent_sdk import query, ClaudeAgentOptions

async def main():
    options = ClaudeAgentOptions(
        # REQUIRED: Set working directory containing .claude/skills/
        cwd="/path/to/project",
        
        # REQUIRED: Enable filesystem settings
        setting_sources=["user", "project"],  # Load from both ~/.claude/skills/ and .claude/skills/
        
        # REQUIRED: Include Skill tool
        allowed_tools=["Skill", "Read", "Write", "Bash"]
    )

    # Claude will now detect and use your custom skills
    async for message in query(
        prompt="Help me process this PDF document",
        options=options
    ):
        print(message)

asyncio.run(main())
```

#### Project Skills Only (Team-Shared via Git)

```python
options = ClaudeAgentOptions(
    cwd="/path/to/project",
    setting_sources=["project"],  # ✅ Load only from .claude/skills/ in project
    allowed_tools=["Skill", "Read", "Write", "Bash"]
)

async for message in query(prompt="Analyze the codebase structure", options=options):
    print(message)
```

**Use case**: Share skills with team via version control. Everyone gets the same skills when they pull the repository.

#### Personal Skills Only (User-Specific, Cross-Project)

```python
options = ClaudeAgentOptions(
    cwd="/path/to/any/directory",  # Still needed for working directory context
    setting_sources=["user"],  # ✅ Load only from ~/.claude/skills/
    allowed_tools=["Skill", "Read", "Write", "Bash"]
)

async for message in query(prompt="Use my personal workflow", options=options):
    print(message)
```

**Use case**: Personal productivity skills you use across all projects, not shared with team.

#### Both Project and Personal Skills

```python
options = ClaudeAgentOptions(
    cwd="/path/to/project",
    setting_sources=["user", "project"],  # ✅ Load both personal and project skills
    allowed_tools=["Skill", "Read", "Write", "Bash"]
)

async for message in query(prompt="Help me with this task", options=options):
    print(message)
```

**Use case**: Combine team-shared project skills with your personal workflow skills.

### TypeScript Agent SDK Configuration

```typescript
import { query, ClaudeAgentOptions } from 'claude-agent-sdk';

async function useSkills() {
  const options: ClaudeAgentOptions = {
    // REQUIRED: Set working directory
    cwd: '/path/to/project',
    
    // REQUIRED: Enable filesystem settings
    settingSources: ['user', 'project'],  // Loads from both ~/.claude/skills/ and .claude/skills/
    
    // REQUIRED: Include Skill tool
    allowedTools: ['Skill', 'Read', 'Write', 'Bash']
  };

  // Claude will now detect and use your custom skills
  for await (const message of query('Help me process this PDF document', options)) {
    console.log(message);
  }
}
```

**Note**: In TypeScript, use `settingSources` and `allowedTools` (camelCase) instead of the Python-style snake_case.

### SDK-Specific Limitations

#### 1. allowed-tools Frontmatter Field Is Ignored

⚠️ **CRITICAL DIFFERENCE**: The `allowed-tools` field in your SKILL.md frontmatter **only works in Claude Code CLI**, not in the Agent SDK.

```yaml
---
name: my-skill
description: My security scanning skill
allowed-tools: Read, Grep, Glob  # ⚠️ COMPLETELY IGNORED by Agent SDK
---
```

**Why?** The SDK applies tool permissions globally, not per-skill. This is a fundamental architectural difference.

**In the Agent SDK**, control tool access through the main `allowed_tools` option:

```python
# This controls tool access for ALL skills in the SDK
options = ClaudeAgentOptions(
    allowed_tools=["Skill", "Read", "Grep", "Glob"],  # Applied to all skills
    setting_sources=["project"]
)
```

#### 2. No Per-Skill Tool Restrictions in SDK

Unlike Claude Code CLI (which respects per-skill tool restrictions defined in SKILL.md), the SDK applies the same tool permissions to all skills.

**Workaround**: Use Pre-Tool-Use hooks for fine-grained control:

```python
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher

async def skill_based_tool_validator(input_data, tool_use_id, context):
    """Restrict tools based on which skill is active"""
    tool_name = input_data["tool_name"]

    # Example: Block destructive tools for read-only skills
    if tool_name in ["Write", "Edit", "Bash"]:
        # Check context to determine if a read-only skill is active
        # (This would require tracking skill state in your application)
        if is_readonly_skill_active(context):
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "Write operations not allowed for read-only skills"
                }
            }

    return {}  # Allow the tool

options = ClaudeAgentOptions(
    setting_sources=["project"],
    allowed_tools=["Skill", "Read", "Write", "Bash", "Edit", "Grep", "Glob"],
    hooks={
        "PreToolUse": [
            HookMatcher(matcher=".*", hooks=[skill_based_tool_validator])
        ]
    }
)
```

### Verification and Debugging

#### Verify Skills Exist Before Running

```python
from pathlib import Path

def verify_skills(project_path: str = "."):
    """Check if skills are available in expected locations"""
    project_root = Path(project_path).resolve()

    # Check project skills
    project_skills_dir = project_root / ".claude" / "skills"
    if project_skills_dir.exists():
        project_skills = [d.name for d in project_skills_dir.iterdir() if d.is_dir()]
        print(f"✅ Found {len(project_skills)} project skills: {project_skills}")
    else:
        print(f"⚠️  No project skills directory found at {project_skills_dir}")

    # Check personal skills
    user_skills_dir = Path.home() / ".claude" / "skills"
    if user_skills_dir.exists():
        user_skills = [d.name for d in user_skills_dir.iterdir() if d.is_dir()]
        print(f"✅ Found {len(user_skills)} user skills: {user_skills}")
    else:
        print(f"⚠️  No user skills directory found at {user_skills_dir}")

# Run before initializing SDK
verify_skills("/path/to/project")
```

#### Debug Skill Activation

Add logging to see when Claude activates skills:

```python
async with ClaudeSDKClient(options=options) as client:
    await client.query("Use my custom skill")

    async for msg in client.receive_response():
        # Detect Skill tool usage
        if hasattr(msg, 'content'):
            for block in msg.content:
                if hasattr(block, 'type') and block.type == 'tool_use':
                    if hasattr(block, 'name') and block.name == 'Skill':
                        skill_info = block.input if hasattr(block, 'input') else {}
                        print(f"🎯 SKILL ACTIVATED: {skill_info}")

        print(msg)
```

#### Verify Configuration

```python
def check_sdk_config(options: ClaudeAgentOptions):
    """Validate SDK configuration for skills"""
    issues = []

    # Check settings sources
    setting_sources = getattr(options, 'setting_sources', None)
    if not setting_sources or len(setting_sources) == 0:
        issues.append("❌ setting_sources is empty or not set")

    # Check Skill tool
    if "Skill" not in (options.allowed_tools or []):
        issues.append("❌ 'Skill' not in allowed_tools")

    # Check working directory
    if setting_sources and not options.cwd:
        issues.append("⚠️  setting_sources configured but cwd not set")

    if issues:
        print("Configuration issues found:")
        for issue in issues:
            print(f"  {issue}")
        return False
    else:
        print("✅ Configuration looks good!")
        return True

# Validate before using
check_sdk_config(options)
```

### Common SDK Issues and Solutions

#### Issue 1: Skills Don't Load

**Symptoms**:
- Claude doesn't use your skills
- Skills exist in filesystem but never activate
- No errors, but skills are ignored

**Root Causes & Solutions**:

| Cause | Check | Solution |
|-------|-------|----------|
| Settings not enabled | `setting_sources` is empty or not set | Set to `["project"]` and/or `["user"]` |
| Skill tool not included | `"Skill"` not in `allowed_tools` | Add `"Skill"` to allowed_tools |
| Wrong cwd | `cwd` doesn't contain `.claude/` | Set `cwd` to correct project root |
| Invalid YAML | Syntax errors in SKILL.md | Validate YAML frontmatter (no tabs!) |
| Vague description | Skill description doesn't match usage | Add specific trigger keywords |

**Debugging checklist**:
```python
# ❌ Wrong - Default configuration
options = ClaudeAgentOptions()

# ✅ Correct - Explicit configuration
options = ClaudeAgentOptions(
    setting_sources=["project", "user"],  # ✓ Enable settings
    allowed_tools=["Skill", "Read"],      # ✓ Include Skill
    cwd="/absolute/path/to/project"       # ✓ Correct path
)
```

#### Issue 2: "Skill Tool Not Available" Error

**Symptoms**:
- Error message about Skill tool not found
- SDK says tool "Skill" is not available

**Solution**:
```python
# ❌ Wrong - Missing "Skill" in allowed_tools
options = ClaudeAgentOptions(
    setting_sources=["project"],
    allowed_tools=["Read", "Write", "Bash"]  # Missing "Skill"!
)

# ✅ Correct - Include "Skill"
options = ClaudeAgentOptions(
    setting_sources=["project"],
    allowed_tools=["Skill", "Read", "Write", "Bash"]  # Include Skill
)
```

#### Issue 3: Skills Not Loading From Expected Location

**Symptoms**:
- Skills exist but SDK can't find them
- Works in Claude Code CLI but not in SDK

**Debug**:
```python
import os
from pathlib import Path

# Print current working directory
print(f"Current CWD: {os.getcwd()}")

# Print resolved path
project_path = Path("/path/to/project").resolve()
skills_path = project_path / ".claude" / "skills"
print(f"Looking for skills at: {skills_path}")
print(f"Skills directory exists: {skills_path.exists()}")

# Use absolute path in options
options = ClaudeAgentOptions(
    setting_sources=["project"],
    cwd=str(project_path),  # Use absolute path
    allowed_tools=["Skill"]
)
```

#### Issue 4: Skill Activates But Fails

**Symptoms**:
- Skill is detected and activated
- But execution fails or produces errors

**Common Causes**:
1. **Missing tools**: Skill instructions reference tools not in `allowed_tools`
2. **File paths**: Skill uses absolute paths that don't exist in SDK context
3. **Dependencies**: Scripts require packages not installed
4. **Permissions**: Skill tries to access restricted resources

**Solutions**:
```python
# 1. Include all tools skill might need
options = ClaudeAgentOptions(
    allowed_tools=["Skill", "Read", "Write", "Edit", "Bash", "Grep", "Glob"],
    setting_sources=["project"]
)

# 2. Use relative paths in SKILL.md
# ❌ Bad: /Users/you/project/scripts/validate.py
# ✅ Good: scripts/validate.py

# 3. Document dependencies in SKILL.md
# ## Prerequisites
# - Python 3.10+
# - requests library
# - jq command-line tool
```

### Complete Working Example

Here's a complete, production-ready example demonstrating skills with the SDK:

```python
import anyio
import sys
from pathlib import Path
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions, AssistantMessage, TextBlock

async def main():
    # 1. Configuration
    project_root = Path(__file__).parent.resolve()
    print(f"Project root: {project_root}")

    # 2. Verify skills exist
    skills_dir = project_root / ".claude" / "skills"
    if not skills_dir.exists():
        print(f"❌ No skills directory found at {skills_dir}")
        print("Create .claude/skills/ and add your skills first!")
        sys.exit(1)

    project_skills = [d.name for d in skills_dir.iterdir() if d.is_dir()]
    if not project_skills:
        print(f"⚠️  Skills directory exists but contains no skills")
        sys.exit(1)

    print(f"✅ Found {len(project_skills)} project skill(s): {project_skills}")

    # 3. Configure SDK with skills enabled
    options = ClaudeAgentOptions(
        # Enable skills loading
        setting_sources=["project", "user"],

        # Include all tools skills might need
        allowed_tools=["Skill", "Read", "Write", "Edit", "Bash", "Grep", "Glob"],

        # Set working directory
        cwd=str(project_root),

        # Optional: Custom system prompt
        system_prompt="You are a helpful development assistant with access to custom skills.",

        # Optional: Limit conversation turns
        max_turns=10
    )

    print("\n✅ SDK initialized with skills enabled\n")

    # 4. Use the SDK with skills
    async with ClaudeSDKClient(options=options) as client:
        # Query that should trigger a skill
        query_text = "Create a new API endpoint for user management with authentication"
        print(f"Query: {query_text}\n")

        await client.query(query_text)

        print("📨 Receiving response...\n")
        print("=" * 80)

        skill_activations = []

        async for msg in client.receive_response():
            # Log skill activations
            if hasattr(msg, 'content'):
                for block in msg.content:
                    if hasattr(block, 'type') and block.type == 'tool_use':
                        if hasattr(block, 'name') and block.name == 'Skill':
                            skill_info = block.input if hasattr(block, 'input') else {}
                            skill_name = skill_info.get('skill_name', 'unknown')
                            skill_activations.append(skill_name)
                            print(f"\n🎯 SKILL ACTIVATED: {skill_name}\n")

            # Print assistant text messages
            if isinstance(msg, AssistantMessage):
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        print(block.text)

        print("=" * 80)

        # 5. Summary
        if skill_activations:
            print(f"\n✅ Skills used: {', '.join(set(skill_activations))}")
        else:
            print("\n⚠️  No skills were activated. Check:")
            print("  - Skill descriptions match the query")
            print("  - Skills are properly formatted")
            print("  - Configuration is correct")

if __name__ == "__main__":
    try:
        anyio.run(main)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
```

### Claude Messages API (For Reference)

If you're using the general Claude Messages API (not the Agent SDK), skill support is different:

#### Pre-built Document Skills

```python
import anthropic

client = anthropic.Anthropic(api_key="your-api-key")

# Claude Messages API supports pre-built document skills via beta headers
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=4096,
    messages=[
        {"role": "user", "content": "Create a financial dashboard in Excel"}
    ],
    betas=["code-execution-2025-08-25", "skills-2025-10-02", "files-api-2025-04-14"]
)

# Access generated file (if returned)
for block in response.content:
    if hasattr(block, 'file_id'):
        file_content = client.files.content(block.file_id)
        with open("dashboard.xlsx", "wb") as f:
            f.write(file_content)
```

**Available pre-built skills** (no custom upload needed):

| Skill ID | Description |
|----------|-------------|
| `xlsx` | Excel workbooks with formulas, charts, formatting |
| `pptx` | PowerPoint presentations |
| `pdf` | Formatted PDF documents |
| `docx` | Word documents |

#### Custom Skills via API

Custom Skills can be uploaded and managed via the `/v1/skills` endpoint:

```python
# Upload a custom skill
with open("my-skill.zip", "rb") as f:
    skill = client.skills.create(file=f)

# Use the skill in a message by specifying the skill_id in container config
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=4096,
    messages=[{"role": "user", "content": "Use my custom skill"}],
    container={"skill_ids": [skill.id]},
    betas=["code-execution-2025-08-25", "skills-2025-10-02", "files-api-2025-04-14"]
)
```

**Note**: Custom Skills uploaded via the API are workspace-wide and accessible to all workspace members.

### Claude Code CLI (For Reference)

In Claude Code CLI, skills are automatically discovered and loaded:

```bash
# Claude Code automatically discovers skills from:
# 1. ~/.claude/skills/ (personal)
# 2. .claude/skills/ (project)
# 3. Plugin-installed skills

# Simply use Claude Code naturally
claude

# Claude automatically:
# - Detects relevant skills based on your query
# - Loads SKILL.md when appropriate
# - Follows skill instructions
# - Respects per-skill allowed-tools from frontmatter
```

**No configuration required** - skills work automatically in Claude Code CLI.

### Team Distribution

#### Sharing Project Skills via Git

```bash
# Developer A: Create and commit skill
git add .claude/skills/api-generator/
git commit -m "Add API generation skill"
git push

# Developer B: Pull and use
git pull

# Skills are now available to Developer B
# Both developers must enable in their SDK code:
options = ClaudeAgentOptions(
    setting_sources=["project"],  # Loads from .claude/skills/
    allowed_tools=["Skill"]
)
```

#### Personal Skills (Not Shared)

```bash
# Create personal skill in your home directory
mkdir -p ~/.claude/skills/my-personal-workflow

# Create SKILL.md
cat > ~/.claude/skills/my-personal-workflow/SKILL.md << 'EOF'
---
name: my-personal-workflow
description: My personal development workflow skill
---

# My Personal Workflow
...
EOF

# Use in any project
options = ClaudeAgentOptions(
    setting_sources=["user"],  # Loads from ~/.claude/skills/
    allowed_tools=["Skill"]
)
```

### Summary: SDK vs. CLI vs. API

| Aspect | Agent SDK | Claude Code CLI | Messages API |
|--------|-----------|----------------|--------------|
| **Custom Skills** | ✅ Yes (filesystem-based) | ✅ Yes (automatic discovery) | ✅ Yes (via `/v1/skills` endpoint) |
| **Pre-built Skills** | ❌ No | ❌ No | ✅ Yes (pptx, xlsx, docx, pdf) |
| **Configuration** | `setting_sources` + `allowed_tools` | Automatic | Beta headers + skill_ids |
| **allowed-tools in SKILL.md** | ❌ Ignored | ✅ Respected | N/A |
| **Network Access** | Depends on host | Full access | ❌ No network |
| **Package Installation** | Depends on host | Local only | ❌ No runtime install |
| **Sharing Scope** | N/A (filesystem) | Personal or project | Workspace-wide |
| **Best For** | Programmatic integration | Interactive development | API-only integration |

---

## Testing and Iteration

### Development Process

#### 1. Build Evaluations First

Before extensive documentation, create three test scenarios:

**Scenario 1**: Simple case
```
Input: "Create a basic user endpoint"
Expected: Model, service, controller, routes, tests
```

**Scenario 2**: Moderate complexity
```
Input: "Create a product endpoint with category relationships"
Expected: Two models with relationship, services, controllers, tests
```

**Scenario 3**: Edge case
```
Input: "Create an endpoint with file uploads and authentication"
Expected: File handling, auth middleware, storage configuration
```

#### 2. Measure Baseline

Test without the skill:
```
Success rate: 40%
Common issues: Inconsistent patterns, missing tests, incorrect middleware
```

#### 3. Develop With Claude

**Claude A**: Helps design the skill
```
"Help me create a skill for generating API endpoints with our architecture"
```

**Claude B**: Tests the skill on real tasks
```
"Create a new product endpoint"
```

Observe Claude B's behavior and return findings to Claude A for refinement.

#### 4. Iterative Refinement

Continue the observe-refine-test cycle:

```
Iteration 1: Basic structure, 60% success rate
Iteration 2: Added validation, 75% success rate
Iteration 3: Added examples, 85% success rate
Iteration 4: Refined descriptions, 95% success rate
```

### Evaluation Metrics

Track these metrics across iterations:

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Success Rate** | >90% | Tasks completed correctly |
| **Activation Accuracy** | >95% | Skill activates when appropriate |
| **Token Efficiency** | Minimize | Tokens used per task |
| **Error Rate** | <5% | Tasks requiring manual fixes |
| **Team Satisfaction** | >4/5 | Developer feedback score |

### Testing Checklist

- [ ] Description is specific with key terms and usage triggers
- [ ] SKILL.md under 500 lines with progressive disclosure
- [ ] Examples are concrete, not abstract
- [ ] File references one level deep from SKILL.md
- [ ] Scripts handle errors explicitly
- [ ] No "magic numbers"—all constants justified
- [ ] Tested with Haiku, Sonnet, and Opus
- [ ] Tested on real usage scenarios
- [ ] Three evaluation scenarios created and passing
- [ ] Team feedback incorporated
- [ ] Documentation is clear and actionable

---

## Real-World Examples

### Example 1: Security Scanning Skill

```markdown
---
name: security-scanner
description: Run automated security scans using OWASP ZAP and Nuclei. Use when testing web applications for vulnerabilities, performing penetration tests, or security assessments.
allowed-tools: Read, Bash, Write
---

# Security Scanner Skill

## Purpose
Automate security scanning workflows using industry-standard tools (OWASP ZAP, Nuclei, SQLMap) following our security testing procedures.

## Prerequisites
Ensure these tools are installed:
- OWASP ZAP
- Nuclei
- SQLMap

## Workflow

1. **Reconnaissance**
   - Identify target application URL
   - Check if target is in approved scope
   - Verify target is not production (unless explicitly authorized)

2. **Configuration**
   - Load scan profiles from `config/`
   - Configure scan intensity (low, medium, high)
   - Set output directories

3. **Scan Execution**
   - Run `scripts/run_zap_scan.sh <target_url> <intensity>`
   - Run `scripts/run_nuclei_scan.sh <target_url>`
   - Wait for completion

4. **Report Generation**
   - Parse scan results
   - Generate executive summary
   - Create detailed technical report
   - Output in JSON and HTML formats

5. **Validation**
   - Verify all scans completed successfully
   - Check for critical/high severity findings
   - Flag any scan errors or timeouts

## Safety Checks
- NEVER scan production systems without explicit authorization
- ALWAYS verify target is in approved scope list
- IMMEDIATELY stop if unauthorized access is detected

## Output Format
```json
{
  "scan_id": "uuid",
  "target": "https://example.com",
  "timestamp": "2024-01-15T10:30:00Z",
  "findings": {
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 8
  },
  "details": [...]
}
```

## Examples
See `examples/` for sample scan reports and configurations.
```

**Supporting script** (`scripts/run_zap_scan.sh`):
```bash
#!/bin/bash
# Run OWASP ZAP scan with specified intensity

TARGET_URL=$1
INTENSITY=${2:-medium}  # Default to medium

# Validate inputs
if [ -z "$TARGET_URL" ]; then
    echo "Error: Target URL required"
    exit 1
fi

# Check if target is approved
if ! grep -q "$TARGET_URL" approved_targets.txt; then
    echo "Error: Target not in approved scope"
    exit 1
fi

# Run scan based on intensity
case $INTENSITY in
    low)
        zap-cli quick-scan -s xss,sqli "$TARGET_URL"
        ;;
    medium)
        zap-cli active-scan "$TARGET_URL"
        ;;
    high)
        zap-cli active-scan -r "$TARGET_URL"
        ;;
    *)
        echo "Error: Invalid intensity. Use low, medium, or high"
        exit 1
        ;;
esac

# Generate report
zap-cli report -o "reports/zap_${TARGET_URL//\//_}_$(date +%Y%m%d).html" -f html

echo "Scan complete. Report saved."
```

### Example 2: React Component Generator

```markdown
---
name: react-component-generator
description: Generate React components following our design system with TypeScript, Tailwind CSS, and accessibility best practices. Use when creating new UI components, pages, or layouts.
allowed-tools: Read, Write, Edit, Glob
---

# React Component Generator

## Purpose
Generate consistent React components following our team's design system, coding standards, and accessibility requirements.

## Tech Stack
- React 18+ with TypeScript
- Tailwind CSS for styling
- React Testing Library for tests
- Storybook for documentation

## Component Types

### 1. Basic Component
Simple presentational component with props interface.

### 2. Feature Component
Complex component with state, effects, and business logic.

### 3. Page Component
Full page layout with routing, data fetching, and SEO.

## File Structure
```
components/
└── {ComponentName}/
    ├── {ComponentName}.tsx
    ├── {ComponentName}.test.tsx
    ├── {ComponentName}.stories.tsx
    ├── index.ts
    └── types.ts (if needed)
```

## Code Template

```typescript
// ComponentName.tsx
import React from 'react';
import { ComponentNameProps } from './types';

export const ComponentName: React.FC<ComponentNameProps> = ({
  // Props with destructuring
  children,
  className = '',
  ...props
}) => {
  return (
    <div
      className={`component-base ${className}`}
      {...props}
    >
      {children}
    </div>
  );
};

ComponentName.displayName = 'ComponentName';
```

## Requirements Checklist
- [ ] TypeScript interface for all props
- [ ] Default props where appropriate
- [ ] Tailwind CSS classes (no inline styles)
- [ ] Accessibility attributes (aria-*, role)
- [ ] Unit tests with >80% coverage
- [ ] Storybook stories for all variants
- [ ] JSDoc comments for complex logic
- [ ] Proper error boundaries

## Accessibility Requirements
- All interactive elements must be keyboard accessible
- Color contrast ratio minimum 4.5:1
- Semantic HTML elements
- ARIA labels for screen readers
- Focus indicators visible

## Testing Pattern
```typescript
// ComponentName.test.tsx
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ComponentName } from './ComponentName';

describe('ComponentName', () => {
  it('renders without crashing', () => {
    render(<ComponentName />);
  });

  it('handles user interactions', async () => {
    const user = userEvent.setup();
    const onClick = jest.fn();
    render(<ComponentName onClick={onClick} />);

    await user.click(screen.getByRole('button'));
    expect(onClick).toHaveBeenCalled();
  });

  it('meets accessibility standards', () => {
    const { container } = render(<ComponentName />);
    // Add axe accessibility tests
  });
});
```

## Examples
See `examples/` directory for:
- Button component (basic)
- DataTable component (feature)
- Dashboard page (page)
```

### Example 3: Database Migration Skill

```markdown
---
name: database-migration-generator
description: Generate database migration files following our schema versioning strategy. Use when creating new tables, modifying schemas, or managing database changes.
allowed-tools: Read, Write, Bash
---

# Database Migration Generator

## Purpose
Create safe, reversible database migrations following our team's schema management practices.

## Migration Workflow

1. **Analyze Change**
   - Identify type: new table, alter table, data migration
   - Check for breaking changes
   - Plan rollback strategy

2. **Generate Migration**
   - Create timestamped migration file
   - Write `up()` migration
   - Write `down()` rollback
   - Add data preservation logic if needed

3. **Validation**
   - Run `scripts/validate_migration.py`
   - Check for common issues:
     - No down() implementation
     - Missing foreign key constraints
     - No indexes on frequently queried columns
     - Data loss risk

4. **Testing**
   - Apply migration to test database
   - Verify schema changes
   - Run application tests
   - Test rollback procedure

5. **Documentation**
   - Add migration notes
   - Document breaking changes
   - Update schema documentation

## Migration File Template

```python
# migrations/YYYYMMDD_HHMMSS_description.py
"""
Migration: Add user_preferences table
Author: Generated by Claude
Date: 2024-01-15
"""

def up():
    """Apply migration."""
    return """
    CREATE TABLE user_preferences (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        theme VARCHAR(20) DEFAULT 'light',
        notifications_enabled BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX idx_user_preferences_user_id ON user_preferences(user_id);
    """

def down():
    """Rollback migration."""
    return """
    DROP TABLE IF EXISTS user_preferences;
    """

# Migration metadata
migration_info = {
    "breaking": False,
    "data_migration": False,
    "dependencies": ["20240110_120000_create_users.py"]
}
```

## Safety Rules
- NEVER drop tables without backup
- ALWAYS implement down() migration
- ALWAYS add indexes for foreign keys
- TEST rollback before production deployment
- PRESERVE existing data during alterations

## Validation Script
Run before applying:
```bash
python scripts/validate_migration.py migrations/latest_migration.py
```

## Common Patterns

### Add Column (Non-Breaking)
```sql
ALTER TABLE users ADD COLUMN avatar_url VARCHAR(255) DEFAULT NULL;
```

### Modify Column (Breaking)
```sql
-- Step 1: Add new column
ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT false;

-- Step 2: Migrate data
UPDATE users SET email_verified = (verification_token IS NULL);

-- Step 3: In next migration, drop old column
ALTER TABLE users DROP COLUMN verification_token;
```

## Examples
See `examples/migrations/` for:
- New table creation
- Column addition/modification
- Data migrations
- Complex schema changes
```

---

## Troubleshooting and Common Pitfalls

### Problem: Claude Doesn't Use the Skill

**Symptoms**: Skill exists but Claude never activates it.

**Causes & Solutions**:

1. **Vague description**
   - ❌ "Helps with APIs"
   - ✅ "Generate RESTful API endpoints following our architecture. Use when creating new routes, controllers, or API modifications."

2. **Missing trigger terms**
   - Add specific terms users would mention: "API", "endpoint", "route", "controller"

3. **Wrong location**
   - Verify skill is in correct directory (`~/.claude/skills/` or `.claude/skills/`)
   - Check file permissions

4. **YAML syntax errors**
   - Validate frontmatter syntax
   - Ensure proper indentation
   - No tabs in YAML (use spaces)

### Problem: Skill Activates at Wrong Times

**Symptoms**: Skill triggers for unrelated tasks.

**Causes & Solutions**:

1. **Overly broad description**
   - Make description more specific
   - Add context about when NOT to use it

2. **Common trigger terms**
   - Avoid generic words like "code", "file", "help"
   - Use domain-specific terminology

3. **Conflicting skills**
   - Review all active skills for overlap
   - Use distinct trigger terminology

### Problem: Skill Has Errors During Execution

**Symptoms**: Skill activates but fails to complete tasks.

**Causes & Solutions**:

1. **Invalid file paths**
   - ❌ Windows-style: `\path\to\file`
   - ✅ Unix-style: `/path/to/file`

2. **Missing dependencies**
   - List required packages in SKILL.md
   - Verify availability in execution environment

3. **Script execution failures**
   - Add error handling to scripts
   - Validate inputs before processing
   - Provide clear error messages

4. **Tool restrictions too strict**
   - If `allowed-tools` is set, ensure necessary tools are included
   - Remove restriction if not needed for security

### Problem: Skill Uses Too Many Tokens

**Symptoms**: Slow responses, high costs, context overflow.

**Causes & Solutions**:

1. **SKILL.md too long**
   - Target: <500 lines
   - Move detailed content to reference files

2. **No progressive disclosure**
   - Link to additional files instead of embedding
   - Let Claude load only what's needed

3. **Redundant information**
   - Remove info Claude already knows
   - Focus on team-specific patterns only

4. **Too many examples**
   - Keep 2-3 representative examples in SKILL.md
   - Move extensive examples to examples.md

### Problem: Inconsistent Results

**Symptoms**: Same task produces different outputs each time.

**Causes & Solutions**:

1. **Insufficient specificity**
   - Provide concrete templates or patterns
   - Use executable scripts for consistency

2. **Missing constraints**
   - Add requirements checklist
   - Include validation steps

3. **Model variance**
   - Test across different models
   - Add more explicit instructions for simpler models

### Problem: Skill Doesn't Work for Team Members

**Symptoms**: Works for you but not others.

**Causes & Solutions**:

1. **Not committed to git**
   ```bash
   git add .claude/skills/
   git commit -m "Add skill"
   git push
   ```

2. **Environment-specific paths**
   - Use relative paths, not absolute
   - ❌ `/Users/you/project/scripts/`
   - ✅ `scripts/` (relative to project root)

3. **Missing dependencies**
   - Document all required tools
   - Provide installation instructions

---

## Advanced Topics

### 1. Multi-File Workflows with Progressive Disclosure

For complex skills, structure information hierarchically:

```markdown
---
name: full-stack-feature-generator
description: Generate complete full-stack features including backend API, database migrations, frontend UI, and tests. Use when building new features end-to-end.
---

# Full-Stack Feature Generator

## Overview
This skill generates complete features across the stack.

## Process
1. Understand requirements
2. See `architecture.md` for system architecture
3. See `backend.md` for backend generation
4. See `frontend.md` for frontend generation
5. See `testing.md` for test generation

## Workflow
1. Generate database migration
2. Generate backend API endpoint
3. Generate frontend components
4. Generate integration tests
5. Validate entire feature

For detailed steps, see the referenced documentation files.
```

Each referenced file loads only when Claude needs it.

### 2. Dynamic Skill Composition

Skills can reference each other for complex workflows:

```markdown
# E-Commerce Feature Generator

## Workflow
1. Use `database-migration-generator` skill to create tables
2. Use `api-endpoint-generator` skill for backend
3. Use `react-component-generator` skill for UI
4. Use `test-generator` skill for E2E tests

This skill orchestrates other skills but doesn't duplicate their instructions.
```

### 3. Environment-Aware Skills

Skills can adapt to different environments:

```markdown
---
name: deployment-manager
description: Manage deployments to staging and production environments. Use when deploying, rolling back, or managing infrastructure.
---

# Deployment Manager

## Workflow

1. **Detect Environment**
   - Check current git branch
   - Read `.env` file
   - Confirm with user before production deploys

2. **Environment-Specific Steps**

   **Staging**:
   - Run `scripts/deploy_staging.sh`
   - No approval required
   - Auto-rollback on failure

   **Production**:
   - Require explicit confirmation
   - Run pre-deployment checks
   - Create backup
   - Run `scripts/deploy_production.sh`
   - Monitor for 5 minutes
   - Rollback if errors detected

3. **Validation**
   - Run health checks
   - Verify key endpoints
   - Check error rates
   - Monitor logs
```

### 4. Skills with State Management

For multi-step workflows that need state tracking:

```markdown
# Security Audit Workflow

## State Tracking
Create a `audit_state.json` file to track progress:

```json
{
  "audit_id": "uuid",
  "started_at": "timestamp",
  "completed_steps": [],
  "findings": [],
  "current_phase": "reconnaissance"
}
```

## Workflow

1. Initialize audit state
2. Phase 1: Reconnaissance (update state)
3. Phase 2: Vulnerability scanning (update state)
4. Phase 3: Manual testing (update state)
5. Phase 4: Report generation (finalize state)

Each step updates the state file, allowing resumption if interrupted.
```

### 5. Skill Version Management

For skills that evolve over time:

```markdown
---
name: api-generator
description: Generate API endpoints (v2.0 - uses new auth system)
---

# API Generator v2.0

## Version History
- **v2.0** (2024-01): Updated for new JWT auth system
- **v1.1** (2023-11): Added GraphQL support
- **v1.0** (2023-09): Initial release

## Migration from v1.x
If you have endpoints generated with v1.x:
1. Run `scripts/migrate_auth_v1_to_v2.py`
2. Update JWT secret in `.env`
3. Regenerate authentication middleware

## Old Patterns (Deprecated)
- Session-based auth (v1.x)
- Manual token validation (v1.x)
```

### 6. Cross-Platform Skills

Skills that work across different platforms:

```markdown
---
name: cross-platform-build
description: Build and package applications for multiple platforms (Windows, macOS, Linux). Use when creating releases or distributing applications.
---

# Cross-Platform Build Manager

## Platform Detection
Automatically detect platform:
- macOS: Use `scripts/build_macos.sh`
- Linux: Use `scripts/build_linux.sh`
- Windows: Use `scripts/build_windows.bat`

## Cross-Compilation
To build for different platform:
```bash
# On macOS, build for Linux
./scripts/cross_compile.sh --target linux

# On Linux, build for Windows
./scripts/cross_compile.sh --target windows
```

## Output Structure
```
dist/
├── macos/
│   └── app.dmg
├── linux/
│   └── app.AppImage
└── windows/
    └── app.exe
```
```

### 7. MCP Tool References

If your Skill uses MCP (Model Context Protocol) tools, always use fully qualified tool names to avoid "tool not found" errors.

**Format**: `ServerName:tool_name`

**Example**:
```markdown
Use the BigQuery:bigquery_schema tool to retrieve table schemas.
Use the GitHub:create_issue tool to create issues.
```

Where:
- `BigQuery` and `GitHub` are MCP server names
- `bigquery_schema` and `create_issue` are the tool names within those servers

Without the server prefix, Claude may fail to locate the tool, especially when multiple MCP servers are available.

### 8. Skills with External API Integration

Skills that interact with external services:

```markdown
---
name: cloud-resource-manager
description: Manage AWS resources (EC2, S3, RDS) using infrastructure as code. Use when provisioning, modifying, or destroying cloud infrastructure.
allowed-tools: Read, Write, Bash
---

# Cloud Resource Manager

## Prerequisites
- AWS CLI configured
- Terraform installed
- Credentials in ~/.aws/credentials

## Workflow

1. **Validate Credentials**
   ```bash
   aws sts get-caller-identity
   ```

2. **Generate Terraform Config**
   - Create `main.tf` based on requirements
   - Define variables in `variables.tf`
   - Configure backend in `backend.tf`

3. **Plan Changes**
   ```bash
   terraform plan -out=tfplan
   ```

4. **Review Plan**
   - Show resource changes
   - Estimate costs
   - Get user confirmation

5. **Apply Changes**
   ```bash
   terraform apply tfplan
   ```

6. **Verify Resources**
   - Check AWS console
   - Test connectivity
   - Validate security groups

## Safety Checks
- NEVER destroy production resources without explicit confirmation
- ALWAYS create state backups before modifications
- IMMEDIATELY stop if unauthorized access detected

## Cost Estimation
Run before applying:
```bash
terraform plan | scripts/estimate_aws_cost.py
```
```

---

## Conclusion

Agent Skills represent a paradigm shift in how we extend Claude's capabilities. By following the principles of progressive disclosure, specificity, and validation, you can create powerful, reusable skills that amplify Claude's effectiveness while maintaining efficiency and reliability.

### Key Takeaways

1. **Start Small**: Begin with focused, single-purpose skills
2. **Iterate Based on Usage**: Refine based on real-world testing
3. **Prioritize Clarity**: Clear descriptions and examples over comprehensive documentation
4. **Leverage Progressive Disclosure**: Keep core instructions lean, provide detailed references separately
5. **Validate Rigorously**: Test across models and scenarios
6. **Share and Collaborate**: Project skills enable team-wide consistency

### Next Steps

1. Identify a repetitive task in your workflow
2. Create your first skill using the step-by-step guide
3. Test with real scenarios
4. Iterate based on results
5. Share with your team
6. Build a library of skills for common patterns

### Resources

**Official Documentation**:
- **Skills Overview**: https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview
- **Best Practices**: https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices
- **Quickstart Tutorial**: https://platform.claude.com/docs/en/agents-and-tools/agent-skills/quickstart
- **API Skills Guide**: https://platform.claude.com/docs/en/build-with-claude/skills-guide
- **SDK Skills**: https://platform.claude.com/docs/en/agent-sdk/skills
- **Claude Code Skills**: https://code.claude.com/docs/en/skills

**Code Resources**:
- **Skills Cookbook**: https://github.com/anthropics/claude-cookbooks/tree/main/skills
- **Skills Repository**: https://github.com/anthropics/skills

**Learning Resources**:
- **Engineering Blog**: https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills
- **Anthropic Academy**: https://www.anthropic.com/learn/build-with-claude

**Help Center** (for claude.ai users):
- [What are Skills?](https://support.claude.com/en/articles/12512176-what-are-skills)
- [Using Skills in Claude](https://support.claude.com/en/articles/12512180-using-skills-in-claude)
- [Creating custom Skills](https://support.claude.com/en/articles/12512198-creating-custom-skills)

---

*This guide is aligned with official Anthropic documentation as of October 2025. As the Skills platform evolves, refer to the official documentation for the latest updates.*
