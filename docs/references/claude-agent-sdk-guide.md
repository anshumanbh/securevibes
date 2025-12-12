# Claude Agent Python SDK - Comprehensive Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation & Prerequisites](#installation--prerequisites)
3. [Quick Start](#quick-start)
4. [Core Concepts](#core-concepts)
5. [Basic Usage - query()](#basic-usage---query)
6. [Advanced Usage - ClaudeSDKClient](#advanced-usage---claudesdkclient)
7. [Custom Tools & MCP Servers](#custom-tools--mcp-servers)
8. [Hooks](#hooks)
9. [Subagents](#subagents)
10. [Agent Skills](#agent-skills)
11. [Slash Commands](#slash-commands)
12. [Permissions & Security](#permissions--security)
13. [Sessions & Context Management](#sessions--context-management)
14. [Structured Outputs](#structured-outputs-v017)
15. [Plugins](#plugins-v015)
16. [Sandbox Configuration](#sandbox-configuration)
17. [File Checkpointing](#file-checkpointing-v0115)
18. [Cost Tracking](#cost-tracking)
19. [Error Handling](#error-handling)
20. [Migration Guide](#migration-guide)
21. [Best Practices](#best-practices)

## Introduction

The Claude Agent Python SDK is a powerful toolkit for building AI agents with Claude. It provides a programmatic interface to Claude Code capabilities, enabling developers to create sophisticated AI assistants for various domains including software development, business automation, and content creation.

### Key Features
- **Automatic Context Management**: Intelligent compaction and context handling
- **Rich Tool Ecosystem**: Built-in tools for file operations, code execution, web search
- **Fine-grained Permissions**: Granular control over tool usage and access
- **Streaming & Single Mode**: Flexible interaction patterns
- **Custom Tools**: Extend capabilities with custom MCP servers
- **Hooks**: Automated feedback and deterministic processing
- **Subagents**: Specialized agents with isolated contexts
- **Cost Tracking**: Built-in usage monitoring

### When to Use
- Building coding assistants (SRE diagnostics, security review bots)
- Creating business agents (legal assistants, customer support)
- Developing content creation tools
- Automating complex workflows
- Integrating Claude into existing applications

## Installation & Prerequisites

### Requirements
- Python 3.10 or higher

### Installation

```bash
pip install claude-agent-sdk
```

> **Note (v0.1.8+)**: The Claude Code CLI is now **automatically bundled** with the package - no separate installation required! The SDK will use the bundled CLI by default.

**Optional**: If you prefer to use a system-wide installation or a specific version:

```bash
# Install Claude Code separately (optional)
curl -fsSL https://claude.ai/install.sh | bash

# Or specify a custom path in your code
options = ClaudeAgentOptions(cli_path="/path/to/claude")

# Local CLI builds are also supported from ~/.claude/local/claude
```

### Authentication Options
The SDK supports three authentication methods:
1. **Claude API Key** (standard)
2. **Amazon Bedrock** (AWS integration)
3. **Google Vertex AI** (GCP integration)

Set your API key:
```bash
export CLAUDE_API_KEY="your-api-key-here"

# Optional: Skip version check if needed
export CLAUDE_AGENT_SDK_SKIP_VERSION_CHECK=1
```

## Quick Start

Here's the simplest way to get started:

```python
import anyio
from claude_agent_sdk import query

async def main():
    async for message in query(prompt="What is 2 + 2?"):
        print(message)

anyio.run(main)
```

### Extracting Text from Responses

```python
from claude_agent_sdk import query, AssistantMessage, TextBlock

async def main():
    async for message in query(prompt="Explain Python decorators"):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    print(block.text)

anyio.run(main)
```

## Core Concepts

### Choosing Between `query()` and `ClaudeSDKClient`

The SDK provides two ways to interact with Claude Code:

| Feature | `query()` | `ClaudeSDKClient` |
|---------|-----------|-------------------|
| **Session** | Creates new session each time | Reuses same session |
| **Conversation** | Single exchange | Multiple exchanges in same context |
| **Connection** | Managed automatically | Manual control |
| **Streaming Input** | Supported | Supported |
| **Interrupts** | Not supported | Supported |
| **Hooks** | Not supported | Supported |
| **Custom Tools** | Not supported | Supported |
| **Continue Chat** | New session each time | Maintains conversation |
| **Use Case** | One-off tasks | Continuous conversations |

**When to Use `query()`**:
- One-off questions where you don't need conversation history
- Independent tasks that don't require context from previous exchanges
- Simple automation scripts
- When you want a fresh start each time

**When to Use `ClaudeSDKClient`**:
- Continuing conversations - when you need Claude to remember context
- Follow-up questions - building on previous responses
- Interactive applications - chat interfaces, REPLs
- Response-driven logic - when next action depends on Claude's response
- Session control - managing conversation lifecycle explicitly
- Custom tools and hooks - requires ClaudeSDKClient

### Message Types
The SDK uses strongly-typed messages for all interactions:
- **UserMessage**: Input from the user
- **AssistantMessage**: Claude's responses
- **SystemMessage**: System-level instructions
- **ResultMessage**: Final result with usage data

### Content Blocks
Messages contain different types of content:
- **TextBlock**: Plain text content
- **ThinkingBlock**: Thinking content (for models with thinking capability)
- **ToolUseBlock**: Tool invocation requests
- **ToolResultBlock**: Tool execution results

> **Important**: When iterating over messages, avoid using `break` to exit early as this can cause asyncio cleanup issues. Instead, let the iteration complete naturally or use flags to track when you've found what you need.

## Basic Usage - query()

The `query()` function is the simplest interface for interacting with Claude Code.

### Basic Query with Options

```python
from claude_agent_sdk import query, ClaudeAgentOptions

async def main():
    options = ClaudeAgentOptions(
        system_prompt="You are a Python expert",
        max_turns=3,
        cwd="/path/to/project"
    )

    async for message in query(
        prompt="Review my Python code for best practices",
        options=options
    ):
        print(message)
```

### Using Tools

```python
from claude_agent_sdk import query, ClaudeAgentOptions

async def main():
    options = ClaudeAgentOptions(
        allowed_tools=["Read", "Write", "Bash"],
        permission_mode='acceptEdits'  # Auto-accept file edits
    )

    async for message in query(
        prompt="Create a Python script that sorts a list",
        options=options
    ):
        # Process tool use and results
        pass
```

### Controlling Base Tool Availability (v0.1.12+)

The `tools` option controls which tools are available at the base level:

```python
# Specific tools only
options = ClaudeAgentOptions(
    tools=["Read", "Edit", "Bash"]  # Only these tools available
)

# Disable all built-in tools
options = ClaudeAgentOptions(
    tools=[]  # No built-in tools (use with custom MCP tools)
)

# Use Claude Code's default toolset
options = ClaudeAgentOptions(
    tools={"type": "preset", "preset": "claude_code"}
)
```

### API Beta Features (v0.1.12+)

Enable Anthropic API beta features:

```python
options = ClaudeAgentOptions(
    betas=["context-1m-2025-08-07"]  # Extended context window
)
```

### Working with Different Directories

```python
from pathlib import Path
from claude_agent_sdk import query, ClaudeAgentOptions

async def main():
    # Using string path
    options = ClaudeAgentOptions(cwd="/home/user/project")

    # Or using Path object
    options = ClaudeAgentOptions(cwd=Path.home() / "project")

    async for message in query(prompt="List all Python files", options=options):
        print(message)
```

### Custom CLI Path

For organizations with non-standard Claude Code installations:

```python
from claude_agent_sdk import query, ClaudeAgentOptions

async def main():
    # Specify custom CLI path
    options = ClaudeAgentOptions(
        cli_path="/custom/path/to/claude",  # Custom installation location
        cwd="/path/to/project"
    )

    async for message in query(prompt="Analyze the codebase", options=options):
        print(message)
```

## Advanced Usage - ClaudeSDKClient

`ClaudeSDKClient` provides bidirectional, interactive conversations with advanced features.

### Basic Client Usage

```python
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions

async def interactive_session():
    options = ClaudeAgentOptions(
        system_prompt="You are a helpful coding assistant",
        allowed_tools=["Read", "Write", "Bash"]
    )

    async with ClaudeSDKClient(options=options) as client:
        # Send initial query
        await client.query("Analyze the authentication module")

        # Receive responses
        async for msg in client.receive_response():
            print(msg)

        # Continue conversation
        await client.query("Now optimize the login function")

        async for msg in client.receive_response():
            print(msg)
```

### Handling Partial Messages

```python
async with ClaudeSDKClient(options=options) as client:
    await client.query("Generate a complex report")

    async for msg in client.receive_response(include_partial=True):
        if msg.partial:
            print("Partial:", msg)
        else:
            print("Complete:", msg)
```

## Custom Tools & MCP Servers

### Creating Simple Custom Tools

```python
from claude_agent_sdk import tool, create_sdk_mcp_server, ClaudeAgentOptions, ClaudeSDKClient

# Define a tool using the @tool decorator
@tool("greet", "Greet a user by name", {"name": str})
async def greet_user(args):
    return {
        "content": [
            {"type": "text", "text": f"Hello, {args['name']}! Welcome!"}
        ]
    }

@tool("calculate", "Perform basic math", {"expression": str})
async def calculate(args):
    try:
        result = eval(args['expression'])
        return {
            "content": [
                {"type": "text", "text": f"Result: {result}"}
            ]
        }
    except Exception as e:
        return {
            "content": [
                {"type": "text", "text": f"Error: {str(e)}"}
            ]
        }

# Create an SDK MCP server
server = create_sdk_mcp_server(
    name="my-tools",
    version="1.0.0",
    tools=[greet_user, calculate]
)

# Use with Claude
async def main():
    options = ClaudeAgentOptions(
        mcp_servers={"tools": server},
        allowed_tools=["mcp__tools__greet", "mcp__tools__calculate"]
    )

    async with ClaudeSDKClient(options=options) as client:
        await client.query("Greet Alice and then calculate 15 * 23")

        async for msg in client.receive_response():
            print(msg)
```

### Advanced Calculator Example

```python
from typing import Dict, Any
from claude_agent_sdk import tool, create_sdk_mcp_server

class Calculator:
    """Advanced calculator with memory"""

    def __init__(self):
        self.memory = 0

    async def add(self, args: Dict[str, Any]):
        a, b = args['a'], args['b']
        result = a + b
        return self._format_result(f"{a} + {b} = {result}")

    async def subtract(self, args: Dict[str, Any]):
        a, b = args['a'], args['b']
        result = a - b
        return self._format_result(f"{a} - {b} = {result}")

    async def memory_store(self, args: Dict[str, Any]):
        self.memory = args['value']
        return self._format_result(f"Stored {self.memory} in memory")

    async def memory_recall(self, args: Dict[str, Any]):
        return self._format_result(f"Memory value: {self.memory}")

    def _format_result(self, text: str):
        return {"content": [{"type": "text", "text": text}]}

# Create calculator instance
calc = Calculator()

# Create MCP server with calculator tools
calculator_server = create_sdk_mcp_server(
    name="calculator",
    version="2.0.0",
    tools=[
        tool("add", "Add two numbers", {"a": float, "b": float})(calc.add),
        tool("subtract", "Subtract numbers", {"a": float, "b": float})(calc.subtract),
        tool("memory_store", "Store value in memory", {"value": float})(calc.memory_store),
        tool("memory_recall", "Recall memory value", {})(calc.memory_recall),
    ]
)
```

### Base64 Image Support (SDK 0.1.3+)

Custom tools can now return base64-encoded images following the MCP standard:

```python
import base64
from claude_agent_sdk import tool, create_sdk_mcp_server

@tool("generate_chart", "Generate a data visualization chart", {"data": str, "chart_type": str})
async def generate_chart(args):
    """Generate a chart and return it as a base64-encoded image"""
    # Your chart generation logic here
    # For example, using matplotlib, plotly, etc.
    chart_bytes = create_chart_image(args['data'], args['chart_type'])

    # Encode to base64
    encoded_image = base64.b64encode(chart_bytes).decode("utf-8")

    return {
        "content": [
            {"type": "text", "text": f"Here's your {args['chart_type']} chart:"},
            {
                "type": "image",
                "mimeType": "image/png",  # or "image/jpeg", "image/webp"
                "data": encoded_image
            }
        ]
    }

# Create server with image-capable tool
chart_server = create_sdk_mcp_server(
    name="charts",
    version="1.0.0",
    tools=[generate_chart]
)

options = ClaudeAgentOptions(
    mcp_servers={"charts": chart_server},
    allowed_tools=["mcp__charts__generate_chart"]
)
```

### Mixed Server Support

You can combine SDK servers (in-process) with external MCP servers:

```python
options = ClaudeAgentOptions(
    mcp_servers={
        "internal": sdk_server,      # In-process SDK server
        "external": {                # External subprocess server
            "type": "stdio",
            "command": "python",
            "args": ["-m", "external_mcp_server"]
        },
        "remote": {                  # Remote HTTP server
            "type": "http",
            "url": "https://api.example.com/mcp",
            "headers": {"Authorization": "Bearer token"}
        }
    }
)
```

## Hooks

Hooks provide deterministic processing at specific points in the Claude agent loop.

> **Note**: Hooks require `ClaudeSDKClient` - they are not supported with the `query()` function.

### Supported Hook Events

| Hook Event | Description |
|------------|-------------|
| `PreToolUse` | Called before tool execution |
| `PostToolUse` | Called after tool execution |
| `UserPromptSubmit` | Called when user submits a prompt |
| `Stop` | Called when stopping execution |
| `SubagentStop` | Called when a subagent stops |
| `PreCompact` | Called before message compaction |

> **Python SDK Limitation**: Due to setup limitations, the Python SDK does **not** support `SessionStart`, `SessionEnd`, and `Notification` hooks.

### Strongly-Typed Hook Inputs (SDK 0.1.3+)

The SDK provides typed input structures for better IDE autocomplete and type safety:
- `PreToolUseHookInput` - Input data for pre-tool-use hooks
- `PostToolUseHookInput` - Input data for post-tool-use hooks
- `UserPromptSubmitHookInput` - Input data for user prompt submission hooks

### Hook Output Fields

Hook outputs can include:
- `permissionDecision`: "approve" or "deny" (for PreToolUse hooks)
- `permissionDecisionReason`: Explanation for the decision
- `reason`: Additional reasoning information
- `continue_`: Whether to continue processing (Python-safe name for `continue`)
- `suppressOutput`: Whether to suppress output display
- `stopReason`: Reason for stopping execution
- `AsyncHookJSONOutput`: For deferred hook execution

### Pre-Tool-Use Hook Example

```python
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, HookMatcher

async def security_check_hook(input_data, tool_use_id, context):
    """Prevent dangerous bash commands"""
    tool_name = input_data["tool_name"]

    if tool_name != "Bash":
        return {}

    command = input_data["tool_input"].get("command", "")

    # Block dangerous commands
    dangerous_patterns = ["rm -rf", "dd if=", "mkfs", "format"]

    for pattern in dangerous_patterns:
        if pattern in command:
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",  # Can also be "approve"
                    "permissionDecisionReason": f"Dangerous command pattern detected: {pattern}",
                    "reason": "Security policy violation"
                }
            }

    return {}  # Allow the command

async def file_backup_hook(input_data, tool_use_id, context):
    """Backup files before editing"""
    tool_name = input_data["tool_name"]

    if tool_name in ["Write", "Edit"]:
        file_path = input_data["tool_input"].get("file_path")
        # Here you could implement backup logic
        print(f"Backing up {file_path} before modification")

    return {}

# Use hooks in options
options = ClaudeAgentOptions(
    allowed_tools=["Bash", "Write", "Edit", "Read"],
    hooks={
        "PreToolUse": [
            HookMatcher(matcher="Bash", hooks=[security_check_hook]),
            HookMatcher(matcher="Write|Edit", hooks=[file_backup_hook])
        ]
    }
)
```

### Post-Tool-Use Hook

```python
async def log_tool_results(result_data, tool_use_id, context):
    """Log all tool execution results"""
    tool_name = result_data.get("tool_name")
    success = result_data.get("success", False)

    print(f"Tool {tool_name} executed: {'Success' if success else 'Failed'}")

    # You could send to logging service, metrics, etc.
    return {}

options = ClaudeAgentOptions(
    hooks={
        "PostToolUse": [
            HookMatcher(matcher=".*", hooks=[log_tool_results])
        ]
    }
)
```

## Subagents

Subagents are specialized AI agents with distinct characteristics and isolated contexts.

### Programmatic Subagents

```python
from claude_agent_sdk import query, ClaudeAgentOptions

# Define specialized subagents
async def main():
    options = ClaudeAgentOptions(
        agents={
            'code-reviewer': {
                'description': 'Expert code review specialist',
                'prompt': '''You are a senior software engineer specializing in code reviews.
                           Focus on: security, performance, maintainability, best practices.
                           Be thorough but constructive in your feedback.''',
                'tools': ['Read', 'Grep', 'Glob']
            },
            'test-writer': {
                'description': 'Test automation expert',
                'prompt': '''You are a test automation specialist.
                           Write comprehensive unit tests and integration tests.
                           Ensure high code coverage and edge case handling.''',
                'tools': ['Read', 'Write', 'Bash']
            },
            'documenter': {
                'description': 'Technical documentation specialist',
                'prompt': '''You are a technical writer specializing in developer documentation.
                           Create clear, comprehensive documentation with examples.''',
                'tools': ['Read', 'Write']
            }
        },
        allowed_tools=["Read", "Write", "Grep", "Glob", "Bash"]
    )

    # Subagents will be automatically invoked based on the task
    async for message in query(
        prompt="Review the authentication module, write tests for it, and update the documentation",
        options=options
    ):
        print(message)
```

### Parallel Subagent Execution

```python
async def parallel_analysis():
    options = ClaudeAgentOptions(
        agents={
            'security-auditor': {
                'description': 'Security vulnerability scanner',
                'prompt': 'Identify security vulnerabilities and risks',
                'tools': ['Read', 'Grep']
            },
            'performance-analyzer': {
                'description': 'Performance optimization expert',
                'prompt': 'Identify performance bottlenecks and optimization opportunities',
                'tools': ['Read', 'Grep', 'Bash']
            }
        }
    )

    # Request parallel execution
    async for message in query(
        prompt="Run security audit and performance analysis in parallel on the API module",
        options=options
    ):
        print(message)
```

### Filesystem-Based Subagents

Create subagents as markdown files in `.claude/agents/`:

```markdown
---
name: database-expert
description: Database optimization and query specialist
tools:
  - Read
  - Bash
---

You are a database expert specializing in:
- SQL query optimization
- Database schema design
- Performance tuning
- Index optimization

Always consider:
- Query execution plans
- Index usage
- Data normalization
- Transaction isolation levels
```

## Agent Skills

### What Are Agent Skills?

Agent Skills extend Claude with specialized capabilities through filesystem-based instructions. Unlike custom tools (which are programmatic functions) or subagents (which are specialized agent personalities), Skills are:

- **Model-Invoked**: Claude autonomously decides when to use them based on context
- **Progressive**: Load content on-demand using a three-tier disclosure pattern
- **Composable**: Multiple skills work together automatically
- **Portable**: Work across Claude Code CLI, Messages API, and the Agent SDK

Skills are particularly useful for:
- Domain-specific workflows (security scanning, API generation, documentation)
- Organization-specific patterns and guidelines
- Complex multi-step processes with validation
- Tasks requiring consistent, repeatable patterns

### Enabling Skills in the SDK

**CRITICAL**: The SDK does **NOT** load filesystem settings by default. You must explicitly enable them.

```python
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions

async def use_skills():
    options = ClaudeAgentOptions(
        # REQUIRED: Enable filesystem settings
        setting_sources=["project", "user"],  # Load from both .claude/skills/ and ~/.claude/skills/

        # REQUIRED: Include Skill tool
        allowed_tools=["Skill", "Read", "Write", "Bash"],

        # REQUIRED: Set working directory containing .claude/
        cwd="/path/to/your/project"
    )

    async with ClaudeSDKClient(options=options) as client:
        await client.query("Use my custom API generation skill")

        async for msg in client.receive_response():
            print(msg)
```

### Skill Locations

Skills are discovered from multiple filesystem locations:

```python
# Project skills (shared with team via git)
# Location: {cwd}/.claude/skills/
options = ClaudeAgentOptions(
    setting_sources=["project"],
    cwd="/path/to/project"
)

# Personal skills (user-specific, cross-project)
# Location: ~/.claude/skills/
options = ClaudeAgentOptions(
    setting_sources=["user"]
)

# Both project and personal skills
options = ClaudeAgentOptions(
    setting_sources=["project", "user"],
    cwd="/path/to/project"
)
```

### Creating a Basic Skill

Skills are defined using `SKILL.md` files with YAML frontmatter:

```bash
# Create project skill
mkdir -p .claude/skills/api-generator

# Create SKILL.md
cat > .claude/skills/api-generator/SKILL.md << 'EOF'
---
name: api-generator
description: Generate RESTful API endpoints following our team's architecture patterns. Use when creating new API routes, controllers, or modifying backend structure.
---

# API Endpoint Generator

## Purpose
This skill generates consistent RESTful API endpoints following our layered architecture.

## Architecture Pattern
We use:
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

## Example
Input: "Create a product endpoint"

Output structure:
- `models/product.py`
- `services/product_service.py`
- `controllers/product_controller.py`
- `routes/product_routes.py`
- `tests/test_product.py`
EOF
```

**Key Points**:
- `name`: Lowercase, hyphens only, descriptive (not vague like "helper")
- `description`: What it does + when to use it + trigger keywords
- Content: Clear instructions, examples, and workflow steps

### SDK-Specific Limitations

#### 1. allowed-tools Frontmatter Ignored

The `allowed-tools` field in SKILL.md frontmatter **only works in Claude Code CLI**, not in the SDK:

```yaml
---
name: my-skill
description: My skill
allowed-tools: Read, Grep, Glob  # ⚠️ IGNORED by Agent SDK
---
```

**In the SDK**, control tool access through the main `allowed_tools` option:

```python
# This controls ALL skills in the SDK
options = ClaudeAgentOptions(
    allowed_tools=["Skill", "Read", "Grep", "Glob"],
    setting_sources=["project"]
)
```

#### 2. No Per-Skill Tool Restrictions

The SDK applies the same tool permissions to all skills. For fine-grained control, use hooks:

```python
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher

async def skill_tool_validator(input_data, tool_use_id, context):
    """Restrict tools based on context"""
    tool_name = input_data["tool_name"]

    # Implement custom logic
    if should_block_tool(tool_name):
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "Tool not allowed in this context"
            }
        }
    return {}

options = ClaudeAgentOptions(
    setting_sources=["project"],
    allowed_tools=["Skill", "Read", "Write", "Bash"],
    hooks={
        "PreToolUse": [
            HookMatcher(matcher=".*", hooks=[skill_tool_validator])
        ]
    }
)
```

### Common Issues and Solutions

#### Skills Don't Load

**Problem**: Claude doesn't use your skills

**Checklist**:
```python
# ❌ Wrong - Default settings don't load skills
options = ClaudeAgentOptions()

# ✅ Correct - Explicitly enable settings
options = ClaudeAgentOptions(
    setting_sources=["project", "user"],  # Enable project and/or user skills
    allowed_tools=["Skill"],               # Don't forget Skill tool
    cwd="/path/to/project"                 # Directory with .claude/
)
```

**Verification**:
```python
from pathlib import Path

# Check if skills exist
skills_dir = Path(".claude/skills")
if skills_dir.exists():
    skills = list(skills_dir.iterdir())
    print(f"Found {len(skills)} skills: {[s.name for s in skills]}")
else:
    print("⚠️  No .claude/skills/ directory found")
```

#### Skill Tool Not Available

**Problem**: Error about Skill tool not found

**Solution**:
```python
# ❌ Wrong - "Skill" not in allowed_tools
options = ClaudeAgentOptions(
    setting_sources=["project"],
    allowed_tools=["Read", "Write"]  # Missing "Skill"
)

# ✅ Correct - Include "Skill"
options = ClaudeAgentOptions(
    setting_sources=["project"],
    allowed_tools=["Skill", "Read", "Write"]
)
```

#### Skills in Wrong Location

**Problem**: Skills not loading from expected location

**Debug**:
```python
import os

# Verify working directory
print(f"CWD: {os.getcwd()}")

# Use absolute path
options = ClaudeAgentOptions(
    setting_sources=["project"],
    cwd="/absolute/path/to/project",  # Explicit path
    allowed_tools=["Skill"]
)
```

### Complete Working Example

```python
import anyio
from pathlib import Path
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions

async def main():
    # 1. Verify skills directory exists
    project_root = Path("/path/to/project")
    skills_dir = project_root / ".claude" / "skills"

    if not skills_dir.exists():
        print("⚠️  No skills directory found. Create one first!")
        return

    # 2. List available skills
    skills = list(skills_dir.iterdir())
    print(f"Available skills: {[s.name for s in skills]}")

    # 3. Configure SDK with skills enabled
    options = ClaudeAgentOptions(
        setting_sources=["project", "user"],
        allowed_tools=["Skill", "Read", "Write", "Edit", "Bash", "Grep", "Glob"],
        cwd=str(project_root),
        system_prompt="You are a helpful assistant with custom skills."
    )

    # 4. Use skills
    async with ClaudeSDKClient(options=options) as client:
        await client.query("Create a new API endpoint for user management")

        async for msg in client.receive_response():
            # Log skill activations
            if hasattr(msg, 'content'):
                for block in msg.content:
                    if hasattr(block, 'type') and block.type == 'tool_use':
                        if hasattr(block, 'name') and block.name == 'Skill':
                            print(f"🎯 Skill activated: {block.input}")
            print(msg)

if __name__ == "__main__":
    anyio.run(main)
```

### Best Practices

1. **Always enable settings explicitly** - Don't rely on defaults
2. **Include "Skill" in allowed_tools** - Required for activation
3. **Use specific descriptions** - Include trigger keywords users would say
4. **Keep SKILL.md under 500 lines** - Use progressive disclosure with separate files
5. **Test across models** - Verify skills work with Haiku, Sonnet, and Opus
6. **Version control project skills** - Share with team via git
7. **Document prerequisites** - List required tools and dependencies

### Team Distribution

```bash
# Developer A: Create and commit skill
git add .claude/skills/api-generator/
git commit -m "Add API generation skill"
git push

# Developer B: Pull and use
git pull

# Both developers use in SDK
options = ClaudeAgentOptions(
    setting_sources=["project"],  # Loads from .claude/skills/
    allowed_tools=["Skill"]
)
```

### Differences from Subagents and Custom Tools

| Feature | Skills | Subagents | Custom Tools |
|---------|--------|-----------|--------------|
| **Definition** | Filesystem (.claude/skills/) | Filesystem or programmatic | Programmatic only |
| **Invocation** | Claude decides based on context | Claude decides based on task | Claude calls as function |
| **Content** | Instructions + resources | Agent personality + prompt | Executable code |
| **Loading** | Progressive (on-demand) | Full context | Runtime registration |
| **Sharing** | Via git (filesystem) | Via git or config | Via code import |
| **SDK Config** | `setting_sources=["project"]` | `agents={}` dict | `mcp_servers={}` dict |

### Further Reading

For comprehensive skill development guidance including:
- Progressive disclosure architecture
- Best practices for skill design
- Real-world examples (security scanner, React generator, DB migrations)
- Advanced patterns (composition, state management, versioning)
- Detailed troubleshooting

See the [Comprehensive Agent Skills Guide](../AGENT_SKILLS_GUIDE.md).

## Slash Commands

Slash commands provide quick access to common operations and custom workflows.

### Built-in Commands

```python
# Clear conversation history
async for message in query(prompt="/clear"):
    print(message)

# Compact conversation to save tokens
async for message in query(prompt="/compact"):
    print(message)
```

### Custom Slash Commands

Create custom commands in `.claude/commands/`:

**File: `.claude/commands/review.md`**
```markdown
---
description: Perform comprehensive code review
arguments:
  - name: path
    description: Path to review
    required: true
---

Perform a comprehensive code review of {path} including:
- Code quality and style
- Security vulnerabilities
- Performance issues
- Best practice violations
- Test coverage

Provide specific, actionable feedback with code examples.
```

**File: `.claude/commands/refactor.md`**
```markdown
---
description: Refactor code with specific patterns
arguments:
  - name: file
    description: File to refactor
    required: true
  - name: pattern
    description: Refactoring pattern to apply
    required: false
    default: "clean-code"
---

Refactor {file} using {pattern} principles:
- Extract methods for clarity
- Improve variable naming
- Reduce complexity
- Apply SOLID principles
- Add appropriate comments

```bash
# Optional: Run tests after refactoring
cd $(dirname {file}) && python -m pytest
```
```

### Using Slash Commands

```python
# Use custom review command
async for message in query(prompt="/review src/auth"):
    print(message)

# Use with arguments
async for message in query(prompt="/refactor src/api/handler.py clean-architecture"):
    print(message)
```

## Permissions & Security

### Permission Modes

```python
from claude_agent_sdk import ClaudeAgentOptions

# Default mode - standard permission checks
options = ClaudeAgentOptions(permission_mode='default')

# Auto-accept file edits
options = ClaudeAgentOptions(permission_mode='acceptEdits')

# Bypass all permissions (use with caution!)
options = ClaudeAgentOptions(permission_mode='bypassPermissions')
```

### Dynamic Permission Control

```python
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions

class PermissionManager:
    def __init__(self):
        self.allowed_paths = ["/project/src", "/project/tests"]
        self.blocked_commands = ["rm -rf", "format", "dd"]

    async def can_use_tool(self, tool_name, tool_input):
        """Dynamic permission callback"""

        if tool_name == "Write":
            file_path = tool_input.get("file_path", "")
            # Check if file path is in allowed directories
            if not any(file_path.startswith(path) for path in self.allowed_paths):
                return False, "File path not in allowed directories"

        elif tool_name == "Bash":
            command = tool_input.get("command", "")
            # Check for blocked commands
            for blocked in self.blocked_commands:
                if blocked in command:
                    return False, f"Command contains blocked pattern: {blocked}"

        return True, None

# Use with client
manager = PermissionManager()

options = ClaudeAgentOptions(
    allowed_tools=["Read", "Write", "Bash"],
    can_use_tool=manager.can_use_tool
)

async with ClaudeSDKClient(options=options) as client:
    await client.query("Delete all temporary files")
    # Permission checks will be applied
```

### Layered Security

```python
options = ClaudeAgentOptions(
    # Layer 1: Specify allowed tools
    allowed_tools=["Read", "Write", "Bash"],

    # Layer 2: Set permission mode
    permission_mode='acceptEdits',

    # Layer 3: Add hooks for fine-grained control
    hooks={
        "PreToolUse": [
            HookMatcher(matcher="Bash", hooks=[security_check])
        ]
    },

    # Layer 4: Dynamic permission callback
    can_use_tool=custom_permission_check
)
```

## Sessions & Context Management

### Basic Session Management

```python
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions

async def session_example():
    options = ClaudeAgentOptions(
        system_prompt="You are a helpful assistant",
        max_turns=5  # Limit conversation length
    )

    async with ClaudeSDKClient(options=options) as client:
        # Session starts
        await client.query("Start a new project")

        async for msg in client.receive_response():
            print(msg)

        # Continue in same session
        await client.query("Add authentication")

        async for msg in client.receive_response():
            print(msg)
    # Session ends, context cleared
```

### Context Compaction

```python
async def long_conversation():
    options = ClaudeAgentOptions(
        max_tokens=100000  # Set token limit
    )

    async with ClaudeSDKClient(options=options) as client:
        # Long conversation...
        for i in range(10):
            await client.query(f"Task {i}")
            async for msg in client.receive_response():
                pass

        # Manually trigger compaction
        await client.query("/compact")

        # Continue with compacted context
        await client.query("Summarize what we've done")
```

### Session Forking

```python
async def explore_alternatives():
    options = ClaudeAgentOptions(
        allowed_tools=["Read", "Write"]
    )

    async with ClaudeSDKClient(options=options) as client:
        # Main conversation path
        await client.query("Design a REST API")
        async for msg in client.receive_response():
            print("Main path:", msg)

        # Fork session to explore alternative
        forked_client = client.fork()

        async with forked_client:
            await forked_client.query("What if we used GraphQL instead?")
            async for msg in forked_client.receive_response():
                print("Alternative:", msg)

        # Original session continues unaffected
        await client.query("Continue with REST implementation")
```

## Structured Outputs (v0.1.7+)

Agents can return validated JSON matching your schema using the `output_format` option:

```python
from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage

options = ClaudeAgentOptions(
    output_format={
        "type": "json_schema",
        "schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "key_points": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "sentiment": {
                    "type": "string",
                    "enum": ["positive", "negative", "neutral"]
                }
            },
            "required": ["summary", "key_points", "sentiment"]
        }
    }
)

async for message in query(
    prompt="Analyze this text and provide a structured analysis",
    options=options
):
    if isinstance(message, ResultMessage) and message.result:
        import json
        analysis = json.loads(message.result)
        print(f"Summary: {analysis['summary']}")
        print(f"Sentiment: {analysis['sentiment']}")
```

See the [Structured Outputs documentation](https://platform.claude.com/docs/en/agent-sdk/structured-outputs) for more details.

## Plugins (v0.1.5+)

Load Claude Code plugins programmatically through the SDK:

```python
from claude_agent_sdk import query, ClaudeAgentOptions

options = ClaudeAgentOptions(
    plugins=[
        {"type": "local", "path": "./my-plugin"},
        {"type": "local", "path": "/absolute/path/to/plugin"}
    ]
)

async for message in query(
    prompt="Use my custom plugin",
    options=options
):
    print(message)
```

For complete information on creating and using plugins, see [Plugins documentation](https://platform.claude.com/docs/en/agent-sdk/plugins).

## Sandbox Configuration

Configure sandbox behavior programmatically for command execution:

### Basic Sandbox Usage

```python
from claude_agent_sdk import query, ClaudeAgentOptions

sandbox_settings = {
    "enabled": True,
    "autoAllowBashIfSandboxed": True,  # Auto-approve bash commands when sandboxed
    "excludedCommands": ["docker"],     # Commands that bypass sandbox
}

async for message in query(
    prompt="Build and test my project",
    options=ClaudeAgentOptions(sandbox=sandbox_settings)
):
    print(message)
```

### Sandbox Settings Reference

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | `bool` | `False` | Enable sandbox mode for command execution |
| `autoAllowBashIfSandboxed` | `bool` | `False` | Auto-approve bash commands when sandbox enabled |
| `excludedCommands` | `list[str]` | `[]` | Commands that always bypass sandbox |
| `allowUnsandboxedCommands` | `bool` | `False` | Allow model to request running commands outside sandbox |
| `network` | `dict` | `None` | Network-specific sandbox configuration |
| `ignoreViolations` | `dict` | `None` | Configure which violations to ignore |

### Network Configuration

```python
sandbox_settings = {
    "enabled": True,
    "network": {
        "allowLocalBinding": True,  # Allow binding to local ports
        "allowUnixSockets": ["/var/run/docker.sock"],  # Allowed Unix sockets
        "allowAllUnixSockets": False,
        "httpProxyPort": 8080,  # Optional HTTP proxy port
    }
}
```

### Permissions Fallback for Unsandboxed Commands

When `allowUnsandboxedCommands` is enabled, the model can request to run commands outside the sandbox:

```python
async def can_use_tool(tool: str, input: dict) -> bool:
    if tool == "Bash" and input.get("dangerouslyDisableSandbox"):
        # Model wants to run this command outside the sandbox
        print(f"Unsandboxed command requested: {input.get('command')}")
        return is_command_authorized(input.get("command"))
    return True

options = ClaudeAgentOptions(
    sandbox={
        "enabled": True,
        "allowUnsandboxedCommands": True
    },
    can_use_tool=can_use_tool
)
```

## File Checkpointing (v0.1.15+)

Enable file change tracking and rewind capabilities:

```python
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions

options = ClaudeAgentOptions(
    enable_file_checkpointing=True,
    allowed_tools=["Read", "Write", "Edit"]
)

async with ClaudeSDKClient(options=options) as client:
    # Make some changes
    await client.query("Create a new Python file with a hello world function")
    async for msg in client.receive_response():
        # Track user_message_id for potential rewind
        if hasattr(msg, 'id'):
            checkpoint_id = msg.id
        print(msg)

    # Later, if you want to revert changes
    await client.rewind_files(checkpoint_id)
```

## Cost Tracking

### Basic Usage Tracking

```python
from claude_agent_sdk import query, ResultMessage

async def track_costs():
    messages = []

    async for message in query(prompt="Write a complex algorithm"):
        messages.append(message)

        # Check if it's the final result message
        if isinstance(message, ResultMessage):
            usage = message.usage
            if usage:
                print(f"Input tokens: {usage.input_tokens}")
                print(f"Output tokens: {usage.output_tokens}")
                print(f"Cache creation: {usage.cache_creation_input_tokens}")
                print(f"Cache read: {usage.cache_read_input_tokens}")
                print(f"Total cost: ${usage.total_cost_usd:.4f}")
```

### Advanced Cost Tracking

```python
class CostTracker:
    def __init__(self):
        self.processed_ids = set()
        self.step_usages = []
        self.total_cost = 0

    def process_message(self, message):
        """Track usage without double-counting"""
        if hasattr(message, 'id') and message.id not in self.processed_ids:
            self.processed_ids.add(message.id)

            if hasattr(message, 'usage') and message.usage:
                usage = message.usage
                step_cost = usage.total_cost_usd or 0

                self.step_usages.append({
                    'message_id': message.id,
                    'input_tokens': usage.input_tokens,
                    'output_tokens': usage.output_tokens,
                    'cost_usd': step_cost
                })

                self.total_cost += step_cost

    def get_summary(self):
        return {
            'total_steps': len(self.step_usages),
            'total_cost_usd': self.total_cost,
            'step_details': self.step_usages
        }

# Use tracker
tracker = CostTracker()

async for message in query(prompt="Complex multi-step task"):
    tracker.process_message(message)
    print(message)

print("Cost Summary:", tracker.get_summary())
```

### Budget Management

**Built-in Budget Control (v0.1.6+)**:

The SDK now provides built-in budget control via `max_budget_usd`:

```python
from claude_agent_sdk import query, ClaudeAgentOptions

options = ClaudeAgentOptions(
    max_budget_usd=1.00  # Session automatically terminates when exceeded
)

async for message in query(prompt="Complex analysis task", options=options):
    print(message)
```

**Custom Budget Manager** (for more control):

```python
class BudgetManager:
    def __init__(self, max_budget_usd: float):
        self.max_budget = max_budget_usd
        self.spent = 0

    async def monitored_query(self, prompt: str, options=None):
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, ResultMessage) and message.usage:
                self.spent += message.usage.total_cost_usd or 0

                if self.spent > self.max_budget:
                    raise Exception(f"Budget exceeded: ${self.spent:.4f} > ${self.max_budget:.4f}")

            yield message

# Use budget manager
manager = BudgetManager(max_budget_usd=1.00)

try:
    async for msg in manager.monitored_query("Expensive operation"):
        print(msg)
except Exception as e:
    print(f"Stopped: {e}")
```

### Extended Thinking Control (v0.1.6+)

Control the maximum tokens allocated for Claude's internal reasoning:

```python
options = ClaudeAgentOptions(
    max_thinking_tokens=2000  # Limit reasoning tokens
)
```

## Error Handling

### Exception Types

```python
from claude_agent_sdk import (
    ClaudeSDKError,      # Base exception
    CLINotFoundError,    # Claude Code not installed
    CLIConnectionError,  # Connection issues
    ProcessError,        # Process failed
    CLIJSONDecodeError,  # JSON parsing issues
)

async def robust_query():
    try:
        async for message in query(prompt="Test query"):
            print(message)

    except CLINotFoundError:
        print("Please install Claude Code: npm install -g @anthropic-ai/claude-code")

    except CLIConnectionError as e:
        print(f"Connection failed: {e}")
        # Retry logic here

    except ProcessError as e:
        print(f"Process failed with exit code: {e.exit_code}")
        print(f"Error output: {e.stderr}")

    except CLIJSONDecodeError as e:
        print(f"Failed to parse response: {e}")
        print(f"Raw output: {e.raw_output}")

    except ClaudeSDKError as e:
        print(f"SDK error: {e}")
```

### Retry Logic

```python
import asyncio
from typing import AsyncIterator

async def query_with_retry(
    prompt: str,
    max_retries: int = 3,
    backoff_seconds: float = 1.0
) -> AsyncIterator:
    for attempt in range(max_retries):
        try:
            async for message in query(prompt=prompt):
                yield message
            return  # Success

        except (CLIConnectionError, ProcessError) as e:
            if attempt == max_retries - 1:
                raise  # Re-raise on final attempt

            wait_time = backoff_seconds * (2 ** attempt)
            print(f"Retry {attempt + 1}/{max_retries} after {wait_time}s")
            await asyncio.sleep(wait_time)
```

### Graceful Degradation

```python
async def query_with_fallback(prompt: str):
    options_priority = [
        ClaudeAgentOptions(
            allowed_tools=["Read", "Write", "Bash"],
            permission_mode='acceptEdits'
        ),
        ClaudeAgentOptions(
            allowed_tools=["Read"],  # Reduced capabilities
            permission_mode='default'
        ),
        ClaudeAgentOptions(
            allowed_tools=[],  # Text-only fallback
            max_turns=1
        )
    ]

    for i, options in enumerate(options_priority):
        try:
            print(f"Attempting with option set {i + 1}")
            async for message in query(prompt=prompt, options=options):
                yield message
            return

        except Exception as e:
            print(f"Option {i + 1} failed: {e}")
            if i == len(options_priority) - 1:
                raise  # No more fallbacks
```

## Migration Guide

### From Claude Code SDK (<0.1.0) to Claude Agent SDK

#### 1. Rename Imports and Classes

```python
# Old (Claude Code SDK)
from claude_code_sdk import ClaudeCodeOptions, query

# New (Claude Agent SDK)
from claude_agent_sdk import ClaudeAgentOptions, query
```

#### 2. Update System Prompt Configuration

```python
# Old - separate fields
options = ClaudeCodeOptions(
    system_prompt_suffix="Additional instructions",
    # system prompt parts were separate
)

# New - unified system prompt
options = ClaudeAgentOptions(
    system_prompt="Complete system prompt including all instructions"
)
```

#### 3. Settings Isolation

```python
# Old - used global settings
options = ClaudeCodeOptions()

# New - explicit control
options = ClaudeAgentOptions(
    setting_sources=["project"],  # Include only project .claude/settings
)
```

#### 4. New Features Available

```python
# Programmatic subagents (new)
options = ClaudeAgentOptions(
    agents={
        'reviewer': {
            'description': 'Code reviewer',
            'prompt': 'Review code for quality',
            'tools': ['Read', 'Grep']
        }
    }
)

# Session forking (new)
forked_client = client.fork()

# In-process MCP servers (new)
server = create_sdk_mcp_server(name="tools", tools=[my_tool])
```

## Best Practices

### 1. Tool Selection

```python
# ✅ Good - Specific tools for the task
options = ClaudeAgentOptions(
    allowed_tools=["Read", "Grep"],  # Only what's needed
)

# ❌ Bad - Allowing all tools unnecessarily
options = ClaudeAgentOptions(
    allowed_tools=["*"],  # Too permissive
)
```

### 2. Error Handling

```python
# ✅ Good - Comprehensive error handling
async def safe_query(prompt):
    try:
        async for msg in query(prompt):
            yield msg
    except CLINotFoundError:
        # Specific handling
        yield "Please install Claude Code"
    except Exception as e:
        # Log error details
        logger.error(f"Query failed: {e}")
        yield "An error occurred"

# ❌ Bad - No error handling
async for msg in query(prompt):
    print(msg)  # Will crash on errors
```

### 3. Context Management

```python
# ✅ Good - Manage long conversations
async def long_task():
    options = ClaudeAgentOptions(max_turns=10)

    async with ClaudeSDKClient(options=options) as client:
        for task in tasks:
            if client.turn_count > 8:
                await client.query("/compact")

            await client.query(task)

# ❌ Bad - Unbounded context growth
async with ClaudeSDKClient() as client:
    for task in tasks:  # May exceed token limits
        await client.query(task)
```

### 4. Custom Tools

```python
# ✅ Good - Well-defined tool with validation
@tool("process_data", "Process data safely", {"data": str, "format": str})
async def process_data(args):
    # Validate inputs
    if args['format'] not in ['json', 'csv', 'xml']:
        return {"content": [{"type": "text", "text": "Invalid format"}]}

    # Process safely
    try:
        result = process(args['data'], args['format'])
        return {"content": [{"type": "text", "text": result}]}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error: {e}"}]}

# ❌ Bad - No validation or error handling
@tool("process", "Process data", {"data": str})
async def process(args):
    return {"content": [{"type": "text", "text": eval(args['data'])}]}  # Dangerous!
```

### 5. Permission Management

```python
# ✅ Good - Layered security
options = ClaudeAgentOptions(
    allowed_tools=["Read", "Write"],
    permission_mode='default',
    hooks={
        "PreToolUse": [security_hook]
    },
    can_use_tool=permission_callback
)

# ❌ Bad - Bypassing all permissions
options = ClaudeAgentOptions(
    permission_mode='bypassPermissions'  # Never in production!
)
```

### 6. Cost Optimization

```python
# ✅ Good - Monitor and optimize costs
async def cost_aware_query(prompt):
    # Use caching
    options = ClaudeAgentOptions(
        use_cache=True,
        max_tokens=4000  # Limit response size
    )

    # Track costs
    async for msg in query(prompt, options):
        if isinstance(msg, ResultMessage):
            log_cost(msg.usage)
        yield msg

# ❌ Bad - No cost awareness
async for msg in query(very_long_prompt):
    print(msg)  # Could be expensive!
```

### 7. Platform-Specific Considerations

#### Windows Command Line Limits (SDK 0.1.3+)

The SDK automatically handles Windows command line length limits (8191 characters) when using multiple subagents with long prompts. When the command line would exceed the limit, the SDK:
- Automatically writes agents JSON to a temporary file
- Uses Claude CLI's `@filepath` syntax to reference the file
- Cleans up temporary files when the transport is closed

This is handled transparently - no code changes required. The fallback only activates when needed on Windows systems.

```python
# This works seamlessly on Windows even with many subagents
options = ClaudeAgentOptions(
    agents={
        'reviewer1': {'description': 'Code reviewer', 'prompt': '...[long prompt]...'},
        'reviewer2': {'description': 'Security reviewer', 'prompt': '...[long prompt]...'},
        'reviewer3': {'description': 'Performance reviewer', 'prompt': '...[long prompt]...'},
        # ... more agents with long prompts
    }
)
# SDK handles command line limits automatically
```

## Conclusion

The Claude Agent Python SDK provides a powerful, flexible framework for building AI agents with Claude. By following this guide and best practices, you can create robust, secure, and cost-effective AI applications.

### Key Takeaways

1. **Start Simple**: Begin with `query()` for basic needs
2. **Graduate to ClaudeSDKClient**: When you need interactivity
3. **Extend with Custom Tools**: Add domain-specific capabilities
4. **Use Subagents**: For specialized, parallel tasks
5. **Implement Security Layers**: Multiple permission controls
6. **Monitor Costs**: Track usage and implement budgets
7. **Handle Errors Gracefully**: Comprehensive error handling
8. **Optimize Context**: Manage long conversations efficiently

### Resources

**Official Documentation**:
- [SDK Overview](https://platform.claude.com/docs/en/agent-sdk/overview) - General SDK concepts
- [Python SDK Reference](https://platform.claude.com/docs/en/agent-sdk/python) - Complete API documentation
- [Structured Outputs](https://platform.claude.com/docs/en/agent-sdk/structured-outputs) - JSON schema validation
- [Plugins](https://platform.claude.com/docs/en/agent-sdk/plugins) - Plugin development guide
- [Skills](https://platform.claude.com/docs/en/agent-sdk/skills) - Agent Skills in the SDK
- [Subagents](https://platform.claude.com/docs/en/agent-sdk/subagents) - Subagent configuration

**Code Resources**:
- [GitHub Repository](https://github.com/anthropics/claude-agent-sdk-python)
- [PyPI Package](https://pypi.org/project/claude-agent-sdk/)
- [Issue Tracker](https://github.com/anthropics/claude-agent-sdk-python/issues)
- [Examples](https://github.com/anthropics/claude-agent-sdk-python/tree/main/examples)

### Community & Support

- Report issues on GitHub
- Check documentation for updates
- Join the Anthropic developer community

---

*This guide covers Claude Agent SDK version 0.1.15 and above. For the latest updates and features, always refer to the [official documentation](https://platform.claude.com/docs/en/agent-sdk/python).*