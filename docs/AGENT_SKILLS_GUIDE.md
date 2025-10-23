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

Agent Skills are a powerful paradigm for extending Claude's capabilities in a modular, composable, and efficient manner. Unlike traditional function calling or tool definitions, Skills are **model-invoked**—Claude autonomously decides when to use them based on context, without requiring explicit user commands.

This guide provides a comprehensive blueprint for creating, deploying, and using Agent Skills with the Claude Agent SDK. It synthesizes official documentation, best practices, and engineering insights to enable coding agents to build effective skills.

---

## What Are Agent Skills?

### Core Characteristics

**Composable**: Skills work together automatically. Claude can combine multiple skills to accomplish complex tasks without manual orchestration.

**Portable**: The same skill format works across:
- Claude apps (Pro, Max, Team, Enterprise users)
- Claude Code
- Claude API (via Messages API and `/v1/skills` endpoint)

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
- No reserved words
- Use gerund form (verb + -ing): `processing-pdfs`, `analyzing-spreadsheets`
- Avoid vague names like `helper`, `utils`, `tool`

**description** (required):
- Maximum 1024 characters
- Specify **what** the skill does and **when** to use it
- Write in third person
- Include specific trigger terms users might mention
- Example: "Extract text and tables from PDFs, fill forms, merge documents. Use when working with PDF files or document extraction."

**allowed-tools** (optional):
- Comma-separated list of tools Claude can use when this skill is active
- Enables read-only skills or limits scope
- Example: `Read, Grep, Glob` (no file modification)
- Example: `Read, Write, Edit, Bash` (full access)

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

### 2. Match Specificity to Task

Choose the right level of freedom:

| Freedom Level | When to Use | Example |
|---------------|-------------|---------|
| **High** (text instructions) | Multiple valid approaches exist | "Follow our code review guidelines" |
| **Medium** (pseudocode with parameters) | Preferred pattern exists | "Use this template: `function {name}({params}) { ... }`" |
| **Low** (specific scripts) | Fragile operations requiring consistency | "Run `scripts/deploy.sh --env production`" |

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

Verify skills work with:
- **Claude Haiku**: Fast, basic tasks
- **Claude Sonnet**: Balanced performance
- **Claude Opus**: Complex reasoning

Effectiveness varies by model capability.

---

## Using Skills with Claude Agent SDK

### API Integration

#### Messages API with Skills

```python
import anthropic

client = anthropic.Anthropic(api_key="your-api-key")

# Create message with skills enabled
response = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=4096,
    messages=[
        {"role": "user", "content": "Create a new user API endpoint"}
    ],
    # Skills are automatically available if configured in the environment
)

print(response.content)
```

#### Built-in Document Skills

Claude provides four pre-built skills via API:

```python
# Excel generation
response = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=4096,
    messages=[
        {"role": "user", "content": "Create a financial dashboard in Excel"}
    ],
    betas=["skills-2025-01-01"]  # Enable skills beta
)

# Access generated file
file_id = response.content[0].file_id
file_content = client.files.content(file_id)
```

**Available built-in skills**:
- `xlsx`: Excel workbooks with formulas, charts, formatting
- `pptx`: PowerPoint presentations
- `pdf`: Formatted PDF documents
- `docx`: Word documents

### Claude Code Integration

Skills in Claude Code are automatically discovered from:
1. `~/.claude/skills/` (personal skills)
2. `.claude/skills/` (project skills)
3. Plugin-installed skills

**Usage**: Simply interact with Claude Code naturally. Claude will activate relevant skills based on context.

```bash
# Example interaction
> "Generate a new API endpoint for products with inventory tracking"

# Claude automatically:
# 1. Detects the api-endpoint-generator skill
# 2. Loads SKILL.md
# 3. Follows the defined workflow
# 4. Generates all required files
# 5. Runs validation scripts
```

### Programmatic Skill Management

```python
# List available skills (API endpoint)
import requests

headers = {
    "anthropic-version": "2023-06-01",
    "x-api-key": "your-api-key"
}

response = requests.get(
    "https://api.anthropic.com/v1/skills",
    headers=headers
)

skills = response.json()
print(f"Available skills: {len(skills['skills'])}")
```

### Custom Skill Distribution

**Via Git** (recommended for teams):
```bash
# In your project repository
git add .claude/skills/
git commit -m "Add custom API generation skill"
git push

# Team members automatically get the skill
git pull
```

**Via Package** (for broader distribution):
```bash
# Create a Claude Code plugin
claude-plugin create my-skills-pack
# Add skills to plugin
# Publish to marketplace
```

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

### 7. Skills with External API Integration

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

- **Official Documentation**: https://docs.claude.com/en/docs/claude-code/skills
- **Skills Repository**: https://github.com/anthropics/skills
- **Cookbooks**: https://github.com/anthropics/claude-cookbooks/tree/main/skills
- **Best Practices**: https://docs.claude.com/en/docs/agents-and-tools/agent-skills/best-practices

---

*This guide is a living document. As you build skills and discover new patterns, update it to reflect your learnings and share with the community.*
