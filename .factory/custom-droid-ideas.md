# Custom Droid Ideas

This document contains suggestions for custom droids based on workflow preferences documented in `.droid-preferences.md`.

---

## What Are Custom Droids?

Custom droids are reusable task templates that automate repetitive workflows. They can be:
- **Project-specific**: Located in `.factory/droids/` (this repo only)
- **Personal**: Located in `~/.factory/droids/` (available across all projects)

---

## Project-Specific Droids

These droids enforce the workflow preferences specific to this SecureVibes project.

### 1. `safe-stage` - Safe Git Staging Workflow

**Purpose**: Make changes and stage them following the git workflow preference  
**Use Case**: Any code change that needs git staging

**Behavior**:
- Make the requested changes (code, tests, docs)
- Run `git add` for all modified files
- 🛑 **STOP and report** what's staged
- Never run `git commit` or `git push`
- Remind user to review with `git status` and `git diff --cached`

**Example Usage**: "safe-stage: Add validation to user input"

---

### 2. `complete-change` - Code + Tests + Docs Together

**Purpose**: Ensure code changes always include tests and documentation  
**Use Case**: Feature additions, bug fixes, API changes

**Behavior**:
- Implement the requested code change
- Add or update tests for the change
- Update all relevant documentation (docstrings, READMEs)
- Remove obsolete docs if deleting features
- Run verification tests before completing
- Stage all changes with git add

**Example Usage**: "complete-change: Add --format flag to export command"

---

### 3. `verify-done` - Pre-Completion Verification

**Purpose**: Run all checks before declaring work complete  
**Use Case**: Final verification step before staging changes

**Behavior**:
- Run `pytest` on relevant test files
- Check for import errors in modified modules
- Verify code examples in documentation still work
- Report any issues found
- Only declare "done" if all checks pass

**Example Usage**: "verify-done: Check changes to scanner module"

---

### 4. `doc-audit` - Documentation Accuracy Check

**Purpose**: Find and flag outdated documentation  
**Use Case**: After deleting features, major refactors, or periodic maintenance

**Behavior**:
- Scan READMEs and docs for code examples
- Check for references to deleted features/commands
- Verify API examples match current code implementation
- Flag inconsistencies between root README and package READMEs
- List all outdated sections found

**Example Usage**: "doc-audit: Check for references to removed --validate flag"

---

### 5. `maintenance-scan` - Health Check Suite

**Purpose**: Run the maintenance checks from `docs/MAINTENANCE.md`  
**Use Case**: Periodic codebase health checks

**Behavior**:
- Detect dead code (unused functions, imports)
- Generate test coverage report
- Check for outdated dependencies (with security advisories)
- Audit documentation accuracy
- Present findings in a report (do not auto-fix)

**Example Usage**: "maintenance-scan: Run full health check"

---

## Personal Droid Ideas

These droids are generally useful across any project.

### 6. `pr-prep` - Pull Request Preparation

**Purpose**: Prepare comprehensive PR with all pre-flight checks  
**Use Case**: Before creating a pull request

**Behavior**:
- Review `git diff` for all changes
- Run tests and linters (if configured)
- Generate PR description from commit messages
- Check for sensitive data in changes (API keys, secrets)
- Verify no TODO/FIXME comments left in
- Stage files (following safe-stage pattern)
- Suggest PR title and description

**Example Usage**: "pr-prep: Prepare changes for review"

---

### 7. `security-audit` - Security Review

**Purpose**: Scan code changes for security issues  
**Use Case**: Before committing security-sensitive code

**Behavior**:
- Check for hardcoded secrets, API keys, passwords
- Review authentication/authorization logic
- Flag SQL injection risks in queries
- Check for command injection in subprocess calls
- Review file permissions and path traversal risks
- Check for dependency vulnerabilities
- Report findings with severity levels

**Example Usage**: "security-audit: Review API endpoint changes"

---

### 8. `refactor-safe` - Safe Refactoring

**Purpose**: Refactor code with safety nets  
**Use Case**: Code restructuring, renaming, moving files

**Behavior**:
- Create a snapshot of current git state
- Perform the requested refactoring
- Run full test suite
- Verify no behavior changes (output comparison if possible)
- Check for broken imports or references
- Rollback automatically if tests fail
- Report what changed and verification results

**Example Usage**: "refactor-safe: Rename getUserData to fetchUserProfile"

---

### 9. `test-boost` - Test Coverage Improvement

**Purpose**: Identify and add missing tests  
**Use Case**: Improving test coverage for existing code

**Behavior**:
- Generate coverage report for specified files
- Identify untested code paths (branches, functions)
- Suggest specific test cases needed
- Generate test stubs with TODO comments
- Run tests to verify stubs work
- Report coverage improvement

**Example Usage**: "test-boost: Improve coverage for auth module"

---

### 10. `dep-check` - Dependency Management

**Purpose**: Audit and update dependencies safely  
**Use Case**: Regular dependency maintenance

**Behavior**:
- List outdated dependencies from requirements.txt/package.json
- Check for security advisories (CVEs)
- Categorize updates (major, minor, patch)
- Suggest safe updates (minor/patch first)
- Generate update plan with risk assessment
- Test after updates (run test suite)
- Rollback if tests fail

**Example Usage**: "dep-check: Audit Python dependencies"

---

## Implementation Guide

### Droid File Structure

Each custom droid is defined in a YAML or JSON file:

```yaml
identifier: safe-stage
description: Make changes and safely stage them for git commit
model: flash  # preferred model
prompt_template: |
  {user_prompt}
  
  After making the requested changes:
  1. Stage all modified files with git add
  2. Stop and report what's staged
  3. Remind user to review with 'git status' and 'git diff --cached'
  4. NEVER run git commit or git push
guardrails:
  - no_auto_commit: true
  - no_auto_push: true
  - stop_after_stage: true
```

### Creating a Droid

1. Create a file in `.factory/droids/` (project) or `~/.factory/droids/` (personal)
2. Name it `<identifier>.yaml` (e.g., `safe-stage.yaml`)
3. Define the behavior in the prompt template
4. Set appropriate guardrails

### Using a Droid

```bash
# In Factory CLI
droid safe-stage "Add input validation to login function"
```

---

## Next Steps

1. **Prioritize**: Choose which droids would be most useful first
2. **Prototype**: Create 1-2 droids to test the workflow
3. **Iterate**: Refine based on actual usage
4. **Document**: Keep this file updated as droids evolve
5. **Share**: Personal droids that work well can become project droids

---

**Created**: 2025-10-11  
**Source**: `.droid-preferences.md`  
**Owner**: @anshumanbh
