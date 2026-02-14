# Codebase Maintenance & Pruning Guide

## 📊 Current State

**SecureVibes Stats:**
- 📁 28 Python files
- 📝 ~4,374 lines of code
- 🧪 181 tests
- 🏗️ Well-structured (16 core modules)

---

## 🎯 Maintenance Strategy

### 1. **Automated Dead Code Detection**

#### A. Set Up Regular Scans

**Tool: `vulture` (Python dead code detector)**
```bash
# Install
pip install vulture

# Create config: vulture.ini
[vulture]
min_confidence = 60
paths = packages/core/securevibes
exclude = venv/,__pycache__/,dist/,build/

# Run regularly
vulture packages/core/securevibes --min-confidence 80
```

**Schedule:** Run monthly or before major releases

**Action Items:**
- [ ] Install vulture
- [ ] Create `.vulture.ini` configuration
- [ ] Add to CI/CD pipeline
- [ ] Review and prune findings quarterly

---

#### B. Manual Dead Code Checklist

Run this checklist quarterly:

```bash
# 1. Find unused imports
cd packages/core
python3 -m pyflakes securevibes/ | grep "imported but unused"

# 2. Find files without imports (potentially unused)
find securevibes -name "*.py" -type f ! -path "*/test*" -exec grep -L "from.*import\|import" {} \;

# 3. Find functions/methods never called
# Use vulture as above

# 4. Check for commented-out code
grep -r "^[ ]*#.*def \|^[ ]*#.*class " securevibes/ --include="*.py"
```

**Review Questions:**
- ✅ Is this imported anywhere?
- ✅ Is this tested?
- ✅ Is this exported in `__all__`?
- ✅ Is this documented?

---

### 2. **Test Coverage Monitoring**

#### A. Set Coverage Targets

```bash
# Install coverage tools
pip install pytest-cov coverage

# Run coverage report
pytest --cov=securevibes --cov-report=html --cov-report=term

# Target: Maintain 80%+ coverage
```

**Coverage Goals:**
- 🎯 **Overall:** 80%+
- 🎯 **Core modules:** 90%+ (scanner, config, agents)
- 🎯 **Utilities:** 70%+ (reporters, CLI)

**Action Items:**
- [ ] Generate coverage report monthly
- [ ] Identify uncovered code
- [ ] Either add tests OR remove if unused
- [ ] Add coverage badge to README

---

#### B. Coverage-Driven Pruning

```python
# Find untested code
pytest --cov=securevibes --cov-report=term-missing | grep "0%"

# Questions for 0% coverage code:
# 1. Is it actually used? → If no, DELETE
# 2. Is it critical? → If yes, ADD TESTS
# 3. Is it experimental? → Move to separate branch
```

---

### 3. **Documentation Maintenance**

#### A. Keep Docs in Sync (CRITICAL)

**Workflow for Every Code Change:**

```bash
# Before committing ANY code change:
1. Update docstrings in changed files
2. Update README.md if public API changed
3. Update ARCHITECTURE.md if structure changed
4. Update tests to match new behavior
5. Remove docs for deleted features (like we did with --streaming)
```

**Automation:**
```bash
# Create pre-commit hook: .git/hooks/pre-commit
#!/bin/bash
echo "🔍 Checking for common doc issues..."

# Check for references to deleted features
git diff --cached --name-only | grep -E "\.(py|md)$" | while read file; do
  # Add patterns for known deleted features
  if git diff --cached "$file" | grep -i "streaming\|assess\|threat-model\|review"; then
    echo "⚠️  Warning: Reference to potentially deleted feature in $file"
  fi
done
```

---

#### B. Documentation Audit Checklist (Quarterly)

```markdown
## Documentation Audit

### READMEs
- [ ] All commands in README actually exist
- [ ] All flags in README actually work
- [ ] Code examples run without errors
- [ ] Installation instructions are current

### Architecture Docs
- [ ] Class names match actual code
- [ ] File paths are correct
- [ ] Diagrams reflect current structure
- [ ] No references to deleted components

### API Documentation
- [ ] Docstrings present for all public functions
- [ ] Parameter types documented
- [ ] Return types documented
- [ ] Examples in docstrings work

### Tests
- [ ] Test docstrings explain what's being tested
- [ ] No tests for deleted features
```

---

### 4. **Dependency Management**

#### A. Regular Dependency Audits

```bash
# Monthly: Check for outdated packages
pip list --outdated

# Quarterly: Security audit
pip-audit  # or: pip install pip-audit

# Yearly: Major version updates
# Review and update pyproject.toml dependencies
```

**Dependency Pruning Questions:**
- ❓ Is this still used?
- ❓ Can we use a lighter alternative?
- ❓ Is this a dev dependency that should be in [dev]?

---

#### B. Monitor Bundle Size

```bash
# Check package size
cd packages/core
python3 -m build
ls -lh dist/

# Target: Keep wheel < 1MB
```

---

### 5. **Code Quality Standards**

#### A. Set Up Automated Linting

```bash
# Install tools
pip install ruff black mypy

# Add to pyproject.toml
[tool.ruff]
line-length = 100
target-version = "py310"
select = ["E", "F", "I", "N", "W"]
ignore = ["E501"]  # Line too long

[tool.black]
line-length = 100
target-version = ["py310"]

[tool.mypy]
python_version = "3.10"
warn_return_any = true
warn_unused_configs = true
```

**Run regularly:**
```bash
# Format
black packages/core/securevibes

# Lint
ruff check packages/core/securevibes

# Type check
mypy packages/core/securevibes
```

---

#### B. Code Review Checklist

For every PR/commit:

```markdown
## Code Review Checklist

### Functionality
- [ ] Code does what it's supposed to
- [ ] Edge cases handled
- [ ] No obvious bugs

### Quality
- [ ] No duplicate code
- [ ] Functions < 50 lines
- [ ] Clear variable names
- [ ] No commented-out code

### Testing
- [ ] New code has tests
- [ ] Tests pass
- [ ] Coverage didn't decrease

### Documentation
- [ ] Docstrings added/updated
- [ ] README updated if needed
- [ ] No broken references

### Maintenance
- [ ] No new dead code introduced
- [ ] Dependencies justified
- [ ] No new warnings
```

---

### 6. **Regular Maintenance Schedule**

#### Weekly
- ✅ Review recent commits for quality
- ✅ Check CI/CD pipeline health
- ✅ Monitor GitHub issues/PRs

#### Monthly
- ✅ Run dead code detection (vulture)
- ✅ Generate test coverage report
- ✅ Check for outdated dependencies
- ✅ Review and close stale issues

#### Quarterly
- ✅ Full documentation audit
- ✅ Security audit (pip-audit)
- ✅ Review and prune unused code
- ✅ Update dependency versions
- ✅ Performance profiling

#### Yearly
- ✅ Major dependency upgrades
- ✅ Architecture review
- ✅ Breaking changes planning
- ✅ Codebase refactoring sprint

---

### 7. **Automated CI/CD Checks**

Create `.github/workflows/maintenance.yml`:

```yaml
name: Code Maintenance

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday
  workflow_dispatch:  # Manual trigger

jobs:
  dead-code-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
      - run: pip install vulture
      - run: vulture packages/core/securevibes --min-confidence 80

  coverage-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
      - run: pip install -e "packages/core[dev]"
      - run: pytest --cov=securevibes --cov-fail-under=80

  dependency-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
      - run: pip install pip-audit
      - run: pip-audit
```

---

### 8. **Pruning Decision Framework**

When deciding whether to keep or remove code:

```
┌─────────────────────────────────────┐
│ Is this code USED?                  │
└─────────────┬───────────────────────┘
              │
      ┌───────┴───────┐
      │               │
     YES             NO
      │               │
      ▼               ▼
┌─────────────┐  ┌──────────────┐
│ Is it       │  │ DELETE IT    │
│ TESTED?     │  │ IMMEDIATELY  │
└─────┬───────┘  └──────────────┘
      │
  ┌───┴────┐
  │        │
 YES      NO
  │        │
  ▼        ▼
┌────┐  ┌──────────────┐
│KEEP│  │ ADD TESTS or │
└────┘  │ DELETE       │
        └──────────────┘
```

**Priority for Deletion:**
1. 🔴 **High Priority:** Unused + Untested + Undocumented
2. 🟡 **Medium Priority:** Unused + Tested (someone wrote tests but it's not used)
3. 🟢 **Low Priority:** Used + Untested (add tests instead of deleting)

---

### 9. **Specific to SecureVibes**

#### A. Keep Scanner Clean
```bash
# scanner/ should only have:
# - scanner.py (core implementation)
# - __init__.py (exports)
# No more validators.py, no helper modules
```

#### B. Monitor Agent Definitions
```bash
# Regularly check:
# 1. Are all 4 agents being used?
# 2. Are prompts up to date?
# 3. Are tool lists minimal?
```

#### C. Reporter Consistency
```bash
# Ensure reporters stay consistent:
# 1. Same interface
# 2. Same output format
# 3. No duplicate code
```

#### D. Artifact Cleanup
```bash
# Monitor .securevibes/ artifacts:
# Core artifacts (always created):
# - SECURITY.md
# - THREAT_MODEL.json
# - VULNERABILITIES.json
# - scan_results.json
# - scan_state.json (commit tracking for pr-review/catchup)

# Optional artifacts (only when --target-url provided):
# - DAST_VALIDATION.json (created by DAST agent)
# - DAST_TEST_ACCOUNTS.json (test accounts for DAST validation)
# - DIFF_CONTEXT.json (created by pr-review)
# - PR_VULNERABILITIES.json (created by pr-review)
# - pr_review_report.md (default markdown report from pr-review)

# Cleanup old artifacts periodically:
rm -rf .securevibes/*.old
rm -rf .securevibes/*~

# Keep artifacts in .gitignore to avoid committing scan results
```

---

### 10. **Practical Implementation Plan**

#### Phase 1: Setup (Week 1)
```bash
# Day 1-2: Install tools
pip install vulture pytest-cov pip-audit ruff black mypy

# Day 3: Create configs
touch .vulture.ini pyproject.toml .github/workflows/maintenance.yml

# Day 4-5: Initial audit
vulture packages/core/securevibes
pytest --cov=securevibes --cov-report=html
```

#### Phase 2: Document (Week 2)
```bash
# Maintenance guide (this document)
# Already created at docs/MAINTENANCE.md

# Update CONTRIBUTING.md if it exists
# Add section on code quality standards
```

#### Phase 3: Automate (Week 3-4)
```bash
# Set up pre-commit hooks
touch .pre-commit-config.yaml

# Configure CI/CD
# Add maintenance workflows

# Create monitoring dashboard
# Track metrics over time
```

#### Phase 4: Execute (Ongoing)
```bash
# Follow the maintenance schedule above
# Weekly, monthly, quarterly checks
```

---

## 🎯 Key Metrics to Track

| Metric | Target | Current |
|--------|--------|---------|
| Lines of Code | < 5,000 | ~4,374 ✅ |
| Test Coverage | > 80% | TBD |
| Number of Tests | Growing | 181 ✅ |
| Files Count | < 35 | 28 ✅ |
| Dependencies | < 10 | TBD |
| Dead Code | 0% | TBD |
| Documentation Coverage | 100% | TBD |

---

## 📋 Monthly Maintenance Checklist

Copy this for your monthly reviews:

```markdown
## SecureVibes Maintenance - [Month/Year]

### Code Health
- [ ] Ran vulture, found X unused items
- [ ] Coverage is at X%
- [ ] All tests passing (X/X)
- [ ] No new warnings

### Documentation
- [ ] README matches CLI commands
- [ ] All examples work
- [ ] Architecture docs current

### Dependencies
- [ ] No security vulnerabilities
- [ ] X outdated packages (list)
- [ ] Updated: [list]

### Cleanup
- [ ] Deleted X unused files
- [ ] Removed X dead functions
- [ ] Pruned X old comments

### Next Month
- [ ] [Planned improvement]
- [ ] [Technical debt to address]
```

---

## 🚀 Quick Win: Today's Actions

**Start now with these 5 commands:**

```bash
# 1. Install essentials
pip install vulture pytest-cov

# 2. Run dead code detection
vulture packages/core/securevibes --min-confidence 80

# 3. Check test coverage
pytest --cov=securevibes --cov-report=term-missing

# 4. Find unused imports
python3 -m pyflakes packages/core/securevibes/ 2>&1 | grep unused

# 5. Review this guide regularly
cat docs/MAINTENANCE.md
```

Then review the results and start pruning!

---

## 💡 Golden Rules

1. **Delete > Comment Out** - Never comment out code, delete it (git has history)
2. **Test or Delete** - Untested code is dead code waiting to break
3. **Document as You Go** - Don't batch documentation updates
4. **Automate Everything** - Manual checks get skipped
5. **Review Weekly** - Small frequent cleanups > big refactors

---

## 🎓 Recent Examples

### Example 1: Removed validators.py (2025-10-11)
- **Found:** `validators.py` with 159 lines
- **Checked:** No imports, no tests, not exported
- **Action:** Deleted entirely
- **Result:** -159 lines, no breakage ✅

### Example 2: Fixed Documentation (2025-10-11)
- **Found:** References to deleted `--streaming` flag and commands
- **Checked:** Commands don't exist anymore
- **Action:** Removed from all READMEs
- **Result:** Documentation accurate ✅

---

## 📚 Additional Resources

- [Vulture Documentation](https://github.com/jendrikseipp/vulture)
- [pytest-cov Documentation](https://pytest-cov.readthedocs.io/)
- [Ruff Linter](https://docs.astral.sh/ruff/)
- [Black Formatter](https://black.readthedocs.io/)

---

**Last Updated:** 2025-10-11
**Maintainer:** @anshumanbh
