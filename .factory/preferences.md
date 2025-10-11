# Droid Workflow Preferences (SecureVibes)

This file contains project-specific workflow preferences. For global preferences that apply across all projects, see `~/.factory/preferences.md`.

**IMPORTANT:** This file should be kept in sync with `~/.factory/preferences.md` for all non-project-specific preferences. When updating global preferences, update both files.

---

## Global Preferences

**All global workflow preferences apply to this project.**

The following sections from `~/.factory/preferences.md` apply here:
- Git workflow (stage files + suggest commit message, then stop)
- Code changes (always update code + tests + docs together)
- Testing requirements
- Documentation standards
- Communication style
- Maintenance guidelines

---

## Project-Specific Overrides

### Testing

Test command for this project:
```bash
pytest packages/core/tests/
```

### Maintenance

This project has a comprehensive maintenance guide. When suggesting maintenance tasks, refer to:
- `docs/MAINTENANCE.md` - Full maintenance procedures and checklists

### Documentation

This project has documentation in multiple locations:
- Root `README.md` - Main project overview
- `packages/core/README.md` - Core package documentation
- `docs/` - Detailed guides and maintenance procedures

**Always update all relevant locations when making documentation changes.**

---

**Last Updated:** 2025-10-11  
**Owner:** @anshumanbh  
**Scope:** SecureVibes project only
