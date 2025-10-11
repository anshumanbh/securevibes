# Droid Workflow Preferences (SecureVibes)

This file contains project-specific workflow preferences. For global preferences that apply across all projects, see `~/.factory/preferences.md`.

---

## Global Preferences

**All global workflow preferences apply to this project.**

See: `~/.factory/preferences.md` for:
- Git workflow (stop after `git add`)
- Code changes (always update code + tests + docs together)
- Testing requirements
- Documentation standards
- Communication style

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
