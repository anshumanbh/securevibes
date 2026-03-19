"""Claude SDK permission mode helpers."""

from __future__ import annotations

import os

PERMISSION_MODE_ENV_VAR = "SECUREVIBES_PERMISSION_MODE"
VALID_PERMISSION_MODES = frozenset({"default", "acceptEdits", "bypassPermissions"})


def resolve_permission_mode(default: str = "default") -> str:
    """Resolve Claude permission mode from environment with validation."""
    mode = os.getenv(PERMISSION_MODE_ENV_VAR, default).strip()
    if mode in VALID_PERMISSION_MODES:
        return mode
    return default
