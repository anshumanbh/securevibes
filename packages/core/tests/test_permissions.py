"""Tests for Claude SDK permission mode resolution."""

from __future__ import annotations

from securevibes.scanner.permissions import (
    PERMISSION_MODE_ENV_VAR,
    resolve_permission_mode,
)


def test_resolve_permission_mode_defaults_to_default(monkeypatch) -> None:
    """Unset environment should return default permission mode."""
    monkeypatch.delenv(PERMISSION_MODE_ENV_VAR, raising=False)
    assert resolve_permission_mode() == "default"


def test_resolve_permission_mode_uses_valid_override(monkeypatch) -> None:
    """Valid override from environment should be honored."""
    monkeypatch.setenv(PERMISSION_MODE_ENV_VAR, "bypassPermissions")
    assert resolve_permission_mode() == "bypassPermissions"


def test_resolve_permission_mode_invalid_value_falls_back(monkeypatch) -> None:
    """Invalid override should fall back to provided default."""
    monkeypatch.setenv(PERMISSION_MODE_ENV_VAR, "invalid")
    assert resolve_permission_mode() == "default"
