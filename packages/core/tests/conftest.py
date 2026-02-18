"""Shared test fixtures."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def mock_scanner_claude_client():
    """Patch scanner Claude client with async context-manager defaults."""
    with patch("securevibes.scanner.scanner.ClaudeSDKClient") as mock_client:
        mock_instance = MagicMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
        yield mock_client, mock_instance
