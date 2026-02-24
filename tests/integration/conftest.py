"""Pytest configuration for integration tests."""

import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers."""
    config.addinivalue_line(
        "markers",
        "integration: marks integration tests (require external MCP servers)",
    )
