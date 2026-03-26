"""Shared test fixtures."""

import pytest


@pytest.fixture(autouse=True)
def _reset_auth_rate_limits():
    """Clear the in-memory rate limiter between every test."""
    try:
        from vlair.webapp.auth.routes import reset_rate_limits

        reset_rate_limits()
    except ImportError:
        pass
    yield
