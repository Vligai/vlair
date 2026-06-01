#!/usr/bin/env python3
"""
Security-focused test suite for vlair webapp.

Tests attack scenarios not covered by test_webapp_auth.py and test_webapp_app.py:
- Path traversal attacks
- Rate limiting enforcement
- Token revocation
- Auth bypass attempts
- HTTP security headers
- TOTP brute force
"""

import os
import sys
import json
import time
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Skip all tests if Flask is not installed
flask = pytest.importorskip("flask", reason="Flask not installed")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _setup_db(tmp_path):
    """Create a fresh database for each test."""
    db_path = str(tmp_path / "test_security.db")
    os.environ["VLAIR_WEBAPP_DB"] = db_path
    os.environ.setdefault("VLAIR_SECRET_KEY", "test-secret-key-for-security-tests")
    yield
    os.environ.pop("VLAIR_WEBAPP_DB", None)


@pytest.fixture()
def app():
    from vlair.webapp.app import create_app

    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def _clear_rate_limits():
    """Reset rate limiter state before each test."""
    from vlair.webapp.auth.routes import reset_rate_limits

    reset_rate_limits()
    yield
    reset_rate_limits()


def _register_user(client, username="sectest", email="sec@test.com", password="Str0ngP@ss!"):
    """Helper to register a user and return the response JSON."""
    resp = client.post(
        "/api/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    return resp.get_json()


def _login_user(client, username="sectest", password="Str0ngP@ss!"):
    """Helper to login and return (access_token, refresh_token)."""
    resp = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    data = resp.get_json()
    return data.get("access_token"), data.get("refresh_token")


def _auth_header(token):
    """Return an Authorization header dict."""
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# 1. Path Traversal Tests
# ===========================================================================


class TestPathTraversal:
    """Ensure _validate_path blocks directory traversal attacks."""

    def _yara_scan_with_mock(self, client, token, **json_body):
        """POST to /api/yara/scan with YARAScanner mocked out."""
        with patch("vlair.tools.yara_scanner.YARAScanner", create=True):
            return client.post(
                "/api/yara/scan",
                json=json_body,
                headers=_auth_header(token),
            )

    def test_path_traversal_dot_dot_slash(self, client):
        """Submitting ../../etc/passwd to YARA scan should be rejected."""
        _register_user(client)
        token, _ = _login_user(client)
        resp = self._yara_scan_with_mock(client, token, file_path="../../etc/passwd")
        assert resp.status_code == 400
        assert "outside allowed directories" in resp.get_json().get("error", "").lower()

    def test_path_traversal_absolute_system_path(self, client):
        """Absolute system paths outside safe roots should be rejected."""
        _register_user(client)
        token, _ = _login_user(client)
        # Try a Unix-style system path
        resp = self._yara_scan_with_mock(client, token, file_path="/etc/shadow")
        assert resp.status_code == 400

        # Try a Windows-style system path
        resp2 = self._yara_scan_with_mock(client, token, file_path="C:\\Windows\\System32\\config\\SAM")
        assert resp2.status_code == 400

    def test_path_traversal_encoded(self, client):
        """URL-encoded traversal sequences should still be caught."""
        _register_user(client)
        token, _ = _login_user(client)
        # %2e%2e%2f = ../
        encoded_path = "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        resp = self._yara_scan_with_mock(client, token, file_path=encoded_path)
        assert resp.status_code == 400

    def test_path_traversal_rules_path(self, client):
        """rules_path parameter should also be validated."""
        _register_user(client)
        token, _ = _login_user(client)
        resp = self._yara_scan_with_mock(
            client,
            token,
            file_path=os.path.join(tempfile.gettempdir(), "dummy.bin"),
            rules_path="/etc/yara_rules",
        )
        assert resp.status_code == 400

    def test_valid_path_in_safe_dir(self):
        """A path within the temp directory should be accepted by _validate_path."""
        from vlair.webapp.app import _validate_path

        safe_file = os.path.join(tempfile.gettempdir(), "safe_test_file.txt")
        # Create the file so resolve() works predictably
        Path(safe_file).touch()
        try:
            result = _validate_path(safe_file)
            assert Path(result).resolve() == Path(safe_file).resolve()
        finally:
            Path(safe_file).unlink(missing_ok=True)


# ===========================================================================
# 2. Rate Limiting Tests
# ===========================================================================


class TestRateLimiting:
    """Ensure auth endpoints enforce rate limits."""

    def test_rate_limit_login_exceeded(self, client):
        """The 11th rapid login attempt should receive 429."""
        _register_user(client)
        for i in range(10):
            client.post(
                "/api/auth/login",
                json={"username": "sectest", "password": "wrong_password"},
            )
        # 11th request should be rate-limited
        resp = client.post(
            "/api/auth/login",
            json={"username": "sectest", "password": "wrong_password"},
        )
        assert resp.status_code == 429
        assert "too many requests" in resp.get_json().get("error", "").lower()

    def test_rate_limit_register_exceeded(self, client):
        """The 11th rapid register attempt should receive 429."""
        for i in range(10):
            client.post(
                "/api/auth/register",
                json={
                    "username": f"ratelimit{i}",
                    "email": f"rl{i}@test.com",
                    "password": "Str0ngP@ss!",
                },
            )
        resp = client.post(
            "/api/auth/register",
            json={
                "username": "ratelimit_final",
                "email": "rl_final@test.com",
                "password": "Str0ngP@ss!",
            },
        )
        assert resp.status_code == 429

    def test_rate_limit_resets_after_window(self, client):
        """After the rate limit window expires, requests should succeed again."""
        from vlair.webapp.auth import routes

        _register_user(client)
        # Exhaust the limit
        for i in range(10):
            client.post(
                "/api/auth/login",
                json={"username": "sectest", "password": "wrong"},
            )
        # Confirm rate-limited
        resp = client.post(
            "/api/auth/login",
            json={"username": "sectest", "password": "wrong"},
        )
        assert resp.status_code == 429

        # Simulate window expiry by clearing the store
        routes.reset_rate_limits()

        # Should succeed again (401 = not rate-limited, just wrong password)
        resp = client.post(
            "/api/auth/login",
            json={"username": "sectest", "password": "wrong"},
        )
        assert resp.status_code == 401


# ===========================================================================
# 3. Token Revocation Tests
# ===========================================================================


class TestTokenRevocation:
    """Ensure revoked and deactivated tokens are rejected."""

    def test_revoked_token_rejected(self, client):
        """A token that has been explicitly revoked should return 401."""
        from vlair.webapp.auth.models import revoke_token
        from vlair.webapp.auth.utils import decode_token

        _register_user(client)
        token, _ = _login_user(client)

        # Verify token works before revocation
        resp = client.get("/api/auth/me", headers=_auth_header(token))
        assert resp.status_code == 200

        # Revoke the token
        payload = decode_token(token)
        revoke_token(payload["jti"], payload["sub"], str(payload["exp"]))

        # Token should now be rejected
        resp = client.get("/api/auth/me", headers=_auth_header(token))
        assert resp.status_code == 401
        assert "revoked" in resp.get_json().get("error", "").lower()

    def test_deactivated_user_tokens_rejected(self, client):
        """Deactivating a user should make their existing tokens return 401."""
        from vlair.webapp.auth.models import deactivate_user, get_user_by_username

        _register_user(client)
        token, _ = _login_user(client)

        # Verify token works
        resp = client.get("/api/auth/me", headers=_auth_header(token))
        assert resp.status_code == 200

        # Deactivate the user
        user = get_user_by_username("sectest")
        deactivate_user(user["id"])

        # Token should now fail
        resp = client.get("/api/auth/me", headers=_auth_header(token))
        assert resp.status_code == 401


# ===========================================================================
# 4. Auth Bypass Tests
# ===========================================================================


class TestAuthBypass:
    """Ensure various authentication bypass attempts are blocked."""

    def test_malformed_jwt_rejected(self, client):
        """Garbage in the Authorization header should return 401."""
        resp = client.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer this.is.garbage"},
        )
        assert resp.status_code == 401

    def test_completely_invalid_auth_header(self, client):
        """A non-Bearer auth scheme should return 401."""
        resp = client.get(
            "/api/auth/me",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert resp.status_code == 401

    def test_expired_token_rejected(self, client):
        """A token with a past expiry should be rejected."""
        from vlair.webapp.auth.utils import _encode_jwt

        payload = {
            "sub": 999,
            "role": "analyst",
            "type": "access",
            "jti": "expired-test-jti",
            "iat": int(time.time()) - 3600,
            "exp": int(time.time()) - 1800,  # Expired 30 minutes ago
        }
        expired_token = _encode_jwt(payload)
        resp = client.get("/api/auth/me", headers=_auth_header(expired_token))
        assert resp.status_code == 401

    def test_wrong_token_type_refresh_as_access(self, client):
        """Using a refresh token as an access token should be rejected."""
        from vlair.webapp.auth.utils import create_refresh_token

        _register_user(client)
        token, _ = _login_user(client)

        # Get the user ID from a real login
        from vlair.webapp.auth.models import get_user_by_username

        user = get_user_by_username("sectest")
        refresh = create_refresh_token(user["id"])

        # Try to use refresh token to access a protected endpoint
        resp = client.get("/api/auth/me", headers=_auth_header(refresh))
        assert resp.status_code == 401

    def test_missing_auth_header(self, client):
        """Hitting a protected endpoint without Authorization should return 401."""
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401
        assert "authentication required" in resp.get_json().get("error", "").lower()

    def test_empty_bearer_token(self, client):
        """An empty Bearer token should return 401."""
        resp = client.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer "},
        )
        assert resp.status_code == 401


# ===========================================================================
# 5. HTTP Security Headers
# ===========================================================================


class TestSecurityHeaders:
    """Ensure security headers are set on responses."""

    def test_security_headers_present(self, client):
        """Verify all required security headers on a response."""
        # Use a public endpoint (404 is fine; headers are set via after_request)
        resp = client.get("/api/auth/me")
        headers = resp.headers

        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-XSS-Protection") == "1; mode=block"
        assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "Content-Security-Policy" in headers
        assert "default-src 'self'" in headers.get("Content-Security-Policy", "")

    def test_security_headers_on_error_responses(self, client):
        """Security headers should be present even on 404 responses."""
        resp = client.get("/api/nonexistent-endpoint")
        assert resp.status_code == 404
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"


# ===========================================================================
# 6. TOTP Brute Force Tests
# ===========================================================================


class TestTOTPBruteForce:
    """Ensure TOTP brute force is mitigated by rate limiting."""

    def test_totp_invalid_codes_rejected(self, client):
        """Submitting wrong TOTP codes at login should not grant access."""
        pytest.importorskip("pyotp", reason="pyotp not installed")
        from vlair.webapp.auth.models import get_user_by_username, set_mfa_secret, enable_mfa

        _register_user(client)
        user = get_user_by_username("sectest")

        secret = "JBSWY3DPEHPK3PXP"
        set_mfa_secret(user["id"], secret)
        enable_mfa(user["id"])

        # Mock verify_totp to always return False, simulating wrong codes
        with patch("vlair.webapp.auth.routes.verify_totp", return_value=False):
            with patch("vlair.webapp.auth.routes.verify_backup_code", return_value=False):
                for bad_code in ["000000", "111111", "222222", "999999"]:
                    resp = client.post(
                        "/api/auth/login",
                        json={
                            "username": "sectest",
                            "password": "Str0ngP@ss!",
                            "totp_code": bad_code,
                        },
                    )
                    data = resp.get_json()
                    # Should not grant access tokens with a wrong TOTP code
                    assert "access_token" not in data, f"Bad TOTP code {bad_code} should not grant access"
                    assert resp.status_code == 401

    def test_totp_rate_limit_applies(self, client):
        """TOTP brute force attempts should eventually hit the rate limiter."""
        pyotp = pytest.importorskip("pyotp", reason="pyotp not installed")
        from vlair.webapp.auth.models import get_user_by_username, set_mfa_secret, enable_mfa

        _register_user(client)
        user = get_user_by_username("sectest")
        secret = pyotp.random_base32()
        set_mfa_secret(user["id"], secret)
        enable_mfa(user["id"])

        # Exhaust the rate limit (10 attempts)
        for i in range(10):
            client.post(
                "/api/auth/login",
                json={
                    "username": "sectest",
                    "password": "Str0ngP@ss!",
                    "totp_code": f"{i:06d}",
                },
            )

        # 11th attempt should be rate-limited
        resp = client.post(
            "/api/auth/login",
            json={
                "username": "sectest",
                "password": "Str0ngP@ss!",
                "totp_code": "999999",
            },
        )
        assert resp.status_code == 429
