"""
Auth utilities: JWT token creation/verification, TOTP helpers.

JWT design
----------
- Access token:  15 min TTL, contains {sub, role, type="access"}
- Refresh token: 7 day TTL, contains {sub, type="refresh"}
- Both are HS256 signed with SECRET_KEY from env

TOTP (optional MFA)
-------------------
Requires the ``pyotp`` package.  If not installed, MFA endpoints return 501.
"""

import os
import time
import base64
import hashlib
import hmac
import json
import struct
from datetime import datetime, timezone
from typing import Optional, Dict

# -----------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------

SECRET_KEY: str = os.getenv("VLAIR_SECRET_KEY", "change-me-in-production")
ACCESS_TOKEN_TTL: int = int(os.getenv("VLAIR_ACCESS_TTL", "900"))  # 15 min
REFRESH_TOKEN_TTL: int = int(os.getenv("VLAIR_REFRESH_TTL", "604800"))  # 7 days

# -----------------------------------------------------------------------
# Minimal JWT implementation (no external deps required)
# -----------------------------------------------------------------------
# We implement HS256 JWT from scratch so that PyJWT is *optional*.
# If PyJWT is available we use it; otherwise we fall back to the built-in.

try:
    import jwt as _pyjwt

    def _encode_jwt(payload: dict) -> str:
        return _pyjwt.encode(payload, SECRET_KEY, algorithm="HS256")

    def _decode_jwt(token: str) -> dict:
        return _pyjwt.decode(token, SECRET_KEY, algorithms=["HS256"])

except ImportError:

    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _b64url_decode(s: str) -> bytes:
        pad = 4 - len(s) % 4
        return base64.urlsafe_b64decode(s + "=" * (pad % 4))

    def _encode_jwt(payload: dict) -> str:
        header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        body = _b64url_encode(json.dumps(payload).encode())
        sig_input = f"{header}.{body}".encode()
        sig = hmac.new(SECRET_KEY.encode(), sig_input, hashlib.sha256).digest()
        return f"{header}.{body}.{_b64url_encode(sig)}"

    def _decode_jwt(token: str) -> dict:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError("Malformed token")
            header_b, body_b, sig_b = parts
            sig_input = f"{header_b}.{body_b}".encode()
            expected_sig = hmac.new(SECRET_KEY.encode(), sig_input, hashlib.sha256).digest()
            provided_sig = _b64url_decode(sig_b)
            if not hmac.compare_digest(expected_sig, provided_sig):
                raise ValueError("Invalid signature")
            payload = json.loads(_b64url_decode(body_b))
            if "exp" in payload and time.time() > payload["exp"]:
                raise ValueError("Token expired")
            return payload
        except (ValueError, KeyError) as exc:
            raise ValueError(str(exc)) from exc


# -----------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------


def create_access_token(user_id: int, role: str) -> str:
    """Return a signed JWT access token valid for ACCESS_TOKEN_TTL seconds."""
    now = int(time.time())
    payload = {
        "sub": user_id,
        "role": role,
        "type": "access",
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
    }
    return _encode_jwt(payload)


def create_refresh_token(user_id: int) -> str:
    """Return a signed JWT refresh token valid for REFRESH_TOKEN_TTL seconds."""
    now = int(time.time())
    payload = {
        "sub": user_id,
        "type": "refresh",
        "iat": now,
        "exp": now + REFRESH_TOKEN_TTL,
    }
    return _encode_jwt(payload)


def decode_token(token: str) -> Optional[Dict]:
    """
    Decode and verify a JWT.  Returns payload dict or None if invalid/expired.
    """
    try:
        return _decode_jwt(token)
    except Exception:
        return None


def verify_access_token(token: str) -> Optional[Dict]:
    """Verify an access token; return payload or None."""
    payload = decode_token(token)
    if payload and payload.get("type") == "access":
        return payload
    return None


def verify_refresh_token(token: str) -> Optional[Dict]:
    """Verify a refresh token; return payload or None."""
    payload = decode_token(token)
    if payload and payload.get("type") == "refresh":
        return payload
    return None


# -----------------------------------------------------------------------
# TOTP helpers (optional dependency: pyotp)
# -----------------------------------------------------------------------

try:
    import pyotp as _pyotp

    _PYOTP_AVAILABLE = True
except ImportError:
    _PYOTP_AVAILABLE = False


def totp_available() -> bool:
    return _PYOTP_AVAILABLE


def generate_totp_secret() -> str:
    """Generate a new random TOTP base32 secret."""
    if not _PYOTP_AVAILABLE:
        raise RuntimeError("pyotp is not installed. Run: pip install pyotp")
    return _pyotp.random_base32()


def get_totp_provisioning_uri(secret: str, username: str, issuer: str = "vlair") -> str:
    """Return an otpauth:// URI suitable for QR code generation."""
    if not _PYOTP_AVAILABLE:
        raise RuntimeError("pyotp is not installed. Run: pip install pyotp")
    totp = _pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    """Return True if the 6-digit TOTP code is valid (±1 window)."""
    if not _PYOTP_AVAILABLE:
        return False
    totp = _pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)
