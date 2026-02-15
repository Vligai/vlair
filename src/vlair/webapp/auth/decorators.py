"""
RBAC decorators for Flask routes.

Usage
-----
    from vlair.webapp.auth.decorators import require_auth, require_role
    from vlair.webapp.auth.models import Role

    @app.route("/api/hash/lookup", methods=["POST"])
    @require_auth          # any authenticated user
    def lookup_hashes():
        user = g.current_user
        ...

    @app.route("/api/admin/users", methods=["GET"])
    @require_role(Role.ADMIN)
    def list_users():
        ...

Authentication order of precedence
-----------------------------------
1. Bearer JWT in Authorization header
2. ``X-API-Key`` header
3. ``api_key`` query parameter  (for tool integrations)

All authenticated requests are written to the audit log.
"""

import functools
from flask import request, jsonify, g

from vlair.webapp.auth.models import (
    Role,
    get_user_by_id,
    lookup_api_key,
    log_action,
)
from vlair.webapp.auth.utils import verify_access_token


def _extract_token() -> tuple[str | None, str]:
    """
    Try to extract credentials from the request.

    Returns (raw_credential, credential_type) where credential_type is
    "bearer" | "apikey" | "none".
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip(), "bearer"

    api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if api_key:
        return api_key, "apikey"

    return None, "none"


def _resolve_user():
    """
    Attempt to identify the calling user from request credentials.

    Sets ``g.current_user`` (dict) and ``g.auth_type`` ("bearer"/"apikey").
    Returns an error JSON response tuple on failure, else None.
    """
    cred, cred_type = _extract_token()

    if cred is None:
        return jsonify({"error": "Authentication required"}), 401

    if cred_type == "bearer":
        payload = verify_access_token(cred)
        if payload is None:
            return jsonify({"error": "Invalid or expired token"}), 401
        user = get_user_by_id(int(payload["sub"]))
        if user is None or not user["is_active"]:
            return jsonify({"error": "Account not found or disabled"}), 401
        g.current_user = user
        g.auth_type = "bearer"
        return None

    if cred_type == "apikey":
        key_info = lookup_api_key(cred)
        if key_info is None:
            return jsonify({"error": "Invalid or expired API key"}), 401
        user = get_user_by_id(key_info["user_id"])
        if user is None or not user["is_active"]:
            return jsonify({"error": "Account not found or disabled"}), 401
        g.current_user = user
        g.auth_type = "apikey"
        return None

    return jsonify({"error": "Authentication required"}), 401


def _write_audit(status_code: int = 200) -> None:
    """Write audit log entry for the current request (best-effort)."""
    user = getattr(g, "current_user", None)
    log_action(
        action=f"{request.method} {request.path}",
        user_id=user["id"] if user else None,
        username=user["username"] if user else None,
        resource=request.path,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
        status_code=status_code,
    )


# ---------------------------------------------------------------------------
# Public decorators
# ---------------------------------------------------------------------------


def require_auth(fn):
    """
    Require any valid authenticated user.
    Sets ``g.current_user`` before calling the wrapped function.
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        err = _resolve_user()
        if err is not None:
            _write_audit(err[1])
            return err
        try:
            response = fn(*args, **kwargs)
            _write_audit(getattr(response, "status_code", 200))
            return response
        except Exception:
            _write_audit(500)
            raise

    return wrapper


def require_role(minimum_role: Role):
    """
    Require a minimum role level.  Implies ``@require_auth``.

    Example::

        @require_role(Role.ADMIN)
        def admin_endpoint(): ...
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            err = _resolve_user()
            if err is not None:
                _write_audit(err[1])
                return err
            user_role = Role(g.current_user["role"])
            if not user_role.has_at_least(minimum_role):
                _write_audit(403)
                return (
                    jsonify(
                        {
                            "error": "Insufficient permissions",
                            "required": minimum_role.value,
                            "current": user_role.value,
                        }
                    ),
                    403,
                )
            try:
                response = fn(*args, **kwargs)
                _write_audit(getattr(response, "status_code", 200))
                return response
            except Exception:
                _write_audit(500)
                raise

        return wrapper

    return decorator
