"""
Authentication Blueprint: /api/auth/*

Endpoints
---------
POST /api/auth/register          - create account (admin or open-registration if enabled)
POST /api/auth/login             - exchange credentials for tokens
POST /api/auth/refresh           - exchange refresh token for new access token
POST /api/auth/logout            - revoke current session (client drops tokens)
GET  /api/auth/me                - current user profile
PUT  /api/auth/me/password       - change own password
POST /api/auth/mfa/setup         - initiate TOTP setup (returns secret + QR URI)
POST /api/auth/mfa/verify        - confirm TOTP code and enable MFA
DELETE /api/auth/mfa             - disable MFA (requires password confirmation)
POST /api/auth/mfa/backup-codes  - regenerate backup codes (requires password confirmation)

POST /api/auth/keys              - create API key
GET  /api/auth/keys              - list own API keys
DELETE /api/auth/keys/<key_id>   - revoke API key

GET  /api/admin/users            - list all users (ADMIN only)
PUT  /api/admin/users/<id>/role  - change role (ADMIN only)
PUT  /api/admin/users/<id>/activate   - activate user (ADMIN only)
PUT  /api/admin/users/<id>/deactivate - deactivate user (ADMIN only)

GET  /api/admin/audit            - query audit log (ADMIN / SENIOR_ANALYST)
"""

import os
import time
import threading
from collections import defaultdict
from flask import Blueprint, request, jsonify, g

from vlair.webapp.auth.models import (
    Role,
    init_db,
    create_user,
    get_user_by_username,
    get_user_by_email,
    get_user_by_id,
    authenticate_user,
    update_user_role,
    activate_user,
    deactivate_user,
    list_users,
    create_api_key,
    list_api_keys,
    revoke_api_key,
    set_mfa_secret,
    enable_mfa,
    disable_mfa,
    get_mfa_secret,
    generate_backup_codes,
    verify_backup_code,
    get_backup_code_count,
    delete_backup_codes,
    get_audit_log,
    log_action,
)
from vlair.webapp.auth.utils import (
    create_access_token,
    create_refresh_token,
    verify_refresh_token,
    totp_available,
    generate_totp_secret,
    get_totp_provisioning_uri,
    verify_totp,
)
from vlair.webapp.auth.decorators import require_auth, require_role

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")
admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

# Whether anyone can register, or only admins can create accounts
OPEN_REGISTRATION = os.getenv("VLAIR_OPEN_REGISTRATION", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Rate limiter — Redis-backed (sliding window) with in-memory fallback.
#
# Redis is preferred because each gunicorn worker has independent in-memory
# state, meaning the effective limit under N workers is N × the configured
# value.  With Redis the counter is shared across all workers and processes.
#
# Falls back to the in-memory implementation automatically when Redis is
# unavailable (no REDIS_URL set, connection refused, etc.).
# ---------------------------------------------------------------------------

# Max attempts per IP within the window
_AUTH_RATE_LIMIT = int(os.getenv("VLAIR_AUTH_RATE_LIMIT", "10"))
_AUTH_RATE_WINDOW = int(os.getenv("VLAIR_AUTH_RATE_WINDOW", "300"))  # 5 min

# ---------------------------------------------------------------------------
# Redis client (lazy, optional)
# ---------------------------------------------------------------------------

_redis_client = None
_redis_available: bool = False
_redis_init_lock = threading.Lock()


def _get_redis():
    """Return a connected Redis client, or None if Redis is unavailable."""
    global _redis_client, _redis_available
    if _redis_client is not None:
        return _redis_client if _redis_available else None
    with _redis_init_lock:
        if _redis_client is not None:
            return _redis_client if _redis_available else None
        redis_url = os.getenv("REDIS_URL", "")
        if not redis_url:
            _redis_available = False
            return None
        try:
            import redis as _redis_lib

            client = _redis_lib.from_url(redis_url, socket_connect_timeout=2, decode_responses=True)
            client.ping()
            _redis_client = client
            _redis_available = True
        except Exception:
            _redis_available = False
    return _redis_client if _redis_available else None


# ---------------------------------------------------------------------------
# In-memory fallback
# ---------------------------------------------------------------------------

_rate_limit_store: dict = defaultdict(list)
_rate_limit_lock = threading.Lock()


def _check_rate_limit_memory(ip: str) -> bool:
    now = time.time()
    cutoff = now - _AUTH_RATE_WINDOW
    with _rate_limit_lock:
        attempts = _rate_limit_store[ip]
        _rate_limit_store[ip] = [t for t in attempts if t > cutoff]
        if len(_rate_limit_store[ip]) >= _AUTH_RATE_LIMIT:
            return False
        _rate_limit_store[ip].append(now)
        return True


def _check_rate_limit_redis(ip: str, r) -> bool:
    """Sliding-window rate limit using a Redis sorted set."""
    key = f"vlair:rl:auth:{ip}"
    now = time.time()
    cutoff = now - _AUTH_RATE_WINDOW
    try:
        pipe = r.pipeline()
        pipe.zremrangebyscore(key, 0, cutoff)
        pipe.zadd(key, {f"{now}:{id(pipe)}": now})
        pipe.zcard(key)
        pipe.expire(key, _AUTH_RATE_WINDOW)
        results = pipe.execute()
        count = results[2]
        return count <= _AUTH_RATE_LIMIT
    except Exception:
        # Redis error mid-request — fall back to memory for this call
        return _check_rate_limit_memory(ip)


def _check_rate_limit(ip: str) -> bool:
    """Return True if the IP is within rate limits, False if exceeded."""
    r = _get_redis()
    if r is not None:
        return _check_rate_limit_redis(ip, r)
    return _check_rate_limit_memory(ip)


def reset_rate_limits() -> None:
    """Clear all rate limit state. Intended for testing."""
    with _rate_limit_lock:
        _rate_limit_store.clear()
    r = _get_redis()
    if r is not None:
        try:
            for key in r.scan_iter("vlair:rl:auth:*"):
                r.delete(key)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


@auth_bp.post("/register")
def register():
    """
    Create a new account.

    Body: {"username": str, "email": str, "password": str}
    New accounts are given the "analyst" role by default.

    Requires ADMIN auth if VLAIR_OPEN_REGISTRATION=false.
    """
    if not _check_rate_limit(request.remote_addr):
        return jsonify({"error": "Too many requests. Try again later."}), 429

    if not OPEN_REGISTRATION:
        # Require existing admin token
        from vlair.webapp.auth.decorators import _resolve_user

        err = _resolve_user()
        if err:
            return err
        if Role(g.current_user["role"]) != Role.ADMIN:
            return jsonify({"error": "Only admins can create accounts"}), 403

    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400

    try:
        user = create_user(username, email, password)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409

    log_action("register", username=user["username"], ip_address=request.remote_addr)
    return jsonify({"message": "Account created", "user": user}), 201


# ---------------------------------------------------------------------------
# Login / token issuance
# ---------------------------------------------------------------------------


@auth_bp.post("/login")
def login():
    """
    Exchange credentials for access + refresh tokens.

    Body: {"username": str, "password": str, "totp_code": str (if MFA enabled)}
    """
    if not _check_rate_limit(request.remote_addr):
        return jsonify({"error": "Too many requests. Try again later."}), 429

    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    user = authenticate_user(username, password)
    if user is None:
        log_action(
            "login_failed",
            username=username,
            ip_address=request.remote_addr,
            status_code=401,
        )
        return jsonify({"error": "Invalid credentials"}), 401

    if not user["is_active"]:
        return jsonify({"error": "Account is disabled"}), 403

    # MFA check
    if user["mfa_enabled"]:
        totp_code = (data.get("totp_code") or "").strip()
        if not totp_code:
            return jsonify({"error": "TOTP code required", "mfa_required": True}), 200
        secret = get_mfa_secret(user["id"])
        totp_ok = secret and verify_totp(secret, totp_code)
        backup_ok = False
        if not totp_ok:
            # Try as a one-time backup code
            backup_ok = verify_backup_code(user["id"], totp_code)
        if not totp_ok and not backup_ok:
            log_action(
                "login_mfa_failed",
                user_id=user["id"],
                username=user["username"],
                ip_address=request.remote_addr,
                status_code=401,
            )
            return jsonify({"error": "Invalid TOTP code"}), 401
        if backup_ok:
            remaining = get_backup_code_count(user["id"])
            log_action(
                "login_backup_code",
                user_id=user["id"],
                username=user["username"],
                ip_address=request.remote_addr,
                detail=f"backup_codes_remaining={remaining}",
            )

    access_token = create_access_token(user["id"], user["role"])
    refresh_token = create_refresh_token(user["id"])

    log_action(
        "login",
        user_id=user["id"],
        username=user["username"],
        ip_address=request.remote_addr,
        status_code=200,
    )
    return jsonify(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "user": user,
        }
    )


@auth_bp.post("/refresh")
def refresh():
    """Exchange a valid refresh token for a new access token."""
    if not _check_rate_limit(request.remote_addr):
        return jsonify({"error": "Too many requests. Try again later."}), 429

    data = request.get_json(force=True) or {}
    refresh_token = data.get("refresh_token", "")
    payload = verify_refresh_token(refresh_token)
    if payload is None:
        return jsonify({"error": "Invalid or expired refresh token"}), 401

    user = get_user_by_id(int(payload["sub"]))
    if user is None or not user["is_active"]:
        return jsonify({"error": "Account not found or disabled"}), 401

    new_access = create_access_token(user["id"], user["role"])
    return jsonify({"access_token": new_access, "token_type": "Bearer"})


@auth_bp.post("/logout")
@require_auth
def logout():
    """
    Invalidate session.
    JWT tokens are stateless; the client must discard both tokens.
    (Future: add token revocation list backed by Redis.)
    """
    log_action(
        "logout",
        user_id=g.current_user["id"],
        username=g.current_user["username"],
        ip_address=request.remote_addr,
    )
    return jsonify({"message": "Logged out successfully"})


# ---------------------------------------------------------------------------
# Current user profile
# ---------------------------------------------------------------------------


@auth_bp.get("/me")
@require_auth
def me():
    """Return the current user's profile."""
    user = get_user_by_id(g.current_user["id"])
    return jsonify({"user": user})


@auth_bp.put("/me/password")
@require_auth
def change_password():
    """
    Change own password.

    Body: {"current_password": str, "new_password": str}
    """
    from vlair.webapp.auth.models import (
        authenticate_user,
        _hash_password,
        _connect,
        revoke_all_user_tokens,
    )

    data = request.get_json(force=True) or {}
    current_pw = data.get("current_password", "")
    new_pw = data.get("new_password", "")

    if not current_pw or not new_pw:
        return jsonify({"error": "current_password and new_password required"}), 400
    if len(new_pw) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400

    # Verify current password
    verified = authenticate_user(g.current_user["username"], current_pw)
    if verified is None:
        return jsonify({"error": "Current password is incorrect"}), 401

    new_hash = _hash_password(new_pw)
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, g.current_user["id"]),
        )

    # Invalidate all active sessions so compromised tokens cannot be reused
    revoke_all_user_tokens(g.current_user["id"])

    log_action(
        "password_changed",
        user_id=g.current_user["id"],
        username=g.current_user["username"],
        ip_address=request.remote_addr,
    )
    return jsonify({"message": "Password changed. All active sessions have been invalidated. Please log in again."})


# ---------------------------------------------------------------------------
# MFA setup
# ---------------------------------------------------------------------------


@auth_bp.post("/mfa/setup")
@require_auth
def mfa_setup():
    """
    Begin TOTP MFA enrollment.

    Returns a secret + provisioning URI for QR code generation.
    The secret is stored but MFA is NOT yet enabled until /mfa/verify is called.
    """
    if not totp_available():
        return jsonify({"error": "MFA not available (install pyotp)"}), 501

    secret = generate_totp_secret()
    set_mfa_secret(g.current_user["id"], secret)
    uri = get_totp_provisioning_uri(secret, g.current_user["username"])

    return jsonify(
        {
            "secret": secret,
            "provisioning_uri": uri,
            "instructions": "Scan the QR code with your authenticator app, then call POST /api/auth/mfa/verify with a 6-digit code to activate MFA.",
        }
    )


@auth_bp.post("/mfa/verify")
@require_auth
def mfa_verify():
    """
    Confirm TOTP setup by verifying a live code and enable MFA.

    Body: {"totp_code": "123456"}
    """
    if not totp_available():
        return jsonify({"error": "MFA not available (install pyotp)"}), 501

    data = request.get_json(force=True) or {}
    code = (data.get("totp_code") or "").strip()
    if not code:
        return jsonify({"error": "totp_code is required"}), 400

    secret = get_mfa_secret(g.current_user["id"])
    if not secret:
        return (
            jsonify({"error": "MFA setup not initiated. Call POST /api/auth/mfa/setup first."}),
            400,
        )

    if not verify_totp(secret, code):
        return jsonify({"error": "Invalid TOTP code"}), 400

    enable_mfa(g.current_user["id"])
    backup_codes = generate_backup_codes(g.current_user["id"])
    log_action(
        "mfa_enabled",
        user_id=g.current_user["id"],
        username=g.current_user["username"],
        ip_address=request.remote_addr,
    )
    return jsonify(
        {
            "message": "MFA enabled successfully",
            "backup_codes": backup_codes,
            "backup_codes_message": "Save these backup codes in a safe place. Each code can only be used once. They will not be shown again.",
        }
    )


@auth_bp.delete("/mfa")
@require_auth
def mfa_disable():
    """
    Disable MFA.  Requires password confirmation as a second factor.

    Body: {"password": str}
    """
    data = request.get_json(force=True) or {}
    password = data.get("password", "")

    if not authenticate_user(g.current_user["username"], password):
        return jsonify({"error": "Password confirmation failed"}), 401

    disable_mfa(g.current_user["id"])
    delete_backup_codes(g.current_user["id"])
    log_action(
        "mfa_disabled",
        user_id=g.current_user["id"],
        username=g.current_user["username"],
        ip_address=request.remote_addr,
    )
    return jsonify({"message": "MFA disabled"})


@auth_bp.post("/mfa/backup-codes")
@require_auth
def mfa_regenerate_backup_codes():
    """
    Regenerate MFA backup codes.  Requires password confirmation.

    Body: {"password": str}

    Replaces any existing unused codes with a fresh set of 10.
    The plaintext codes are returned ONCE and not stored.
    """
    data = request.get_json(force=True) or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "password is required"}), 400

    if not authenticate_user(g.current_user["username"], password):
        return jsonify({"error": "Password confirmation failed"}), 401

    user = get_user_by_id(g.current_user["id"])
    if not user or not user["mfa_enabled"]:
        return jsonify({"error": "MFA is not enabled on this account"}), 400

    codes = generate_backup_codes(g.current_user["id"])
    log_action(
        "backup_codes_regenerated",
        user_id=g.current_user["id"],
        username=g.current_user["username"],
        ip_address=request.remote_addr,
    )
    return jsonify(
        {
            "message": "Backup codes regenerated. Save these codes - they will not be shown again.",
            "backup_codes": codes,
        }
    )


# ---------------------------------------------------------------------------
# API key management
# ---------------------------------------------------------------------------


@auth_bp.post("/keys")
@require_auth
def create_key():
    """
    Create a new API key for the current user.

    Body: {"name": str, "expires_at": "2026-12-31T00:00:00" (optional)}

    The plaintext key is returned ONCE and not stored.
    """
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    expires_at = data.get("expires_at")

    if not name:
        return jsonify({"error": "name is required"}), 400

    raw_key = create_api_key(g.current_user["id"], name, expires_at=expires_at)
    log_action(
        "api_key_created",
        user_id=g.current_user["id"],
        username=g.current_user["username"],
        detail=f"key_name={name}",
        ip_address=request.remote_addr,
    )
    return (
        jsonify(
            {
                "message": "API key created. Save this key - it will not be shown again.",
                "api_key": raw_key,
                "name": name,
            }
        ),
        201,
    )


@auth_bp.get("/keys")
@require_auth
def get_keys():
    """List current user's API keys (no plaintext keys - prefix only)."""
    keys = list_api_keys(g.current_user["id"])
    return jsonify({"keys": keys})


@auth_bp.delete("/keys/<int:key_id>")
@require_auth
def delete_key(key_id: int):
    """Revoke an API key (enforces ownership)."""
    revoked = revoke_api_key(key_id, g.current_user["id"])
    if not revoked:
        return jsonify({"error": "Key not found or not owned by you"}), 404
    log_action(
        "api_key_revoked",
        user_id=g.current_user["id"],
        username=g.current_user["username"],
        detail=f"key_id={key_id}",
        ip_address=request.remote_addr,
    )
    return jsonify({"message": "API key revoked"})


# ---------------------------------------------------------------------------
# Admin: user management
# ---------------------------------------------------------------------------


@admin_bp.get("/users")
@require_role(Role.ADMIN)
def admin_list_users():
    """List all user accounts."""
    return jsonify({"users": list_users()})


@admin_bp.put("/users/<int:user_id>/role")
@require_role(Role.ADMIN)
def admin_change_role(user_id: int):
    """Change a user's role. Body: {"role": "analyst"}"""
    data = request.get_json(force=True) or {}
    role_str = data.get("role", "")
    try:
        new_role = Role(role_str)
    except ValueError:
        valid = [r.value for r in Role]
        return jsonify({"error": f"Invalid role. Valid: {valid}"}), 400

    target = get_user_by_id(user_id)
    if target is None:
        return jsonify({"error": "User not found"}), 404

    update_user_role(user_id, new_role)
    log_action(
        "role_changed",
        user_id=g.current_user["id"],
        username=g.current_user["username"],
        detail=f"target_user={target['username']} new_role={new_role.value}",
        ip_address=request.remote_addr,
    )
    return jsonify({"message": f"Role updated to {new_role.value}", "user_id": user_id})


@admin_bp.put("/users/<int:user_id>/deactivate")
@require_role(Role.ADMIN)
def admin_deactivate(user_id: int):
    """Deactivate a user account."""
    target = get_user_by_id(user_id)
    if target is None:
        return jsonify({"error": "User not found"}), 404
    deactivate_user(user_id)
    log_action(
        "user_deactivated",
        user_id=g.current_user["id"],
        username=g.current_user["username"],
        detail=f"target_user={target['username']}",
        ip_address=request.remote_addr,
    )
    return jsonify({"message": "User deactivated"})


@admin_bp.put("/users/<int:user_id>/activate")
@require_role(Role.ADMIN)
def admin_activate(user_id: int):
    """Reactivate a user account."""
    target = get_user_by_id(user_id)
    if target is None:
        return jsonify({"error": "User not found"}), 404
    activate_user(user_id)
    log_action(
        "user_activated",
        user_id=g.current_user["id"],
        username=g.current_user["username"],
        detail=f"target_user={target['username']}",
        ip_address=request.remote_addr,
    )
    return jsonify({"message": "User activated"})


# ---------------------------------------------------------------------------
# Admin: audit log
# ---------------------------------------------------------------------------


@admin_bp.get("/audit")
@require_role(Role.SENIOR_ANALYST)
def admin_audit():
    """
    Query the audit log.

    Query params: user_id, limit (default 100), offset (default 0)
    """
    user_id = request.args.get("user_id", type=int)
    limit = min(request.args.get("limit", 100, type=int), 1000)
    offset = request.args.get("offset", 0, type=int)
    entries = get_audit_log(user_id=user_id, limit=limit, offset=offset)
    return jsonify({"audit_log": entries, "count": len(entries)})
