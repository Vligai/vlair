"""Authentication package for the vlair web application."""

from vlair.webapp.auth.models import Role, init_db, revoke_token, is_token_revoked
from vlair.webapp.auth.decorators import require_auth, require_role
from vlair.webapp.auth.routes import auth_bp, admin_bp

__all__ = [
    "Role",
    "init_db",
    "require_auth",
    "require_role",
    "auth_bp",
    "admin_bp",
    "revoke_token",
    "is_token_revoked",
]
