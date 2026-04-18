"""Authentication and authorization middleware for ARGUS web API.

Supports three auth modes (checked in order):
1. User session token (argus_sess_*) — username/password login sessions
2. Database API keys with role-based access control (admin/operator/viewer)
3. Legacy bearer token (ARGUS_WEB_TOKEN) — backwards compatible

Role permissions:
- admin: Full access (manage keys, targets, scans, view all)
- operator: Run scans, manage targets, view results
- viewer: View results only (read-only endpoints)
"""

from __future__ import annotations

import logging
import os
import secrets
from enum import Enum

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)

_bearer_scheme = HTTPBearer(auto_error=False)


class Role(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


# Permission matrix — which roles can access which operation types
_ROLE_PERMISSIONS: dict[str, set[Role]] = {
    "admin": {Role.ADMIN},
    "write": {Role.ADMIN, Role.OPERATOR},
    "read": {Role.ADMIN, Role.OPERATOR, Role.VIEWER},
}


class AuthContext:
    """Authentication context attached to each request."""

    def __init__(
        self,
        authenticated: bool = False,
        role: Role = Role.VIEWER,
        key_name: str = "",
        key_id: str = "",
        auth_method: str = "none",
    ) -> None:
        self.authenticated = authenticated
        self.role = role
        self.key_name = key_name
        self.key_id = key_id
        self.auth_method = auth_method

    def has_permission(self, operation: str) -> bool:
        """Check if this auth context has permission for an operation type."""
        if not self.authenticated:
            return False
        allowed_roles = _ROLE_PERMISSIONS.get(operation, set())
        return self.role in allowed_roles


def _get_legacy_token() -> str:
    """Get the legacy bearer token (backwards compatible)."""
    return os.environ.get("ARGUS_WEB_TOKEN", "").strip()


async def authenticate(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> AuthContext:
    """Authenticate a request using bearer token or API key.

    Accepts token via:
      1. Authorization: Bearer <token>  (standard)
      2. X-Argus-Token: <token>         (fallback for proxied environments)

    Tries database API key first, falls back to legacy token.
    """
    # Try X-Argus-Token header first (works through reverse proxies that
    # override the Authorization header, e.g. basic-auth tunnels).
    alt_token = request.headers.get("X-Argus-Token", "").strip()
    if alt_token:
        token = alt_token
    elif credentials is not None and credentials.scheme.lower() == "bearer":
        token = credentials.credentials
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Try user session token first (argus_sess_* prefix)
    if token.startswith("argus_sess_"):
        try:
            from argus.db.repository import UserRepository

            repo = UserRepository()
            try:
                user_info = repo.validate_session(token)
            finally:
                repo.close()
            if user_info:
                return AuthContext(
                    authenticated=True,
                    role=Role(user_info["role"]),
                    key_name=user_info.get("display_name") or user_info["username"],
                    key_id=user_info["id"],
                    auth_method="user_session",
                )
        except Exception:  # noqa: S110
            pass
        # Session token format but invalid — don't fall through to API key check
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Try database API key
    try:
        from argus.db.repository import APIKeyRepository

        repo = APIKeyRepository()
        try:
            key_info = repo.authenticate(token)
        finally:
            repo.close()
        if key_info:
            return AuthContext(
                authenticated=True,
                role=Role(key_info["role"]),
                key_name=key_info["name"],
                key_id=key_info["id"],
                auth_method="api_key",
            )
    except Exception:  # noqa: S110
        # Database not initialized or other error — fall through to legacy
        pass

    # Fall back to legacy token
    legacy_token = _get_legacy_token()
    if legacy_token and secrets.compare_digest(token, legacy_token):
        return AuthContext(
            authenticated=True,
            role=Role.ADMIN,  # Legacy token gets full access
            key_name="legacy_token",
            auth_method="legacy_token",
        )

    # Check the auto-generated token from server module
    try:
        from argus.web.server import WEB_TOKEN

        if secrets.compare_digest(token, WEB_TOKEN):
            return AuthContext(
                authenticated=True,
                role=Role.ADMIN,
                key_name="auto_generated",
                auth_method="auto_generated",
            )
    except ImportError:
        pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token or API key",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(operation: str):
    """Dependency that checks role-based access for an operation type.

    Usage:
        @app.post("/api/scans", dependencies=[Depends(require_role("write"))])
    """

    async def _check(auth: AuthContext = Depends(authenticate)) -> AuthContext:
        if not auth.has_permission(operation):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {operation}. Your role: {auth.role.value}",
            )
        return auth

    return _check
