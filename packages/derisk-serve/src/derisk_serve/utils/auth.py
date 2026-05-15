"""Authentication utilities — resolve user identity from headers/session/JWT."""

import logging
from typing import Any, Dict, List, Optional

from fastapi import Header, HTTPException, Request

from derisk._private.pydantic import BaseModel

logger = logging.getLogger(__name__)


class UserRequest(BaseModel):
    """Resolved user identity passed to FastAPI endpoints."""

    user_id: Optional[str] = None
    user_no: Optional[str] = None
    real_name: Optional[str] = None
    user_name: Optional[str] = None
    user_channel: Optional[str] = None
    role: Optional[str] = "normal"
    nick_name: Optional[str] = None
    email: Optional[str] = None
    avatar_url: Optional[str] = None
    nick_name_like: Optional[str] = None
    # RBAC: None means plugin disabled (no checks)
    permissions: Optional[Dict[str, List[str]]] = None
    roles: Optional[List[str]] = None
    # JWT raw token for downstream propagation (agent → tool → MCP)
    _raw_token: Optional[str] = None


def _is_permissions_enabled() -> bool:
    """Check whether RBAC permissions are enabled.

    Priority:
      1. TOML config: ``[service.web] rbac_enabled = true``
      2. derisk.json: ``feature_plugins.permissions.enabled`` (legacy)
    """
    # 1. TOML config (primary for deployments)
    try:
        from derisk._private.config import Config

        c = Config()
        if hasattr(c, "service") and hasattr(c.service, "web"):
            val = getattr(c.service.web, "rbac_enabled", None)
            if val is not None:
                return bool(val)
    except Exception:
        pass

    # 2. derisk.json legacy
    try:
        from derisk_core.config import ConfigManager

        cfg = ConfigManager.get()
        entry = (cfg.feature_plugins or {}).get("permissions")
        if entry is not None:
            if hasattr(entry, "enabled"):
                return bool(entry.enabled)
            if isinstance(entry, dict):
                return bool(entry.get("enabled"))
    except Exception:
        pass

    return False


def _load_rbac_from_db(user_id: int):
    """Load RBAC permissions from database (fallback when JWT has no rbac)."""
    try:
        from derisk_ext.plugin.auth.rbac.service import PermissionService

        perms = PermissionService().get_user_permissions(user_id)
        return perms.role_names, perms.permissions_map
    except Exception:
        return [], {}


def _resolve_legacy_role(user_id: int) -> str:
    """Look up legacy role field from user table."""
    try:
        from derisk_ext.plugin.auth.user.models import UserEntity
        from derisk.storage.metadata.db_manager import db

        with db.session(commit=False) as s:
            user_obj = s.query(UserEntity).filter(UserEntity.id == user_id).first()
            if user_obj and user_obj.role:
                return user_obj.role
    except Exception:
        pass
    return "normal"


def get_user_from_headers(
    request: Request = None,
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    authorization: Optional[str] = Header(None),
) -> UserRequest:
    """Unified user identity resolver.

    Resolves user from:
      1. permissions OFF → mock admin (backward compatible)
      2. X-User-ID: admin → local dev bypass
      3. derisk_session cookie → JWT or legacy session token
      4. Authorization: Bearer <token> → JWT

    JWT tokens are verified with derisk_ext.plugin.auth.jwt.verify_token().
    Legacy session tokens are verified with the old verify_session_token()
    during migration.
    """
    try:
        if not _is_permissions_enabled():
            if x_user_id:
                return UserRequest(
                    user_id=x_user_id,
                    role="admin",
                    nick_name=x_user_id,
                    real_name=x_user_id,
                )
            return UserRequest(
                user_id="001",
                role="admin",
                nick_name="derisk",
                real_name="derisk",
            )

        # Local dev bypass
        if x_user_id == "admin":
            role_names, permissions_map = _load_rbac_from_db(3)
            return UserRequest(
                user_id="3",
                user_no="admin",
                real_name="System Admin",
                nick_name="System Admin",
                role="admin",
                permissions=permissions_map,
                roles=role_names,
            )

        # Extract token from cookie or Authorization header
        token: Optional[str] = None
        if request:
            token = request.cookies.get("derisk_session")
        if not token and authorization:
            token = authorization.replace("Bearer ", "")
        if not token:
            raise HTTPException(status_code=401, detail="Authentication required")

        # Try JWT first, fall back to legacy session token
        claims = None
        raw_token = token
        jws_verified = False

        try:
            from derisk_ext.plugin.auth.jwt import verify_token, decode_token

            claims = verify_token(token)
            jws_verified = True
        except Exception:
            pass

        if not jws_verified:
            # Fallback: try legacy session token (migration period)
            try:
                from derisk_app.auth.session import verify_session_token

                user_data = verify_session_token(token)
                if user_data:
                    claims = _legacy_user_data_to_claims(user_data)
            except Exception:
                pass

        if claims is None:
            raise HTTPException(status_code=401, detail="Invalid or expired session")

        user_id = int(claims.get("sub", 0)) if claims.get("sub") else 0

        # Load RBAC: prefer JWT claims, fallback to DB
        rbac = claims.get("rbac", {})
        if rbac and rbac.get("permissions"):
            role_names = rbac.get("roles", [])
            permissions_map = rbac.get("permissions", {})
        else:
            role_names, permissions_map = _load_rbac_from_db(user_id)

        legacy_role = claims.get("role") or _resolve_legacy_role(user_id)

        return UserRequest(
            user_id=str(user_id),
            user_no=str(user_id),
            real_name=claims.get("name", ""),
            nick_name=claims.get("name", ""),
            email=claims.get("email", ""),
            avatar_url=claims.get("avatar_url", ""),
            role=legacy_role,
            permissions=permissions_map,
            roles=role_names,
            _raw_token=raw_token,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Authentication failed!")
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")


def _legacy_user_data_to_claims(user_data: Dict[str, Any]) -> Dict[str, Any]:
    """Convert legacy session user_data to JWT-like claims dict."""
    return {
        "sub": str(user_data.get("id", "")),
        "name": user_data.get("name", user_data.get("login", "")),
        "email": user_data.get("email", ""),
        "avatar_url": user_data.get("avatar_url", user_data.get("avatar", "")),
        "role": user_data.get("role", "normal"),
    }


def format_permissions_summary(
    permissions: Optional[Dict[str, List[str]]], rbac_enabled: bool
) -> str:
    """Format permissions map as human-readable summary string."""
    if not rbac_enabled:
        return "全部权限 (RBAC 未启用)"

    if not permissions:
        return "none"

    parts = []
    for resource_type, actions in permissions.items():
        if actions:
            parts.append(f"{resource_type}: {', '.join(actions)}")

    return "; ".join(parts) if parts else "none"


def build_user_context(
    user_request: UserRequest, rbac_enabled: bool
) -> Dict[str, Any]:
    """Build user_context dict from UserRequest for agent context injection.

    When JWT _raw_token is available, user_context is built from JWT claims
    (preferred). Otherwise falls back to UserRequest fields.
    """
    name = (
        user_request.real_name
        or user_request.nick_name
        or user_request.user_id
        or "Unknown"
    )

    if not rbac_enabled:
        return {
            "user_id": user_request.user_id or "001",
            "name": name,
            "email": None,
            "avatar_url": None,
            "role": user_request.role or "admin",
            "roles": [user_request.role or "admin"],
            "permissions_map": None,
            "permissions_summary": format_permissions_summary(None, rbac_enabled=False),
            "rbac_enabled": False,
            "auth_token": user_request._raw_token,
        }

    return {
        "user_id": user_request.user_id or "",
        "name": name,
        "email": user_request.email,
        "avatar_url": user_request.avatar_url,
        "role": user_request.role or "normal",
        "roles": user_request.roles or [user_request.role or "normal"],
        "permissions_map": user_request.permissions,
        "permissions_summary": format_permissions_summary(
            user_request.permissions, rbac_enabled=True
        ),
        "rbac_enabled": True,
        "auth_token": user_request._raw_token,
    }
