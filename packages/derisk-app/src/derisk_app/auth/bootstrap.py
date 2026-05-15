"""Register auth-related routers from derisk-ext plugin at startup."""

import logging

from fastapi import FastAPI

logger = logging.getLogger(__name__)


def _is_rbac_enabled() -> bool:
    """Check whether RBAC is enabled via TOML config ``[service.web] rbac_enabled``."""
    try:
        from derisk._private.config import Config

        c = Config()
        if hasattr(c, "service") and hasattr(c.service, "web"):
            return bool(getattr(c.service.web, "rbac_enabled", False))
    except Exception:
        pass
    return False


def register_enabled_feature_plugin_routers(app: FastAPI) -> None:
    """Mount RBAC API routes if ``rbac_enabled = true`` in TOML config."""
    if not _is_rbac_enabled():
        logger.info("RBAC disabled (set rbac_enabled=true in [service.web] to enable)")
        return

    # Mount permissions API
    from derisk_app.auth.permissions_api import router as permissions_router

    app.include_router(permissions_router, prefix="/api/v1")
    logger.info("Mounted: permissions at /api/v1/permissions")

    # Mount user groups API
    from derisk_app.auth.groups_api import router as user_groups_router

    app.include_router(user_groups_router, prefix="/api/v1")
    logger.info("Mounted: user_groups at /api/v1/user-groups")

    # Seed default roles + admin user
    from derisk_ext.plugin.auth.rbac.seed import ensure_default_roles
    from derisk_ext.plugin.auth.user.dao import UserDao
    from derisk_ext.plugin.auth.user.models import UserEntity
    from derisk.storage.metadata.db_manager import db
    from sqlalchemy import or_
    from datetime import datetime

    try:
        db.create_all()
    except Exception as e:
        logger.warning("Failed to create all tables: %s", e)

    user_dao = UserDao()

    def _create_admin_user() -> int:
        with db.session() as s:
            user = UserEntity(
                name="admin",
                fullname="System Administrator",
                oauth_provider="local",
                oauth_id="admin",
                email="admin@derisk.local",
                role="admin",
                is_active=1,
                gmt_create=datetime.utcnow(),
                gmt_modify=datetime.utcnow(),
            )
            s.add(user)
            s.flush()
            user_id = user.id
            s.commit()
            return user_id

    def _set_admin_password(user_id: int, password: str) -> None:
        user_dao.set_password(user_id, password)

    def _get_existing_admin_id():
        with db.session(commit=False) as s:
            existing = s.query(UserEntity).filter(
                or_(UserEntity.oauth_id == "admin", UserEntity.name == "admin")
            ).first()
            return existing.id if existing else None

    def _get_all_active_user_ids():
        with db.session(commit=False) as s:
            users = s.query(UserEntity).filter(UserEntity.is_active == 1).all()
            return [u.id for u in users]

    def _user_has_role(user_id: int, role_id: int) -> bool:
        from derisk_ext.plugin.auth.rbac.models import UserRoleEntity

        with db.session(commit=False) as s:
            ur = (
                s.query(UserRoleEntity)
                .filter(
                    UserRoleEntity.user_id == user_id,
                    UserRoleEntity.role_id == role_id,
                )
                .first()
            )
            return ur is not None

    def _assign_user_role(user_id: int, role_id: int) -> None:
        from derisk_ext.plugin.auth.rbac.dao import PermissionDao

        PermissionDao().assign_role_to_user(user_id, role_id)

    ensure_default_roles(
        create_admin_user=_create_admin_user,
        set_admin_password=_set_admin_password,
        get_existing_admin_id=_get_existing_admin_id,
        get_all_active_user_ids=_get_all_active_user_ids,
        user_has_role=_user_has_role,
        assign_user_role=_assign_user_role,
    )
