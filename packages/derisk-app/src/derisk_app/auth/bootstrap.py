"""Register auth-related routers from derisk-ext plugin at startup."""

import logging

from fastapi import FastAPI

logger = logging.getLogger(__name__)


def register_enabled_feature_plugin_routers(app: FastAPI) -> None:
    """Conditionally mount plugin HTTP routes (requires restart after toggling plugins)."""
    # Load feature plugin config from database or config file
    try:
        from derisk_ext.plugin.auth.system_config import SystemConfigDao

        dao = SystemConfigDao()
        raw = dao.get_all_configs("feature_plugin")
        logger.info("Loaded feature plugins from database: %s", raw)
    except Exception as e:
        logger.warning("Feature plugins: failed to load from database: %s", e)
        raw = {}

    # Fall back to config file if database is empty
    if not raw:
        try:
            from derisk_core.config import ConfigManager

            cfg = ConfigManager.get()
            raw_cfg = getattr(cfg, "feature_plugins", None) or {}
            raw = {
                k: v.model_dump(mode="json") if hasattr(v, "model_dump") else dict(v)
                for k, v in raw_cfg.items()
            }
        except Exception as e:
            logger.warning(
                "Feature plugins: skip router registration (config unavailable): %s", e
            )
            return

    def _enabled(plugin_id: str) -> bool:
        entry = raw.get(plugin_id)
        if entry is None:
            return False
        if isinstance(entry, dict):
            return bool(entry.get("enabled"))
        return False

    access_control_enabled = _enabled("access_control")
    user_groups_enabled = _enabled("user_groups") or access_control_enabled
    permissions_enabled = _enabled("permissions") or access_control_enabled

    if user_groups_enabled:
        from derisk_app.feature_plugins.user_groups.api import (
            router as user_groups_router,
        )

        app.include_router(user_groups_router, prefix="/api/v1")
        logger.info("Feature plugin mounted: user_groups at /api/v1/user-groups")

    if permissions_enabled:
        from derisk_app.auth.permissions_api import (
            router as permissions_router,
        )

        app.include_router(permissions_router, prefix="/api/v1")
        logger.info("Feature plugin mounted: permissions at /api/v1/permissions")

        from derisk_ext.plugin.auth.rbac.seed import ensure_default_roles
        from derisk_ext.plugin.auth.user.dao import UserDao
        from derisk_ext.plugin.auth.user.models import UserEntity
        from derisk.storage.metadata.db_manager import db
        from sqlalchemy import or_
        from datetime import datetime

        # Ensure permission tables exist before seeding
        try:
            db.create_all()
        except Exception as e:
            logger.warning("Failed to create all tables: %s", e)

        # Wire up seed callbacks
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
