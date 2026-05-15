"""User DAO - CRUD operations for user table."""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import or_

from derisk.storage.metadata import BaseDao

from .models import UserEntity, user_to_dict

logger = logging.getLogger(__name__)


def _ensure_user_has_role(user_id: int, rbac_default_role: str = "viewer") -> None:
    """Ensure a user has at least one RBAC role assigned."""
    try:
        from derisk_ext.plugin.auth.rbac.dao import PermissionDao

        dao = PermissionDao()
        existing_roles = dao.get_user_roles(user_id)
        if existing_roles:
            return

        default_role = dao.get_role_by_name(rbac_default_role)
        if default_role:
            dao.assign_role_to_user(user_id, default_role["id"])
            logger.info(
                "Auto-assigned '%s' role to user %d (missing RBAC role)",
                rbac_default_role,
                user_id,
            )
        else:
            viewer_role = dao.get_role_by_name("viewer")
            if viewer_role:
                dao.assign_role_to_user(user_id, viewer_role["id"])
                logger.warning(
                    "Configured default role '%s' not found, "
                    "fallback to 'viewer' for user %d",
                    rbac_default_role,
                    user_id,
                )
            else:
                logger.error(
                    "Neither '%s' nor 'viewer' role found in RBAC — "
                    "user %d has no permissions",
                    rbac_default_role,
                    user_id,
                )
    except ImportError:
        logger.debug("RBAC plugin not available, skipping role assignment")
    except Exception as e:
        logger.error("Failed to auto-assign default RBAC role to user %d: %s", user_id, e)


class UserDao(BaseDao):
    """DAO for user table operations."""

    def get_by_oauth(self, provider: str, oauth_id: str) -> Optional[Dict[str, Any]]:
        """Get user by OAuth provider and id."""
        with self.session() as session:
            user = (
                session.query(UserEntity)
                .filter(
                    UserEntity.oauth_provider == provider,
                    UserEntity.oauth_id == oauth_id,
                )
                .first()
            )
            return user_to_dict(user) if user else None

    def get_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by id."""
        with self.session() as session:
            user = session.query(UserEntity).filter(UserEntity.id == user_id).first()
            return user_to_dict(user) if user else None

    def create_or_update_from_oauth(
        self,
        provider: str,
        oauth_id: str,
        user_info: Dict[str, Any],
        role: str = "normal",
        rbac_default_role: str = "viewer",
    ) -> Dict[str, Any]:
        """Create or update user from OAuth user info, return plain dict."""
        with self.session() as session:
            user = (
                session.query(UserEntity)
                .filter(
                    UserEntity.oauth_provider == provider,
                    UserEntity.oauth_id == oauth_id,
                )
                .first()
            )
            name = (
                user_info.get("login")
                or user_info.get("username")
                or user_info.get("name", "")
            )
            fullname = user_info.get("name") or user_info.get("fullname", "")
            email = user_info.get("email", "")
            avatar = (
                user_info.get("avatar_url")
                or user_info.get("avatar")
                or user_info.get("picture", "")
            )

            if user:
                user.name = name or user.name
                user.fullname = fullname or user.fullname
                user.email = email or user.email
                user.avatar = avatar or user.avatar
                merged = session.merge(user)
                session.commit()
                session.refresh(merged)
                user_dict = user_to_dict(merged)
                _ensure_user_has_role(user.id, rbac_default_role)
                return user_dict
            else:
                user = UserEntity(
                    name=name,
                    fullname=fullname,
                    oauth_provider=provider,
                    oauth_id=oauth_id,
                    email=email,
                    avatar=avatar,
                    role=role,
                    is_active=1,
                )
                session.add(user)
                session.commit()
                session.refresh(user)
                _ensure_user_has_role(user.id, rbac_default_role)
                return user_to_dict(user)

    def list_users(
        self, page: int = 1, page_size: int = 20, keyword: str = ""
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List users with pagination and optional keyword filter."""
        with self.session() as session:
            query = session.query(UserEntity)
            if keyword:
                like = f"%{keyword}%"
                query = query.filter(
                    or_(
                        UserEntity.name.ilike(like),
                        UserEntity.fullname.ilike(like),
                        UserEntity.email.ilike(like),
                    )
                )
            total = query.count()
            users = (
                query.order_by(UserEntity.gmt_create.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [user_to_dict(u) for u in users], total

    def update_user(
        self,
        user_id: int,
        role: Optional[str] = None,
        is_active: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Update user role or is_active status."""
        with self.session() as session:
            user = session.query(UserEntity).filter(UserEntity.id == user_id).first()
            if not user:
                return None
            if role is not None:
                user.role = role
            if is_active is not None:
                user.is_active = is_active
            session.commit()
            session.refresh(user)

            if role == "admin":
                _ensure_user_has_role(user_id, "admin")

            return user_to_dict(user)

    def delete_user(self, user_id: int) -> bool:
        """Soft delete user by setting is_active=0."""
        with self.session() as session:
            user = session.query(UserEntity).filter(UserEntity.id == user_id).first()
            if not user:
                return False
            user.is_active = 0
            session.commit()
            logger.info("User %d (%s) soft deleted", user_id, user.name)
            return True

    def verify_local_login(
        self, username: str, password: str
    ) -> Optional[Dict[str, Any]]:
        """Verify username/password for local login."""
        import hashlib

        with self.session() as session:
            user = (
                session.query(UserEntity)
                .filter(
                    UserEntity.oauth_provider == "local",
                    UserEntity.name == username,
                    UserEntity.is_active == 1,
                )
                .first()
            )
            if not user or not user.password_hash:
                return None

            try:
                import bcrypt

                if not bcrypt.checkpw(
                    password.encode("utf-8"), user.password_hash.encode("utf-8")
                ):
                    return None
            except ImportError:
                sha = hashlib.sha256(password.encode("utf-8")).hexdigest()
                if user.password_hash != sha:
                    return None

            _ensure_user_has_role(user.id, "admin" if user.role == "admin" else "viewer")
            return user_to_dict(user)

    def set_password(self, user_id: int, password: str) -> bool:
        """Set password for a user (bcrypt hash)."""
        try:
            import bcrypt

            password_hash = bcrypt.hashpw(
                password.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")
        except ImportError:
            import hashlib

            password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()

        with self.session() as session:
            user = session.query(UserEntity).filter(UserEntity.id == user_id).first()
            if not user:
                return False
            user.password_hash = password_hash
            session.commit()
            return True

    def has_local_users(self) -> bool:
        """Check if any local users with passwords exist."""
        with self.session() as session:
            return (
                session.query(UserEntity)
                .filter(
                    UserEntity.oauth_provider == "local",
                    UserEntity.password_hash.isnot(None),
                )
                .first()
                is not None
            )
