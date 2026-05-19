"""User service - business logic for user operations."""

import logging
from typing import Any, Dict, List, Optional, Tuple

from .dao import UserDao

logger = logging.getLogger(__name__)


class UserService:
    """Service for user operations."""

    def __init__(self):
        self._dao = UserDao()

    def get_or_create_from_oauth(
        self,
        provider: str,
        oauth_id: str,
        user_info: Dict[str, Any],
        role: str = "normal",
        rbac_default_role: str = "viewer",
    ) -> Optional[Dict[str, Any]]:
        """Get or create user from OAuth info, return user dict for session."""
        try:
            return self._dao.create_or_update_from_oauth(
                provider, oauth_id, user_info, role=role, rbac_default_role=rbac_default_role
            )
        except Exception as e:
            logger.exception("Failed to get/create user from OAuth: %s", e)
            return None

    def list_users(
        self, page: int = 1, page_size: int = 20, keyword: str = ""
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List users with pagination."""
        try:
            return self._dao.list_users(page, page_size, keyword)
        except Exception as e:
            logger.exception("Failed to list users: %s", e)
            return [], 0

    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get a single user by id."""
        try:
            return self._dao.get_by_id(user_id)
        except Exception as e:
            logger.exception("Failed to get user %d: %s", user_id, e)
            return None

    def update_user(
        self,
        user_id: int,
        role: Optional[str] = None,
        is_active: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Update user role or active status."""
        try:
            return self._dao.update_user(user_id, role=role, is_active=is_active)
        except Exception as e:
            logger.exception("Failed to update user %d: %s", user_id, e)
            return None

    def delete_user(self, user_id: int) -> bool:
        """Delete user (soft delete)."""
        try:
            return self._dao.delete_user(user_id)
        except Exception as e:
            logger.exception("Failed to delete user %d: %s", user_id, e)
            return False

    def verify_local_login(
        self, username: str, password: str
    ) -> Optional[Dict[str, Any]]:
        """Verify username/password for local login."""
        try:
            return self._dao.verify_local_login(username, password)
        except Exception as e:
            logger.exception("Failed to verify local login: %s", e)
            return None

    def set_password(self, user_id: int, password: str) -> bool:
        """Set password for a user."""
        try:
            return self._dao.set_password(user_id, password)
        except Exception as e:
            logger.exception("Failed to set password for user %d: %s", user_id, e)
            return False

    def has_local_users(self) -> bool:
        """Check if any local users with passwords exist."""
        try:
            return self._dao.has_local_users()
        except Exception:
            return False
