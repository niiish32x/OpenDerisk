"""Shim: re-export user models/dao/service from derisk-ext.

Keeps the _ensure_user_has_role helper for backward compatibility.
"""

from derisk_ext.plugin.auth.user.dao import _ensure_user_has_role
from derisk_ext.plugin.auth.user.dao import UserDao
from derisk_ext.plugin.auth.user.models import UserEntity, user_to_dict as _entity_to_dict
from derisk_ext.plugin.auth.user.service import UserService

__all__ = [
    "_ensure_user_has_role",
    "UserDao",
    "UserEntity",
    "UserService",
]
