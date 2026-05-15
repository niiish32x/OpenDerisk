"""Shim: re-export user group models from derisk-ext."""

from derisk_ext.plugin.auth.rbac.models import UserGroupEntity, UserGroupMemberEntity

__all__ = ["UserGroupEntity", "UserGroupMemberEntity"]
