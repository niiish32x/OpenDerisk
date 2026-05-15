"""Shim: re-export RBAC DAO from derisk-ext."""

from derisk_ext.plugin.auth.rbac.dao import PermissionDao

__all__ = ["PermissionDao"]
