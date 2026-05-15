"""Seed data initialization for built-in roles and default admin user.

User creation is done via callback injection to avoid derisk-ext depending
on derisk-app. The caller (derisk-app bootstrap) provides concrete
implementations of user creation/password-setting functions.
"""

import logging
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .dao import PermissionDao

logger = logging.getLogger(__name__)

# Default permission definitions that can be assigned to roles
SEED_PERMISSION_DEFINITIONS = [
    {"name": "agent_read_all", "description": "可读取所有智能体", "resource_type": "agent", "resource_id": "*", "action": "read"},
    {"name": "agent_chat_all", "description": "可与所有智能体对话", "resource_type": "agent", "resource_id": "*", "action": "chat"},
    {"name": "agent_write_all", "description": "可管理所有智能体配置", "resource_type": "agent", "resource_id": "*", "action": "write"},
    {"name": "agent_admin_all", "description": "可完全管理所有智能体", "resource_type": "agent", "resource_id": "*", "action": "admin"},
    {"name": "tool_read_all", "description": "可读取所有工具", "resource_type": "tool", "resource_id": "*", "action": "read"},
    {"name": "tool_execute_all", "description": "可执行所有工具", "resource_type": "tool", "resource_id": "*", "action": "execute"},
    {"name": "tool_manage_all", "description": "可管理所有工具", "resource_type": "tool", "resource_id": "*", "action": "manage"},
    {"name": "knowledge_read_all", "description": "可读取所有知识库", "resource_type": "knowledge", "resource_id": "*", "action": "read"},
    {"name": "knowledge_query_all", "description": "可检索所有知识库", "resource_type": "knowledge", "resource_id": "*", "action": "query"},
    {"name": "knowledge_write_all", "description": "可管理所有知识库", "resource_type": "knowledge", "resource_id": "*", "action": "write"},
    {"name": "model_read_all", "description": "可读取所有模型", "resource_type": "model", "resource_id": "*", "action": "read"},
    {"name": "model_chat_all", "description": "可使用所有模型对话", "resource_type": "model", "resource_id": "*", "action": "chat"},
    {"name": "model_manage_all", "description": "可管理所有模型", "resource_type": "model", "resource_id": "*", "action": "manage"},
    {"name": "system_admin", "description": "系统管理员权限", "resource_type": "system", "resource_id": "*", "action": "admin"},
]

SEED_ROLES = [
    {
        "name": "guest",
        "description": "访客（仅可查看模型和监控，不能查看智能体/工具/知识库）",
        "is_system": 1,
        "permissions": [("model", "read"), ("model", "chat")],
    },
    {
        "name": "viewer",
        "description": "只读访问所有资源（可查看界面和详情，但不能对话/执行/编辑）",
        "is_system": 1,
        "permissions": [
            ("agent", "read"), ("tool", "read"),
            ("knowledge", "read"), ("model", "read"),
        ],
    },
    {
        "name": "operator",
        "description": "操作员（可查看、对话、执行工具、检索知识库，但不能编辑配置）",
        "is_system": 1,
        "permissions": [
            ("agent", "read"), ("agent", "chat"),
            ("tool", "read"), ("tool", "execute"),
            ("knowledge", "read"), ("knowledge", "query"),
            ("model", "read"), ("model", "chat"),
        ],
    },
    {
        "name": "editor",
        "description": "编辑者（可查看、使用、编辑所有资源配置）",
        "is_system": 1,
        "permissions": [
            ("agent", "read"), ("agent", "chat"), ("agent", "write"),
            ("tool", "read"), ("tool", "execute"), ("tool", "manage"),
            ("knowledge", "read"), ("knowledge", "query"), ("knowledge", "write"),
            ("model", "read"), ("model", "chat"), ("model", "manage"),
        ],
    },
    {
        "name": "admin",
        "description": "完全管理权限",
        "is_system": 1,
        "permissions": [
            ("agent", "read"), ("agent", "chat"), ("agent", "write"), ("agent", "admin"),
            ("tool", "read"), ("tool", "execute"), ("tool", "manage"), ("tool", "admin"),
            ("knowledge", "read"), ("knowledge", "query"), ("knowledge", "write"), ("knowledge", "admin"),
            ("model", "read"), ("model", "chat"), ("model", "manage"), ("model", "admin"),
            ("system", "admin"),
        ],
    },
]


def _ensure_system_role_permissions(
    dao: PermissionDao, role_id: int, expected_permissions: list
) -> None:
    """Ensure built-in system role has all expected wildcard permissions."""
    current = dao.list_role_permissions(role_id)
    current_keys = {
        (p.get("resource_type"), p.get("action"), p.get("resource_id", "*"))
        for p in current
    }

    for resource_type, action in expected_permissions:
        key = (resource_type, action, "*")
        if key in current_keys:
            continue
        try:
            dao.add_role_permission(
                role_id=role_id, resource_type=resource_type, action=action, resource_id="*"
            )
            logger.info(
                "Added missing permission %s:%s(*) to system role id=%s",
                resource_type, action, role_id,
            )
        except Exception as e:
            logger.warning(
                "Failed to add missing permission %s:%s to role id=%s: %s",
                resource_type, action, role_id, e,
            )


def ensure_default_roles(
    create_admin_user: Optional[Callable[[], int]] = None,
    set_admin_password: Optional[Callable[[int, str], None]] = None,
    get_existing_admin_id: Optional[Callable[[], Optional[int]]] = None,
    get_all_active_user_ids: Optional[Callable[[], List[int]]] = None,
    user_has_role: Optional[Callable[[int, int], bool]] = None,
    assign_user_role: Optional[Callable[[int, int], None]] = None,
) -> None:
    """Idempotent: create built-in roles and default admin user.

    All interactions with the User table are done through injected callbacks
    to avoid derisk-ext depending on derisk-app directly.

    Args:
        create_admin_user: Create the default admin user, return user_id.
        set_admin_password: Set password for a user.
        get_existing_admin_id: Return existing admin user ID or None.
        get_all_active_user_ids: Return list of active user IDs for backfill.
        user_has_role: Check if a user already has a given role.
        assign_user_role: Assign a role to a user.
    """
    dao = PermissionDao()

    # 1. Create default roles
    admin_role_id = None
    for role_def in SEED_ROLES:
        existing = dao.get_role_by_name(role_def["name"])
        if existing:
            logger.debug("Seed role already exists: %s", role_def["name"])
            _ensure_system_role_permissions(dao, existing["id"], role_def["permissions"])
            if role_def["name"] == "admin":
                admin_role_id = existing["id"]
            continue
        try:
            role = dao.create_role(
                name=role_def["name"],
                description=role_def["description"],
                is_system=role_def["is_system"],
            )
            for resource_type, action in role_def["permissions"]:
                dao.add_role_permission(
                    role_id=role["id"], resource_type=resource_type, action=action
                )
            logger.info("Seed role created: %s", role_def["name"])
            if role_def["name"] == "admin":
                admin_role_id = role["id"]
        except Exception as e:
            logger.exception("Failed to create seed role %s: %s", role_def["name"], e)

    # 2. Create default admin user via callbacks
    if admin_role_id and create_admin_user and set_admin_password and assign_user_role:
        try:
            default_password = "admin"
            existing_admin_id = get_existing_admin_id() if get_existing_admin_id else None

            if existing_admin_id:
                logger.debug("Admin user already exists: id=%s", existing_admin_id)
                if user_has_role and not user_has_role(existing_admin_id, admin_role_id):
                    assign_user_role(existing_admin_id, admin_role_id)
                    logger.info("Assigned admin role to existing admin user")
                if set_admin_password:
                    set_admin_password(existing_admin_id, default_password)
            else:
                admin_user_id = create_admin_user()
                if admin_user_id:
                    if set_admin_password:
                        set_admin_password(admin_user_id, default_password)
                    assign_user_role(admin_user_id, admin_role_id)
                    logger.info(
                        "DEFAULT ADMIN USER CREATED: username=admin, password=admin, "
                        "provider=local, user_id=%s", admin_user_id
                    )
        except Exception as e:
            logger.warning("Failed to create/assign admin user: %s", e)

    # 3. Backfill default 'viewer' role for existing users without RBAC roles
    if get_all_active_user_ids and assign_user_role:
        _backfill_viewer_role_for_existing_users(
            dao, get_all_active_user_ids, user_has_role, assign_user_role
        )

    # 4. Create default permission definitions
    _ensure_default_permission_definitions(dao)


def _backfill_viewer_role_for_existing_users(
    dao: PermissionDao,
    get_all_active_user_ids: Callable[[], List[int]],
    user_has_role: Optional[Callable[[int, int], bool]],
    assign_user_role: Callable[[int, int], None],
) -> None:
    viewer_role = dao.get_role_by_name("viewer")
    if not viewer_role:
        logger.warning("viewer role not found, skipping existing user backfill")
        return

    try:
        active_user_ids = get_all_active_user_ids()
        viewer_role_id = viewer_role["id"]
        backfilled = 0
        for uid in active_user_ids:
            if user_has_role and user_has_role(uid, viewer_role_id):
                continue
            # Check if user has any role
            existing_roles = dao.get_user_roles(uid)
            if not existing_roles:
                assign_user_role(uid, viewer_role_id)
                backfilled += 1
                logger.info("Backfilled 'viewer' role for user id=%s", uid)
        if backfilled > 0:
            logger.info("Backfilled 'viewer' role for %d existing users", backfilled)
    except Exception as e:
        logger.error("Failed to backfill default role for existing users: %s", e)


def _ensure_default_permission_definitions(dao: PermissionDao) -> None:
    """Idempotent: create default permission definitions."""
    for perm_def in SEED_PERMISSION_DEFINITIONS:
        try:
            all_defs = dao.list_permission_definitions()
            existing = next((d for d in all_defs if d["name"] == perm_def["name"]), None)
        except Exception:
            existing = None

        if existing:
            logger.debug("Seed permission definition already exists: %s", perm_def["name"])
            continue

        try:
            dao.create_permission_definition(
                name=perm_def["name"],
                description=perm_def["description"],
                resource_type=perm_def["resource_type"],
                resource_id=perm_def["resource_id"],
                action=perm_def["action"],
                effect="allow",
            )
            logger.info("Seed permission definition created: %s", perm_def["name"])
        except Exception as e:
            logger.warning(
                "Failed to create seed permission definition %s: %s", perm_def["name"], e
            )
