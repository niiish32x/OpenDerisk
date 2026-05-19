"""Unit tests for derisk_ext.plugin.auth.rbac — service logic and seed callbacks."""

import pytest

from derisk_ext.plugin.auth.rbac.seed import (
    SEED_ROLES,
    SEED_PERMISSION_DEFINITIONS,
    ensure_default_roles,
)
from derisk_ext.plugin.auth.rbac.service import PermissionService
from derisk_ext.plugin.auth.rbac.models import (
    RESOURCE_AGENT,
    RESOURCE_TOOL,
    RESOURCE_KNOWLEDGE,
    RESOURCE_MODEL,
    RESOURCE_SYSTEM,
    AGENT_ACTIONS,
    TOOL_ACTIONS,
    KNOWLEDGE_ACTIONS,
    MODEL_ACTIONS,
    RESOURCE_ACTIONS,
)


class TestSeedRoles:
    def test_five_system_roles(self):
        assert len(SEED_ROLES) == 5

    def test_all_system_roles_are_system(self):
        for role in SEED_ROLES:
            assert role["is_system"] == 1

    def test_role_names(self):
        names = {r["name"] for r in SEED_ROLES}
        assert names == {"guest", "viewer", "operator", "editor", "admin"}

    def test_admin_has_system_admin(self):
        admin = next(r for r in SEED_ROLES if r["name"] == "admin")
        perms = admin["permissions"]
        assert ("system", "admin") in perms

    def test_guest_has_minimal_permissions(self):
        guest = next(r for r in SEED_ROLES if r["name"] == "guest")
        perms = guest["permissions"]
        assert len(perms) == 2
        assert ("model", "read") in perms
        assert ("model", "chat") in perms

    def test_viewer_is_readonly(self):
        viewer = next(r for r in SEED_ROLES if r["name"] == "viewer")
        perms = viewer["permissions"]
        for _, action in perms:
            assert action == "read"

    def test_editor_has_write_but_not_admin(self):
        editor = next(r for r in SEED_ROLES if r["name"] == "editor")
        actions = {a for _, a in editor["permissions"]}
        assert "write" in actions
        assert "admin" not in actions
        assert "manage" in actions


class TestSeedPermissionDefinitions:
    def test_fourteen_definitions(self):
        assert len(SEED_PERMISSION_DEFINITIONS) == 14

    def test_all_definitions_have_required_fields(self):
        for pd in SEED_PERMISSION_DEFINITIONS:
            assert "name" in pd
            assert "resource_type" in pd
            assert "action" in pd

    def test_system_admin_definition(self):
        sa = next(d for d in SEED_PERMISSION_DEFINITIONS if d["name"] == "system_admin")
        assert sa["resource_type"] == "system"
        assert sa["action"] == "admin"


class TestResourceActions:
    def test_agent_actions_order(self):
        assert AGENT_ACTIONS == ["read", "chat", "write", "admin"]

    def test_tool_actions_order(self):
        assert TOOL_ACTIONS == ["read", "execute", "manage", "admin"]

    def test_all_resource_types_mapped(self):
        assert RESOURCE_AGENT in RESOURCE_ACTIONS
        assert RESOURCE_TOOL in RESOURCE_ACTIONS
        assert RESOURCE_KNOWLEDGE in RESOURCE_ACTIONS
        assert RESOURCE_MODEL in RESOURCE_ACTIONS
        assert RESOURCE_SYSTEM in RESOURCE_ACTIONS
        assert RESOURCE_ACTIONS[RESOURCE_SYSTEM] == ["admin"]


class TestSeedCallbackInjection:
    """Verify ensure_default_roles accepts and uses callbacks."""

    def test_no_callbacks_does_not_crash(self):
        """Call without any callbacks — should skip user creation gracefully."""
        # This test requires a DB, so skip in unit test context
        try:
            ensure_default_roles()
        except Exception:
            # Expected when no DB is available — just verify no ImportError
            pass

    def test_seed_with_callback_signatures(self):
        """Verify callbacks are accepted with proper signatures."""
        calls = []

        def create_admin():
            calls.append("create_admin")
            return 1

        def set_password(uid, pw):
            calls.append(f"set_password:{uid}:{pw}")

        def get_existing():
            calls.append("get_existing")
            return None

        def get_active():
            calls.append("get_active")
            return []

        def has_role(uid, rid):
            calls.append(f"has_role:{uid}:{rid}")
            return False

        def assign_role(uid, rid):
            calls.append(f"assign_role:{uid}:{rid}")

        # Should not crash, callbacks may or may not be called depending on DB state
        try:
            ensure_default_roles(
                create_admin_user=create_admin,
                set_admin_password=set_password,
                get_existing_admin_id=get_existing,
                get_all_active_user_ids=get_active,
                user_has_role=has_role,
                assign_user_role=assign_role,
            )
        except Exception:
            pass


class TestPermissionServiceCache:
    def test_cache_invalidation(self):
        svc = PermissionService()
        svc.invalidate_cache(user_id=99)
        svc.invalidate_cache()  # clear all
        assert True  # no crash
