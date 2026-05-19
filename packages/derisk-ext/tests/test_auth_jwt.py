"""Unit tests for derisk_ext.plugin.auth.jwt module."""

import os
import time

import pytest

from derisk_ext.plugin.auth.jwt import (
    JWTError,
    create_token,
    decode_token,
    verify_token,
)


class TestCreateToken:
    def test_basic_user_token(self):
        token = create_token(user={"id": 3, "name": "Alice", "email": "alice@x.com"})
        assert isinstance(token, str)
        assert "." not in token.split(".")[:2]  # not base64, it's JWT

    def test_token_with_agent_identity(self):
        token = create_token(
            user={"id": 3, "name": "Alice"},
            agent={"agent_name": "sre-agent", "app_id": "app_123", "agent_role": "operator"},
        )
        claims = decode_token(token)
        assert claims["act"]["agent_name"] == "sre-agent"
        assert claims["act"]["agent_role"] == "operator"

    def test_token_with_rbac(self):
        token = create_token(
            user={"id": 3, "name": "Alice"},
            rbac={"role": "editor", "roles": ["editor"], "permissions": {"agent": ["read", "chat"]}},
        )
        claims = decode_token(token)
        assert claims["rbac"]["role"] == "editor"
        assert "agent" in claims["rbac"]["permissions"]

    def test_token_without_agent_has_no_act(self):
        token = create_token(user={"id": 3, "name": "Alice"})
        claims = decode_token(token)
        assert "act" not in claims

    def test_token_issuer(self):
        token = create_token(user={"id": 3})
        claims = decode_token(token)
        assert claims["iss"] == "derisk"

    def test_token_audience_default(self):
        token = create_token(user={"id": 3})
        claims = decode_token(token)
        assert "derisk-api" in claims["aud"]


class TestVerifyToken:
    def test_valid_token_verifies(self):
        token = create_token(user={"id": 1, "name": "Test"})
        claims = verify_token(token)
        assert claims["sub"] == "1"
        assert claims["name"] == "Test"

    def test_tampered_token_raises(self):
        token = create_token(user={"id": 1})
        tampered = token[:-5] + "xxxxx"
        with pytest.raises(JWTError):
            verify_token(tampered)

    def test_expired_token_raises(self, monkeypatch):
        monkeypatch.setenv("OAUTH2_JWT_EXPIRE_SECONDS", "0")
        token = create_token(user={"id": 1})
        time.sleep(1)
        with pytest.raises(JWTError, match="Token expired"):
            verify_token(token)
        monkeypatch.delenv("OAUTH2_JWT_EXPIRE_SECONDS", raising=False)


class TestDecodeToken:
    def test_decode_without_verification(self):
        token = create_token(user={"id": 5, "name": "Bob", "email": "bob@x.com"})
        claims = decode_token(token)
        assert claims["sub"] == "5"
        assert claims["name"] == "Bob"
        assert claims["email"] == "bob@x.com"

    def test_decode_invalid_returns_empty(self):
        claims = decode_token("not.a.valid.token")
        assert claims == {}


class TestKeyConfiguration:
    def test_custom_expiry_from_env(self, monkeypatch):
        monkeypatch.setenv("OAUTH2_JWT_EXPIRE_SECONDS", "3600")
        from derisk_ext.plugin.auth.jwt import _get_expire_seconds
        assert _get_expire_seconds() == 3600
        monkeypatch.delenv("OAUTH2_JWT_EXPIRE_SECONDS", raising=False)

    def test_default_expiry(self):
        from derisk_ext.plugin.auth.jwt import DEFAULT_EXPIRE_SECONDS, _get_expire_seconds
        assert _get_expire_seconds() == DEFAULT_EXPIRE_SECONDS


class TestUserRoundTrip:
    """End-to-end: create → verify → decode to ensure full cycle works."""

    def test_full_round_trip(self):
        user = {"id": 42, "name": "张三", "email": "zhangsan@example.com", "avatar_url": "https://img/avatar.png"}
        rbac = {"role": "viewer", "roles": ["viewer"], "permissions": {"agent": ["read"], "model": ["read"]}}
        agent = {"agent_name": "test-agent", "app_id": "app_1", "agent_role": "viewer"}

        token = create_token(user=user, agent=agent, rbac=rbac)
        claims = verify_token(token)

        assert claims["sub"] == "42"
        assert claims["name"] == "张三"
        assert claims["email"] == "zhangsan@example.com"
        assert claims["act"]["agent_name"] == "test-agent"
        assert claims["rbac"]["role"] == "viewer"
        assert claims["rbac"]["permissions"]["agent"] == ["read"]
