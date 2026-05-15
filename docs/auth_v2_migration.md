# Auth v2 迁移指南

从旧路径迁移到新路径的 import 对照表。

## Import 路径对照

| 旧路径 | 新路径 |
|---|---|
| `derisk_app.auth.session.create_session_token` | `derisk_ext.plugin.auth.jwt.create_token` |
| `derisk_app.auth.session.verify_session_token` | `derisk_ext.plugin.auth.jwt.verify_token` |
| `derisk_app.auth.session.SessionManager` | 保留（CSRF state 管理，非 JWT） |
| `derisk_app.auth.oauth.OAuth2Service` | `derisk_ext.plugin.auth.oauth.OAuth2Service` |
| `derisk_app.auth.user_service.UserEntity` | `derisk_ext.plugin.auth.user.models.UserEntity` |
| `derisk_app.auth.user_service.UserDao` | `derisk_ext.plugin.auth.user.dao.UserDao` |
| `derisk_app.auth.user_service.UserService` | `derisk_ext.plugin.auth.user.service.UserService` |
| `derisk_app.feature_plugins.permissions.dao.PermissionDao` | `derisk_ext.plugin.auth.rbac.dao.PermissionDao` |
| `derisk_app.feature_plugins.permissions.service.PermissionService` | `derisk_ext.plugin.auth.rbac.service.PermissionService` |
| `derisk_app.feature_plugins.permissions.models.*` | `derisk_ext.plugin.auth.rbac.models.*` |
| `derisk_app.feature_plugins.permissions.seed.*` | `derisk_ext.plugin.auth.rbac.seed.*` |
| `derisk_app.feature_plugins.catalog.*` | `derisk_ext.plugin.auth.catalog.*` |
| `derisk_app.feature_plugins.system_config_dao.SystemConfigDao` | `derisk_ext.plugin.auth.system_config.SystemConfigDao` |
| `derisk_app.feature_plugins.system_config_model.SystemConfigEntity` | `derisk_ext.plugin.auth.system_config.SystemConfigEntity` |
| `derisk_app.feature_plugins.user_groups.models.*` | `derisk_ext.plugin.auth.rbac.models.*` |
| `derisk_app.feature_plugins.permissions.checker.require_permission` | `derisk_app.auth.checker.require_permission` |

## Token 格式变更

| 维度 | 旧 | 新 |
|---|---|---|
| 格式 | 自定义 HMAC base64 | 标准 JWT (RS256) |
| 载荷 | `{user: {...}, exp, iat}` | `{sub, name, email, act, rbac, aud, exp, iat}` |
| 签名 | HMAC-SHA256 | RSA-SHA256 |
| Agent 身份 | 无 | `act` claim |
| RBAC 权限 | 每次查 DB | JWT 内嵌（自包含） |

## JWT Claims 示例

```json
{
  "iss": "derisk",
  "sub": "3",
  "name": "张三",
  "email": "zhangsan@example.com",
  "act": {
    "agent_name": "sre-agent",
    "app_id": "app_123",
    "agent_role": "operator"
  },
  "rbac": {
    "role": "editor",
    "roles": ["editor"],
    "permissions": {"agent": ["read", "chat"], "model": ["read"]}
  },
  "aud": ["derisk-api"],
  "exp": 1715692800,
  "iat": 1715088000
}
```

## 配置

| 环境变量 | 说明 | 默认 |
|---|---|---|
| `OAUTH2_JWT_PRIVATE_KEY` | RSA 私钥（PEM） | 自动生成 `~/.derisk/jwt/private.pem` |
| `OAUTH2_JWT_PUBLIC_KEY` | RSA 公钥（PEM） | 自动生成 `~/.derisk/jwt/public.pem` |
| `OAUTH2_JWT_EXPIRE_SECONDS` | Token 过期时间（秒） | 604800 (7 天) |

## 架构变更

```
旧: derisk-app/auth/ + derisk-app/feature_plugins/ (全部逻辑)
新:
  derisk-ext/plugin/auth/   ← 核心逻辑 (JWT + OAuth + User + RBAC)
  derisk-serve/utils/auth.py ← 桥接层
  derisk-app/auth/          ← 薄 Web 适配层
```
