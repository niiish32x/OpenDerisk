"""MOZI (alibaba-inc) OAuth2 provider.

MOZI is Alibaba's internal SSO platform.  This provider uses the legacy
OAuth2 endpoints (access_token.json / user_info.json).

Note: MOZI can also be configured for full OIDC.  When OIDC is enabled on
the MOZI application, the token.json endpoint returns an id_token (JWT)
whose claims carry ``email``, ``picture`` and other fields not available
through the legacy user_info.json API.  To enable that path the provider
would switch *token_url* to token.json and decode the id_token.
"""

import logging
from typing import Any, Dict, Optional

import httpx

from derisk_ext.plugin.auth.providers.base import BaseOAuthProvider, decode_jwt_payload

logger = logging.getLogger(__name__)

MOZI_AUTH_URL = "https://mozi-login.alibaba-inc.com/oauth2/auth.htm"
MOZI_TOKEN_URL = "https://mozi-login.alibaba-inc.com/rpc/oauth2/access_token.json"
MOZI_USERINFO_URL = "https://mozi-login.alibaba-inc.com/rpc/oauth2/user_info.json"

# Fields observed in the user_info.json response:
#   account, empId, employeeCode, lastName, namespace,
#   nickNameCn, openid, realmId, realmName
# Notably *not* returned: email, picture / avatar.


def _claims_to_userinfo(claims: Dict[str, Any]) -> Dict[str, Any]:
    """Convert MOZI id_token claims into our standard user_info dict."""
    return {
        "id": claims.get("sub") or claims.get("emp_id") or "",
        "login": claims.get("account") or claims.get("sub", ""),
        "nickname": claims.get("nickNameCn") or claims.get("nickname", ""),
        "username": claims.get("nickNameCn") or claims.get("name", ""),
        "name": claims.get("realName") or claims.get("name", ""),
        "email": claims.get("email") or claims.get("mail", ""),
        "avatar_url": claims.get("picture", ""),
        "avatar": claims.get("picture", ""),
        "picture": claims.get("picture", ""),
    }


class MoziProvider(BaseOAuthProvider):
    """MOZI (alibaba-inc) OAuth2 provider."""

    def get_authorization_url(
        self,
        provider_config: Dict[str, Any],
        redirect_uri: str,
        state: str,
    ) -> Optional[str]:
        client_id = provider_config.get("client_id", "")
        scope = provider_config.get("scope", "get_user_info")
        if not client_id:
            return None
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "response_type": "code",
        }
        if scope:
            params["scope"] = scope
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{MOZI_AUTH_URL}?{qs}"

    async def exchange_code_for_token(
        self,
        provider_config: Dict[str, Any],
        redirect_uri: str,
        code: str,
    ) -> Optional[Dict[str, Any]]:
        data = {
            "client_id": provider_config.get("client_id", ""),
            "client_secret": provider_config.get("client_secret", ""),
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    MOZI_TOKEN_URL,
                    data=data,
                    headers={"Accept": "application/json"},
                )
                resp.raise_for_status()
                return resp.json()
        except Exception:
            logger.exception("MOZI token exchange failed")
            return None

    async def fetch_userinfo(
        self,
        provider_config: Dict[str, Any],
        token_data: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        id_token = token_data.get("id_token")
        access_token = token_data.get("access_token")

        # Preferred: decode id_token (available when MOZI OIDC is enabled).
        if id_token:
            claims = decode_jwt_payload(id_token)
            if claims:
                logger.info("MOZI userinfo resolved via id_token")
                return _claims_to_userinfo(claims)

        # Fallback: legacy user_info.json API.
        if access_token:
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        MOZI_USERINFO_URL,
                        data={"access_token": access_token},
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded"
                        },
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    return {
                        "id": str(
                            data.get("empId")
                            or data.get("employeeCode")
                            or data.get("openid")
                            or data.get("sub")
                            or data.get("id")
                            or ""
                        ),
                        "login": data.get("account", ""),
                        "nickname": data.get("nickNameCn", ""),
                        "username": data.get("nickNameCn", ""),
                        "name": data.get("lastName", ""),
                        "email": (
                            data.get("email")
                            or data.get("mail")
                            or data.get("email_address")
                            or ""
                        ),
                        "avatar_url": data.get("avatar_url", data.get("avatar", "")),
                        "avatar": data.get("avatar", ""),
                        "picture": data.get("picture", ""),
                    }
            except Exception:
                logger.exception("MOZI userinfo fetch failed")
                return None

        logger.warning(
            "MOZI fetch_userinfo: no id_token and no access_token in token_data "
            "keys=%s", list(token_data.keys())
        )
        return None
